import vm from "node:vm";
import { parse } from "@babel/parser";
import * as t from "@babel/types";
import { generate, traverse, type NodePath } from "./babel-interop.js";

export interface KnownBits {
  /** Bits guaranteed to be 0 (unsigned 32-bit mask). */
  readonly zeroMask: number;
  /** Bits guaranteed to be 1 (unsigned 32-bit mask). */
  readonly oneMask: number;
}

export interface BvSimplifierStats {
  readonly knownBitBindings: number;
  readonly pureDigestCallsEvaluated: number;
  readonly opaquePredicatesFolded: number;
  readonly conditionalStringsCollapsed: number;
  readonly constantExpressionsFolded: number;
  readonly deadBranchesRemoved: number;
  readonly writeOnlyShadowCallsRemoved: number;
  readonly unreachableDeclarationsPruned: number;
  readonly integritySealBindingsDetached: number;
  readonly disjointSensorIifesDetached: number;
}

export interface BvSimplifyResult {
  readonly code: string;
  readonly stats: BvSimplifierStats;
}

const UNKNOWN_BITS: KnownBits = { zeroMask: 0, oneMask: 0 };

function exactBits(val: number): KnownBits {
  const u = (val | 0) >>> 0;
  return {
    oneMask: u,
    zeroMask: (~u) >>> 0,
  };
}

function isExactBits(kb: KnownBits): boolean {
  return ((kb.oneMask | kb.zeroMask) >>> 0) === 0xffffffff;
}

const FORBIDDEN_GLOBALS_IN_PURE_EVAL = new Set([
  "require",
  "process",
  "global",
  "globalThis",
  "window",
  "document",
  "fetch",
  "Buffer",
  "__filename",
  "__dirname",
  "module",
  "exports",
  "console",
  "eval",
  "Function",
]);

function isJsonLiteralAst(node: t.Node | null | undefined): boolean {
  if (!node) return false;
  if (
    t.isStringLiteral(node) ||
    t.isNumericLiteral(node) ||
    t.isBooleanLiteral(node) ||
    t.isNullLiteral(node)
  ) {
    return true;
  }
  if (
    t.isUnaryExpression(node) &&
    node.operator === "-" &&
    t.isNumericLiteral(node.argument)
  ) {
    return true;
  }
  if (t.isArrayExpression(node)) {
    return node.elements.every(
      (el) => el !== null && !t.isSpreadElement(el) && isJsonLiteralAst(el),
    );
  }
  if (t.isObjectExpression(node)) {
    return node.properties.every(
      (p) =>
        t.isObjectProperty(p) && !p.computed && isJsonLiteralAst(p.value),
    );
  }
  if (
    t.isCallExpression(node) &&
    t.isMemberExpression(node.callee) &&
    t.isIdentifier(node.callee.object, { name: "Object" }) &&
    t.isIdentifier(node.callee.property, { name: "freeze" }) &&
    node.arguments.length === 1 &&
    isJsonLiteralAst(node.arguments[0]!)
  ) {
    return true;
  }
  return false;
}

function isSideEffectFreeDataInit(node: t.Node | null | undefined): boolean {
  if (!node) return true;
  if (isJsonLiteralAst(node)) return true;
  if (t.isParenthesizedExpression(node)) {
    return isSideEffectFreeDataInit(node.expression);
  }
  if (t.isBinaryExpression(node) || t.isLogicalExpression(node)) {
    return (
      isSideEffectFreeDataInit(node.left) &&
      isSideEffectFreeDataInit(node.right)
    );
  }
  if (t.isConditionalExpression(node)) {
    return (
      isSideEffectFreeDataInit(node.test) &&
      isSideEffectFreeDataInit(node.consequent) &&
      isSideEffectFreeDataInit(node.alternate)
    );
  }
  if (t.isUnaryExpression(node) && node.operator !== "delete") {
    return isSideEffectFreeDataInit(node.argument);
  }
  if (t.isArrayExpression(node)) {
    return node.elements.every(
      (el) => el !== null && !t.isSpreadElement(el) && isSideEffectFreeDataInit(el),
    );
  }
  if (t.isObjectExpression(node)) {
    return node.properties.every(
      (p) =>
        (t.isObjectProperty(p) &&
          !p.computed &&
          isSideEffectFreeDataInit(p.value)) ||
        (t.isObjectMethod(p) && !p.computed),
    );
  }
  if (
    t.isNewExpression(node) &&
    t.isIdentifier(node.callee, { name: "Array" }) &&
    node.arguments.every((a) => isSideEffectFreeDataInit(a))
  ) {
    return true;
  }
  if (t.isCallExpression(node) && t.isMemberExpression(node.callee) && !node.callee.computed) {
    const prop = node.callee.property;
    if (
      t.isIdentifier(node.callee.object, { name: "Object" }) &&
      t.isIdentifier(prop, { name: "freeze" }) &&
      node.arguments.length === 1 &&
      isSideEffectFreeDataInit(node.arguments[0]!)
    ) {
      return true;
    }
    if (
      t.isIdentifier(prop) &&
      (prop.name === "concat" ||
        prop.name === "split" ||
        prop.name === "slice" ||
        prop.name === "fill")
    ) {
      return (
        isSideEffectFreeDataInit(node.callee.object) &&
        node.arguments.every((a) => isSideEffectFreeDataInit(a))
      );
    }
    if (t.isIdentifier(prop, { name: "map" }) && isSideEffectFreeDataInit(node.callee.object)) {
      const cb = node.arguments[0];
      if (cb && (t.isFunctionExpression(cb) || t.isArrowFunctionExpression(cb))) {
        return true;
      }
    }
  }
  return false;
}

/**
 * Evaluates a self-contained pure top-level function call (such as BLA's
 * `_deriveContainmentCorpusDigest_<tag>(0)`) inside a zero-capability VM context.
 */
function tryEvalClosedPureCall(
  call: t.CallExpression,
  topFunctions: ReadonlyMap<string, t.FunctionDeclaration>,
  pureConstDecls: ReadonlyMap<string, t.VariableDeclarator>,
): number | boolean | string | undefined {
  if (!t.isIdentifier(call.callee)) return undefined;
  const fnDecl = topFunctions.get(call.callee.name);
  if (!fnDecl) return undefined;
  if (!call.arguments.every((a) => isJsonLiteralAst(a))) return undefined;

  const neededConsts = new Set<string>();
  let safe = true;
  const subAst = t.file(t.program([t.cloneNode(fnDecl, true)]));
  traverse(subAst, {
    ReferencedIdentifier(p) {
      const name = p.node.name;
      if (p.scope.hasBinding(name)) return;
      if (
        name === "Math" ||
        name === "Array" ||
        name === "Object" ||
        name === "String" ||
        name === "Number" ||
        name === "undefined"
      ) {
        return;
      }
      if (FORBIDDEN_GLOBALS_IN_PURE_EVAL.has(name)) {
        safe = false;
        p.stop();
        return;
      }
      if (pureConstDecls.has(name)) {
        neededConsts.add(name);
      } else {
        safe = false;
        p.stop();
      }
    },
  });
  if (!safe) return undefined;

  const preludeLines: string[] = [];
  for (const cname of neededConsts) {
    const decl = pureConstDecls.get(cname)!;
    preludeLines.push(`const ${cname} = ${generate(decl.init!).code};`);
  }
  preludeLines.push(generate(fnDecl).code);
  preludeLines.push(`(${generate(call).code});`);

  try {
    const sandbox = vm.createContext({
      Math,
      Array,
      Object,
      String,
      Number,
    });
    const res: unknown = vm.runInContext(preludeLines.join("\n"), sandbox, {
      timeout: 50,
    });
    if (
      typeof res === "number" ||
      typeof res === "boolean" ||
      typeof res === "string"
    ) {
      return res;
    }
  } catch {
    return undefined;
  }
  return undefined;
}

function isTypeofFunctionEveryCheck(
  node: t.Node,
  topFunctions: ReadonlyMap<string, t.FunctionDeclaration>,
): boolean {
  // Matches `[fn1, fn2, ...].every(_f => typeof _f === "function")`
  if (
    !t.isCallExpression(node) ||
    !t.isMemberExpression(node.callee) ||
    node.callee.computed ||
    !t.isIdentifier(node.callee.property, { name: "every" }) ||
    !t.isArrayExpression(node.callee.object) ||
    node.arguments.length !== 1
  ) {
    return false;
  }
  const elements = node.callee.object.elements;
  if (elements.length === 0) return false;
  for (const el of elements) {
    if (!el || !t.isIdentifier(el) || !topFunctions.has(el.name)) {
      return false;
    }
  }
  const pred = node.arguments[0]!;
  if (!t.isArrowFunctionExpression(pred) && !t.isFunctionExpression(pred)) {
    return false;
  }
  if (pred.params.length !== 1 || !t.isIdentifier(pred.params[0]!)) {
    return false;
  }
  const paramName = pred.params[0]!.name;
  let bodyExpr: t.Node | null = null;
  if (t.isExpression(pred.body)) {
    bodyExpr = pred.body;
  } else if (
    t.isBlockStatement(pred.body) &&
    pred.body.body.length === 1 &&
    t.isReturnStatement(pred.body.body[0]!) &&
    pred.body.body[0]!.argument
  ) {
    bodyExpr = pred.body.body[0]!.argument;
  }
  if (!bodyExpr || !t.isBinaryExpression(bodyExpr, { operator: "===" })) {
    return false;
  }
  return (
    t.isUnaryExpression(bodyExpr.left, { operator: "typeof" }) &&
    t.isIdentifier(bodyExpr.left.argument, { name: paramName }) &&
    t.isStringLiteral(bodyExpr.right, { value: "function" })
  );
}

function inferKnownBits(
  node: t.Node | null | undefined,
  knownMap: ReadonlyMap<string, KnownBits>,
  topFunctions: ReadonlyMap<string, t.FunctionDeclaration>,
  pureConstDecls: ReadonlyMap<string, t.VariableDeclarator>,
  counter: { pureDigestCallsEvaluated: number },
): KnownBits {
  if (!node) return UNKNOWN_BITS;
  if (t.isParenthesizedExpression(node)) {
    return inferKnownBits(
      node.expression,
      knownMap,
      topFunctions,
      pureConstDecls,
      counter,
    );
  }
  if (t.isNumericLiteral(node)) {
    return exactBits(node.value);
  }
  if (t.isUnaryExpression(node)) {
    if (node.operator === "-" && t.isNumericLiteral(node.argument)) {
      return exactBits(-node.argument.value);
    }
    if (node.operator === "~") {
      const inner = inferKnownBits(
        node.argument,
        knownMap,
        topFunctions,
        pureConstDecls,
        counter,
      );
      return { oneMask: inner.zeroMask, zeroMask: inner.oneMask };
    }
  }
  if (t.isIdentifier(node)) {
    return knownMap.get(node.name) ?? UNKNOWN_BITS;
  }
  if (t.isConditionalExpression(node)) {
    const testVal = tryEvaluateStaticBool(
      node.test,
      knownMap,
      topFunctions,
      pureConstDecls,
      counter,
    );
    if (testVal === true) {
      return inferKnownBits(
        node.consequent,
        knownMap,
        topFunctions,
        pureConstDecls,
        counter,
      );
    }
    if (testVal === false) {
      return inferKnownBits(
        node.alternate,
        knownMap,
        topFunctions,
        pureConstDecls,
        counter,
      );
    }
    const cBits = inferKnownBits(
      node.consequent,
      knownMap,
      topFunctions,
      pureConstDecls,
      counter,
    );
    const aBits = inferKnownBits(
      node.alternate,
      knownMap,
      topFunctions,
      pureConstDecls,
      counter,
    );
    return {
      oneMask: (cBits.oneMask & aBits.oneMask) >>> 0,
      zeroMask: (cBits.zeroMask & aBits.zeroMask) >>> 0,
    };
  }
  if (t.isBinaryExpression(node)) {
    const left = inferKnownBits(
      node.left,
      knownMap,
      topFunctions,
      pureConstDecls,
      counter,
    );
    const right = inferKnownBits(
      node.right,
      knownMap,
      topFunctions,
      pureConstDecls,
      counter,
    );
    switch (node.operator) {
      case "&":
        return {
          oneMask: (left.oneMask & right.oneMask) >>> 0,
          zeroMask: (left.zeroMask | right.zeroMask) >>> 0,
        };
      case "|":
        return {
          oneMask: (left.oneMask | right.oneMask) >>> 0,
          zeroMask: (left.zeroMask & right.zeroMask) >>> 0,
        };
      case "^":
        return {
          oneMask:
            ((left.oneMask & right.zeroMask) |
              (left.zeroMask & right.oneMask)) >>>
            0,
          zeroMask:
            ((left.zeroMask & right.zeroMask) |
              (left.oneMask & right.oneMask)) >>>
            0,
        };
      case ">>>":
        if (isExactBits(right)) {
          const shift = right.oneMask & 31;
          const topZeros = shift === 0 ? 0 : (~(0xffffffff >>> shift)) >>> 0;
          return {
            oneMask: (left.oneMask >>> shift) >>> 0,
            zeroMask: ((left.zeroMask >>> shift) | topZeros) >>> 0,
          };
        }
        return UNKNOWN_BITS;
      case "<<":
        if (isExactBits(right)) {
          const shift = right.oneMask & 31;
          const lowZeros = shift === 0 ? 0 : ((1 << shift) - 1) >>> 0;
          return {
            oneMask: (left.oneMask << shift) >>> 0,
            zeroMask: ((left.zeroMask << shift) | lowZeros) >>> 0,
          };
        }
        return UNKNOWN_BITS;
      default:
        return UNKNOWN_BITS;
    }
  }
  return UNKNOWN_BITS;
}

function tryEvaluateStaticBool(
  node: t.Node,
  knownMap: ReadonlyMap<string, KnownBits>,
  topFunctions: ReadonlyMap<string, t.FunctionDeclaration>,
  pureConstDecls: ReadonlyMap<string, t.VariableDeclarator>,
  counter: { pureDigestCallsEvaluated: number },
): boolean | undefined {
  if (t.isParenthesizedExpression(node)) {
    return tryEvaluateStaticBool(
      node.expression,
      knownMap,
      topFunctions,
      pureConstDecls,
      counter,
    );
  }
  if (t.isBooleanLiteral(node)) return node.value;
  if (isTypeofFunctionEveryCheck(node, topFunctions)) {
    return true;
  }
  if (t.isLogicalExpression(node)) {
    const lv = tryEvaluateStaticBool(
      node.left,
      knownMap,
      topFunctions,
      pureConstDecls,
      counter,
    );
    if (node.operator === "&&") {
      if (lv === false) return false;
      if (lv === true) {
        return tryEvaluateStaticBool(
          node.right,
          knownMap,
          topFunctions,
          pureConstDecls,
          counter,
        );
      }
      return undefined;
    }
    if (node.operator === "||") {
      if (lv === true) return true;
      if (lv === false) {
        return tryEvaluateStaticBool(
          node.right,
          knownMap,
          topFunctions,
          pureConstDecls,
          counter,
        );
      }
      return undefined;
    }
  }
  if (
    t.isBinaryExpression(node) &&
    (node.operator === "===" || node.operator === "!==")
  ) {
    if (
      t.isUnaryExpression(node.left, { operator: "typeof" }) &&
      t.isIdentifier(node.left.argument) &&
      topFunctions.has(node.left.argument.name) &&
      t.isStringLiteral(node.right)
    ) {
      const eq = node.right.value === "function";
      return node.operator === "===" ? eq : !eq;
    }
    const evalSide = (side: t.Node): number | string | boolean | undefined => {
      if (t.isNumericLiteral(side)) return side.value;
      if (t.isStringLiteral(side)) return side.value;
      if (t.isBooleanLiteral(side)) return side.value;
      if (t.isCallExpression(side)) {
        const val = tryEvalClosedPureCall(side, topFunctions, pureConstDecls);
        if (val !== undefined) counter.pureDigestCallsEvaluated++;
        return val;
      }
      const kb = inferKnownBits(
        side,
        knownMap,
        topFunctions,
        pureConstDecls,
        counter,
      );
      if (isExactBits(kb)) return kb.oneMask | 0;
      return undefined;
    };
    const lv = evalSide(node.left);
    const rv = evalSide(node.right);
    if (lv !== undefined && rv !== undefined) {
      return node.operator === "===" ? lv === rv : lv !== rv;
    }
  }
  return undefined;
}

interface ExprAnalysis {
  readonly pure: boolean;
  readonly varCounts: Map<string, number>;
  readonly hasBitwiseOrImul: boolean;
  readonly numericLiterals: number[];
}

const ALLOWED_BINARY_OPS = new Set([
  "+",
  "-",
  "*",
  "&",
  "|",
  "^",
  "<<",
  ">>",
  ">>>",
  "===",
  "!==",
  "==",
  "!=",
  "<",
  "<=",
  ">",
  ">=",
]);

const BITWISE_OPS = new Set(["&", "|", "^", "<<", ">>", ">>>"]);

function analyzePureBitVectorExpr(node: t.Node): ExprAnalysis {
  const varCounts = new Map<string, number>();
  const numericLiterals: number[] = [];
  let pure = true;
  let hasBitwiseOrImul = false;

  function visit(n: t.Node | null | undefined): void {
    if (!pure || !n) {
      pure = false;
      return;
    }
    if (t.isParenthesizedExpression(n)) {
      visit(n.expression);
      return;
    }
    if (t.isNumericLiteral(n)) {
      numericLiterals.push(n.value);
      return;
    }
    if (t.isBooleanLiteral(n)) {
      return;
    }
    if (t.isIdentifier(n)) {
      if (n.name === "undefined" || n.name === "NaN" || n.name === "Infinity") {
        pure = false;
        return;
      }
      varCounts.set(n.name, (varCounts.get(n.name) ?? 0) + 1);
      return;
    }
    if (t.isUnaryExpression(n)) {
      if (
        n.operator === "-" ||
        n.operator === "+" ||
        n.operator === "~" ||
        n.operator === "!"
      ) {
        if (n.operator === "~") hasBitwiseOrImul = true;
        visit(n.argument);
        return;
      }
      pure = false;
      return;
    }
    if (t.isBinaryExpression(n)) {
      if (!ALLOWED_BINARY_OPS.has(n.operator) || !t.isExpression(n.left)) {
        pure = false;
        return;
      }
      if (BITWISE_OPS.has(n.operator)) hasBitwiseOrImul = true;
      visit(n.left);
      visit(n.right);
      return;
    }
    if (t.isLogicalExpression(n)) {
      if (n.operator === "&&" || n.operator === "||") {
        visit(n.left);
        visit(n.right);
        return;
      }
      pure = false;
      return;
    }
    if (t.isCallExpression(n)) {
      if (
        t.isMemberExpression(n.callee) &&
        !n.callee.computed &&
        t.isIdentifier(n.callee.object, { name: "Math" }) &&
        t.isIdentifier(n.callee.property, { name: "imul" }) &&
        n.arguments.length === 2 &&
        t.isExpression(n.arguments[0]!) &&
        t.isExpression(n.arguments[1]!)
      ) {
        hasBitwiseOrImul = true;
        visit(n.arguments[0]!);
        visit(n.arguments[1]!);
        return;
      }
      pure = false;
      return;
    }
    pure = false;
  }

  visit(node);
  return { pure, varCounts, hasBitwiseOrImul, numericLiterals };
}

function evalAstWithEnv(
  node: t.Node,
  env: ReadonlyMap<string, number>,
): number | boolean {
  if (t.isParenthesizedExpression(node)) {
    return evalAstWithEnv(node.expression, env);
  }
  if (t.isNumericLiteral(node)) return node.value;
  if (t.isBooleanLiteral(node)) return node.value;
  if (t.isIdentifier(node)) {
    const v = env.get(node.name);
    if (v === undefined) throw new Error(`Unbound var ${node.name}`);
    return v;
  }
  if (t.isUnaryExpression(node)) {
    const arg = evalAstWithEnv(node.argument, env);
    switch (node.operator) {
      case "-":
        return -(arg as number);
      case "+":
        return +(arg as number);
      case "~":
        return ~(arg as number);
      case "!":
        return !arg;
      default:
        throw new Error(`Unsupported unary ${node.operator}`);
    }
  }
  if (t.isLogicalExpression(node)) {
    const lv = evalAstWithEnv(node.left, env);
    if (node.operator === "&&") return lv ? evalAstWithEnv(node.right, env) : lv;
    if (node.operator === "||") return lv ? lv : evalAstWithEnv(node.right, env);
    throw new Error(`Unsupported logical ${node.operator}`);
  }
  if (t.isBinaryExpression(node)) {
    const lv = evalAstWithEnv(node.left as t.Node, env) as any;
    const rv = evalAstWithEnv(node.right, env) as any;
    switch (node.operator) {
      case "+":
        return lv + rv;
      case "-":
        return lv - rv;
      case "*":
        return lv * rv;
      case "&":
        return lv & rv;
      case "|":
        return lv | rv;
      case "^":
        return lv ^ rv;
      case "<<":
        return lv << rv;
      case ">>":
        return lv >> rv;
      case ">>>":
        return lv >>> rv;
      case "===":
        return lv === rv;
      case "!==":
        return lv !== rv;
      case "==":
        // eslint-disable-next-line eqeqeq
        return lv == rv;
      case "!=":
        // eslint-disable-next-line eqeqeq
        return lv != rv;
      case "<":
        return lv < rv;
      case "<=":
        return lv <= rv;
      case ">":
        return lv > rv;
      case ">=":
        return lv >= rv;
      default:
        throw new Error(`Unsupported binary ${node.operator}`);
    }
  }
  if (t.isCallExpression(node)) {
    const a0 = Number(evalAstWithEnv(node.arguments[0]!, env));
    const a1 = Number(evalAstWithEnv(node.arguments[1]!, env));
    return Math.imul(a0, a1);
  }
  throw new Error(`Unsupported AST node ${node.type}`);
}

const BASIS_VECTORS: readonly number[] = (() => {
  const vec: number[] = [
    0,
    1,
    -1,
    2,
    -2,
    3,
    5,
    7,
    8,
    15,
    16,
    31,
    32,
    63,
    64,
    127,
    255,
    1024,
    4096,
    65535,
    0x7fffffff,
    -0x80000000,
    0x55555555,
    -0x55555556,
    0x12345678,
    -0x61c88647,
  ];
  let s = 0x9e3779b9;
  for (let i = 0; i < 38; i++) {
    s = (Math.imul(s ^ (s >>> 15), 0x85ebca6b) + 0xc2b2ae35) | 0;
    vec.push(s);
  }
  return vec;
})();

function evaluateBitVectorBoolInvariant(
  node: t.Expression,
  scope: NodePath["scope"],
  knownBitsMap: ReadonlyMap<string, KnownBits>,
  programScope: NodePath["scope"],
): boolean | undefined {
  const info = analyzePureBitVectorExpr(node);
  if (!info.pure) return undefined;
  if (info.varCounts.size > 3) return undefined;

  const vars = [...info.varCounts.keys()];
  if (vars.length === 0) {
    try {
      const val = evalAstWithEnv(node, new Map());
      return typeof val === "boolean" ? val : undefined;
    } catch {
      return undefined;
    }
  }

  const varConstraints = new Map<string, KnownBits>();
  for (const v of vars) {
    const binding = scope.getBinding(v);
    const isTopLevelKnown =
      knownBitsMap.has(v) &&
      binding !== undefined &&
      binding.scope === programScope &&
      binding.constant;
    if (isTopLevelKnown) {
      varConstraints.set(v, knownBitsMap.get(v)!);
    } else if ((info.varCounts.get(v) ?? 0) >= 2 && info.hasBitwiseOrImul) {
      varConstraints.set(v, UNKNOWN_BITS);
    } else {
      return undefined;
    }
  }

  const candidatePool: number[] = [...BASIS_VECTORS];
  for (const lit of info.numericLiterals) {
    const n = lit | 0;
    candidatePool.push(n, (n - 1) | 0, (n + 1) | 0, ~n, (n ^ 1) | 0);
  }

  let expected: boolean | undefined;
  const env = new Map<string, number>();

  for (let i = 0; i < candidatePool.length; i++) {
    for (let mode = 0; mode < 2; mode++) {
      for (let vIdx = 0; vIdx < vars.length; vIdx++) {
        const vName = vars[vIdx]!;
        const kb = varConstraints.get(vName)!;
        const raw = candidatePool[(i + vIdx * 17) % candidatePool.length]!;
        const maskedUnsigned =
          (((raw >>> 0) & (~kb.zeroMask >>> 0)) | kb.oneMask) >>> 0;
        const val =
          mode === 0 || (kb.oneMask & 0x80000000) !== 0
            ? maskedUnsigned | 0
            : maskedUnsigned >>> 0;
        env.set(vName, val);
      }
      let out: number | boolean;
      try {
        out = evalAstWithEnv(node, env);
      } catch {
        return undefined;
      }
      if (typeof out !== "boolean") return undefined;
      if (expected === undefined) {
        expected = out;
      } else if (out !== expected) {
        return undefined;
      }
    }
  }

  return expected;
}

function hasLexicalDeclarations(stmts: readonly t.Statement[]): boolean {
  return stmts.some(
    (s) =>
      (t.isVariableDeclaration(s) && s.kind !== "var") ||
      t.isFunctionDeclaration(s) ||
      t.isClassDeclaration(s),
  );
}

function unwrapParens(node: t.Node): t.Node {
  let cur = node;
  while (t.isParenthesizedExpression(cur)) {
    cur = cur.expression;
  }
  return cur;
}

function stripDisjointSensorIifes(ast: t.File): number {
  let removed = 0;
  ast.program.body = ast.program.body.filter((stmt) => {
    if (!t.isExpressionStatement(stmt)) return true;
    let expr = unwrapParens(stmt.expression);
    if (t.isUnaryExpression(expr, { operator: "void" })) {
      expr = unwrapParens(expr.argument);
    }
    if (!t.isCallExpression(expr) || expr.arguments.length !== 0) {
      return true;
    }
    const callee = unwrapParens(expr.callee);
    if (!t.isFunctionExpression(callee) && !t.isArrowFunctionExpression(callee)) {
      return true;
    }
    const iifeCode = generate(stmt).code;
    const touchesModuleExports = /\bexports\b|\bmodule\b/.test(iifeCode);
    const isSensorDeceptionIife =
      iifeCode.includes("HARDWARE_ENCLAVE_DELEGATED") ||
      iifeCode.includes("enclave:vsock:attestation-ready") ||
      iifeCode.includes("TEE-ENCLAVE-SOVEREIGN:");
    if (!touchesModuleExports && isSensorDeceptionIife) {
      removed++;
      return false;
    }
    return true;
  });
  return removed;
}

function stripWriteOnlyShadowHeapCalls(
  ast: t.File,
  exportedNames: ReadonlySet<string>,
): number {
  const programBody = ast.program.body;
  const topVarObjects = new Set<string>();
  const topFunctions = new Map<string, t.FunctionDeclaration>();

  for (const stmt of programBody) {
    if (t.isVariableDeclaration(stmt)) {
      for (const decl of stmt.declarations) {
        if (
          t.isIdentifier(decl.id) &&
          !exportedNames.has(decl.id.name) &&
          decl.init &&
          t.isObjectExpression(decl.init)
        ) {
          topVarObjects.add(decl.id.name);
        }
      }
    } else if (
      t.isFunctionDeclaration(stmt) &&
      stmt.id &&
      !exportedNames.has(stmt.id.name)
    ) {
      topFunctions.set(stmt.id.name, stmt);
    }
  }

  if (topVarObjects.size === 0) return 0;

  const deadStepperFns = new Set<string>();

  for (const heapName of topVarObjects) {
    let referencedOutsidePrivateFns = false;
    const touchingFns = new Set<string>();

    traverse(ast, {
      ReferencedIdentifier(p) {
        if (p.node.name !== heapName) return;
        const fnParent = p.getFunctionParent();
        if (
          !fnParent ||
          !fnParent.isFunctionDeclaration() ||
          !fnParent.node.id
        ) {
          referencedOutsidePrivateFns = true;
          return;
        }
        const fnName = fnParent.node.id.name;
        if (!topFunctions.has(fnName) || exportedNames.has(fnName)) {
          referencedOutsidePrivateFns = true;
          return;
        }
        touchingFns.add(fnName);
      },
    });

    if (referencedOutsidePrivateFns || touchingFns.size === 0) continue;

    let allPureClosed = true;
    for (const fnName of touchingFns) {
      const fnNode = topFunctions.get(fnName)!;
      const fnFile = t.file(t.program([t.cloneNode(fnNode, true)]));
      traverse(fnFile, {
        ThrowStatement(p) {
          allPureClosed = false;
          p.stop();
        },
        AssignmentExpression(p) {
          let root: t.Node = p.node.left;
          while (t.isMemberExpression(root)) {
            root = root.object;
          }
          if (!t.isIdentifier(root)) {
            allPureClosed = false;
            p.stop();
            return;
          }
          if (root.name !== heapName && !p.scope.hasBinding(root.name)) {
            allPureClosed = false;
            p.stop();
          }
        },
        ReferencedIdentifier(p) {
          const name = p.node.name;
          if (
            name === heapName ||
            touchingFns.has(name) ||
            p.scope.hasBinding(name)
          ) {
            return;
          }
          if (
            name === "Math" ||
            name === "Array" ||
            name === "String" ||
            name === "Number"
          ) {
            return;
          }
          allPureClosed = false;
          p.stop();
        },
      });
      if (!allPureClosed) break;
    }
    if (!allPureClosed) continue;

    let callSitesDiscardedOnly = true;
    traverse(ast, {
      ReferencedIdentifier(p) {
        const fnName = p.node.name;
        if (!touchingFns.has(fnName)) return;
        const fnParent = p.getFunctionParent();
        if (
          fnParent &&
          fnParent.isFunctionDeclaration() &&
          fnParent.node.id &&
          touchingFns.has(fnParent.node.id.name)
        ) {
          return;
        }
        if (p.parentPath.isUnaryExpression({ operator: "void" })) return;
        if (
          p.parentPath.isCallExpression() &&
          p.parentPath.node.callee === p.node &&
          p.parentPath.parentPath.isExpressionStatement() &&
          p.parentPath.node.arguments.every((a: t.Node) =>
            isSideEffectFreeDataInit(a),
          )
        ) {
          return;
        }
        callSitesDiscardedOnly = false;
        p.stop();
      },
    });

    if (callSitesDiscardedOnly) {
      for (const fnName of touchingFns) deadStepperFns.add(fnName);
    }
  }

  if (deadStepperFns.size === 0) return 0;

  let removedCalls = 0;
  traverse(ast, {
    ExpressionStatement(p) {
      const expr = p.node.expression;
      if (
        t.isCallExpression(expr) &&
        t.isIdentifier(expr.callee) &&
        deadStepperFns.has(expr.callee.name)
      ) {
        p.remove();
        removedCalls++;
      }
    },
  });

  return removedCalls;
}

function looksLikeSelfSealMeasureFunction(fn: t.FunctionDeclaration): boolean {
  const code = generate(fn).code;
  return (
    code.includes("node:crypto") &&
    code.includes("createHash") &&
    code.includes("digest >>> 0")
  );
}

function isSelfSealDigestAst(
  init: t.Node | null | undefined,
  selfSealMeasureFns: ReadonlySet<string>,
): boolean {
  if (!init || selfSealMeasureFns.size === 0) return false;
  let found = false;
  const check = (n: t.Node | null | undefined): void => {
    if (!n || found) return;
    if (
      t.isCallExpression(n) &&
      t.isIdentifier(n.callee) &&
      selfSealMeasureFns.has(n.callee.name)
    ) {
      found = true;
      return;
    }
    if (t.isBinaryExpression(n)) {
      check(n.left);
      check(n.right);
    } else if (t.isParenthesizedExpression(n)) {
      check(n.expression);
    }
  };
  check(init);
  return found;
}

function isProcessPidSeedAst(init: t.Node | null | undefined): boolean {
  if (!init) return false;
  // Matches `((typeof process !== "undefined" && process.pid ? process.pid & 0xff : 42) | 1)`
  if (
    t.isBinaryExpression(init, { operator: "|" }) &&
    t.isNumericLiteral(init.right, { value: 1 }) &&
    t.isConditionalExpression(init.left)
  ) {
    return true;
  }
  return false;
}

function isNoopTopExpressionStatement(
  stmt: t.Statement,
  topDeclaredNames: ReadonlySet<string>,
): boolean {
  if (!t.isExpressionStatement(stmt)) return false;
  let expr = unwrapParens(stmt.expression);
  if (t.isUnaryExpression(expr, { operator: "void" })) {
    expr = unwrapParens(expr.argument);
  }
  if (t.isIdentifier(expr) && topDeclaredNames.has(expr.name)) {
    return true;
  }
  if (
    t.isStringLiteral(expr) ||
    t.isNumericLiteral(expr) ||
    t.isBooleanLiteral(expr)
  ) {
    return true;
  }
  if (t.isArrayExpression(expr)) {
    return expr.elements.every(
      (el) =>
        el !== null &&
        !t.isSpreadElement(el) &&
        ((t.isIdentifier(el) && topDeclaredNames.has(el.name)) ||
          isJsonLiteralAst(el)),
    );
  }
  return false;
}

/**
 * O(V + E) forward reachability slicer from module export roots and
 * top-level side-effecting statements.
 */
function pruneUnreferencedTopDeclarations(
  ast: t.File,
  exportedNames: ReadonlySet<string>,
  knownBitsMap: ReadonlyMap<string, KnownBits>,
  selfSealMeasureFns: ReadonlySet<string>,
): { pruned: number; sealDetached: number } {
  let programScope!: NodePath["scope"];
  traverse(ast, {
    Program(p) {
      p.scope.crawl();
      programScope = p.scope;
      p.stop();
    },
  });

  const prunableFns = new Map<t.FunctionDeclaration, string>();
  const prunableDecls = new Map<t.VariableDeclarator, { name: string; isSeal: boolean }>();

  for (const stmt of ast.program.body) {
    if (t.isFunctionDeclaration(stmt) && stmt.id && !exportedNames.has(stmt.id.name)) {
      prunableFns.set(stmt, stmt.id.name);
    } else if (t.isVariableDeclaration(stmt)) {
      for (const decl of stmt.declarations) {
        if (!t.isIdentifier(decl.id) || exportedNames.has(decl.id.name)) continue;
        const name = decl.id.name;
        const isSeal = isSelfSealDigestAst(decl.init, selfSealMeasureFns);
        const isSafeToDrop =
          isSideEffectFreeDataInit(decl.init) ||
          knownBitsMap.has(name) ||
          isSeal ||
          isProcessPidSeedAst(decl.init);
        if (isSafeToDrop) {
          prunableDecls.set(decl, { name, isSeal });
        }
      }
    }
  }

  const edges = new Map<string, Set<string>>();
  const roots = new Set<string>(exportedNames);

  const addEdge = (from: string, to: string) => {
    if (from === to) return;
    let s = edges.get(from);
    if (!s) {
      s = new Set();
      edges.set(from, s);
    }
    s.add(to);
  };

  traverse(ast, {
    ReferencedIdentifier(p) {
      const refName = p.node.name;
      const binding = p.scope.getBinding(refName);
      if (!binding || binding.scope !== programScope) return;

      // Determine which top-level unit owns this reference
      let ownerSymbol: string | null = null;
      let cur: NodePath | null = p;
      while (cur && cur.parentPath && !cur.parentPath.isProgram()) {
        if (cur.isVariableDeclarator() && cur.parentPath.parentPath?.isProgram()) {
          const info = prunableDecls.get(cur.node);
          if (info) ownerSymbol = info.name;
          break;
        }
        cur = cur.parentPath;
      }
      if (ownerSymbol === null && cur && cur.isFunctionDeclaration()) {
        ownerSymbol = prunableFns.get(cur.node) ?? null;
      }

      if (ownerSymbol !== null) {
        addEdge(ownerSymbol, refName);
      } else {
        roots.add(refName);
      }
    },
  });

  // BFS from roots
  const reachable = new Set<string>(roots);
  const queue = [...roots];
  while (queue.length > 0) {
    const sym = queue.pop()!;
    const targets = edges.get(sym);
    if (!targets) continue;
    for (const next of targets) {
      if (!reachable.has(next)) {
        reachable.add(next);
        queue.push(next);
      }
    }
  }

  let pruned = 0;
  let sealDetached = 0;
  const nextBody: t.Statement[] = [];

  for (const stmt of ast.program.body) {
    if (t.isFunctionDeclaration(stmt) && prunableFns.has(stmt)) {
      const sym = prunableFns.get(stmt)!;
      if (!reachable.has(sym)) {
        pruned++;
        continue;
      }
    } else if (t.isVariableDeclaration(stmt)) {
      const keptDecls: t.VariableDeclarator[] = [];
      for (const decl of stmt.declarations) {
        const info = prunableDecls.get(decl);
        if (info && !reachable.has(info.name)) {
          pruned++;
          if (info.isSeal) sealDetached++;
          continue;
        }
        keptDecls.push(decl);
      }
      if (keptDecls.length === 0) continue;
      stmt.declarations = keptDecls;
    }
    nextBody.push(stmt);
  }

  ast.program.body = nextBody;
  return { pruned, sealDetached };
}

/**
 * Runs 32-bit bit-vector & parity-invariant constant folding, collapses
 * BLA's combinatorial strings & split integers, eliminates dead tarpit branches,
 * removes write-only shadow-heap churn calls, and slices unreachable chaff/deception
 * declarations in memory (zero disk mutation).
 */
export function simplifyJavaScriptWithBv(source: string): BvSimplifyResult {
  const ast = parse(source, {
    sourceType: "unambiguous",
    plugins: ["typescript", "jsx"],
  });

  let pureDigestCallsEvaluated = 0;
  let opaquePredicatesFolded = 0;
  let conditionalStringsCollapsed = 0;
  let constantExpressionsFolded = 0;
  let deadBranchesRemoved = 0;

  // 1. Collect top-level immutable candidates & pure helper functions
  const topFunctions = new Map<string, t.FunctionDeclaration>();
  const pureConstDecls = new Map<string, t.VariableDeclarator>();
  const mutatedBindings = new Set<string>();

  traverse(ast, {
    AssignmentExpression(p) {
      const ids = t.getBindingIdentifiers(p.node.left);
      for (const k of Object.keys(ids)) mutatedBindings.add(k);
    },
    UpdateExpression(p) {
      if (t.isIdentifier(p.node.argument)) {
        mutatedBindings.add(p.node.argument.name);
      }
    },
  });

  for (const stmt of ast.program.body) {
    if (t.isFunctionDeclaration(stmt) && stmt.id) {
      topFunctions.set(stmt.id.name, stmt);
    } else if (t.isVariableDeclaration(stmt)) {
      for (const decl of stmt.declarations) {
        if (
          t.isIdentifier(decl.id) &&
          !mutatedBindings.has(decl.id.name) &&
          isJsonLiteralAst(decl.init)
        ) {
          pureConstDecls.set(decl.id.name, decl);
        }
      }
    }
  }

  // 2. Infer KnownBits for top-level non-mutated integer bindings (including typeof-entangled seeds)
  const knownBitsMap = new Map<string, KnownBits>();
  const digestCounter = { pureDigestCallsEvaluated: 0 };

  for (const stmt of ast.program.body) {
    if (!t.isVariableDeclaration(stmt)) continue;
    for (const decl of stmt.declarations) {
      if (
        !t.isIdentifier(decl.id) ||
        mutatedBindings.has(decl.id.name) ||
        !decl.init
      ) {
        continue;
      }
      const kb = inferKnownBits(
        decl.init,
        knownBitsMap,
        topFunctions,
        pureConstDecls,
        digestCounter,
      );
      if ((kb.oneMask | kb.zeroMask) !== 0) {
        knownBitsMap.set(decl.id.name, kb);
      }
    }
  }
  pureDigestCallsEvaluated = digestCounter.pureDigestCallsEvaluated;

  let programScope!: NodePath["scope"];
  traverse(ast, {
    Program(p) {
      programScope = p.scope;
      p.stop();
    },
  });

  // 3. Fixed-point bit-vector predicate & constant folding
  for (let pass = 0; pass < 6; pass++) {
    let changed = false;

    traverse(ast, {
      ConditionalExpression: {
        exit(p) {
          if (!t.isBooleanLiteral(p.node.test)) {
            const inv = evaluateBitVectorBoolInvariant(
              p.node.test,
              p.scope,
              knownBitsMap,
              programScope,
            );
            if (inv !== undefined) {
              p.get("test").replaceWith(t.booleanLiteral(inv));
              opaquePredicatesFolded++;
              changed = true;
            }
          }
          if (t.isBooleanLiteral(p.node.test)) {
            const branch = p.node.test.value
              ? p.node.consequent
              : p.node.alternate;
            if (t.isStringLiteral(branch)) conditionalStringsCollapsed++;
            p.replaceWith(branch);
            constantExpressionsFolded++;
            changed = true;
          }
        },
      },
      IfStatement: {
        exit(p) {
          if (!t.isBooleanLiteral(p.node.test)) {
            const inv = evaluateBitVectorBoolInvariant(
              p.node.test,
              p.scope,
              knownBitsMap,
              programScope,
            );
            if (inv !== undefined) {
              p.get("test").replaceWith(t.booleanLiteral(inv));
              opaquePredicatesFolded++;
              changed = true;
            }
          }
          if (t.isBooleanLiteral(p.node.test)) {
            if (p.node.test.value) {
              const cons = p.node.consequent;
              if (t.isBlockStatement(cons) && !hasLexicalDeclarations(cons.body)) {
                p.replaceWithMultiple(cons.body);
              } else {
                p.replaceWith(cons);
              }
              deadBranchesRemoved++;
              changed = true;
            } else {
              if (p.node.alternate) {
                const alt = p.node.alternate;
                if (t.isBlockStatement(alt) && !hasLexicalDeclarations(alt.body)) {
                  p.replaceWithMultiple(alt.body);
                } else {
                  p.replaceWith(alt);
                }
              } else {
                p.remove();
              }
              deadBranchesRemoved++;
              changed = true;
            }
          }
        },
      },
      BinaryExpression: {
        exit(p) {
          const { left, right, operator } = p.node;
          if (
            operator === "+" &&
            t.isStringLiteral(left) &&
            t.isStringLiteral(right)
          ) {
            p.replaceWith(t.stringLiteral(left.value + right.value));
            constantExpressionsFolded++;
            changed = true;
            return;
          }
          const numVal = (n: t.Node): number | undefined => {
            if (t.isNumericLiteral(n)) return n.value;
            if (
              t.isUnaryExpression(n) &&
              n.operator === "-" &&
              t.isNumericLiteral(n.argument)
            ) {
              return -n.argument.value;
            }
            return undefined;
          };
          const lv = numVal(left);
          const rv = numVal(right);
          if (lv !== undefined && rv !== undefined) {
            let computed: number | boolean | undefined;
            switch (operator) {
              case "+":
                computed = lv + rv;
                break;
              case "-":
                computed = lv - rv;
                break;
              case "*":
                computed = lv * rv;
                break;
              case "&":
                computed = lv & rv;
                break;
              case "|":
                computed = lv | rv;
                break;
              case "^":
                computed = lv ^ rv;
                break;
              case "<<":
                computed = lv << rv;
                break;
              case ">>":
                computed = lv >> rv;
                break;
              case ">>>":
                computed = lv >>> rv;
                break;
              case "===":
                computed = lv === rv;
                break;
              case "!==":
                computed = lv !== rv;
                break;
            }
            if (typeof computed === "number" && Number.isSafeInteger(computed)) {
              p.replaceWith(
                computed < 0
                  ? t.unaryExpression("-", t.numericLiteral(-computed))
                  : t.numericLiteral(computed),
              );
              constantExpressionsFolded++;
              changed = true;
            } else if (typeof computed === "boolean") {
              p.replaceWith(t.booleanLiteral(computed));
              constantExpressionsFolded++;
              changed = true;
            }
          }
        },
      },
    });

    if (!changed) break;
  }

  // 4. Remove top-level side-effect-free anchor statements (`void id;`, `[fn1, fn2, ...];`) & sensor IIFEs
  const topDeclaredNames = new Set<string>();
  for (const stmt of ast.program.body) {
    if (t.isFunctionDeclaration(stmt) && stmt.id) {
      topDeclaredNames.add(stmt.id.name);
    } else if (t.isVariableDeclaration(stmt)) {
      for (const d of stmt.declarations) {
        if (t.isIdentifier(d.id)) topDeclaredNames.add(d.id.name);
      }
    }
  }
  ast.program.body = ast.program.body.filter(
    (stmt) => !isNoopTopExpressionStatement(stmt, topDeclaredNames),
  );
  const disjointSensorIifesDetached = stripDisjointSensorIifes(ast);

  // 5. Collect exported names / module interface roots
  const exportedNames = new Set<string>();
  let hasExplicitModuleExports = false;

  traverse(ast, {
    ExportNamedDeclaration(p) {
      hasExplicitModuleExports = true;
      if (p.node.declaration) {
        const ids = t.getOuterBindingIdentifiers(p.node.declaration);
        for (const k of Object.keys(ids)) exportedNames.add(k);
      }
      for (const spec of p.node.specifiers) {
        if (t.isExportSpecifier(spec)) {
          exportedNames.add(spec.local.name);
        }
      }
    },
    ExportDefaultDeclaration() {
      hasExplicitModuleExports = true;
    },
    ExportAllDeclaration() {
      hasExplicitModuleExports = true;
    },
    AssignmentExpression(p) {
      const left = p.node.left;
      if (t.isMemberExpression(left)) {
        if (t.isIdentifier(left.object, { name: "exports" })) {
          hasExplicitModuleExports = true;
        } else if (
          t.isMemberExpression(left.object) &&
          t.isIdentifier(left.object.object, { name: "module" }) &&
          t.isIdentifier(left.object.property, { name: "exports" })
        ) {
          hasExplicitModuleExports = true;
        } else if (
          t.isIdentifier(left.object, { name: "module" }) &&
          t.isIdentifier(left.property, { name: "exports" })
        ) {
          hasExplicitModuleExports = true;
        }
      }
    },
  });

  let unreachableDeclarationsPruned = 0;
  let integritySealBindingsDetached = 0;
  let writeOnlyShadowCallsRemoved = 0;

  if (hasExplicitModuleExports) {
    const selfSealMeasureFns = new Set<string>();
    for (const stmt of ast.program.body) {
      if (
        t.isFunctionDeclaration(stmt) &&
        stmt.id &&
        looksLikeSelfSealMeasureFunction(stmt)
      ) {
        selfSealMeasureFns.add(stmt.id.name);
      }
    }

    // Pass 1: Prune dead functions (including `_reconstructSplitShare` & tarpit/labyrinth graphs)
    const p1 = pruneUnreferencedTopDeclarations(
      ast,
      exportedNames,
      knownBitsMap,
      selfSealMeasureFns,
    );
    unreachableDeclarationsPruned += p1.pruned;
    integritySealBindingsDetached += p1.sealDetached;

    // Pass 2: Eliminate write-only shadow heap mutator calls now that dead helpers are gone
    writeOnlyShadowCallsRemoved = stripWriteOnlyShadowHeapCalls(
      ast,
      exportedNames,
    );

    // Pass 3: Prune the now-unreferenced `shadowHeap` object & mutator function
    const p2 = pruneUnreferencedTopDeclarations(
      ast,
      exportedNames,
      knownBitsMap,
      selfSealMeasureFns,
    );
    unreachableDeclarationsPruned += p2.pruned;
    integritySealBindingsDetached += p2.sealDetached;
  }

  traverse(ast, {
    enter(p) {
      t.removeComments(p.node);
    },
  });

  const output = generate(ast, { comments: false });
  return {
    code: output.code,
    stats: {
      knownBitBindings: knownBitsMap.size,
      pureDigestCallsEvaluated,
      opaquePredicatesFolded,
      conditionalStringsCollapsed,
      constantExpressionsFolded,
      deadBranchesRemoved,
      writeOnlyShadowCallsRemoved,
      unreachableDeclarationsPruned,
      integritySealBindingsDetached,
      disjointSensorIifesDetached,
    },
  };
}
