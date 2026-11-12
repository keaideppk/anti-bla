import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import inspector from "node:inspector/promises";
import Module, { createRequire } from "node:module";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { parse } from "@babel/parser";
import * as t from "@babel/types";
import { generate, traverse } from "./babel-interop.js";

export interface NormalizedCoverageRange {
  readonly start: number;
  readonly end: number;
  readonly count: number;
}

export interface V8CoveragePruneResult<TOutput = unknown> {
  readonly projectedCode: string;
  readonly diskSha256Before: string;
  readonly diskSha256After: string;
  readonly diskBytesUnmodified: boolean;
  readonly totalV8Functions: number;
  readonly executedV8Functions: number;
  readonly coldFunctionsPruned: number;
  readonly coldBranchesPruned: number;
  readonly unreferencedTopDeclsPruned: number;
  readonly workloadOutput: TOutput;
}

function sha256Hex(buf: Buffer): string {
  return createHash("sha256").update(buf).digest("hex");
}

function isRangeCold(
  nodeStart: number | null | undefined,
  nodeEnd: number | null | undefined,
  deadRanges: readonly NormalizedCoverageRange[],
): boolean {
  if (nodeStart == null || nodeEnd == null || nodeEnd <= nodeStart) return false;
  // Find the tightest dead range containing [nodeStart, nodeEnd]
  for (const r of deadRanges) {
    if (r.count === 0 && r.start <= nodeStart && r.end >= nodeEnd) {
      return true;
    }
  }
  return false;
}

/**
 * Executes an on-disk JS module under V8's built-in `Profiler.takePreciseCoverage`
 * without altering `NODE_OPTIONS`, `process.execArgv`, or a single byte on disk
 * (preserving BLA `--self-seal` canonical SHA-256 self-digests), then projects
 * an in-memory AST with all `count === 0` functions and branches pruned.
 */
export async function pruneWithV8PreciseCoverage<TOutput>(
  modulePath: string,
  workloadDriver: (loadedModule: Record<string, any>) => TOutput | Promise<TOutput>,
): Promise<V8CoveragePruneResult<TOutput>> {
  const absPath = resolve(modulePath);
  const fileUrl = pathToFileURL(absPath).href;
  const rawBytesBefore = readFileSync(absPath);
  const diskSha256Before = sha256Hex(rawBytesBefore);
  const source = rawBytesBefore.toString("utf8");
  const isCjs = absPath.endsWith(".cjs") || absPath.endsWith(".js");

  const session = new inspector.Session();
  session.connect();

  let workloadOutput!: TOutput;
  let scriptCov: inspector.Profiler.ScriptCoverage | undefined;

  try {
    await session.post("Profiler.enable");
    await session.post("Profiler.startPreciseCoverage", {
      callCount: true,
      detailed: true,
    });

    if (isCjs) {
      const req = createRequire(import.meta.url);
      // Clear require cache so module top-level + self-seal checks execute fresh under coverage
      const resolvedId = req.resolve(absPath);
      delete req.cache[resolvedId];
      const mod = req(absPath) as Record<string, any>;
      workloadOutput = await workloadDriver(mod);
    } else {
      const mod = (await import(`${fileUrl}?cov=${Date.now()}`)) as Record<string, any>;
      workloadOutput = await workloadDriver(mod);
    }

    const { result } = await session.post("Profiler.takePreciseCoverage");
    scriptCov = result.find(
      (entry) =>
        entry.url === absPath ||
        entry.url === fileUrl ||
        entry.url.startsWith(`${fileUrl}?`),
    );

    await session.post("Profiler.stopPreciseCoverage");
    await session.post("Profiler.disable");
  } finally {
    session.disconnect();
  }

  const rawBytesAfter = readFileSync(absPath);
  const diskSha256After = sha256Hex(rawBytesAfter);
  const diskBytesUnmodified = diskSha256Before === diskSha256After;

  if (!scriptCov) {
    return {
      projectedCode: source,
      diskSha256Before,
      diskSha256After,
      diskBytesUnmodified,
      totalV8Functions: 0,
      executedV8Functions: 0,
      coldFunctionsPruned: 0,
      coldBranchesPruned: 0,
      unreferencedTopDeclsPruned: 0,
      workloadOutput,
    };
  }

  // Detect CommonJS wrapper prefix offset (`(function (exports, require, ...) { `)
  const cjsPrefixLen =
    (Module as unknown as { wrapper?: readonly string[] }).wrapper?.[0]?.length ?? 62;
  const maxObservedEnd = Math.max(
    0,
    ...scriptCov.functions.flatMap((fn) => fn.ranges.map((r) => r.endOffset)),
  );
  const wrapperShift =
    isCjs && maxObservedEnd > source.length ? cjsPrefixLen : 0;

  const deadFunctionRanges: NormalizedCoverageRange[] = [];
  const deadBlockRanges: NormalizedCoverageRange[] = [];

  let totalV8Functions = 0;
  let executedV8Functions = 0;

  for (const fnCov of scriptCov.functions) {
    if (fnCov.ranges.length === 0) continue;
    const root = fnCov.ranges[0]!;
    // Skip Node's synthetic outer wrapper itself when checking inner functions
    const rootStart = Math.max(0, root.startOffset - wrapperShift);
    const rootEnd = Math.min(source.length, root.endOffset - wrapperShift);
    if (rootEnd <= rootStart) continue;

    // Outer module range covers entire file [0, source.length]
    const isModuleRoot = rootStart === 0 && rootEnd >= source.length - 2;
    if (!isModuleRoot) {
      totalV8Functions++;
      if (root.count > 0) {
        executedV8Functions++;
      } else {
        deadFunctionRanges.push({
          start: rootStart,
          end: rootEnd,
          count: 0,
        });
      }
    }

    for (let i = 1; i < fnCov.ranges.length; i++) {
      const r = fnCov.ranges[i]!;
      if (r.count === 0) {
        const s = Math.max(0, r.startOffset - wrapperShift);
        const e = Math.min(source.length, r.endOffset - wrapperShift);
        if (e > s) {
          deadBlockRanges.push({ start: s, end: e, count: 0 });
        }
      }
    }
  }

  const ast = parse(source, {
    sourceType: "unambiguous",
    plugins: ["typescript", "jsx"],
  });

  let coldFunctionsPruned = 0;
  let coldBranchesPruned = 0;

  // Drop side-effect-free top-level anchor statements (`void fn;` or `void [fn1, fn2, ...];`)
  ast.program.body = ast.program.body.filter((stmt) => {
    if (!t.isExpressionStatement(stmt)) return true;
    let expr: t.Node = stmt.expression;
    if (t.isUnaryExpression(expr, { operator: "void" })) {
      expr = expr.argument;
    }
    if (t.isIdentifier(expr)) return false;
    if (
      t.isArrayExpression(expr) &&
      expr.elements.every((el) => el !== null && t.isIdentifier(el))
    ) {
      return false;
    }
    return true;
  });

  // 1. Prune cold FunctionDeclarations & cold branches
  traverse(ast, {
    FunctionDeclaration(p) {
      if (isRangeCold(p.node.start, p.node.end, deadFunctionRanges)) {
        p.remove();
        coldFunctionsPruned++;
      }
    },
    IfStatement: {
      exit(p) {
        const consCold = isRangeCold(
          p.node.consequent.start,
          p.node.consequent.end,
          deadBlockRanges,
        );
        const altCold = p.node.alternate
          ? isRangeCold(
              p.node.alternate.start,
              p.node.alternate.end,
              deadBlockRanges,
            )
          : false;

        if (consCold && (!p.node.alternate || altCold)) {
          p.remove();
          coldBranchesPruned++;
        } else if (consCold && p.node.alternate) {
          p.replaceWith(p.node.alternate);
          coldBranchesPruned++;
        } else if (altCold && p.node.alternate) {
          p.node.alternate = null;
          coldBranchesPruned++;
        }
      },
    },
    ConditionalExpression: {
      exit(p) {
        const consCold = isRangeCold(
          p.node.consequent.start,
          p.node.consequent.end,
          deadBlockRanges,
        );
        const altCold = isRangeCold(
          p.node.alternate.start,
          p.node.alternate.end,
          deadBlockRanges,
        );
        if (consCold && !altCold) {
          p.replaceWith(p.node.alternate);
          coldBranchesPruned++;
        } else if (altCold && !consCold) {
          p.replaceWith(p.node.consequent);
          coldBranchesPruned++;
        }
      },
    },
  });

  // 2. Clean up top-level pure `const`/`var` chaff tables no longer referenced after cold-function removal
  let unreferencedTopDeclsPruned = 0;
  for (let pass = 0; pass < 3; pass++) {
    let bindingsMap: Record<string, any> = {};
    traverse(ast, {
      Program(p) {
        p.scope.crawl();
        bindingsMap = p.scope.bindings;
        p.stop();
      },
    });
    let changed = false;
    const nextBody: t.Statement[] = [];
    for (const stmt of ast.program.body) {
      if (t.isVariableDeclaration(stmt)) {
        const kept = stmt.declarations.filter((decl) => {
          if (!t.isIdentifier(decl.id)) return true;
          const b = bindingsMap[decl.id.name];
          if (!b || b.referencePaths.length === 0) {
            unreferencedTopDeclsPruned++;
            changed = true;
            return false;
          }
          return true;
        });
        if (kept.length === 0) continue;
        stmt.declarations = kept;
      }
      nextBody.push(stmt);
    }
    ast.program.body = nextBody;
    if (!changed) break;
  }

  traverse(ast, {
    enter(p) {
      t.removeComments(p.node);
    },
  });

  return {
    projectedCode: generate(ast, { comments: false }).code,
    diskSha256Before,
    diskSha256After,
    diskBytesUnmodified,
    totalV8Functions,
    executedV8Functions,
    coldFunctionsPruned,
    coldBranchesPruned,
    unreferencedTopDeclsPruned,
    workloadOutput,
  };
}
