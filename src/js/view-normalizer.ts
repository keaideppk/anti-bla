import { parse } from "@babel/parser";
import * as t from "@babel/types";
import { generate, traverse } from "./babel-interop.js";
import { simplifyJavaScriptWithBv, type BvSimplifierStats } from "./bv-simplifier.js";
import {
  analyzeStaticJsBudget,
  type StaticJsBudgetReport,
} from "../metrics/token-budget.js";

export interface ViewNormalizeStats {
  readonly identifiersAlphaRenamed: number;
  readonly inertBlobsSummarized: number;
}

export interface ResilientJsPipelineResult {
  readonly normalizedCode: string;
  readonly bvStats: BvSimplifierStats;
  readonly viewStats: ViewNormalizeStats;
  readonly beforeBudget: StaticJsBudgetReport;
  readonly afterBudget: StaticJsBudgetReport;
  readonly tokenReductionRatio: number;
  readonly byteReductionRatio: number;
}

function isHighEntropyObfuscatedIdentifier(name: string): boolean {
  // Matches BLA's BPE amplifier (`Zq_X9_Kv_W7`) or PRNG-salted camel/hex identifiers (`_7f3a`, `xQ8_...`)
  if (/^(?:[A-Za-z0-9]{1,3}_){2,}[A-Za-z0-9_]+$/.test(name)) return true;
  if (/_[0-9a-f]{4,8}$/i.test(name)) return true;
  if (name.length >= 16) {
    const transitions = (name.match(/[a-z][A-Z]|[A-Za-z]\d|\d[A-Za-z]|_/g) ?? []).length;
    if (transitions >= 3) return true;
  }
  return false;
}

/**
 * Alpha-renames local BPE-amplified identifiers (`Zq_X9_Kv_W7` -> `p0`, `v0`) while
 * strictly preserving module export property names, globals, and object property keys.
 * Also summarizes any remaining oversized literal string blobs if configured.
 */
export function normalizeAnalysisView(
  source: string,
  options: {
    readonly alphaRenameLocals?: boolean;
    readonly maxLiteralPreviewLength?: number;
  } = {},
): { readonly code: string; readonly stats: ViewNormalizeStats } {
  const alphaRenameLocals = options.alphaRenameLocals !== false;
  const maxLiteralLen = options.maxLiteralPreviewLength ?? 512;

  const ast = parse(source, {
    sourceType: "unambiguous",
    plugins: ["typescript", "jsx"],
  });

  // Collect exported top-level identifiers and `exports.<publicName> = <localId>` aliases
  const exportedIds = new Set<string>();
  const cjsExportAliasMap = new Map<string, string>();
  for (const stmt of ast.program.body) {
    if (t.isExportNamedDeclaration(stmt)) {
      if (stmt.declaration) {
        for (const k of Object.keys(t.getOuterBindingIdentifiers(stmt.declaration))) {
          exportedIds.add(k);
        }
      }
      for (const spec of stmt.specifiers) {
        if (t.isExportSpecifier(spec)) exportedIds.add(spec.local.name);
      }
    } else if (
      t.isExpressionStatement(stmt) &&
      t.isAssignmentExpression(stmt.expression, { operator: "=" }) &&
      t.isMemberExpression(stmt.expression.left) &&
      !stmt.expression.left.computed &&
      t.isIdentifier(stmt.expression.left.object, { name: "exports" }) &&
      t.isIdentifier(stmt.expression.left.property) &&
      t.isIdentifier(stmt.expression.right)
    ) {
      cjsExportAliasMap.set(
        stmt.expression.right.name,
        stmt.expression.left.property.name,
      );
    }
  }

  let identifiersAlphaRenamed = 0;
  let inertBlobsSummarized = 0;

  if (alphaRenameLocals) {
    let fnCounter = 0;
    traverse(ast, {
      Scope(path) {
        let paramIdx = 0;
        let localIdx = 0;
        const bindings = Object.entries(path.scope.bindings);
        for (const [name, binding] of bindings) {
          if (exportedIds.has(name)) continue;
          const cjsPublicName = path.scope.path.isProgram()
            ? cjsExportAliasMap.get(name)
            : undefined;
          if (cjsPublicName && name !== cjsPublicName && !path.scope.hasBinding(cjsPublicName)) {
            path.scope.rename(name, cjsPublicName);
            identifiersAlphaRenamed++;
            continue;
          }
          if (!isHighEntropyObfuscatedIdentifier(name)) continue;
          if (path.scope.path.isProgram() && binding.kind === "hoisted") {
            if (cjsPublicName === name) continue;
            const nextName = `fn_${fnCounter++}`;
            if (!path.scope.hasBinding(nextName)) {
              path.scope.rename(name, nextName);
              identifiersAlphaRenamed++;
            }
            continue;
          }
          const prefix = binding.kind === "param" ? "p" : "v";
          const idx = binding.kind === "param" ? paramIdx++ : localIdx++;
          let candidate = `${prefix}${idx}`;
          while (path.scope.hasBinding(candidate)) {
            candidate = `${prefix}${binding.kind === "param" ? paramIdx++ : localIdx++}`;
          }
          path.scope.rename(name, candidate);
          identifiersAlphaRenamed++;
        }
      },
    });
  }

  if (maxLiteralLen > 0) {
    traverse(ast, {
      StringLiteral(path) {
        if (path.node.value.length > maxLiteralLen) {
          path.node.value = `[inert_blob:${path.node.value.length}B]`;
          inertBlobsSummarized++;
        }
      },
    });
  }

  return {
    code: generate(ast, { comments: false }).code,
    stats: {
      identifiersAlphaRenamed,
      inertBlobsSummarized,
    },
  };
}

/**
 * Full static resilient JavaScript pipeline:
 * 1. Measures baseline static/BPE/contamination cost
 * 2. Applies 32-bit bit-vector & parity-invariant simplification + shadow-heap/export slicing
 * 3. Applies BPE identifier alpha-normalization on remaining local bindings
 * 4. Measures post-projection cost & reduction ratios
 */
export function runResilientJsPipeline(
  hardenedSource: string,
  options: { readonly summarizeLargeBlobs?: boolean } = {},
): ResilientJsPipelineResult {
  const beforeBudget = analyzeStaticJsBudget(hardenedSource);
  const bv = simplifyJavaScriptWithBv(hardenedSource);
  const norm = normalizeAnalysisView(bv.code, {
    alphaRenameLocals: true,
    maxLiteralPreviewLength: options.summarizeLargeBlobs ? 512 : 0,
  });
  const afterBudget = analyzeStaticJsBudget(norm.code);

  const tokenReductionRatio =
    beforeBudget.bpe.estimatedTokens > 0
      ? Number(
          (
            1 -
            afterBudget.bpe.estimatedTokens / beforeBudget.bpe.estimatedTokens
          ).toFixed(4),
        )
      : 0;
  const byteReductionRatio =
    beforeBudget.bytes > 0
      ? Number((1 - afterBudget.bytes / beforeBudget.bytes).toFixed(4))
      : 0;

  return {
    normalizedCode: norm.code,
    bvStats: bv.stats,
    viewStats: norm.stats,
    beforeBudget,
    afterBudget,
    tokenReductionRatio,
    byteReductionRatio,
  };
}
