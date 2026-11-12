import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import vm from "node:vm";
import { beforeAll, describe, expect, it } from "vitest";
import {
  buildDrillFixtureSuite,
  type DrillFixtureSuite,
  inspectAsarResilientComparison,
  inspectBeamResilientComparison,
  inspectSqliteNaiveBaseline,
  inspectSqliteResilient,
  inspectWasmNaiveBaseline,
  inspectWasmResilient,
  parseSafetensorsNaiveBaseline,
  parseSafetensorsResilient,
  pruneWithV8PreciseCoverage,
  runResilientJsPipeline,
  simplifyJavaScriptWithBv,
} from "../src/index.js";

describe("anti-bla resilient analysis suite", () => {
  let suite!: DrillFixtureSuite;

  beforeAll(async () => {
    suite = await buildDrillFixtureSuite();
  }, 60_000);
  it("preserves genuine business branches without false-positive constant folding", () => {
    const businessCode = `
      function checkCoupon(code, flags) {
        if (code === 987654321) {
          return "rare-vip";
        }
        return (flags & 1) === 1 ? "flagged" : "normal";
      }
      exports.checkCoupon = checkCoupon;
    `;
    const res = simplifyJavaScriptWithBv(businessCode);
    expect(res.stats.opaquePredicatesFolded).toBe(0);
    expect(res.code).toContain("987654321");
    expect(res.code).toContain("rare-vip");
  });

  it("collapses BLA bankrupt + self-seal JS token amplification by >90% while preserving exact semantics", async () => {
    expect(suite.js.selfSealVerified).toBe(true);

    const pipeline = runResilientJsPipeline(suite.js.hardenedSource);
    expect(pipeline.tokenReductionRatio).toBeGreaterThan(0.9);
    expect(pipeline.afterBudget.maxAdditiveConditionalChain).toBe(0);
    expect(pipeline.afterBudget.contamination.totalMatches).toBe(0);
    expect(pipeline.afterBudget.wouldTripReaDefaultLimits).toBe(false);

    // Execute clean vs projected in VM
    const runMod = (src: string) => {
      const exportsObj: Record<string, any> = {};
      const moduleObj = { exports: exportsObj };
      const fn = vm.runInNewContext(`(function(exports, module) {\n${src}\n})`, {
        Math,
        String,
        Number,
        Object,
        Array,
      });
      fn(exportsObj, moduleObj);
      return moduleObj.exports;
    };

    const cleanMod = runMod(suite.js.cleanSource);
    const recoveredMod = runMod(pipeline.normalizedCode);

    expect(recoveredMod.computeQuote("enterprise", 15, true)).toEqual(
      cleanMod.computeQuote("enterprise", 15, true),
    );
    expect(recoveredMod.computeQuote("basic", 3, false)).toEqual(
      cleanMod.computeQuote("basic", 3, false),
    );
    expect(recoveredMod.verifyChecksumFrame(19, 512)).toBe(
      cleanMod.verifyChecksumFrame(19, 512),
    );
  });

  it("prunes cold tarpit functions via V8 precise coverage without modifying self-sealed disk bytes", async () => {
    const dir = mkdtempSync(join(tmpdir(), "anti-bla-test-cov-"));
    try {
      const modPath = join(dir, "sealed.cjs");
      writeFileSync(modPath, suite.js.hardenedSource, "utf8");

      const cov = await pruneWithV8PreciseCoverage(modPath, (mod) => ({
        ent: mod.computeQuote("enterprise", 10, true),
        std: mod.computeQuote("standard", 2, false),
        chk: mod.verifyChecksumFrame(3, 64),
      }));

      expect(cov.diskBytesUnmodified).toBe(true);
      expect(cov.coldFunctionsPruned).toBeGreaterThan(0);
      expect(cov.workloadOutput.ent).toEqual({
        badge: "tier:enterprise/v2",
        seats: 10,
        finalCents: 106250,
      });
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("bypasses SQLite VIRTUAL enclave_unseal_payload traps and quarantines honey tables losslessly", async () => {
    const naive = inspectSqliteNaiveBaseline(suite.sqlite.hardenedBuffer);
    expect(naive.status).toBe("error");
    expect(naive.errorMessage).toContain("enclave_unseal_payload");

    const cleanReport = inspectSqliteResilient(suite.sqlite.cleanBuffer);
    const resilient = inspectSqliteResilient(suite.sqlite.hardenedBuffer);

    expect(resilient.status).toBe("ok");
    expect(resilient.virtualTrapColumnsBypassed).toBeGreaterThan(0);
    expect(resilient.quarantinedHoneyTables.length).toBeGreaterThan(0);
    expect(resilient.businessTables.map((t) => t.rowsSha256)).toEqual(
      cleanReport.businessTables.map((t) => t.rowsSha256),
    );
  });

  it("skips >32-level Safetensors JSON nesting breakers in O(1) stack space", async () => {
    const naive = parseSafetensorsNaiveBaseline(suite.safetensors.hardenedBuffer, 32);
    expect(naive.status).toBe("error");
    expect(naive.maxObservedDepth).toBeGreaterThan(32);

    const cleanSt = parseSafetensorsResilient(suite.safetensors.cleanBuffer);
    const resilient = parseSafetensorsResilient(suite.safetensors.hardenedBuffer);

    expect(resilient.status).toBe("ok");
    expect(resilient.maxSkippedNestingDepth).toBeGreaterThan(32);
    expect(resilient.tensorPayloadSha256).toBe(cleanSt.tensorPayloadSha256);
    expect(resilient.tensors.length).toBe(cleanSt.tensors.length);
  });

  it("canonicalizes WASM export floods and recovers ASAR / Erlang BEAM inventories", async () => {
    const wasmNaive = inspectWasmNaiveBaseline(suite.wasm.hardenedBuffer);
    const wasmRes = inspectWasmResilient(suite.wasm.hardenedBuffer);
    expect(wasmRes.totalRawExports).toBeGreaterThan(200);
    expect(wasmRes.canonicalGroups.length).toBe(1);
    expect(wasmRes.representationBytes).toBeLessThan(wasmNaive.representationChargeBytes / 100);

    const asar = inspectAsarResilientComparison(suite.asar.hardenedBuffer);
    expect(asar.baselineStatus).toBe("error");
    expect(asar.resilientStatus).toBe("ok");
    expect(asar.realEntries).toEqual(expect.arrayContaining(["package.json", "main.js"]));

    const beam = inspectBeamResilientComparison(suite.beam.hardenedBuffer);
    expect(beam.baselineStatus).toBe("error");
    expect(beam.resilientStatus).toBe("ok");
    expect(beam.genuineAtoms).toEqual(expect.arrayContaining(["billing", "quote", "init"]));
  });
});
