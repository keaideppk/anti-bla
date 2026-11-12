export interface WasmBaselineOutcome {
  readonly status: "ok" | "error";
  readonly totalExports: number;
  readonly customSections: number;
  readonly representationChargeBytes: number;
  readonly errorMessage: string | null;
}

export interface CanonicalWasmFunctionGroup {
  readonly kind: number;
  readonly index: number;
  readonly canonicalName: string;
  readonly signature: string;
  readonly aliasCount: number;
  readonly suppressedDecoyAliases: number;
}

export interface WasmResilientReport {
  readonly status: "ok";
  readonly totalRawExports: number;
  readonly canonicalGroups: readonly CanonicalWasmFunctionGroup[];
  readonly quarantinedCustomSections: readonly string[];
  readonly representationBytes: number;
}

export interface BeamComparisonReport {
  readonly baselineStatus: "ok" | "error";
  readonly baselineError: string | null;
  readonly resilientStatus: "ok";
  readonly totalChunks: number;
  readonly skippedVendorChunks: readonly string[];
  readonly totalAtoms: number;
  readonly genuineAtoms: readonly string[];
  readonly quarantinedDecoyAtoms: number;
}

export interface AsarComparisonReport {
  readonly headerBytes: number;
  readonly baselineStatus: "ok" | "error";
  readonly baselineError: string | null;
  readonly resilientStatus: "ok";
  readonly totalEntries: number;
  readonly realEntries: readonly string[];
  readonly collapsedDecoyPrefixes: Readonly<Record<string, number>>;
}

function readUleb128(buf: Buffer, offset: number): { value: number; next: number } {
  let result = 0;
  let shift = 0;
  let pos = offset;
  while (pos < buf.length) {
    const byte = buf[pos++]!;
    result |= (byte & 0x7f) << shift;
    if ((byte & 0x80) === 0) {
      return { value: result >>> 0, next: pos };
    }
    shift += 7;
    if (shift > 35) throw new Error("ULEB128 overflow");
  }
  throw new Error("Unexpected EOF in ULEB128");
}

function valTypeName(b: number): string {
  switch (b) {
    case 0x7f:
      return "i32";
    case 0x7e:
      return "i64";
    case 0x7d:
      return "f32";
    case 0x7c:
      return "f64";
    default:
      return `0x${b.toString(16)}`;
  }
}

/**
 * Simulates REA's WABT -> `WasmInterfaceBudget` charge (`32 MiB` ceiling), where
 * each long-name export is materialized across export + Wat + symbol tables.
 */
export function inspectWasmNaiveBaseline(
  bytes: Buffer,
  budgetBytes = 33_554_432,
): WasmBaselineOutcome {
  let offset = 8;
  let totalExports = 0;
  let customSections = 0;
  let representationChargeBytes = 0;

  while (offset < bytes.length) {
    const sectionId = bytes[offset++]!;
    const { value: size, next } = readUleb128(bytes, offset);
    const end = next + size;
    if (end > bytes.length) break;

    if (sectionId === 0) {
      customSections++;
      representationChargeBytes += size * 4;
    } else if (sectionId === 7) {
      const { value: count, next: p0 } = readUleb128(bytes, next);
      let p = p0;
      for (let i = 0; i < count && p < end; i++) {
        const { value: nameLen, next: afterLen } = readUleb128(bytes, p);
        p = afterLen + nameLen;
        if (p >= end) break;
        p++; // kind
        const { next: afterIdx } = readUleb128(bytes, p);
        p = afterIdx;
        totalExports++;
        // REA's WabtWat + WasmInterfaceEntry representation multiplies long export names across AST/WAT/JSON views
        representationChargeBytes += 512 + nameLen * 12;
      }
    }
    offset = end;
  }

  if (representationChargeBytes > budgetBytes) {
    return {
      status: "error",
      totalExports,
      customSections,
      representationChargeBytes,
      errorMessage: `WasmResourceFailure: Interface representation charge (${representationChargeBytes} B) exceeds WASM_INTERFACE_REPRESENTATION_BYTES (${budgetBytes} B)`,
    };
  }

  return {
    status: "ok",
    totalExports,
    customSections,
    representationChargeBytes,
    errorMessage: null,
  };
}

/**
 * Resilient WASM Canonical Interface Extractor:
 * - Groups all Export Section entries by `(kind, index)` so 250+ `enclave_export_...`
 *   alias decoys pointing to the same function body collapse to 1 canonical entry.
 * - Quarantines untrusted `sectionId === 0` custom/honey-name sections.
 */
export function inspectWasmResilient(bytes: Buffer): WasmResilientReport {
  if (bytes.length < 8 || bytes.readUInt32LE(0) !== 0x6d736100) {
    throw new Error("Invalid WASM header");
  }

  const types: string[] = [];
  const funcTypeIndices: number[] = [];
  const rawExports: Array<{ name: string; kind: number; index: number }> = [];
  const quarantinedCustomSections: string[] = [];

  let offset = 8;
  while (offset < bytes.length) {
    const sectionId = bytes[offset++]!;
    const { value: size, next } = readUleb128(bytes, offset);
    const end = next + size;
    if (end > bytes.length) break;

    if (sectionId === 0) {
      try {
        const { value: nameLen, next: nameStart } = readUleb128(bytes, next);
        const cName = bytes.subarray(nameStart, nameStart + nameLen).toString("utf8");
        quarantinedCustomSections.push(cName);
      } catch {
        quarantinedCustomSections.push("<malformed-custom>");
      }
    } else if (sectionId === 1) {
      const { value: count, next: p0 } = readUleb128(bytes, next);
      let p = p0;
      for (let i = 0; i < count && p < end; i++) {
        const form = bytes[p++]!;
        if (form !== 0x60) break;
        const { value: paramCount, next: p1 } = readUleb128(bytes, p);
        p = p1;
        const params: string[] = [];
        for (let j = 0; j < paramCount; j++) params.push(valTypeName(bytes[p++]!));
        const { value: resCount, next: p2 } = readUleb128(bytes, p);
        p = p2;
        const results: string[] = [];
        for (let j = 0; j < resCount; j++) results.push(valTypeName(bytes[p++]!));
        types.push(`(${params.join(", ")}) -> (${results.join(", ")})`);
      }
    } else if (sectionId === 3) {
      const { value: count, next: p0 } = readUleb128(bytes, next);
      let p = p0;
      for (let i = 0; i < count && p < end; i++) {
        const { value: tIdx, next: p1 } = readUleb128(bytes, p);
        p = p1;
        funcTypeIndices.push(tIdx);
      }
    } else if (sectionId === 7) {
      const { value: count, next: p0 } = readUleb128(bytes, next);
      let p = p0;
      for (let i = 0; i < count && p < end; i++) {
        const { value: nameLen, next: afterLen } = readUleb128(bytes, p);
        const name = bytes.subarray(afterLen, afterLen + nameLen).toString("utf8");
        p = afterLen + nameLen;
        const kind = bytes[p++]!;
        const { value: idx, next: afterIdx } = readUleb128(bytes, p);
        p = afterIdx;
        rawExports.push({ name, kind, index: idx });
      }
    }

    offset = end;
  }

  // Group exports by `(kind, index)`
  const grouped = new Map<string, Array<{ name: string; kind: number; index: number }>>();
  for (const exp of rawExports) {
    const key = `${exp.kind}:${exp.index}`;
    const list = grouped.get(key) ?? [];
    list.push(exp);
    grouped.set(key, list);
  }

  const canonicalGroups: CanonicalWasmFunctionGroup[] = [];
  for (const [, list] of grouped) {
    // Prefer shortest non-decoy export name as canonical symbol
    const sorted = [...list].sort((a, b) => {
      const aDecoy = /^enclave_export_/i.test(a.name) ? 1 : 0;
      const bDecoy = /^enclave_export_/i.test(b.name) ? 1 : 0;
      if (aDecoy !== bDecoy) return aDecoy - bDecoy;
      return a.name.length - b.name.length;
    });
    const primary = sorted[0]!;
    const decoys = list.filter(
      (e) => e !== primary && (/^enclave_export_/i.test(e.name) || e.name.length > 96),
    ).length;
    const typeIdx = primary.kind === 0 ? funcTypeIndices[primary.index] : undefined;
    const signature =
      typeIdx !== undefined ? (types[typeIdx] ?? "(unknown)") : `kind:${primary.kind}`;

    canonicalGroups.push({
      kind: primary.kind,
      index: primary.index,
      canonicalName: primary.name.slice(0, 64),
      signature,
      aliasCount: list.length,
      suppressedDecoyAliases: decoys,
    });
  }

  const representationBytes = Buffer.byteLength(
    JSON.stringify(canonicalGroups),
    "utf8",
  );

  return {
    status: "ok",
    totalRawExports: rawExports.length,
    canonicalGroups,
    quarantinedCustomSections,
    representationBytes,
  };
}

const STANDARD_BEAM_CHUNKS = new Set([
  "Atom",
  "AtU8",
  "Code",
  "StrT",
  "ImpT",
  "ExpT",
  "FunT",
  "LitT",
  "LocT",
  "Attr",
  "CInf",
  "Dbgi",
  "Line",
  "Type",
]);

function decodeCompactBeamUint(
  payload: Buffer,
  at: number,
): { value: number; next: number } | null {
  if (at >= payload.length) return null;
  const first = payload[at]!;
  if ((first & 0x07) !== 0) return null;
  if ((first & 0x08) === 0) return { value: first >> 4, next: at + 1 };
  if ((first & 0x10) === 0) {
    if (at + 1 >= payload.length) return null;
    return { value: ((first >> 5) << 8) | payload[at + 1]!, next: at + 2 };
  }
  const byteCount = (first >> 5) + 2;
  if (at + byteCount >= payload.length) return null;
  let val = 0;
  for (let i = 0; i < byteCount; i++) {
    val = (val << 8) | payload[at + 1 + i]!;
  }
  return { value: val >>> 0, next: at + 1 + byteCount };
}

function parseBeamAtomNames(payload: Buffer): string[] {
  if (payload.length < 4) return [];
  const rawCount = payload.readInt32BE(0);
  const compact = rawCount < 0;
  const count = Math.abs(rawCount);
  const atoms: string[] = [];
  let p = 4;
  for (let i = 0; i < count && p < payload.length; i++) {
    let len = 0;
    if (compact) {
      const dec = decodeCompactBeamUint(payload, p);
      if (!dec) break;
      len = dec.value;
      p = dec.next;
    } else {
      len = payload[p++]!;
    }
    if (p + len > payload.length) break;
    atoms.push(payload.subarray(p, p + len).toString("utf8"));
    p += len;
  }
  return atoms;
}

/**
 * Compares REA's default Erlang BEAM admission (`maxChunks = 64`, `maxAtoms = 4096`)
 * against chunk-selective resilient BEAM inspection.
 */
export function inspectBeamResilientComparison(bytes: Buffer): BeamComparisonReport {
  if (
    bytes.length < 12 ||
    bytes.subarray(0, 4).toString("latin1") !== "FOR1" ||
    bytes.subarray(8, 12).toString("latin1") !== "BEAM"
  ) {
    throw new Error("Invalid Erlang BEAM container");
  }
  const formSize = bytes.readUInt32BE(4);
  const formEnd = Math.min(bytes.length, 8 + formSize);

  let totalChunks = 0;
  const skippedVendorChunks: string[] = [];
  let allAtoms: string[] = [];

  let at = 12;
  while (at + 8 <= formEnd) {
    const name = bytes.subarray(at, at + 4).toString("latin1");
    const size = bytes.readUInt32BE(at + 4);
    const payloadStart = at + 8;
    const paddedEnd = payloadStart + size + ((4 - (size % 4)) % 4);
    if (payloadStart + size > formEnd) break;
    totalChunks++;

    if (!STANDARD_BEAM_CHUNKS.has(name)) {
      skippedVendorChunks.push(name);
    } else if (name === "AtU8" || name === "Atom") {
      allAtoms = parseBeamAtomNames(bytes.subarray(payloadStart, payloadStart + size));
    }
    at = paddedEnd;
  }

  let baselineStatus: "ok" | "error" = "ok";
  let baselineError: string | null = null;
  if (totalChunks > 64) {
    baselineStatus = "error";
    baselineError = `BeamCapacityFailure: chunk count ${totalChunks} exceeds default max_chunks (64)`;
  } else if (allAtoms.length > 4096) {
    baselineStatus = "error";
    baselineError = `BeamCapacityFailure: atom count ${allAtoms.length} exceeds default max_atoms (4096)`;
  }

  const genuineAtoms = allAtoms.filter(
    (a) => !/^(?:enclave_|bla_|canary_|sentinel_)/i.test(a) && a.length <= 80,
  );

  return {
    baselineStatus,
    baselineError,
    resilientStatus: "ok",
    totalChunks,
    skippedVendorChunks,
    totalAtoms: allAtoms.length,
    genuineAtoms,
    quarantinedDecoyAtoms: allAtoms.length - genuineAtoms.length,
  };
}

/**
 * Compares REA's default Electron ASAR 16 MiB header admission against
 * prefix-collapsing resilient ASAR tree inspection.
 */
export function inspectAsarResilientComparison(
  bytes: Buffer,
  defaultMaxHeaderBytes = 16 * 1024 * 1024,
): AsarComparisonReport {
  if (bytes.length < 16) {
    throw new Error("Invalid ASAR archive (< 16 bytes)");
  }
  const headerStringLen = bytes.readUInt32LE(12);
  if (16 + headerStringLen > bytes.length) {
    throw new Error("Truncated ASAR Pickle JSON header");
  }

  const baselineExceeded = headerStringLen > defaultMaxHeaderBytes;
  const baselineStatus: "ok" | "error" = baselineExceeded ? "error" : "ok";
  const baselineError = baselineExceeded
    ? `AsarHeaderLimitExceeded: Pickle JSON header (${headerStringLen} B) exceeds DEFAULT_ASAR_MAX_HEADER_BYTES (${defaultMaxHeaderBytes} B)`
    : null;

  const root = JSON.parse(
    bytes.subarray(16, 16 + headerStringLen).toString("utf8"),
  ) as { files?: Record<string, unknown> };

  let totalEntries = 0;
  const realEntries: string[] = [];
  const collapsedDecoyPrefixes: Record<string, number> = {};

  function walk(node: { files?: Record<string, any> }, prefix: string): void {
    if (!node.files) return;
    for (const [name, child] of Object.entries(node.files)) {
      const rel = prefix ? `${prefix}/${name}` : name;
      if (child && typeof child === "object" && "files" in child) {
        walk(child as { files?: Record<string, any> }, rel);
      } else {
        totalEntries++;
        if (/^enclave\/shards\/ring0-slot-/i.test(rel) || rel.length > 256) {
          const groupKey = prefix || "<root-padded>";
          collapsedDecoyPrefixes[groupKey] =
            (collapsedDecoyPrefixes[groupKey] ?? 0) + 1;
        } else {
          realEntries.push(rel);
        }
      }
    }
  }

  walk(root, "");

  return {
    headerBytes: headerStringLen,
    baselineStatus,
    baselineError,
    resilientStatus: "ok",
    totalEntries,
    realEntries,
    collapsedDecoyPrefixes,
  };
}
