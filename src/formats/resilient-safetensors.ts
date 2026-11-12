import { createHash } from "node:crypto";

export interface SafetensorsTensorDescriptor {
  readonly name: string;
  readonly dtype: string;
  readonly shape: readonly number[];
  readonly dataOffsets: readonly [number, number];
  readonly skippedExtensionKeys: readonly string[];
}

export interface SafetensorsBaselineOutcome {
  readonly status: "ok" | "error";
  readonly errorMessage: string | null;
  readonly maxObservedDepth: number;
  readonly headerBytes: number;
}

export interface SafetensorsResilientReport {
  readonly status: "ok";
  readonly headerBytes: number;
  readonly tensors: readonly SafetensorsTensorDescriptor[];
  readonly cleanMetadata: Readonly<Record<string, string>>;
  readonly quarantinedMetadataKeys: number;
  readonly maxSkippedNestingDepth: number;
  readonly tensorPayloadBytes: number;
  readonly tensorPayloadSha256: string;
  readonly cleanSummaryBytes: number;
}

function measureMaxJsonNestingBounded(text: string, maxDepth: number): {
  readonly exceeded: boolean;
  readonly observedDepth: number;
} {
  let depth = 0;
  let maxObserved = 0;
  let inString = false;
  let escaped = false;

  for (let i = 0; i < text.length; i++) {
    const ch = text.charCodeAt(i);
    if (inString) {
      if (escaped) {
        escaped = false;
      } else if (ch === 92) {
        escaped = true;
      } else if (ch === 34) {
        inString = false;
      }
      continue;
    }
    if (ch === 34) {
      inString = true;
    } else if (ch === 123 || ch === 91) {
      depth++;
      if (depth > maxObserved) maxObserved = depth;
      if (depth > maxDepth) {
        return { exceeded: true, observedDepth: depth };
      }
    } else if (ch === 125 || ch === 93) {
      depth--;
    }
  }
  return { exceeded: false, observedDepth: maxObserved };
}

/**
 * Reproduces REA's `MODEL_MAX_JSON_NESTING = 32` header parser admission check,
 * which aborts with `ModelFormatFailure` on BLA's `enclave_topology_seal` nesting breaker.
 */
export function parseSafetensorsNaiveBaseline(
  bytes: Buffer,
  maxDepth = 32,
): SafetensorsBaselineOutcome {
  if (bytes.length < 8) {
    return {
      status: "error",
      errorMessage: "Truncated Safetensors header (< 8 bytes)",
      maxObservedDepth: 0,
      headerBytes: 0,
    };
  }
  const headerLen = Number(bytes.readBigUInt64LE(0));
  if (headerLen <= 0 || 8 + headerLen > bytes.length) {
    return {
      status: "error",
      errorMessage: "Invalid Safetensors header length",
      maxObservedDepth: 0,
      headerBytes: headerLen,
    };
  }
  const headerText = bytes.subarray(8, 8 + headerLen).toString("utf8");
  const depthCheck = measureMaxJsonNestingBounded(headerText, maxDepth);
  if (depthCheck.exceeded) {
    return {
      status: "error",
      errorMessage: `ModelFormatFailure: Safetensors JSON nesting depth ${depthCheck.observedDepth} exceeds MODEL_MAX_JSON_NESTING (${maxDepth})`,
      maxObservedDepth: depthCheck.observedDepth,
      headerBytes: headerLen,
    };
  }
  return {
    status: "ok",
    errorMessage: null,
    maxObservedDepth: depthCheck.observedDepth,
    headerBytes: headerLen,
  };
}

class FlatJsonCursor {
  private pos = 0;
  private readonly len: number;

  constructor(private readonly text: string) {
    this.len = text.length;
  }

  skipWhitespace(): void {
    while (this.pos < this.len) {
      const c = this.text.charCodeAt(this.pos);
      if (c === 32 || c === 9 || c === 10 || c === 13) {
        this.pos++;
      } else {
        break;
      }
    }
  }

  peekChar(): string {
    this.skipWhitespace();
    return this.pos < this.len ? this.text[this.pos]! : "";
  }

  expectChar(expected: string): void {
    this.skipWhitespace();
    const actual = this.text[this.pos];
    if (actual !== expected) {
      throw new Error(
        `Expected '${expected}' at offset ${this.pos}, got '${actual ?? "EOF"}'`,
      );
    }
    this.pos++;
  }

  readString(): string {
    this.skipWhitespace();
    if (this.text[this.pos] !== '"') {
      throw new Error(`Expected string at offset ${this.pos}`);
    }
    const start = this.pos;
    this.pos++;
    let escaped = false;
    while (this.pos < this.len) {
      const c = this.text.charCodeAt(this.pos);
      if (escaped) {
        escaped = false;
        this.pos++;
      } else if (c === 92) {
        escaped = true;
        this.pos++;
      } else if (c === 34) {
        this.pos++;
        return JSON.parse(this.text.slice(start, this.pos)) as string;
      } else {
        this.pos++;
      }
    }
    throw new Error("Unterminated JSON string in Safetensors header");
  }

  readNumberArray(): number[] {
    this.expectChar("[");
    const out: number[] = [];
    if (this.peekChar() === "]") {
      this.pos++;
      return out;
    }
    while (this.pos < this.len) {
      this.skipWhitespace();
      const numStart = this.pos;
      while (
        this.pos < this.len &&
        /[0-9eE+.-]/.test(this.text[this.pos]!)
      ) {
        this.pos++;
      }
      const numVal = Number(this.text.slice(numStart, this.pos));
      if (!Number.isFinite(numVal)) {
        throw new Error(`Invalid numeric value at ${numStart}`);
      }
      out.push(numVal);
      const next = this.peekChar();
      if (next === ",") {
        this.pos++;
      } else if (next === "]") {
        this.pos++;
        return out;
      } else {
        throw new Error(`Unexpected token '${next}' in array`);
      }
    }
    throw new Error("Unterminated array");
  }

  /**
   * Iteratively skips any arbitrary JSON value in O(1) stack space,
   * returning the maximum bracket nesting depth encountered inside the skipped value.
   */
  skipArbitraryValue(baseDepth = 2): number {
    this.skipWhitespace();
    const first = this.text[this.pos];
    if (first === '"') {
      this.readString();
      return baseDepth;
    }
    if (first !== "{" && first !== "[") {
      while (
        this.pos < this.len &&
        ![",", "}", "]", " ", "\t", "\n", "\r"].includes(this.text[this.pos]!)
      ) {
        this.pos++;
      }
      return baseDepth;
    }

    let relDepth = 0;
    let maxDepth = baseDepth;
    let inString = false;
    let escaped = false;

    while (this.pos < this.len) {
      const ch = this.text.charCodeAt(this.pos++);
      if (inString) {
        if (escaped) {
          escaped = false;
        } else if (ch === 92) {
          escaped = true;
        } else if (ch === 34) {
          inString = false;
        }
        continue;
      }
      if (ch === 34) {
        inString = true;
      } else if (ch === 123 || ch === 91) {
        relDepth++;
        if (baseDepth + relDepth > maxDepth) {
          maxDepth = baseDepth + relDepth;
        }
      } else if (ch === 125 || ch === 93) {
        relDepth--;
        if (relDepth === 0) {
          return maxDepth;
        }
      }
    }
    throw new Error("Unterminated nested JSON value in Safetensors header");
  }
}

function isQuarantinedMetadataKey(key: string): boolean {
  return /^(?:enclave\.|bla\.|canary\.|tee\.)/i.test(key);
}

/**
 * Iterative O(1)-stack Safetensors header reader:
 * - Selectively extracts canonical `dtype`, `shape`, and `data_offsets` per tensor.
 * - Skips arbitrary non-spec extension fields (such as 35-level `enclave_topology_seal`)
 *   using a flat bracket counter without recursion or depth failure.
 * - Quarantines `enclave.*` / `bla.*` chaff & canary strings inside `__metadata__`.
 */
export function parseSafetensorsResilient(bytes: Buffer): SafetensorsResilientReport {
  if (bytes.length < 8) {
    throw new Error("Invalid Safetensors buffer (< 8 bytes)");
  }
  const headerBytes = Number(bytes.readBigUInt64LE(0));
  if (headerBytes <= 0 || 8 + headerBytes > bytes.length) {
    throw new Error("Safetensors header length out of bounds");
  }

  const headerText = bytes.subarray(8, 8 + headerBytes).toString("utf8");
  const cursor = new FlatJsonCursor(headerText);

  const tensors: SafetensorsTensorDescriptor[] = [];
  const cleanMetadata: Record<string, string> = {};
  let quarantinedMetadataKeys = 0;
  let maxSkippedNestingDepth = 0;

  cursor.expectChar("{");
  if (cursor.peekChar() !== "}") {
    while (true) {
      const topKey = cursor.readString();
      cursor.expectChar(":");

      if (topKey === "__metadata__") {
        cursor.expectChar("{");
        if (cursor.peekChar() !== "}") {
          while (true) {
            const mKey = cursor.readString();
            cursor.expectChar(":");
            if (cursor.peekChar() === '"') {
              const mVal = cursor.readString();
              if (isQuarantinedMetadataKey(mKey)) {
                quarantinedMetadataKeys++;
              } else {
                cleanMetadata[mKey] = mVal;
              }
            } else {
              const d = cursor.skipArbitraryValue(2);
              if (d > maxSkippedNestingDepth) maxSkippedNestingDepth = d;
              quarantinedMetadataKeys++;
            }
            const sep = cursor.peekChar();
            if (sep === ",") {
              cursor.expectChar(",");
            } else {
              break;
            }
          }
        }
        cursor.expectChar("}");
      } else {
        cursor.expectChar("{");
        let dtype = "UNKNOWN";
        let shape: number[] = [];
        let dataOffsets: [number, number] = [0, 0];
        const skippedExtensionKeys: string[] = [];

        if (cursor.peekChar() !== "}") {
          while (true) {
            const fieldKey = cursor.readString();
            cursor.expectChar(":");
            if (fieldKey === "dtype") {
              dtype = cursor.readString();
            } else if (fieldKey === "shape") {
              shape = cursor.readNumberArray();
            } else if (fieldKey === "data_offsets") {
              const arr = cursor.readNumberArray();
              if (arr.length === 2) {
                dataOffsets = [arr[0]!, arr[1]!];
              }
            } else {
              skippedExtensionKeys.push(fieldKey);
              const d = cursor.skipArbitraryValue(2);
              if (d > maxSkippedNestingDepth) maxSkippedNestingDepth = d;
            }
            const sep = cursor.peekChar();
            if (sep === ",") {
              cursor.expectChar(",");
            } else {
              break;
            }
          }
        }
        cursor.expectChar("}");
        tensors.push({
          name: topKey,
          dtype,
          shape,
          dataOffsets,
          skippedExtensionKeys,
        });
      }

      const topSep = cursor.peekChar();
      if (topSep === ",") {
        cursor.expectChar(",");
      } else {
        break;
      }
    }
  }
  cursor.expectChar("}");

  const tensorSlice = bytes.subarray(8 + headerBytes);
  const tensorPayloadSha256 = createHash("sha256").update(tensorSlice).digest("hex");
  const cleanSummaryBytes = Buffer.byteLength(
    JSON.stringify({ tensors, metadata: cleanMetadata }),
    "utf8",
  );

  return {
    status: "ok",
    headerBytes,
    tensors,
    cleanMetadata,
    quarantinedMetadataKeys,
    maxSkippedNestingDepth,
    tensorPayloadBytes: tensorSlice.length,
    tensorPayloadSha256,
    cleanSummaryBytes,
  };
}
