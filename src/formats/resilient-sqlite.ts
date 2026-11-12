import { createHash } from "node:crypto";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";

export interface SqliteBaselineOutcome {
  readonly status: "ok" | "error";
  readonly errorMessage: string | null;
  readonly tablesScanned: number;
  readonly outputBytes: number;
}

export interface SqliteRecoveredTable {
  readonly name: string;
  readonly physicalColumns: readonly string[];
  readonly skippedVirtualColumns: readonly string[];
  readonly rowCount: number;
  readonly rowsSha256: string;
  readonly sampleRows: readonly Record<string, unknown>[];
}

export interface SqliteResilientReport {
  readonly status: "ok";
  readonly totalTables: number;
  readonly businessTables: readonly SqliteRecoveredTable[];
  readonly quarantinedHoneyTables: readonly string[];
  readonly virtualTrapColumnsBypassed: number;
  readonly cleanSummaryBytes: number;
}

function quoteIdent(name: string): string {
  return `"${name.replace(/"/g, '""')}"`;
}

const DECEPTION_CONTENT_REGEX =
  /PROTECTED_CREDENTIAL_AND_DRM_KEY_MATERIAL|hardware-tee-delegated|ring0\.sgx\.vault|remediation_rabbit_hole|ENCLAVE_ATTESTATION|HARDWARE_TEE|enclave_cid/i;

function isHoneyTableByStructureAndContent(
  physicalColumns: readonly string[],
  skippedVirtualColumns: readonly string[],
  sampleRows: readonly Record<string, unknown>[],
): boolean {
  if (
    physicalColumns.includes("remediation_rabbit_hole") ||
    physicalColumns.includes("ambiguous_transport_url") ||
    physicalColumns.includes("enclave_cid")
  ) {
    return true;
  }
  if (sampleRows.length === 0) return false;
  const sampleJson = JSON.stringify(sampleRows);
  if (DECEPTION_CONTENT_REGEX.test(sampleJson)) {
    return true;
  }
  // If table has missing-UDF virtual columns AND every sampled row contains hex/enclave lease tokens
  if (
    skippedVirtualColumns.length > 0 &&
    /ent_enclave_|quote_[0-9a-f]{8}/i.test(sampleJson)
  ) {
    return true;
  }
  return false;
}

/**
 * Simulates a naive static SQLite inspector (`SELECT * FROM <table>`) on a bare
 * read-only connection without registering custom UDFs. Trips immediately on
 * BLA's `GENERATED ALWAYS AS (enclave_unseal_payload(...)) VIRTUAL` columns.
 */
export function inspectSqliteNaiveBaseline(bytes: Buffer): SqliteBaselineOutcome {
  const dir = mkdtempSync(join(tmpdir(), "anti-bla-sqlite-base-"));
  const dbPath = join(dir, "sample.sqlite");
  try {
    writeFileSync(dbPath, bytes);
    const db = new DatabaseSync(dbPath, { readOnly: true });
    try {
      const tables = db
        .prepare(
          "SELECT name FROM sqlite_schema WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name",
        )
        .all() as Array<{ name: string }>;

      const dump: Record<string, unknown[]> = {};
      for (const t of tables) {
        dump[t.name] = db.prepare(`SELECT * FROM ${quoteIdent(t.name)}`).all() as unknown[];
      }
      const json = JSON.stringify(dump);
      return {
        status: "ok",
        errorMessage: null,
        tablesScanned: tables.length,
        outputBytes: Buffer.byteLength(json, "utf8"),
      };
    } catch (err) {
      return {
        status: "error",
        errorMessage: err instanceof Error ? err.message : String(err),
        tablesScanned: 0,
        outputBytes: 0,
      };
    } finally {
      db.close();
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

/**
 * Resilient SQLite inspector:
 * 1. Inspects `PRAGMA table_xinfo(table)` on every table to identify `hidden === 2`
 *    (VIRTUAL) and `hidden === 3` (STORED generated) columns, projecting `SELECT`
 *    strictly over physical `hidden === 0` columns so missing UDF traps never abort.
 * 2. Classifies and quarantines honey/chaff tables by structural & content signals
 *    while preserving 100% of genuine business tables (even if a business table itself
 *    had a virtual trap column attached!).
 */
export function inspectSqliteResilient(bytes: Buffer): SqliteResilientReport {
  const dir = mkdtempSync(join(tmpdir(), "anti-bla-sqlite-res-"));
  const dbPath = join(dir, "sample.sqlite");
  try {
    writeFileSync(dbPath, bytes);
    const db = new DatabaseSync(dbPath, { readOnly: true });
    try {
      const schemaRows = db
        .prepare(
          "SELECT name, sql FROM sqlite_schema WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name",
        )
        .all() as Array<{ name: string; sql: string | null }>;

      const businessTables: SqliteRecoveredTable[] = [];
      const quarantinedHoneyTables: string[] = [];
      let virtualTrapColumnsBypassed = 0;

      for (const row of schemaRows) {
        const xinfo = db
          .prepare(`PRAGMA table_xinfo(${quoteIdent(row.name)})`)
          .all() as Array<{
          cid: number;
          name: string;
          type: string;
          hidden: number;
        }>;

        const physicalColumns: string[] = [];
        const skippedVirtualColumns: string[] = [];

        for (const col of xinfo) {
          if (col.hidden === 0) {
            physicalColumns.push(col.name);
          } else if (col.hidden === 2 || col.hidden === 3) {
            // Probe whether evaluating this generated column would fail due to unregistered UDF
            try {
              db.prepare(
                `SELECT ${quoteIdent(col.name)} FROM ${quoteIdent(row.name)} LIMIT 1`,
              ).get();
              physicalColumns.push(col.name);
            } catch {
              skippedVirtualColumns.push(col.name);
              virtualTrapColumnsBypassed++;
            }
          }
        }

        if (physicalColumns.length === 0) continue;

        const selectCols = physicalColumns.map(quoteIdent).join(", ");
        const dataRows = db
          .prepare(`SELECT ${selectCols} FROM ${quoteIdent(row.name)}`)
          .all() as Record<string, unknown>[];

        const sampleRows = dataRows.slice(0, 5);
        if (
          isHoneyTableByStructureAndContent(
            physicalColumns,
            skippedVirtualColumns,
            sampleRows,
          )
        ) {
          quarantinedHoneyTables.push(row.name);
          continue;
        }

        const canonicalJson = JSON.stringify(dataRows);
        const rowsSha256 = createHash("sha256")
          .update(canonicalJson, "utf8")
          .digest("hex");

        businessTables.push({
          name: row.name,
          physicalColumns,
          skippedVirtualColumns,
          rowCount: dataRows.length,
          rowsSha256,
          sampleRows,
        });
      }

      const summaryPayload = JSON.stringify({
        businessTables,
        quarantinedHoneyTableCount: quarantinedHoneyTables.length,
      });

      return {
        status: "ok",
        totalTables: schemaRows.length,
        businessTables,
        quarantinedHoneyTables,
        virtualTrapColumnsBypassed,
        cleanSummaryBytes: Buffer.byteLength(summaryPayload, "utf8"),
      };
    } finally {
      db.close();
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}
