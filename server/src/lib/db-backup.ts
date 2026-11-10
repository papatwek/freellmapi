import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import { gzipSync, gunzipSync } from 'zlib';
import type { Db } from '../db/types.js';
import type { Scheduler } from './scheduler.js';
import { defaultDbFactory, getDefaultDbPath } from '../db/index.js';
import { restrictToOwner } from './file-permissions.js';

const MAGIC = Buffer.from('FAPIBK1\0');
const DEFAULT_INTERVAL_MS = 5 * 60 * 1000;
function fetchTimeoutMs(): number {
  const raw = process.env.FREEAPI_DB_BACKUP_TIMEOUT_MS;
  if (!raw) return 30 * 1000;
  const value = Number(raw);
  if (!Number.isFinite(value) || value < 5_000) return 30 * 1000;
  return Math.min(Math.floor(value), 10 * 60 * 1000);
}
const PLACEHOLDER_KEY = 'replace-with-64-char-hex';

export interface DbBackupResult {
  ok: boolean;
  target?: string;
  bytes?: number;
  restored?: boolean;
  skipped?: string;
}

function backupTarget(): string | null {
  const raw = process.env.FREEAPI_DB_BACKUP_TARGET
    ?? process.env.FREEAPI_DB_BACKUP_URL
    ?? process.env.FREEAPI_DB_BACKUP_PATH
    ?? '';
  const trimmed = raw.trim();
  return trimmed.length > 0 ? trimmed : null;
}

export function isDbBackupConfigured(): boolean {
  return backupTarget() !== null;
}

function backupIntervalMs(): number {
  const raw = process.env.FREEAPI_DB_BACKUP_INTERVAL_MS;
  if (!raw) return DEFAULT_INTERVAL_MS;
  const n = Number(raw);
  return Number.isFinite(n) && n > 0 ? Math.floor(n) : DEFAULT_INTERVAL_MS;
}

function isHttpTarget(target: string): boolean {
  return target.startsWith('https://') || target.startsWith('http://');
}

function parseBackupKey(): Buffer {
  const raw = (process.env.FREEAPI_DB_BACKUP_KEY || process.env.ENCRYPTION_KEY || '').trim();
  if (!raw || raw === PLACEHOLDER_KEY || !/^[0-9a-fA-F]{64}$/.test(raw)) {
    throw new Error('FREEAPI_DB_BACKUP_KEY or ENCRYPTION_KEY must be a 64-character hex key when DB backup is enabled');
  }
  return Buffer.from(raw, 'hex');
}

function encryptBackup(plain: Buffer): Buffer {
  const key = parseBackupKey();
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const ciphertext = Buffer.concat([cipher.update(plain), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([MAGIC, iv, tag, ciphertext]);
}

function decryptBackup(payload: Buffer): Buffer {
  if (payload.length < MAGIC.length + 12 + 16 || !payload.subarray(0, MAGIC.length).equals(MAGIC)) {
    throw new Error('backup payload has an unsupported format');
  }
  const key = parseBackupKey();
  const ivStart = MAGIC.length;
  const tagStart = ivStart + 12;
  const bodyStart = tagStart + 16;
  const iv = payload.subarray(ivStart, tagStart);
  const tag = payload.subarray(tagStart, bodyStart);
  const ciphertext = payload.subarray(bodyStart);
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
}

/**
 * Split a Hugging Face `/resolve/` download URL into the pieces the commit API
 * needs, or null for anything else.
 *
 * A HF repo serves downloads at `/{type}/{ns}/{repo}/resolve/{rev}/{path}`, but
 * that route is read-only: a PUT to it is answered 404/405 and the blob never
 * lands. Writes go through the commit API instead. Both halves are derived from
 * the one URL the operator configures, so FREEAPI_DB_BACKUP_TARGET stays the
 * plain download URL they can paste into a browser.
 *
 * Models are the type with no prefix segment (`/{ns}/{repo}/resolve/...`);
 * datasets and spaces name themselves. The API path pluralizes the type.
 */
export function parseHuggingFaceTarget(target: string): { commitUrl: string; filePath: string } | null {
  let url: URL;
  try {
    url = new URL(target);
  } catch {
    return null;
  }
  if (url.hostname !== 'huggingface.co') return null;

  const segments = url.pathname.split('/').filter(Boolean);
  const prefixed = segments[0] === 'datasets' || segments[0] === 'spaces';
  const type = prefixed ? segments[0] : 'models';
  const rest = prefixed ? segments.slice(1) : segments;
  // ns / repo / 'resolve' / rev / path…
  if (rest.length < 5 || rest[2] !== 'resolve') return null;
  const [namespace, repo, , revision] = rest;
  const filePath = rest.slice(4).map(decodeURIComponent).join('/');
  if (!namespace || !repo || !revision || !filePath) return null;

  return {
    commitUrl: `https://huggingface.co/api/${type}/${namespace}/${repo}/commit/${revision}`,
    filePath,
  };
}

/**
 * Upload one file through the HF commit API: newline-delimited JSON, a header
 * line naming the commit followed by a line per file.
 *
 * The blob is sent as base64 TEXT rather than as bytes — `encoding: 'utf-8'`,
 * NOT 'base64', because that flag would tell HF to decode the content back to
 * binary before writing it, which is exactly what we are avoiding: repos on Xet
 * storage reject binary blobs pushed through this route. Base64 costs a third
 * more bytes and buys a file the route will actually accept. readTarget()
 * reverses it.
 */
async function uploadToHuggingFace(
  commitUrl: string,
  filePath: string,
  payload: Buffer,
  token: string,
): Promise<void> {
  const lines = [
    { key: 'header', value: { summary: `chore: update ${filePath}` } },
    { key: 'file', value: { path: filePath, content: payload.toString('base64'), encoding: 'utf-8' } },
  ];
  const res = await fetch(commitUrl, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-ndjson',
      Authorization: `Bearer ${token}`,
    },
    body: lines.map(line => JSON.stringify(line)).join('\n'),
    signal: AbortSignal.timeout(fetchTimeoutMs()),
  });
  if (!res.ok) {
    const detail = await res.text().catch(() => '');
    throw new Error(`backup upload failed: HF commit HTTP ${res.status}${detail ? ` — ${detail.slice(0, 200)}` : ''}`);
  }
}

/** Undo the base64 wrapper uploadToHuggingFace applies. Sniffed rather than
 *  assumed: a blob left behind by an older build is raw and starts with MAGIC,
 *  and a restore that silently base64-decoded it would turn a recoverable
 *  database into a corrupt one. */
function decodeHuggingFacePayload(raw: Buffer): Buffer {
  if (raw.subarray(0, MAGIC.length).equals(MAGIC)) return raw;
  return Buffer.from(raw.toString('utf8'), 'base64');
}

async function readTarget(target: string): Promise<Buffer | null> {
  if (isHttpTarget(target)) {
    const headers: Record<string, string> = {};
    const token = process.env.FREEAPI_DB_BACKUP_TOKEN?.trim();
    if (token) headers.Authorization = `Bearer ${token}`;
    const res = await fetch(target, { method: 'GET', headers, signal: AbortSignal.timeout(fetchTimeoutMs()) });
    if (res.status === 404 || res.status === 204) return null;
    if (!res.ok) throw new Error(`backup restore failed: HTTP ${res.status}`);
    const raw = Buffer.from(await res.arrayBuffer());
    return parseHuggingFaceTarget(target) ? decodeHuggingFacePayload(raw) : raw;
  }

  if (!fs.existsSync(target)) return null;
  return fs.readFileSync(target);
}

async function writeTarget(target: string, payload: Buffer): Promise<void> {
  if (isHttpTarget(target)) {
    const token = process.env.FREEAPI_DB_BACKUP_TOKEN?.trim();
    const huggingFace = parseHuggingFaceTarget(target);
    if (huggingFace) {
      // Anonymous writes do not exist on HF; without a token every upload would
      // 401 on a schedule and only ever be noticed as an empty restore.
      if (!token) throw new Error('FREEAPI_DB_BACKUP_TOKEN is required to upload a backup to Hugging Face');
      await uploadToHuggingFace(huggingFace.commitUrl, huggingFace.filePath, payload, token);
      return;
    }

    const headers: Record<string, string> = { 'Content-Type': 'application/octet-stream' };
    if (token) headers.Authorization = `Bearer ${token}`;
    const res = await fetch(target, {
      method: 'PUT',
      headers,
      body: payload,
      signal: AbortSignal.timeout(fetchTimeoutMs()),
    });
    if (!res.ok) throw new Error(`backup upload failed: HTTP ${res.status}`);
    return;
  }

  fs.mkdirSync(path.dirname(path.resolve(target)), { recursive: true });
  // Encrypted, but not therefore safe to leave world-readable: the key is
  // FREEAPI_DB_BACKUP_KEY or ENCRYPTION_KEY, which on a normal install sits in a
  // .env file on the same host. The mode covers creation; restrictToOwner covers
  // the overwrite case, where an existing file keeps the mode it already had —
  // and covers Windows, where the mode argument is a no-op.
  const absoluteTarget = path.resolve(target);
  const tempPath = path.join(
    path.dirname(absoluteTarget),
    `.${path.basename(absoluteTarget)}.backup-${process.pid}-${crypto.randomBytes(8).toString('hex')}.tmp`,
  );

  try {
    fs.writeFileSync(tempPath, payload, { mode: 0o600, flag: 'wx' });
    if (!restrictToOwner(tempPath)) {
      console.warn(`[db-backup] could not restrict permissions on temporary backup file ${tempPath}`);
    }
    fs.renameSync(tempPath, absoluteTarget);
    if (!restrictToOwner(absoluteTarget)) {
      console.warn(`[db-backup] could not restrict permissions on ${absoluteTarget}`);
    }
  } finally {
    try {
      fs.rmSync(tempPath, { force: true });
    } catch {
      console.warn(`[db-backup] could not remove temporary backup file ${tempPath}`);
    }
  }
}

const SQLITE_HEADER = Buffer.from('SQLite format 3\0');

export function validateRestoredSqlite(filePath: string): void {
  const fd = fs.openSync(filePath, 'r');
  try {
    const header = Buffer.alloc(SQLITE_HEADER.length);
    const bytesRead = fs.readSync(fd, header, 0, header.length, 0);
    if (bytesRead !== SQLITE_HEADER.length || !header.equals(SQLITE_HEADER)) {
      throw new Error('backup does not contain a valid SQLite database header');
    }
  } finally {
    fs.closeSync(fd);
  }

  const validationDb = defaultDbFactory()(filePath);
  try {
    validationDb.pragma('query_only = ON');
    const rows = validationDb.pragma('integrity_check');
    const row = Array.isArray(rows) ? rows[0] : undefined;
    const result = row && typeof row === 'object'
      ? Object.values(row as Record<string, unknown>)[0]
      : undefined;

    if (result !== 'ok') {
      throw new Error('backup failed SQLite integrity_check');
    }

    const tables = validationDb.prepare(
      "SELECT COUNT(*) AS count FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'",
    ).get() as { count?: number } | undefined;

    if (!tables || Number(tables.count) < 1) {
      throw new Error('backup contains no application tables');
    }
  } finally {
    validationDb.close?.();
  }
}

export async function restoreDbBackupIfNeeded(dbPath = getDefaultDbPath()): Promise<DbBackupResult> {
  const target = backupTarget();
  if (!target) return { ok: true, skipped: 'not configured' };
  if (dbPath === ':memory:') return { ok: true, target, skipped: 'memory database' };
  if (fs.existsSync(dbPath) && fs.statSync(dbPath).size > 0) return { ok: true, target, skipped: 'database already exists' };

  const payload = await readTarget(target);
  if (!payload || payload.length === 0) return { ok: true, target, skipped: 'no backup found' };

  let restored: Buffer;
  try {
    restored = gunzipSync(decryptBackup(payload));
  } catch (err) {
    const detail = err instanceof Error ? err.message : String(err);
    throw new Error(`could not restore SQLite backup from ${target}: ${detail}`);
  }

  fs.mkdirSync(path.dirname(path.resolve(dbPath)), { recursive: true });

  const tempPath = path.join(
    path.dirname(path.resolve(dbPath)),
    `.${path.basename(dbPath)}.restore-${process.pid}-${crypto.randomBytes(8).toString('hex')}.tmp`,
  );

  try {
    // Keep the decrypted candidate owner-only and validate it before touching
    // the configured database path.
    fs.writeFileSync(tempPath, restored, { mode: 0o600, flag: 'wx' });
    if (!restrictToOwner(tempPath)) {
      console.warn(`[db-backup] could not restrict permissions on temporary restore file ${tempPath}`);
    }

    validateRestoredSqlite(tempPath);

    // Recheck the destination immediately before installation. Never replace
    // a database that another process has populated during the download.
    if (fs.existsSync(dbPath)) {
      if (fs.statSync(dbPath).size > 0) {
        throw new Error('database file changed during restore; refusing to replace it');
      }
      fs.rmSync(dbPath);
    }

    // The temporary file is in the same directory, allowing a same-filesystem
    // rename after validation rather than writing decrypted bytes in-place.
    fs.renameSync(tempPath, dbPath);

    if (!restrictToOwner(dbPath)) {
      console.warn(`[db-backup] could not restrict permissions on the restored database at ${dbPath}`);
    }
  } catch (err) {
    const detail = err instanceof Error ? err.message : String(err);
    throw new Error(`could not restore SQLite backup from ${target}: ${detail}`);
  } finally {
    try {
      fs.rmSync(tempPath, { force: true });
    } catch {
      console.warn(`[db-backup] could not remove temporary restore file ${tempPath}`);
    }
  }

  console.log(`[db-backup] restored ${restored.length} validated bytes from ${target}`);
  return { ok: true, target, bytes: restored.length, restored: true };
}

const activeBackupRuns = new Map<string, Promise<DbBackupResult>>();

function checkpointWalForBackup(db: Db): void {
  let result: unknown;
  try {
    result = db.pragma('wal_checkpoint(TRUNCATE)');
  } catch (err) {
    const detail = err instanceof Error ? err.message : String(err);
    throw new Error(`SQLite WAL checkpoint failed: ${detail}`);
  }

  const row = Array.isArray(result) ? result[0] : result;
  if (!row || typeof row !== 'object') {
    throw new Error('SQLite WAL checkpoint returned an invalid result; backup cancelled');
  }

  const busy = Number((row as Record<string, unknown>).busy);
  if (!Number.isFinite(busy)) {
    throw new Error('SQLite WAL checkpoint did not report busy status; backup cancelled');
  }
  if (busy !== 0) {
    throw new Error(`SQLite WAL checkpoint is busy (${busy}); backup cancelled`);
  }
}

async function performDbBackup(
  db: Db,
  dbPath: string,
  target: string,
): Promise<DbBackupResult> {
  if (!fs.existsSync(dbPath)) {
    return { ok: false, target, skipped: 'database file missing' };
  }

  checkpointWalForBackup(db);

  const plain = fs.readFileSync(dbPath);
  const payload = encryptBackup(gzipSync(plain));
  await writeTarget(target, payload);

  console.log(`[db-backup] uploaded ${plain.length} bytes to ${target}`);
  return { ok: true, target, bytes: plain.length };
}

function backupLockKey(dbPath: string, target: string): string {
  let databasePath = path.resolve(dbPath);
  let destination = isHttpTarget(target) ? target : path.resolve(target);

  if (process.platform === 'win32') {
    databasePath = databasePath.toLowerCase();
    if (!isHttpTarget(target)) destination = destination.toLowerCase();
  }
  return JSON.stringify([databasePath, destination]);
}

export function backupDbNow(db: Db, dbPath = getDefaultDbPath()): Promise<DbBackupResult> {
  const target = backupTarget();
  if (!target) return Promise.resolve({ ok: true, skipped: 'not configured' });
  if (dbPath === ':memory:') return Promise.resolve({ ok: true, target, skipped: 'memory database' });

  const key = backupLockKey(dbPath, target);
  const existing = activeBackupRuns.get(key);
  if (existing) return existing;

  let pending: Promise<DbBackupResult>;
  pending = performDbBackup(db, dbPath, target).finally(() => {
    if (activeBackupRuns.get(key) === pending) activeBackupRuns.delete(key);
  });
  activeBackupRuns.set(key, pending);
  return pending;
}

export function startDbBackupPump(db: Db, scheduler: Scheduler, dbPath = getDefaultDbPath()): (() => void) | null {
  if (!backupTarget()) return null;

  const run = async (): Promise<void> => {
    try {
      await backupDbNow(db, dbPath);
    } catch (err) {
      console.warn(`[db-backup] ${err instanceof Error ? err.message : err}`);
    }
  };

  void run();
  return scheduler.every(backupIntervalMs(), run);
}
