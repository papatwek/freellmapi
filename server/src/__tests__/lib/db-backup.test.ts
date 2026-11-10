import fs from 'fs';
import os from 'os';
import path from 'path';
import Database from 'better-sqlite3';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { backupDbNow, parseHuggingFaceTarget, restoreDbBackupIfNeeded, validateRestoredSqlite } from '../../lib/db-backup.js';
import { aclEntries } from '../helpers/acl.js';

const ORIGINAL_BACKUP_PATH = process.env.FREEAPI_DB_BACKUP_PATH;
const ORIGINAL_BACKUP_TARGET = process.env.FREEAPI_DB_BACKUP_TARGET;
const ORIGINAL_BACKUP_URL = process.env.FREEAPI_DB_BACKUP_URL;
const ORIGINAL_BACKUP_KEY = process.env.FREEAPI_DB_BACKUP_KEY;
const ORIGINAL_BACKUP_TOKEN = process.env.FREEAPI_DB_BACKUP_TOKEN;
const ORIGINAL_ENCRYPTION_KEY = process.env.ENCRYPTION_KEY;

function restoreEnv() {
  if (ORIGINAL_BACKUP_PATH === undefined) delete process.env.FREEAPI_DB_BACKUP_PATH;
  else process.env.FREEAPI_DB_BACKUP_PATH = ORIGINAL_BACKUP_PATH;
  if (ORIGINAL_BACKUP_TARGET === undefined) delete process.env.FREEAPI_DB_BACKUP_TARGET;
  else process.env.FREEAPI_DB_BACKUP_TARGET = ORIGINAL_BACKUP_TARGET;
  if (ORIGINAL_BACKUP_URL === undefined) delete process.env.FREEAPI_DB_BACKUP_URL;
  else process.env.FREEAPI_DB_BACKUP_URL = ORIGINAL_BACKUP_URL;
  if (ORIGINAL_BACKUP_KEY === undefined) delete process.env.FREEAPI_DB_BACKUP_KEY;
  else process.env.FREEAPI_DB_BACKUP_KEY = ORIGINAL_BACKUP_KEY;
  if (ORIGINAL_BACKUP_TOKEN === undefined) delete process.env.FREEAPI_DB_BACKUP_TOKEN;
  else process.env.FREEAPI_DB_BACKUP_TOKEN = ORIGINAL_BACKUP_TOKEN;
  if (ORIGINAL_ENCRYPTION_KEY === undefined) delete process.env.ENCRYPTION_KEY;
  else process.env.ENCRYPTION_KEY = ORIGINAL_ENCRYPTION_KEY;
}

describe('encrypted SQLite backup', () => {
  afterEach(() => restoreEnv());

  it('backs up and restores a SQLite file from a configured path', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'freeapi-db-backup-'));
    const dbPath = path.join(dir, 'freeapi.db');
    const backupPath = path.join(dir, 'backup.bin');
    process.env.ENCRYPTION_KEY = 'a'.repeat(64);
    process.env.FREEAPI_DB_BACKUP_PATH = backupPath;

    const db = new Database(dbPath);
    db.exec('CREATE TABLE items (name TEXT NOT NULL); INSERT INTO items (name) VALUES (\'survived\')');
    const backup = await backupDbNow(db, dbPath);
    db.close();

    expect(backup.ok).toBe(true);
    expect(fs.existsSync(backupPath)).toBe(true);
    expect(fs.readFileSync(backupPath).includes(Buffer.from('survived'))).toBe(false);

    fs.rmSync(dbPath);
    const restore = await restoreDbBackupIfNeeded(dbPath);
    expect(restore.restored).toBe(true);

    const restored = new Database(dbPath);
    expect((restored.prepare('SELECT name FROM items').get() as { name: string }).name).toBe('survived');
    restored.close();
  });
});



describe('safe restore installation', () => {
  afterEach(() => restoreEnv());

  it('does not install an invalid SQLite backup over an empty destination', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'freeapi-safe-restore-'));
    const sourcePath = path.join(dir, 'source.db');
    const invalidSourcePath = path.join(dir, 'invalid-source.db');
    const backupPath = path.join(dir, 'backup.bin');
    const destinationPath = path.join(dir, 'destination.db');

    const db = new Database(sourcePath);
    db.exec('CREATE TABLE items (name TEXT NOT NULL)');
    fs.writeFileSync(invalidSourcePath, 'not a SQLite database');

    process.env.ENCRYPTION_KEY = 'b'.repeat(64);
    delete process.env.FREEAPI_DB_BACKUP_TARGET;
    delete process.env.FREEAPI_DB_BACKUP_URL;
    process.env.FREEAPI_DB_BACKUP_PATH = backupPath;

    await backupDbNow(db, invalidSourcePath);
    db.close();

    fs.writeFileSync(destinationPath, '');

    await expect(restoreDbBackupIfNeeded(destinationPath))
      .rejects.toThrow(/valid SQLite database header/);

    expect(fs.statSync(destinationPath).size).toBe(0);
    expect(
      fs.readdirSync(dir).filter(name => name.startsWith('.destination.db.restore-')),
    ).toEqual([]);
  });
});

describe('restored SQLite validation', () => {
  it('accepts a valid SQLite database containing an application table', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'freeapi-validate-valid-'));
    const dbPath = path.join(dir, 'valid.db');
    const db = new Database(dbPath);
    db.exec('CREATE TABLE items (name TEXT NOT NULL)');
    db.close();

    expect(() => validateRestoredSqlite(dbPath)).not.toThrow();
  });

  it('rejects a file without a SQLite header', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'freeapi-validate-header-'));
    const dbPath = path.join(dir, 'invalid.db');
    fs.writeFileSync(dbPath, 'not a SQLite database');

    expect(() => validateRestoredSqlite(dbPath)).toThrow(/valid SQLite database header/);
  });

  it('rejects a SQLite database with no application tables', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'freeapi-validate-empty-'));
    const dbPath = path.join(dir, 'empty.db');
    const db = new Database(dbPath);
    db.exec('CREATE TABLE temporary_items (value TEXT); DROP TABLE temporary_items;');
    db.close();

    expect(() => validateRestoredSqlite(dbPath)).toThrow(/no application tables/);
  });
});


describe('backup reliability', () => {
  afterEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
    restoreEnv();
  });

  it('refuses to upload when the WAL checkpoint is busy', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'freeapi-wal-busy-'));
    const dbPath = path.join(dir, 'database.db');
    const backupPath = path.join(dir, 'backup.bin');
    fs.writeFileSync(dbPath, 'database fixture');

    delete process.env.FREEAPI_DB_BACKUP_TARGET;
    delete process.env.FREEAPI_DB_BACKUP_URL;
    process.env.FREEAPI_DB_BACKUP_PATH = backupPath;

    const db = {
      pragma: vi.fn(() => [{ busy: 1, log: 2, checkpointed: 0 }]),
    } as unknown as Parameters<typeof backupDbNow>[0];

    await expect(backupDbNow(db, dbPath)).rejects.toThrow(/WAL checkpoint is busy/);
    expect(db.pragma).toHaveBeenCalledWith('wal_checkpoint(TRUNCATE)');
    expect(fs.existsSync(backupPath)).toBe(false);
  });

  it('coalesces simultaneous requests into one upload', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'freeapi-single-flight-'));
    const dbPath = path.join(dir, 'database.db');
    const db = new Database(dbPath);
    db.exec('CREATE TABLE items (name TEXT);');

    delete process.env.FREEAPI_DB_BACKUP_URL;
    delete process.env.FREEAPI_DB_BACKUP_PATH;
    process.env.FREEAPI_DB_BACKUP_TARGET = 'https://storage.example.com/freeapi.db.enc';
    process.env.ENCRYPTION_KEY = 'c'.repeat(64);

    let releaseFetch: ((response: Response) => void) | undefined;
    const fetchMock = vi.fn(
      (_url: string, _init: RequestInit) =>
        new Promise<Response>(resolve => { releaseFetch = resolve; }),
    );
    vi.stubGlobal('fetch', fetchMock);

    let pending: Promise<unknown> | undefined;
    try {
      pending = backupDbNow(db, dbPath);
      const duplicate = backupDbNow(db, dbPath);

      expect(duplicate).toBe(pending);
      expect(fetchMock).toHaveBeenCalledTimes(1);

      if (!releaseFetch) throw new Error('Upload did not start.');
      releaseFetch(new Response('', { status: 200 }));

      await Promise.all([pending, duplicate]);
      expect(fetchMock).toHaveBeenCalledTimes(1);
    } finally {
      releaseFetch?.(new Response('', { status: 200 }));
      await pending?.catch(() => undefined);
      db.close();
    }
  });

  it('preserves an existing backup when atomic replacement fails', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'freeapi-atomic-backup-'));
    const dbPath = path.join(dir, 'database.db');
    const backupPath = path.join(dir, 'backup.bin');
    const db = new Database(dbPath);
    db.exec('CREATE TABLE items (name TEXT);');
    fs.writeFileSync(backupPath, 'previous-good-backup');

    delete process.env.FREEAPI_DB_BACKUP_TARGET;
    delete process.env.FREEAPI_DB_BACKUP_URL;
    process.env.FREEAPI_DB_BACKUP_PATH = backupPath;
    process.env.ENCRYPTION_KEY = 'd'.repeat(64);

    const renameSpy = vi.spyOn(fs, 'renameSync').mockImplementation(() => {
      throw new Error('simulated rename failure');
    });

    try {
      await expect(backupDbNow(db, dbPath))
        .rejects.toThrow(/simulated rename failure/);
    } finally {
      renameSpy.mockRestore();
      db.close();
    }

    expect(fs.readFileSync(backupPath, 'utf8')).toBe('previous-good-backup');
    expect(
      fs.readdirSync(dir).filter(name => name.startsWith('.backup.bin.backup-')),
    ).toEqual([]);
  });
});

describe('backup file permissions', () => {
  // The blob is AES-256-GCM encrypted and the restored file is a plain SQLite
  // database, but both live on a host that also holds the key — usually in a
  // .env in the same tree — so neither may be left world-readable.
  //
  // As elsewhere, each platform asserts what it can actually enforce: Node
  // synthesizes a 0o666 mode on Windows regardless of the ACL, so a POSIX-mode
  // assertion there would pass or fail for reasons unrelated to the guarantee.
  const isWindows = process.platform === 'win32';
  const itPosix = it.skipIf(isWindows);
  const itWindows = it.skipIf(!isWindows);

  afterEach(() => restoreEnv());

  async function backupInto(dir: string): Promise<string> {
    const dbPath = path.join(dir, 'freeapi.db');
    const backupPath = path.join(dir, 'backup.bin');
    process.env.ENCRYPTION_KEY = 'a'.repeat(64);
    process.env.FREEAPI_DB_BACKUP_PATH = backupPath;

    const db = new Database(dbPath);
    db.exec('CREATE TABLE items (name TEXT NOT NULL)');
    await backupDbNow(db, dbPath);
    db.close();
    return backupPath;
  }

  itPosix('writes the backup blob owner-only', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'freeapi-backup-perms-'));
    const backupPath = await backupInto(dir);

    expect(fs.statSync(backupPath).mode & 0o077).toBe(0);
  });

  itPosix('tightens a backup target that already existed', async () => {
    // writeFileSync's mode argument only applies when the file is created, so
    // every backup after the first overwrites a file that keeps whatever mode
    // it already had. Without the explicit restrict call this is the case that
    // stays group-readable forever.
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'freeapi-backup-perms-'));
    const backupPath = path.join(dir, 'backup.bin');
    fs.writeFileSync(backupPath, 'stale');
    // chmod rather than a creation mode: the mode argument is filtered through
    // the runner's umask, so a strict umask would leave this pre-condition
    // asserting the very thing it means to rule out.
    fs.chmodSync(backupPath, 0o644);
    expect(fs.statSync(backupPath).mode & 0o077).not.toBe(0);

    await backupInto(dir);

    expect(fs.statSync(backupPath).mode & 0o077).toBe(0);
  });

  itPosix('writes the restored database owner-only', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'freeapi-backup-perms-'));
    const dbPath = path.join(dir, 'freeapi.db');
    await backupInto(dir);
    fs.rmSync(dbPath);

    // The restore lands before connectDb runs, and sometimes in a different
    // process entirely; the decrypted database must not be readable in between.
    expect((await restoreDbBackupIfNeeded(dbPath)).restored).toBe(true);
    expect(fs.statSync(dbPath).mode & 0o077).toBe(0);
  });

  itWindows('replaces the inherited ACL on the backup blob', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'freeapi-backup-perms-'));
    const backupPath = await backupInto(dir);

    const entries = aclEntries(backupPath);
    expect(entries.filter(e => e.includes('(I)'))).toEqual([]);
    expect(entries).toHaveLength(3);
  });
});

describe('parseHuggingFaceTarget', () => {
  it('maps a dataset download URL onto the commit API', () => {
    expect(parseHuggingFaceTarget('https://huggingface.co/datasets/acme/state/resolve/main/backups/freeapi.db.enc')).toEqual({
      commitUrl: 'https://huggingface.co/api/datasets/acme/state/commit/main',
      filePath: 'backups/freeapi.db.enc',
    });
  });

  it('treats the prefix-less repo path as a model repo', () => {
    expect(parseHuggingFaceTarget('https://huggingface.co/acme/state/resolve/main/freeapi.db.enc')).toEqual({
      commitUrl: 'https://huggingface.co/api/models/acme/state/commit/main',
      filePath: 'freeapi.db.enc',
    });
  });

  it('maps a space download URL', () => {
    expect(parseHuggingFaceTarget('https://huggingface.co/spaces/acme/app/resolve/main/data/freeapi.db.enc')?.commitUrl)
      .toBe('https://huggingface.co/api/spaces/acme/app/commit/main');
  });

  it('leaves every other target alone', () => {
    expect(parseHuggingFaceTarget('https://example.com/acme/state/resolve/main/freeapi.db.enc')).toBeNull();
    // A HF URL that is not a /resolve/ download has no commit route to derive.
    expect(parseHuggingFaceTarget('https://huggingface.co/acme/state')).toBeNull();
    expect(parseHuggingFaceTarget('/var/backups/freeapi.db.enc')).toBeNull();
  });
});

describe('Hugging Face backup target', () => {
  // The /resolve/ URL a HF repo serves downloads from is read-only: the PUT this
  // used to send was answered 404 and the blob never landed, so an ephemeral
  // host restored nothing on its next cold start. Uploads go through the commit
  // API, and the blob travels as base64 text because repos on Xet storage reject
  // binary pushed through that route.
  const TARGET = 'https://huggingface.co/datasets/acme/state/resolve/main/backups/freeapi.db.enc';

  afterEach(() => {
    vi.unstubAllGlobals();
    restoreEnv();
  });

  function seedDb(dir: string): string {
    const dbPath = path.join(dir, 'freeapi.db');
    const db = new Database(dbPath);
    db.exec('CREATE TABLE items (name TEXT NOT NULL); INSERT INTO items (name) VALUES (\'survived\')');
    db.close();
    return dbPath;
  }

  it('uploads through the commit API as base64 and restores it', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'freeapi-hf-backup-'));
    const dbPath = seedDb(dir);
    process.env.ENCRYPTION_KEY = 'a'.repeat(64);
    process.env.FREEAPI_DB_BACKUP_TARGET = TARGET;
    process.env.FREEAPI_DB_BACKUP_TOKEN = 'hf_token';

    let stored = '';
    const fetchMock = vi.fn(async (url: string, init: RequestInit) => {
      if (init.method === 'POST') {
        stored = String(init.body);
        return new Response('{}', { status: 200 });
      }
      return new Response(stored, { status: 200 });
    });
    vi.stubGlobal('fetch', fetchMock);

    const db = new Database(dbPath);
    expect((await backupDbNow(db, dbPath)).ok).toBe(true);
    db.close();

    const [uploadUrl, uploadInit] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(uploadUrl).toBe('https://huggingface.co/api/datasets/acme/state/commit/main');
    expect(uploadInit.method).toBe('POST');
    expect((uploadInit.headers as Record<string, string>)['Content-Type']).toBe('application/x-ndjson');
    expect((uploadInit.headers as Record<string, string>).Authorization).toBe('Bearer hf_token');

    const [header, file] = String(uploadInit.body).split('\n').map(line => JSON.parse(line));
    expect(header).toEqual({ key: 'header', value: { summary: 'chore: update backups/freeapi.db.enc' } });
    expect(file.key).toBe('file');
    expect(file.value.path).toBe('backups/freeapi.db.enc');
    // Base64 text, not bytes — 'base64' here would make HF write the binary back.
    expect(file.value.encoding).toBe('utf-8');
    expect(file.value.content).toMatch(/^[A-Za-z0-9+/]+={0,2}$/);
    expect(file.value.content).not.toContain('survived');

    // What HF serves back from /resolve/ is that base64 text; the restore has to
    // decode it before it is a database again.
    stored = file.value.content;
    fs.rmSync(dbPath);
    expect((await restoreDbBackupIfNeeded(dbPath)).restored).toBe(true);

    const restored = new Database(dbPath);
    expect((restored.prepare('SELECT name FROM items').get() as { name: string }).name).toBe('survived');
    restored.close();
  });

  it('still restores a blob that was stored raw', async () => {
    // Anything a previous build managed to land is raw ciphertext. Sniffing the
    // magic header keeps that path recoverable instead of base64-decoding it
    // into garbage.
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'freeapi-hf-legacy-'));
    const dbPath = seedDb(dir);
    const blobPath = path.join(dir, 'backup.bin');
    process.env.ENCRYPTION_KEY = 'a'.repeat(64);
    process.env.FREEAPI_DB_BACKUP_PATH = blobPath;

    const db = new Database(dbPath);
    await backupDbNow(db, dbPath);
    db.close();
    const raw = fs.readFileSync(blobPath);

    delete process.env.FREEAPI_DB_BACKUP_PATH;
    process.env.FREEAPI_DB_BACKUP_TARGET = TARGET;
    vi.stubGlobal('fetch', vi.fn(async () => new Response(raw, { status: 200 })));

    fs.rmSync(dbPath);
    expect((await restoreDbBackupIfNeeded(dbPath)).restored).toBe(true);
    const restored = new Database(dbPath);
    expect((restored.prepare('SELECT name FROM items').get() as { name: string }).name).toBe('survived');
    restored.close();
  });

  it('refuses to upload without a token rather than 401ing on a schedule', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'freeapi-hf-token-'));
    const dbPath = seedDb(dir);
    process.env.ENCRYPTION_KEY = 'a'.repeat(64);
    process.env.FREEAPI_DB_BACKUP_TARGET = TARGET;
    delete process.env.FREEAPI_DB_BACKUP_TOKEN;

    const fetchMock = vi.fn();
    vi.stubGlobal('fetch', fetchMock);

    const db = new Database(dbPath);
    await expect(backupDbNow(db, dbPath)).rejects.toThrow(/FREEAPI_DB_BACKUP_TOKEN is required/);
    db.close();
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('surfaces a rejected commit', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'freeapi-hf-error-'));
    const dbPath = seedDb(dir);
    process.env.ENCRYPTION_KEY = 'a'.repeat(64);
    process.env.FREEAPI_DB_BACKUP_TARGET = TARGET;
    process.env.FREEAPI_DB_BACKUP_TOKEN = 'hf_token';
    vi.stubGlobal('fetch', vi.fn(async () => new Response('repo not found', { status: 404 })));

    const db = new Database(dbPath);
    await expect(backupDbNow(db, dbPath)).rejects.toThrow(/HF commit HTTP 404 — repo not found/);
    db.close();
  });

  it('leaves a plain HTTP target on the PUT path', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'freeapi-http-backup-'));
    const dbPath = seedDb(dir);
    process.env.ENCRYPTION_KEY = 'a'.repeat(64);
    process.env.FREEAPI_DB_BACKUP_TARGET = 'https://storage.example.com/freeapi.db.enc';
    process.env.FREEAPI_DB_BACKUP_TOKEN = 'plain_token';

    const fetchMock = vi.fn(async () => new Response('', { status: 200 }));
    vi.stubGlobal('fetch', fetchMock);

    const db = new Database(dbPath);
    expect((await backupDbNow(db, dbPath)).ok).toBe(true);
    db.close();

    const [url, init] = fetchMock.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toBe('https://storage.example.com/freeapi.db.enc');
    expect(init.method).toBe('PUT');
    expect((init.headers as Record<string, string>)['Content-Type']).toBe('application/octet-stream');
    expect(Buffer.isBuffer(init.body)).toBe(true);
  });
});
