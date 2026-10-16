import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

test('home migration copies regular credentials and refuses symlinked credential directories', () => {
  const root = mkdtempSync(join(tmpdir(), 'hb-migration-')), old = join(root, 'old'), next = join(root, 'new');
  try {
    for (const user of ['alice', 'bob']) mkdirSync(join(old, user), { recursive: true });
    for (const dir of ['.claude', '.codex']) {
      mkdirSync(join(old, 'bob', dir));
      symlinkSync(join('..', 'bob', dir), join(old, 'alice', dir));
    }
    writeFileSync(join(old, 'bob', '.claude', '.credentials.json'), 'bob-claude');
    writeFileSync(join(old, 'bob', '.codex', 'auth.json'), 'bob-codex');
    const r = spawnSync('sh', [join(import.meta.dirname, '..', 'deploy', 'move-homes.sh'), old, next, 'app'], { encoding: 'utf8' });
    assert.equal(r.status, 0, r.stderr);
    assert.equal(readFileSync(join(next, 'app', 'bob', 'claude-code', '.claude', '.credentials.json'), 'utf8'), 'bob-claude');
    assert.equal(readFileSync(join(next, 'app', 'bob', 'codex', '.codex', 'auth.json'), 'utf8'), 'bob-codex');
    assert.equal(existsSync(join(next, 'app', 'alice', 'claude-code', '.claude', '.credentials.json')), false);
    assert.equal(existsSync(join(next, 'app', 'alice', 'codex', '.codex', 'auth.json')), false);
  } finally { rmSync(root, { recursive: true, force: true }); }
});
