// Isolated process: an unhandled async onEvent rejection must not kill all users' boxes.
import assert from 'node:assert/strict';
import { mkdir, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { claudeCode, createRunner } from '../src/index.mjs';

const root = process.argv[2], homes = join(root, 'homes'), dir = join(root, 'job');
const hb = await createRunner({ homes, adapters: [claudeCode], bins: { 'claude-code': join(import.meta.dirname, 'fake-claude') }, socat: join(import.meta.dirname, 'fake-socat') });
try {
  await hb.detect();
  await mkdir(join(homes, 'alice', 'claude-code', '.claude'), { recursive: true });
  await writeFile(join(homes, 'alice', 'claude-code', '.claude', '.credentials.json'), '{"fake":true}');
  await mkdir(dir);
  const r = await hb.run('alice', 'claude-code', { prompt: 'x', dir, onEvent: async () => { throw new Error('a rejected callback'); } });
  assert.equal(r.code, 0);
  assert.equal(r.text, 'done (ok)');
  await new Promise((r) => setImmediate(r));
  console.log('event handler survived');
} finally { await hb.close(); }
