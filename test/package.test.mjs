// Exercise the artifact another project installs, including its probe entrypoint. All CLI paths intentionally do not exist:
// the probe should run and report no usable harness, without a real account or any model/network request.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

test('a fresh consumer imports the packed library and can invoke its shipped probe', () => {
  const root = mkdtempSync(join(tmpdir(), 'hb-package-test-')), consumer = join(root, 'consumer');
  const run = (args, cwd, env = process.env) => spawnSync('npm', args, { cwd, env, encoding: 'utf8', timeout: 30000 });
  try {
    const packed = run(['pack', '--offline', '--ignore-scripts', '--json', '--pack-destination', root], join(import.meta.dirname, '..'));
    assert.equal(packed.status, 0, packed.stderr);
    const pack = JSON.parse(packed.stdout)[0];
    mkdirSync(consumer);
    const install = run(['install', '--offline', '--ignore-scripts', '--no-audit', '--no-fund', join(root, pack.filename)], consumer);
    assert.equal(install.status, 0, install.stderr);
    const imported = spawnSync(process.execPath, ['--input-type=module', '-e', 'import { createRunner, readOut } from "harnessbox"; console.log(typeof createRunner, typeof readOut)'], { cwd: consumer, encoding: 'utf8' });
    assert.equal(imported.status, 0, imported.stderr);
    assert.equal(imported.stdout.trim(), 'function function');
    const types = join(consumer, 'consumer.mts'), project = join(import.meta.dirname, '..');
    writeFileSync(types, 'import {createRunner,grok,type RunResult} from "harnessbox";\nconst hb=await createRunner({homes:"/homes",adapters:[grok],maxOutputBytes:1024});\nconst r:RunResult=await hb.run("alice","grok",{prompt:"x",dir:"/jobs/1"});\nawait hb.close();\n');
    const typed = spawnSync(process.execPath, [join(project, 'node_modules/typescript/bin/tsc'), '--strict', '--noEmit', '--module', 'NodeNext', '--target', 'ES2023', '--typeRoots', join(project, 'node_modules/@types'), types], { cwd: consumer, encoding: 'utf8', timeout: 30000 });
    assert.equal(typed.status, 0, typed.stdout + typed.stderr);
    const probe = run(['--prefix', join(consumer, 'node_modules', 'harnessbox'), 'run', 'probe'], consumer, {
      ...process.env, HB_HOMES: join(root, 'homes'), HB_SOCAT: join(import.meta.dirname, 'fake-socat'),
      HB_BIN_CLAUDE_CODE: '/nonexistent/claude', HB_BIN_CODEX: '/nonexistent/codex', HB_BIN_GROK: '/nonexistent/grok',
    });
    assert.equal(probe.status, 1, 'no usable harness is an unsuccessful probe');
    assert.match(probe.stdout, /SUMMARY/, probe.stderr);
    assert.doesNotMatch(probe.stderr, /MODULE_NOT_FOUND/);
  } finally { rmSync(root, { recursive: true, force: true }); }
});
