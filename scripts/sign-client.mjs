#!/usr/bin/env node
// Signs src/client.mjs with the harnessbox maintainers' Ed25519 key into src/client.mjs.sig (base64), which the service hands out
// with it (GET /v1/client) and clients check against the key in their own copy (autoUpdate). The key: HB_SIGNING_KEY (a PEM file),
// default ~/.config/harnessbox/client-signing-key.pem; it never goes in the repository.
import { createPrivateKey, sign } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';

const key = createPrivateKey(readFileSync(process.env.HB_SIGNING_KEY ?? join(homedir(), '.config/harnessbox/client-signing-key.pem')));
const file = new URL('../src/client.mjs', import.meta.url);
writeFileSync(new URL('../src/client.mjs.sig', import.meta.url), `${sign(null, readFileSync(file), key).toString('base64')}\n`);
console.log('signed src/client.mjs');
