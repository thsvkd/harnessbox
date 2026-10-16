/// <reference types="node" />
// Types for src/client.mjs (import from 'harnessbox/client', or vendor both files). The service's API: docs/service.md.
export class HarnessboxError extends Error { status: number; code?: string; constructor(status: number, code?: string, message?: string) }
export interface HarnessStatus { harness: string; installed?: boolean; loggedIn?: boolean; method?: string | null; plan?: string | null; checkedAt?: string; busy?: true; error?: string }
export interface LoginView {
  state: 'starting' | 'waiting' | 'done' | 'failed'; url: string | null; code: string | null; needsCode: boolean;
  startedAt: string; expiresAt: string; error?: string; status?: HarnessStatus;
}
export interface RunFile { path: string; base64?: string; text?: string; copies?: string[] }
export interface RunRequest {
  user: string; harness: string; prompt: string; model?: string; files?: RunFile[]; readonly?: string[]; outputs?: string[];
  validate?: { argv: string[]; net?: 'none'; timeoutMs?: number }; timeoutMs?: number; args?: string[];
}
export interface Run {
  id: string; user: string; harness: string; model: string | null; state: 'queued' | 'running' | 'validating' | 'done' | 'failed' | 'canceled';
  createdAt: string; startedAt: string | null; endedAt: string | null; stage: string; events: number; error?: string;
  result: { code: number; text: string; usage: { input: number; output: number; unknown?: true }; error: string; stderr: string; why: string | null; timedOut: boolean; canceled: boolean; loggedIn?: boolean } | null;
  validator: { code: number; out: string; why: string | null } | null;
  /** base64 per requested path; null when missing, a link or too big. Present on GET and the end event. */
  outputs?: Record<string, string | null> | null;
}
export interface Harnessbox {
  harnesses(): Promise<{ harnesses: { id: string; name: string; version: string | null; usable: boolean; why: string | null }[] }>;
  statuses(user: string): Promise<{ harnesses: HarnessStatus[] }>;
  status(user: string, harness: string): Promise<HarnessStatus>;
  login(user: string, harness: string): Promise<LoginView>;
  loginState(user: string, harness: string): Promise<LoginView>;
  submitCode(user: string, harness: string, code: string): Promise<null>;
  cancelLogin(user: string, harness: string): Promise<null>;
  logout(user: string, harness: string): Promise<HarnessStatus>;
  purge(user: string): Promise<null>;
  run(body: RunRequest): Promise<Run>;
  getRun(id: string): Promise<Run>;
  cancelRun(id: string): Promise<null>;
  events(id: string, onEvent?: (event: 'state' | 'progress' | 'end', run: Run) => void): Promise<Run>;
}
export function harnessbox(options: { socketPath?: string; url?: string; token: string }): Harnessbox;
