/// <reference types="node" />
import type { ChildProcess } from 'node:child_process';
import type { Server, Socket } from 'node:net';

export type Env = Record<string, string>;
export type ReadOnlyBind = string | readonly [source: string, destination: string];
/** All event fields come from the box and must be validated before use. */
export type JsonEvent = Record<string, any>;
export interface Usage { input: number; output: number; unknown?: true }
export interface Status { installed: boolean; loggedIn: boolean; method?: string | null; plan?: string | null }
export interface ShortResult { code: number; out: string; why: string | null }
export interface Accumulator {
  text: string; usage: Usage; reports: number; error: string; stage: string; last?: string;
  [key: string]: unknown;
}
export interface Adapter {
  id: string; name: string; bin: string;
  globalArgs?: readonly string[];
  hosts: readonly string[];
  keep: readonly string[];
  keepJsonKeys?: Record<string, readonly string[]>;
  seed?: Record<string, string>;
  env?: Env;
  nested?: boolean;
  flags?: { args: readonly string[]; needs: readonly string[]; optional?: readonly string[] };
  checks?: readonly { args: readonly string[]; why: string; nested?: boolean }[];
  login: {
    kind: 'paste-code' | 'device-code'; args: readonly string[]; urlHosts: readonly string[];
    parse(text: string): { url: string; code?: string } | null;
  };
  status: { args: readonly string[]; parse(result: ShortResult): Omit<Status, 'installed'> };
  logout: readonly string[];
  expired?: RegExp;
  /** job.command turns on the CLI's own server-side web search when options.webSearch is true; without it such a run is refused. */
  webSearch?: boolean;
  job: {
    command(options: { prompt: string; dir: string; has: Set<string>; extra: readonly string[]; webSearch: boolean }): { args: readonly string[]; stdin?: string };
    event(event: JsonEvent, acc: Accumulator): void;
    finish?(acc: Accumulator, options: { dir: string; readOut: typeof readOut }): Promise<void>;
  };
}
export interface RunnerOptions {
  homes: string; adapters: readonly Adapter[];
  bins?: Record<string, string>; pins?: Record<string, string>; bwrap?: string; socat?: string;
  maxJobs?: number; maxQuick?: number; maxProcs?: number; maxBytes?: number; maxEntries?: number; maxOutputBytes?: number;
  log?: (line: string) => void | Promise<void>; passEnv?: Env;
}
export interface DetectRow {
  id: string; name: string; bin: string | null; version: string | null; usable: boolean; why: string | null; has: Set<string>;
  /** The adapter supports webSearch (Adapter.webSearch). */
  webSearch: boolean;
}
export interface RunOptions {
  prompt: string; dir: string; timeoutMs?: number; args?: readonly string[]; env?: Env;
  roBinds?: readonly ReadOnlyBind[]; signal?: AbortSignal;
  /** Where the box sees dir (default: the same path), e.g. '/work'. */
  boxDir?: string;
  /** Passed to the CLI as --model. */
  model?: string;
  /** The box started (after the user's lock and a job slot). */
  onStart?: () => void;
  /** Notifications are fire-and-forget; synchronous errors and rejected promises are contained. */
  onEvent?: (event: JsonEvent, info: { stage: string }) => void | Promise<void>;
  /** The CLI's own server-side web search on (adapters with webSearch only; default false). The box's hosts stay the same. */
  webSearch?: boolean;
}
export interface RunResult {
  code: number; text: string; usage: Usage; error: string; stderr: string; why: string | null;
  timedOut: boolean; canceled: boolean; loggedIn?: boolean;
}
export interface ExecOptions {
  net?: 'none' | 'proxy'; dir?: string; boxDir?: string; ms?: number; stdin?: string; env?: Env;
  roBinds?: readonly ReadOnlyBind[]; nested?: boolean; signal?: AbortSignal;
  /** A throwaway home instead of the user's (no lock then): for a command someone else chose. */
  home?: string;
}
export interface LoginWaiting { url: string; code: string | null; needsCode: boolean }
export type LoginResult = { ok: true; status: Status } | { ok: false; error: string };
export interface LoginSession {
  state: 'starting' | 'waiting' | 'refused' | 'done' | 'failed';
  url: string | null; code: string | null; needsCode: boolean; error?: string;
  waiting: Promise<LoginWaiting>; done: Promise<LoginResult>;
  submitCode(code: string): boolean; cancel(): void;
}
export interface Box {
  child: ChildProcess; home: string; dir?: string; why: string | null; closed: Promise<number>; kill(): void;
}
/** userId is `user` or `scope/user`, each part [A-Za-z0-9_-]{1,64}; homes are <homes>/<userId>/<harness>. */
export interface Runner {
  detect(): Promise<DetectRow[]>;
  status(userId: string, id: string, options?: { waitMs?: number }): Promise<Status>;
  login(userId: string, id: string): LoginSession;
  logout(userId: string, id: string, options?: { waitMs?: number }): Promise<Status>;
  purge(userId: string): Promise<void>;
  run(userId: string, id: string, options: RunOptions): Promise<RunResult>;
  exec(userId: string, id: string, argv: readonly string[], options?: ExecOptions): Promise<ShortResult>;
  close(): Promise<void>;
  boxes: Map<number, Box>;
  bin(id: string): string | null;
}
export class Busy extends Error {}
export function createRunner(options: RunnerOptions): Promise<Runner>;
export const claudeCode: Adapter;
export const codex: Adapter;
export const grok: Adapter;

export const ID: RegExp;
export const BOX_TMP_BYTES: number;
export function privateIp(ip: string): boolean;
export interface ProxyOptions {
  allow: readonly string[]; label: string; log: (line: string) => void;
  lookup?: (host: string, options: { family: 4 }) => Promise<{ address: string; family: number }>;
  connect?: (options: { host: string; port: number }) => Socket;
}
export function startProxy(sockPath: string, options: ProxyOptions): Promise<Server>;
export function scrubHome(home: string, keep?: readonly string[], jsonKeys?: Record<string, readonly string[]>): Promise<void>;
export function readOut(realDir: string, name: string, max?: number): Promise<string | null>;
export function readOutBytes(realDir: string, name: string, max?: number): Promise<Buffer | null>;
export function parseStat(text: string): { pid: number; ppid: number };
export function countDescendants(rootPids: readonly number[], procDir?: string): Promise<Map<number, number>>;
export function diskUse(roots: readonly string[], cap?: number): Promise<{ bytes: number; entries: number }>;
export function seccompFilter(arch?: string): Buffer;
export interface BoxOptions {
  home: string; path: string; cmd: readonly string[]; dir?: string; net?: 'none' | 'proxy'; sock?: string; socat?: string;
  env?: Env; roBinds?: readonly ReadOnlyBind[]; chdir?: string; maxTasks?: number; nested?: boolean; seccomp?: boolean; boxDir?: string;
}
export function boxArgs(options: BoxOptions): string[];
