/**
 * macOS seatbelt sandbox integration.
 *
 * When GOOSE_SANDBOX=true, goosed is launched under `sandbox-exec` with a
 * dynamically-generated profile derived from `.gooseignore`. Absolute-path
 * entries in the ignore file are translated directly into seatbelt deny rules;
 * glob-style entries (e.g. `**\/.env`) are already enforced at the application
 * layer by the Rust developer extension and are not repeated here.
 *
 * The profile allows everything by default and then adds targeted denies:
 *
 *   (version 1)
 *   (allow default)
 *   (deny file-read*
 *       (subpath "/Users/alice/notes/Personal/Health"))
 *   (deny file-write*
 *       (subpath "/Users/alice/Projects/readonly-archive"))
 */

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

// ── Types ────────────────────────────────────────────────────────────────────

interface DeniedPaths {
  read: string[];
  write: string[];
}

// ── Public API ────────────────────────────────────────────────────────────────

/** Returns true when the macOS seatbelt sandbox should be applied. */
export function isSandboxEnabled(): boolean {
  return process.env.GOOSE_SANDBOX === 'true' && process.platform === 'darwin';
}

/**
 * Given the goosed binary path and its arguments, return the command and args
 * needed to launch it under `sandbox-exec` using a profile built from the
 * `.gooseignore` files found relative to `workingDir`.
 *
 * If sandboxing is not enabled this returns the original command/args unchanged.
 */
export function buildGoosedSandboxSpawn(
  goosedPath: string,
  goosedArgs: string[],
  workingDir: string
): { command: string; args: string[] } {
  if (!isSandboxEnabled()) {
    return { command: goosedPath, args: goosedArgs };
  }

  const denied = loadDeniedPaths(workingDir);
  const profile = buildSandboxProfile(denied);

  return {
    command: 'sandbox-exec',
    args: ['-p', profile, goosedPath, ...goosedArgs],
  };
}

// ── Profile generation ────────────────────────────────────────────────────────

/** Build the seatbelt profile string from sets of denied absolute paths. */
export function buildSandboxProfile(denied: DeniedPaths): string {
  const lines: string[] = ['(version 1)', '(allow default)'];

  if (denied.read.length > 0) {
    lines.push('(deny file-read*');
    for (const p of denied.read) {
      lines.push(`    (subpath "${escapeSbpl(p)}")`);
    }
    lines.push(')');
  }

  if (denied.write.length > 0) {
    lines.push('(deny file-write*');
    for (const p of denied.write) {
      lines.push(`    (subpath "${escapeSbpl(p)}")`);
    }
    lines.push(')');
  }

  return lines.join('\n');
}

// ── .gooseignore parsing ──────────────────────────────────────────────────────

/**
 * Load denied paths from the global and local `.gooseignore` files.
 *
 * Only absolute-path patterns (those starting with `~/` or `/`) are returned.
 * Glob patterns (e.g. `**\/.env`) are already handled at the application layer
 * and cannot be expressed as seatbelt subpath rules.
 */
export function loadDeniedPaths(workingDir: string): DeniedPaths {
  const home = os.homedir();
  const denied: DeniedPaths = { read: [], write: [] };

  const globalPath = path.join(
    process.env.XDG_CONFIG_HOME || path.join(home, '.config'),
    'goose',
    '.gooseignore'
  );
  const localPath = path.join(workingDir, '.gooseignore');

  for (const filePath of [globalPath, localPath]) {
    if (fs.existsSync(filePath)) {
      const content = fs.readFileSync(filePath, 'utf8');
      parseGooseignore(content, home, denied);
    }
  }

  return denied;
}

/** Parse `.gooseignore` content and accumulate absolute denied paths. */
export function parseGooseignore(content: string, home: string, denied: DeniedPaths): void {
  for (const rawLine of content.split('\n')) {
    const line = rawLine.trim();
    if (!line || line.startsWith('#')) continue;

    let pattern: string;
    let denyRead = true;
    let denyWrite = true;

    if (line.startsWith('read:')) {
      pattern = line.slice('read:'.length).trim();
      denyWrite = false;
    } else if (line.startsWith('write:')) {
      pattern = line.slice('write:'.length).trim();
      denyRead = false;
    } else if (line.startsWith('both:')) {
      pattern = line.slice('both:'.length).trim();
    } else {
      pattern = line;
    }

    const absPath = resolveAbsolutePath(pattern, home);
    if (absPath === null) {
      // Glob pattern — enforced at app layer, skip for seatbelt
      continue;
    }

    // Strip trailing slash for seatbelt subpath (it matches the subtree regardless)
    const normalised = absPath.replace(/\/+$/, '');

    if (denyRead) denied.read.push(normalised);
    if (denyWrite) denied.write.push(normalised);
  }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/**
 * Resolve a pattern to an absolute path, or return null if it is a glob
 * (contains `*` or `?`) that cannot be represented as a seatbelt subpath.
 */
function resolveAbsolutePath(pattern: string, home: string): string | null {
  if (pattern.includes('*') || pattern.includes('?')) return null;

  if (pattern.startsWith('~/')) {
    return path.join(home, pattern.slice(2));
  }
  if (pattern.startsWith('/')) {
    return pattern;
  }
  // Relative pattern without a glob — not safe to assume a base dir at this
  // layer, so skip (the Rust layer handles it relative to working_dir).
  return null;
}

/** Escape characters that have special meaning inside SBPL string literals. */
function escapeSbpl(value: string): string {
  return value.replace(/\\/g, '\\\\').replace(/"/g, '\\"');
}
