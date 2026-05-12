import { describe, it, expect, vi, afterEach } from 'vitest';
import { buildSandboxProfile, parseGooseignore, isSandboxEnabled, buildGoosedSandboxSpawn } from './index';

const HOME = '/Users/testuser';

// ── parseGooseignore ──────────────────────────────────────────────────────────

describe('parseGooseignore', () => {
  it('no-prefix denies read and write', () => {
    const denied = { read: [] as string[], write: [] as string[] };
    parseGooseignore('~/notes/Private/', HOME, denied);
    expect(denied.read).toEqual([`${HOME}/notes/Private`]);
    expect(denied.write).toEqual([`${HOME}/notes/Private`]);
  });

  it('both: prefix denies read and write', () => {
    const denied = { read: [] as string[], write: [] as string[] };
    parseGooseignore('both:~/notes/Private/', HOME, denied);
    expect(denied.read).toEqual([`${HOME}/notes/Private`]);
    expect(denied.write).toEqual([`${HOME}/notes/Private`]);
  });

  it('read: prefix denies read only', () => {
    const denied = { read: [] as string[], write: [] as string[] };
    parseGooseignore('read:~/Documents/Confidential', HOME, denied);
    expect(denied.read).toEqual([`${HOME}/Documents/Confidential`]);
    expect(denied.write).toEqual([]);
  });

  it('write: prefix denies write only', () => {
    const denied = { read: [] as string[], write: [] as string[] };
    parseGooseignore('write:~/Projects/archive/', HOME, denied);
    expect(denied.read).toEqual([]);
    expect(denied.write).toEqual([`${HOME}/Projects/archive`]);
  });

  it('skips blank lines and comments', () => {
    const denied = { read: [] as string[], write: [] as string[] };
    parseGooseignore('# comment\n\n~/Private/', HOME, denied);
    expect(denied.read).toHaveLength(1);
    expect(denied.write).toHaveLength(1);
  });

  it('skips glob patterns', () => {
    const denied = { read: [] as string[], write: [] as string[] };
    parseGooseignore('**/.env\n**/.env.*\n**/secrets.*', HOME, denied);
    expect(denied.read).toHaveLength(0);
    expect(denied.write).toHaveLength(0);
  });

  it('handles absolute paths', () => {
    const denied = { read: [] as string[], write: [] as string[] };
    parseGooseignore('/etc/sensitive/', HOME, denied);
    expect(denied.read).toEqual(['/etc/sensitive']);
    expect(denied.write).toEqual(['/etc/sensitive']);
  });

  it('skips relative non-glob patterns (no base dir at this layer)', () => {
    const denied = { read: [] as string[], write: [] as string[] };
    parseGooseignore('secrets/', HOME, denied);
    expect(denied.read).toHaveLength(0);
    expect(denied.write).toHaveLength(0);
  });

  it('handles mixed prefixes in one file', () => {
    const content = [
      '~/notes/Health/',
      'read:~/Documents/Confidential',
      'write:~/Projects/archive/',
      '**/.env',
    ].join('\n');
    const denied = { read: [] as string[], write: [] as string[] };
    parseGooseignore(content, HOME, denied);

    expect(denied.read).toContain(`${HOME}/notes/Health`);
    expect(denied.write).toContain(`${HOME}/notes/Health`);
    expect(denied.read).toContain(`${HOME}/Documents/Confidential`);
    expect(denied.write).not.toContain(`${HOME}/Documents/Confidential`);
    expect(denied.write).toContain(`${HOME}/Projects/archive`);
    expect(denied.read).not.toContain(`${HOME}/Projects/archive`);
  });

  it('handles paths with spaces (Swedish characters)', () => {
    const denied = { read: [] as string[], write: [] as string[] };
    parseGooseignore('~/gitrepos/obsidian/Privat JH/', HOME, denied);
    expect(denied.read).toEqual([`${HOME}/gitrepos/obsidian/Privat JH`]);
    expect(denied.write).toEqual([`${HOME}/gitrepos/obsidian/Privat JH`]);
  });

  it('handles paths with unicode characters', () => {
    const denied = { read: [] as string[], write: [] as string[] };
    parseGooseignore('~/notes/Hälsa/', HOME, denied);
    expect(denied.read).toEqual([`${HOME}/notes/Hälsa`]);
    expect(denied.write).toEqual([`${HOME}/notes/Hälsa`]);
  });

  it('handles absolute path without tilde', () => {
    const denied = { read: [] as string[], write: [] as string[] };
    parseGooseignore('/Users/testuser/private/', HOME, denied);
    expect(denied.read).toEqual(['/Users/testuser/private']);
    expect(denied.write).toEqual(['/Users/testuser/private']);
  });

  it('strips trailing slashes for seatbelt subpath', () => {
    const denied = { read: [] as string[], write: [] as string[] };
    parseGooseignore('~/notes/Private///', HOME, denied);
    expect(denied.read[0]).not.toMatch(/\/$/);
  });

  it('multiple entries accumulate correctly', () => {
    const content = [
      '~/notes/Health/',
      'read:~/Documents/Confidential/',
      'write:~/Projects/archive/',
      '~/.aws/',
      '**/.env',  // glob — skipped for seatbelt
    ].join('\n');
    const denied = { read: [] as string[], write: [] as string[] };
    parseGooseignore(content, HOME, denied);

    expect(denied.read).toContain(`${HOME}/notes/Health`);
    expect(denied.write).toContain(`${HOME}/notes/Health`);
    expect(denied.read).toContain(`${HOME}/Documents/Confidential`);
    expect(denied.write).not.toContain(`${HOME}/Documents/Confidential`);
    expect(denied.write).toContain(`${HOME}/Projects/archive`);
    expect(denied.read).not.toContain(`${HOME}/Projects/archive`);
    expect(denied.read).toContain(`${HOME}/.aws`);
    expect(denied.write).toContain(`${HOME}/.aws`);
    expect(denied.read).toHaveLength(3);  // Health, Confidential, .aws
    expect(denied.write).toHaveLength(3); // Health, archive, .aws
  });

  it('overlapping parent and child paths both included', () => {
    // Both entries are passed through — seatbelt handles the redundancy
    const content = '~/vault/\n~/vault/health/\n';
    const denied = { read: [] as string[], write: [] as string[] };
    parseGooseignore(content, HOME, denied);
    expect(denied.read).toContain(`${HOME}/vault`);
    expect(denied.read).toContain(`${HOME}/vault/health`);
  });

  it('same path with different prefixes both recorded correctly', () => {
    const content = `read:~/shared/\nwrite:~/shared/\n`;
    const denied = { read: [] as string[], write: [] as string[] };
    parseGooseignore(content, HOME, denied);
    expect(denied.read).toContain(`${HOME}/shared`);
    expect(denied.write).toContain(`${HOME}/shared`);
  });

  it('empty content produces no entries', () => {
    const denied = { read: [] as string[], write: [] as string[] };
    parseGooseignore('', HOME, denied);
    expect(denied.read).toHaveLength(0);
    expect(denied.write).toHaveLength(0);
  });

  it('all-comment content produces no entries', () => {
    const denied = { read: [] as string[], write: [] as string[] };
    parseGooseignore('# comment 1\n# comment 2\n', HOME, denied);
    expect(denied.read).toHaveLength(0);
    expect(denied.write).toHaveLength(0);
  });
});

// ── buildSandboxProfile ───────────────────────────────────────────────────────

describe('buildSandboxProfile', () => {
  it('produces a valid allow-default profile with no denies', () => {
    const profile = buildSandboxProfile({ read: [], write: [] });
    expect(profile).toContain('(version 1)');
    expect(profile).toContain('(allow default)');
    expect(profile).not.toContain('(deny');
  });

  it('adds file-read* deny block for read-denied paths', () => {
    const profile = buildSandboxProfile({
      read: [`${HOME}/notes/Health`],
      write: [],
    });
    expect(profile).toContain('(deny file-read*');
    expect(profile).toContain(`(subpath "${HOME}/notes/Health")`);
    expect(profile).not.toContain('(deny file-write*');
  });

  it('adds file-write* deny block for write-denied paths', () => {
    const profile = buildSandboxProfile({
      read: [],
      write: [`${HOME}/Projects/archive`],
    });
    expect(profile).toContain('(deny file-write*');
    expect(profile).toContain(`(subpath "${HOME}/Projects/archive")`);
    expect(profile).not.toContain('(deny file-read*');
  });

  it('includes both deny blocks when both are populated', () => {
    const profile = buildSandboxProfile({
      read: [`${HOME}/notes/Health`],
      write: [`${HOME}/Projects/archive`],
    });
    expect(profile).toContain('(deny file-read*');
    expect(profile).toContain('(deny file-write*');
  });

  it('escapes backslashes and double-quotes in paths', () => {
    const profile = buildSandboxProfile({
      read: ['/path/with "quotes"'],
      write: [],
    });
    expect(profile).toContain('(subpath "/path/with \\"quotes\\"")')
  });

  it('handles paths with spaces correctly in profile', () => {
    const profile = buildSandboxProfile({
      read: [`${HOME}/gitrepos/obsidian/Privat JH`],
      write: [],
    });
    expect(profile).toContain(`(subpath "${HOME}/gitrepos/obsidian/Privat JH")`);
  });

  it('handles paths with unicode characters in profile', () => {
    const profile = buildSandboxProfile({
      read: [`${HOME}/notes/Hälsa`],
      write: [],
    });
    expect(profile).toContain(`(subpath "${HOME}/notes/Hälsa")`);
  });

  it('multiple read paths each get their own subpath entry', () => {
    const profile = buildSandboxProfile({
      read: [`${HOME}/health`, `${HOME}/finance`, `${HOME}/legal`],
      write: [],
    });
    expect(profile).toContain(`(subpath "${HOME}/health")`);
    expect(profile).toContain(`(subpath "${HOME}/finance")`);
    expect(profile).toContain(`(subpath "${HOME}/legal")`);
  });

  it('overlapping parent and child paths both appear as subpath entries', () => {
    const profile = buildSandboxProfile({
      read: [`${HOME}/vault`, `${HOME}/vault/health`],
      write: [],
    });
    expect(profile).toContain(`(subpath "${HOME}/vault")`);
    expect(profile).toContain(`(subpath "${HOME}/vault/health")`);
  });

  it('profile is valid SBPL structure', () => {
    const profile = buildSandboxProfile({
      read: [`${HOME}/private`],
      write: [`${HOME}/readonly`],
    });
    const lines = profile.split('\n');
    expect(lines[0]).toBe('(version 1)');
    expect(lines[1]).toBe('(allow default)');
    // deny blocks are properly opened and closed
    expect(profile).toMatch(/\(deny file-read\*\n.*\(subpath/s);
    expect(profile).toMatch(/\(deny file-write\*\n.*\(subpath/s);
    // all parens balanced
    const opens = (profile.match(/\(/g) ?? []).length;
    const closes = (profile.match(/\)/g) ?? []).length;
    expect(opens).toBe(closes);
  });
});

// ── isSandboxEnabled ──────────────────────────────────────────────────────────

describe('isSandboxEnabled', () => {
  afterEach(() => {
    vi.unstubAllEnvs();
  });

  it('returns false when GOOSE_SANDBOX is not set', () => {
    vi.stubEnv('GOOSE_SANDBOX', '');
    // Can't easily stub process.platform in vitest without mocking the module,
    // so we just verify the env-var path: with empty string it should be falsy.
    expect(isSandboxEnabled()).toBe(false);
  });

  it('returns false when GOOSE_SANDBOX is false', () => {
    vi.stubEnv('GOOSE_SANDBOX', 'false');
    expect(isSandboxEnabled()).toBe(false);
  });
});

// ── buildGoosedSandboxSpawn ───────────────────────────────────────────────────

describe('buildGoosedSandboxSpawn', () => {
  afterEach(() => {
    vi.unstubAllEnvs();
  });

  it('passes through unchanged when sandbox is disabled', () => {
    vi.stubEnv('GOOSE_SANDBOX', 'false');
    const result = buildGoosedSandboxSpawn('/usr/bin/goosed', ['agent'], '/tmp/work');
    expect(result.command).toBe('/usr/bin/goosed');
    expect(result.args).toEqual(['agent']);
  });

  it('on non-darwin platform, sandbox is never enabled', () => {
    // isSandboxEnabled checks process.platform === 'darwin'
    // On any CI runner that isn't macOS this test confirms passthrough
    vi.stubEnv('GOOSE_SANDBOX', 'true');
    const result = buildGoosedSandboxSpawn('/usr/bin/goosed', ['agent'], '/tmp/work');
    if (process.platform !== 'darwin') {
      expect(result.command).toBe('/usr/bin/goosed');
    }
    // On darwin with GOOSE_SANDBOX=true it would wrap — we verify the structure
    if (process.platform === 'darwin') {
      expect(result.command).toBe('sandbox-exec');
      expect(result.args[0]).toBe('-p');
      expect(result.args[result.args.length - 2]).toBe('/usr/bin/goosed');
      expect(result.args[result.args.length - 1]).toBe('agent');
    }
  });

  it('when enabled on darwin, wraps with sandbox-exec -p <profile>', () => {
    if (process.platform !== 'darwin') return;
    vi.stubEnv('GOOSE_SANDBOX', 'true');
    const result = buildGoosedSandboxSpawn('/usr/bin/goosed', ['agent'], '/tmp/work');
    expect(result.command).toBe('sandbox-exec');
    expect(result.args[0]).toBe('-p');
    const profile = result.args[1];
    expect(profile).toContain('(version 1)');
    expect(profile).toContain('(allow default)');
  });
});
