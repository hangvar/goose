import { describe, it, expect } from 'vitest';
import { buildSandboxProfile, parseGooseignore } from './index';

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
});
