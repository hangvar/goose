use ignore::gitignore::{Gitignore, GitignoreBuilder};
use std::path::{Path, PathBuf};

/// Default deny-both patterns applied when no `.gooseignore` file exists.
const DEFAULT_PATTERNS: &[&str] = &["**/.env", "**/.env.*", "**/secrets.*"];

/// Enforces `.gooseignore` access rules for the developer tools.
///
/// ## File format
///
/// Each non-blank, non-comment line is a gitignore-style pattern optionally prefixed
/// with an access type:
///
/// ```text
/// # Deny both read and write — no prefix (implicit) or both: prefix (explicit)
/// ~/notes/Personal/Health/
/// both:~/notes/Personal/Finance/
/// **/.env
///
/// # Deny read access only
/// read:~/Documents/Confidential/
///
/// # Deny write access only
/// write:~/Projects/readonly-archive/
/// ```
///
/// Tilde (`~`) at the start of a pattern is expanded to the user's home directory.
/// Relative patterns in `{working_dir}/.gooseignore` are resolved relative to that directory.
///
/// ## Sources
///
/// 1. `~/.config/goose/.gooseignore` — global rules.
/// 2. `{working_dir}/.gooseignore` — local rules.
///
/// If neither file exists, the built-in defaults (`**/.env`, `**/.env.*`, `**/secrets.*`)
/// are applied as deny-both rules.
pub struct GooseIgnore {
    deny_read: Gitignore,
    deny_write: Gitignore,
}

impl GooseIgnore {
    pub fn load(working_dir: Option<&Path>) -> Self {
        let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("/"));
        let global_path = dirs::config_dir().map(|d| d.join("goose").join(".gooseignore"));
        let local_path = working_dir.map(|d| d.join(".gooseignore"));

        let has_global = global_path.as_ref().is_some_and(|p| p.exists());
        let has_local = local_path.as_ref().is_some_and(|p| p.exists());

        // Both builders are rooted at "/" so that absolute patterns resolve correctly.
        let mut read_builder = GitignoreBuilder::new("/");
        let mut write_builder = GitignoreBuilder::new("/");

        if !has_global && !has_local {
            for pattern in DEFAULT_PATTERNS {
                let _ = read_builder.add_line(None, pattern);
                let _ = write_builder.add_line(None, pattern);
            }
        } else {
            if has_global {
                let content =
                    std::fs::read_to_string(global_path.as_ref().unwrap()).unwrap_or_default();
                add_patterns(&content, &home, &home, &mut read_builder, &mut write_builder);
            }
            if has_local {
                let pattern_root = working_dir.unwrap();
                let content =
                    std::fs::read_to_string(local_path.as_ref().unwrap()).unwrap_or_default();
                add_patterns(
                    &content,
                    pattern_root,
                    &home,
                    &mut read_builder,
                    &mut write_builder,
                );
            }
        }

        Self {
            deny_read: read_builder.build().unwrap_or_else(|_| Gitignore::empty()),
            deny_write: write_builder.build().unwrap_or_else(|_| Gitignore::empty()),
        }
    }

    /// Returns true if `path` (or any of its parents) is denied for **read** access.
    pub fn is_read_ignored(&self, path: &Path) -> bool {
        let is_dir = path.is_dir();
        self.deny_read
            .matched_path_or_any_parents(path, is_dir)
            .is_ignore()
    }

    /// Returns true if `path` (or any of its parents) is denied for **write** access.
    pub fn is_write_ignored(&self, path: &Path) -> bool {
        let is_dir = path.is_dir();
        self.deny_write
            .matched_path_or_any_parents(path, is_dir)
            .is_ignore()
    }
}

/// Parse lines from a `.gooseignore` file and add them to the appropriate builders.
///
/// `pattern_root` is the directory used to resolve relative patterns (not starting
/// with `/` or `~`). For the global file this is the home dir; for a local file it
/// is the `working_dir` the file lives in.
fn add_patterns(
    content: &str,
    pattern_root: &Path,
    home: &Path,
    read_builder: &mut GitignoreBuilder,
    write_builder: &mut GitignoreBuilder,
) {
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        let (raw_pattern, deny_read, deny_write) =
            if let Some(p) = trimmed.strip_prefix("read:") {
                (p.trim(), true, false)
            } else if let Some(p) = trimmed.strip_prefix("write:") {
                (p.trim(), false, true)
            } else if let Some(p) = trimmed.strip_prefix("both:") {
                (p.trim(), true, true)
            } else {
                (trimmed, true, true)
            };

        let abs_pattern = expand_pattern(raw_pattern, pattern_root, home);

        if deny_read {
            let _ = read_builder.add_line(None, &abs_pattern);
        }
        if deny_write {
            let _ = write_builder.add_line(None, &abs_pattern);
        }
    }
}

/// Expand a raw pattern to an absolute string suitable for a `/`-rooted `GitignoreBuilder`.
///
/// - `~/…`  → `{home}/…`
/// - `/…`   → unchanged (already absolute)
/// - `**/…` → unchanged (glob anchored nowhere, matches anywhere)
/// - other  → `{pattern_root}/…` (relative to the file's directory)
fn expand_pattern(pattern: &str, pattern_root: &Path, home: &Path) -> String {
    if let Some(rest) = pattern.strip_prefix("~/") {
        format!("{}/{}", home.display(), rest)
    } else if pattern.starts_with('/') || pattern.starts_with("**/") {
        pattern.to_string()
    } else {
        format!("{}/{}", pattern_root.display(), pattern)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    fn write_ignore(dir: &TempDir, content: &str) {
        fs::write(dir.path().join(".gooseignore"), content).unwrap();
    }

    // ── default patterns ─────────────────────────────────────────────────────

    #[test]
    fn defaults_block_env_file_for_both() {
        let dir = tempfile::tempdir().unwrap();
        let env_file = dir.path().join(".env");
        fs::write(&env_file, "SECRET=x").unwrap();

        let ignore = GooseIgnore::load(Some(dir.path()));
        assert!(ignore.is_read_ignored(&env_file));
        assert!(ignore.is_write_ignored(&env_file));
    }

    #[test]
    fn defaults_block_dotenv_variants() {
        let dir = tempfile::tempdir().unwrap();
        let env_local = dir.path().join(".env.local");
        fs::write(&env_local, "KEY=val").unwrap();

        let ignore = GooseIgnore::load(Some(dir.path()));
        assert!(ignore.is_read_ignored(&env_local));
        assert!(ignore.is_write_ignored(&env_local));
    }

    // ── no-prefix (deny both) ─────────────────────────────────────────────────

    #[test]
    fn no_prefix_denies_read_and_write() {
        let dir = tempfile::tempdir().unwrap();
        let secrets_dir = dir.path().join("secrets");
        fs::create_dir_all(&secrets_dir).unwrap();
        let file = secrets_dir.join("passwords.txt");
        fs::write(&file, "hunter2").unwrap();
        write_ignore(&dir, "secrets/\n");

        let ignore = GooseIgnore::load(Some(dir.path()));
        assert!(ignore.is_read_ignored(&file));
        assert!(ignore.is_write_ignored(&file));
    }

    #[test]
    fn no_prefix_allows_non_matching_path() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("public.txt");
        fs::write(&file, "hello").unwrap();
        write_ignore(&dir, "secrets/\n");

        let ignore = GooseIgnore::load(Some(dir.path()));
        assert!(!ignore.is_read_ignored(&file));
        assert!(!ignore.is_write_ignored(&file));
    }

    // ── both: prefix ─────────────────────────────────────────────────────────

    #[test]
    fn both_prefix_denies_read_and_write() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("sensitive.txt");
        fs::write(&file, "data").unwrap();
        write_ignore(&dir, "both:sensitive.txt\n");

        let ignore = GooseIgnore::load(Some(dir.path()));
        assert!(ignore.is_read_ignored(&file));
        assert!(ignore.is_write_ignored(&file));
    }

    // ── read: prefix ──────────────────────────────────────────────────────────

    #[test]
    fn read_prefix_denies_read_but_allows_write() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("private.txt");
        fs::write(&file, "data").unwrap();
        write_ignore(&dir, "read:private.txt\n");

        let ignore = GooseIgnore::load(Some(dir.path()));
        assert!(ignore.is_read_ignored(&file));
        assert!(!ignore.is_write_ignored(&file));
    }

    // ── write: prefix ─────────────────────────────────────────────────────────

    #[test]
    fn write_prefix_allows_read_but_denies_write() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("archive.txt");
        fs::write(&file, "data").unwrap();
        write_ignore(&dir, "write:archive.txt\n");

        let ignore = GooseIgnore::load(Some(dir.path()));
        assert!(!ignore.is_read_ignored(&file));
        assert!(ignore.is_write_ignored(&file));
    }

    // ── mixed rules ───────────────────────────────────────────────────────────

    #[test]
    fn mixed_prefixes_apply_independently() {
        let dir = tempfile::tempdir().unwrap();
        let read_file = dir.path().join("confidential.txt");
        let write_file = dir.path().join("readonly.txt");
        let both_file = dir.path().join("sensitive.txt");
        let free_file = dir.path().join("open.txt");
        for f in [&read_file, &write_file, &both_file, &free_file] {
            fs::write(f, "data").unwrap();
        }
        write_ignore(
            &dir,
            "read:confidential.txt\nwrite:readonly.txt\nsensitive.txt\n",
        );

        let ignore = GooseIgnore::load(Some(dir.path()));

        assert!(ignore.is_read_ignored(&read_file));
        assert!(!ignore.is_write_ignored(&read_file));

        assert!(!ignore.is_read_ignored(&write_file));
        assert!(ignore.is_write_ignored(&write_file));

        assert!(ignore.is_read_ignored(&both_file));
        assert!(ignore.is_write_ignored(&both_file));

        assert!(!ignore.is_read_ignored(&free_file));
        assert!(!ignore.is_write_ignored(&free_file));
    }
}
