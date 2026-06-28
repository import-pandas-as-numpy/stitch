use std::collections::VecDeque;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};

use globset::{Glob, GlobSet, GlobSetBuilder};
use thiserror::Error;

use crate::cli::CommonArgs;

#[derive(Debug, Clone)]
pub struct DiscoveryConfig {
    roots: Vec<PathBuf>,
    recursive: bool,
    include: GlobSet,
    exclude: GlobSet,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveredInput {
    pub path: PathBuf,
    pub collection_root: PathBuf,
}

#[derive(Debug, Error)]
pub enum DiscoveryError {
    #[error("no input paths were provided")]
    NoInputs,
    #[error("input path is neither a file nor directory: {path}")]
    UnsupportedInput { path: PathBuf },
    #[error("failed to read input path file {path}: {source}")]
    PathsFromRead {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to read directory {path}: {source}")]
    DirectoryRead {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to inspect path {path}: {source}")]
    PathInspect {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("invalid {kind} glob {pattern:?}: {source}")]
    InvalidGlob {
        kind: GlobKind,
        pattern: String,
        #[source]
        source: globset::Error,
    },
}

#[derive(Debug, Clone, Copy)]
pub enum GlobKind {
    Include,
    Exclude,
}

impl std::fmt::Display for GlobKind {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Include => formatter.write_str("include"),
            Self::Exclude => formatter.write_str("exclude"),
        }
    }
}

impl DiscoveryConfig {
    #[must_use]
    pub fn new(roots: Vec<PathBuf>, recursive: bool, include: GlobSet, exclude: GlobSet) -> Self {
        Self {
            roots,
            recursive,
            include,
            exclude,
        }
    }

    #[must_use]
    pub fn roots(&self) -> &[PathBuf] {
        &self.roots
    }
}

impl TryFrom<&CommonArgs> for DiscoveryConfig {
    type Error = DiscoveryError;

    fn try_from(args: &CommonArgs) -> Result<Self, Self::Error> {
        let mut roots = args.input.clone();

        if let Some(paths_file) = &args.paths_from {
            roots.extend(read_paths_from(paths_file)?);
        }

        if roots.is_empty() {
            return Err(DiscoveryError::NoInputs);
        }

        let include = build_glob_set(GlobKind::Include, &args.include)?;
        let exclude = build_glob_set(GlobKind::Exclude, &args.exclude)?;

        Ok(Self::new(roots, !args.no_recursive, include, exclude))
    }
}

pub fn discover_inputs(config: &DiscoveryConfig) -> Result<Vec<DiscoveredInput>, DiscoveryError> {
    let mut discovered = Vec::new();

    for root in config.roots() {
        discover_root(config, root, &mut discovered)?;
    }

    discovered.sort_by(|left, right| left.path.cmp(&right.path));
    Ok(discovered)
}

fn discover_root(
    config: &DiscoveryConfig,
    root: &Path,
    discovered: &mut Vec<DiscoveredInput>,
) -> Result<(), DiscoveryError> {
    let metadata = root
        .metadata()
        .map_err(|source| DiscoveryError::PathInspect {
            path: root.to_path_buf(),
            source,
        })?;

    if metadata.is_file() {
        push_file(config, root, root, discovered);
        return Ok(());
    }

    if metadata.is_dir() {
        discover_directory(config, root, root, discovered)?;
        return Ok(());
    }

    Err(DiscoveryError::UnsupportedInput {
        path: root.to_path_buf(),
    })
}

fn discover_directory(
    config: &DiscoveryConfig,
    root: &Path,
    directory: &Path,
    discovered: &mut Vec<DiscoveredInput>,
) -> Result<(), DiscoveryError> {
    let mut pending = VecDeque::from([directory.to_path_buf()]);

    while let Some(current) = pending.pop_front() {
        let entries = current
            .read_dir()
            .map_err(|source| DiscoveryError::DirectoryRead {
                path: current.clone(),
                source,
            })?;

        for entry in entries {
            let entry = entry.map_err(|source| DiscoveryError::DirectoryRead {
                path: current.clone(),
                source,
            })?;
            let path = entry.path();
            let file_type = entry
                .file_type()
                .map_err(|source| DiscoveryError::PathInspect {
                    path: path.clone(),
                    source,
                })?;

            if file_type.is_file() {
                push_file(config, root, &path, discovered);
            } else if file_type.is_dir() && config.recursive {
                pending.push_back(path);
            }
        }
    }

    Ok(())
}

fn push_file(
    config: &DiscoveryConfig,
    root: &Path,
    path: &Path,
    discovered: &mut Vec<DiscoveredInput>,
) {
    if !is_evtx_path(path) || !is_included(config, path) {
        return;
    }

    discovered.push(DiscoveredInput {
        path: path.to_path_buf(),
        collection_root: root.to_path_buf(),
    });
}

fn is_included(config: &DiscoveryConfig, path: &Path) -> bool {
    let included = config.include.is_empty() || config.include.is_match(path);
    included && !config.exclude.is_match(path)
}

fn is_evtx_path(path: &Path) -> bool {
    path.extension()
        .is_some_and(|extension| extension.eq_ignore_ascii_case("evtx"))
}

fn read_paths_from(path: &Path) -> Result<Vec<PathBuf>, DiscoveryError> {
    let file = File::open(path).map_err(|source| DiscoveryError::PathsFromRead {
        path: path.to_path_buf(),
        source,
    })?;
    let reader = BufReader::new(file);
    let mut paths = Vec::new();

    for line in reader.lines() {
        let line = line.map_err(|source| DiscoveryError::PathsFromRead {
            path: path.to_path_buf(),
            source,
        })?;
        let trimmed = line.trim();

        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        paths.push(PathBuf::from(trimmed));
    }

    Ok(paths)
}

fn build_glob_set(kind: GlobKind, patterns: &[String]) -> Result<GlobSet, DiscoveryError> {
    let mut builder = GlobSetBuilder::new();

    for pattern in patterns {
        let glob = Glob::new(pattern).map_err(|source| DiscoveryError::InvalidGlob {
            kind,
            pattern: pattern.clone(),
            source,
        })?;
        builder.add(glob);
    }

    builder
        .build()
        .map_err(|source| DiscoveryError::InvalidGlob {
            kind,
            pattern: patterns.join(", "),
            source,
        })
}

#[cfg(test)]
mod tests {
    use std::fs;

    use globset::GlobSetBuilder;
    use tempfile::TempDir;

    use super::*;

    #[test]
    fn discovers_nested_evtx_files_by_default() {
        let fixture = Fixture::new();
        fixture.write("Security.evtx");
        fixture.write("nested/System.EVTX");
        fixture.write("nested/ignored.txt");

        let discovered = discover_inputs(&fixture.config(true)).expect("discovery should succeed");
        let paths = fixture.relative_paths(&discovered);

        assert_eq!(
            paths,
            vec!["Security.evtx", "nested/System.EVTX"],
            "recursive discovery should include nested EVTX files only"
        );
    }

    #[test]
    fn can_disable_recursive_directory_discovery() {
        let fixture = Fixture::new();
        fixture.write("Security.evtx");
        fixture.write("nested/System.evtx");

        let discovered = discover_inputs(&fixture.config(false)).expect("discovery should succeed");
        let paths = fixture.relative_paths(&discovered);

        assert_eq!(
            paths,
            vec!["Security.evtx"],
            "non-recursive discovery should skip nested EVTX files"
        );
    }

    #[test]
    fn applies_include_and_exclude_globs() {
        let fixture = Fixture::new();
        fixture.write("Security.evtx");
        fixture.write("System.evtx");
        fixture.write("nested/Sysmon.evtx");

        let config = DiscoveryConfig::new(
            vec![fixture.root()],
            true,
            glob_set(&["**/*.evtx", "*.evtx"]),
            glob_set(&["**/System.evtx"]),
        );

        let discovered = discover_inputs(&config).expect("discovery should succeed");
        let paths = fixture.relative_paths(&discovered);

        assert_eq!(
            paths,
            vec!["Security.evtx", "nested/Sysmon.evtx"],
            "include and exclude globs should filter discovered files"
        );
    }

    struct Fixture {
        directory: TempDir,
    }

    impl Fixture {
        fn new() -> Self {
            Self {
                directory: tempfile::tempdir().expect("temp directory should be created"),
            }
        }

        fn root(&self) -> PathBuf {
            self.directory.path().to_path_buf()
        }

        fn config(&self, recursive: bool) -> DiscoveryConfig {
            DiscoveryConfig::new(
                vec![self.root()],
                recursive,
                GlobSetBuilder::new()
                    .build()
                    .expect("empty include glob set should build"),
                GlobSetBuilder::new()
                    .build()
                    .expect("empty exclude glob set should build"),
            )
        }

        fn write(&self, relative_path: &str) {
            let path = self.directory.path().join(relative_path);

            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).expect("fixture parent should be created");
            }

            fs::write(path, b"fixture").expect("fixture file should be written");
        }

        fn relative_paths(&self, discovered: &[DiscoveredInput]) -> Vec<String> {
            discovered
                .iter()
                .map(|input| {
                    input
                        .path
                        .strip_prefix(self.directory.path())
                        .expect("discovered path should be under fixture root")
                        .to_string_lossy()
                        .replace('\\', "/")
                })
                .collect()
        }
    }

    fn glob_set(patterns: &[&str]) -> GlobSet {
        let mut builder = GlobSetBuilder::new();

        for pattern in patterns {
            builder.add(Glob::new(pattern).expect("test glob should compile"));
        }

        builder.build().expect("test glob set should build")
    }
}
