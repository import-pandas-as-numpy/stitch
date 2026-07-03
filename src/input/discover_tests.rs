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

#[test]
fn defaults_to_current_directory_when_no_roots_are_provided() {
    let common = CommonArgs {
        input: Vec::new(),
        paths_from: None,
        no_recursive: false,
        jobs: 0,
        no_progress: false,
        quiet: false,
        strict: false,
        from: None,
        to: None,
        include: Vec::new(),
        exclude: Vec::new(),
        stats: false,
        no_color: false,
    };

    let config = DiscoveryConfig::try_from(&common).expect("default discovery should build");

    assert_eq!(
        config.roots(),
        [PathBuf::from(".")],
        "omitted input roots should behave as if the current directory was passed"
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
