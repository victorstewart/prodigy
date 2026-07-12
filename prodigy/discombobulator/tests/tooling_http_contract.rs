use std::fs;
use std::path::{Path, PathBuf};
#[cfg(target_os = "linux")]
use std::process::Command;

fn source(name: &str) -> String {
    fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join(name),
    )
    .unwrap()
}

fn collect_rust_sources(directory: &Path, sources: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(directory).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            collect_rust_sources(&path, sources);
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            sources.push(path);
        }
    }
}

#[test]
fn no_other_blocking_http_tooling_callsite_exists() {
    let source_root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut sources = Vec::new();
    collect_rust_sources(&source_root, &mut sources);

    for path in sources {
        let relative = path.strip_prefix(&source_root).unwrap();
        let contents = fs::read_to_string(&path).unwrap();
        if relative != Path::new("build.rs") {
            assert!(
                !contents.contains("reqwest::blocking"),
                "unapproved blocking reqwest callsite in {}",
                relative.display()
            );
        }
        assert!(
            !contents.contains("reqwest::get") && !contents.contains("ureq::"),
            "unapproved synchronous HTTP callsite in {}",
            relative.display()
        );

        for line in contents.lines().filter(|line| line.contains("curl ")) {
            let approved_rustup = relative == Path::new("build_portable.rs")
                && line.trim_start().starts_with("curl --proto '=https'");
            let package_name = relative == Path::new("build_portable.rs")
                && line.contains("build-essential curl ca-certificates");
            assert!(
                approved_rustup || package_name,
                "unapproved curl callsite in {}: {line}",
                relative.display()
            );
        }
        assert!(
            !contents.contains("wget "),
            "unapproved wget callsite in {}",
            relative.display()
        );
    }
}

#[test]
fn registry_http_is_the_only_bounded_blocking_tooling_client() {
    let build = source("build.rs");
    for required in [
        "const REGISTRY_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);",
        "const REGISTRY_REQUEST_TIMEOUT: Duration = Duration::from_secs(15 * 60);",
        "const REGISTRY_REDIRECT_LIMIT: usize = 5;",
        "const MAX_OCI_MANIFEST_BYTES: u64 = 4 * 1024 * 1024;",
        "const MAX_OCI_CONFIG_BYTES: u64 = 4 * 1024 * 1024;",
        "const MAX_OCI_LAYER_BYTES: u64 = 1024 * 1024 * 1024;",
        "const MAX_REGISTRY_TOKEN_BYTES: u64 = 64 * 1024;",
        ".connect_timeout(REGISTRY_CONNECT_TIMEOUT)",
        ".timeout(REGISTRY_REQUEST_TIMEOUT)",
        ".take(maximum_bytes + 1)",
        "registry tooling requires verified HTTPS outside loopback",
        "registry redirect rejected HTTPS downgrade",
        "registry blob digest verification failed",
        "registry manifest digest verification failed",
    ] {
        assert!(
            build.contains(required),
            "missing registry HTTP bound: {required}"
        );
    }
    assert_eq!(build.matches("HttpClient::builder()").count(), 1);
    assert!(!build.contains("response.bytes()"));
    assert!(!build.contains("String::from_utf8_lossy(&body)"));
    assert!(!build.contains("String::from_utf8_lossy(&bytes)"));
}

#[test]
fn portable_rustup_download_is_bounded_before_execution() {
    let portable = source("build_portable.rs");
    for required in [
        "curl --proto '=https' --tlsv1.2 --fail --silent --show-error --location",
        "--max-redirs 3 --connect-timeout 10 --max-time 120 --max-filesize 2097152",
        "--output \\\"$rustup_script\\\" https://sh.rustup.rs",
        "test \\\"$(wc -c < \\\"$rustup_script\\\")\\\" -le 2097152",
        "sh \\\"$rustup_script\\\" -s -- -y --profile minimal --default-toolchain stable",
    ] {
        assert!(
            portable.contains(required),
            "missing rustup HTTP bound: {required}"
        );
    }
    assert_eq!(portable.matches("curl --proto").count(), 1);
    assert!(!portable.contains("curl https://sh.rustup.rs"));
    assert!(!portable.contains("| sh -s"));
}

#[cfg(target_os = "linux")]
#[test]
fn non_loopback_cleartext_registry_fails_before_network_io() {
    let project = tempfile::tempdir().unwrap();
    let binary = env!("CARGO_BIN_EXE_discombobulator");
    let added = Command::new(binary)
        .current_dir(project.path())
        .args(["remote", "add", "insecure", "http://192.0.2.1"])
        .output()
        .unwrap();
    assert!(added.status.success());
    let fetched = Command::new(binary)
        .current_dir(project.path())
        .args([
            "remote",
            "fetch",
            "insecure",
            "sample:latest",
            "--arch",
            "x86_64",
        ])
        .output()
        .unwrap();
    assert!(!fetched.status.success());
    let error = String::from_utf8_lossy(&fetched.stderr);
    assert!(
        error.contains("registry tooling requires verified HTTPS outside loopback"),
        "{error}"
    );
}
