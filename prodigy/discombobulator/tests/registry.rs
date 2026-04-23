use std::process::Command;

#[test]
fn remote_add_list_remove_roundtrip() {
    let temp = tempfile::tempdir().unwrap();
    let binary = env!("CARGO_BIN_EXE_discombobulator");

    let added = Command::new(binary)
        .current_dir(temp.path())
        .args([
            "remote",
            "add",
            "dockerhub",
            "docker.io",
            "--prefix",
            "library",
        ])
        .output()
        .unwrap();
    assert!(
        added.status.success(),
        "{}",
        String::from_utf8_lossy(&added.stderr)
    );

    let listed = Command::new(binary)
        .current_dir(temp.path())
        .args(["remote", "list"])
        .output()
        .unwrap();
    assert!(
        listed.status.success(),
        "{}",
        String::from_utf8_lossy(&listed.stderr)
    );
    let stdout = String::from_utf8_lossy(&listed.stdout);
    assert!(stdout.contains("dockerhub\tdocker.io\tlibrary"));

    let removed = Command::new(binary)
        .current_dir(temp.path())
        .args(["remote", "remove", "dockerhub"])
        .output()
        .unwrap();
    assert!(
        removed.status.success(),
        "{}",
        String::from_utf8_lossy(&removed.stderr)
    );
}

#[test]
fn remote_fetch_unknown_remote_fails_clearly() {
    let temp = tempfile::tempdir().unwrap();
    let binary = env!("CARGO_BIN_EXE_discombobulator");

    let fetched = Command::new(binary)
        .current_dir(temp.path())
        .args([
            "remote",
            "fetch",
            "missing",
            "library/ubuntu:latest",
            "--arch",
            "x86_64",
        ])
        .output()
        .unwrap();
    assert!(!fetched.status.success());
    assert!(
        String::from_utf8_lossy(&fetched.stderr).contains("unknown remote missing"),
        "{}",
        String::from_utf8_lossy(&fetched.stderr)
    );
}

#[test]
fn remote_add_upsert_replaces_host_and_prefix() {
    let temp = tempfile::tempdir().unwrap();
    let binary = env!("CARGO_BIN_EXE_discombobulator");

    let first_add = Command::new(binary)
        .current_dir(temp.path())
        .args(["remote", "add", "dockerhub", "docker.io", "--prefix", "library"])
        .output()
        .unwrap();
    assert!(
        first_add.status.success(),
        "{}",
        String::from_utf8_lossy(&first_add.stderr)
    );

    let second_add = Command::new(binary)
        .current_dir(temp.path())
        .args([
            "remote",
            "add",
            "dockerhub",
            "mirror.example.test",
            "--prefix",
            "mirrored/library",
        ])
        .output()
        .unwrap();
    assert!(
        second_add.status.success(),
        "{}",
        String::from_utf8_lossy(&second_add.stderr)
    );

    let listed = Command::new(binary)
        .current_dir(temp.path())
        .args(["remote", "list"])
        .output()
        .unwrap();
    assert!(
        listed.status.success(),
        "{}",
        String::from_utf8_lossy(&listed.stderr)
    );
    let stdout = String::from_utf8_lossy(&listed.stdout);
    assert!(stdout.contains("dockerhub\tmirror.example.test\tmirrored/library"));
    assert!(!stdout.contains("dockerhub\tdocker.io\tlibrary"));
}

#[cfg(target_os = "linux")]
#[test]
fn commands_fail_fast_when_not_run_as_root() {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    if unsafe { libc_geteuid() } != 0 {
        return;
    }

    let temp = tempfile::tempdir().unwrap();
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o777)).unwrap();
    let binary = temp.path().join("discombobulator");
    fs::copy(env!("CARGO_BIN_EXE_discombobulator"), &binary).unwrap();
    fs::set_permissions(&binary, fs::Permissions::from_mode(0o755)).unwrap();

    let remote_list = Command::new("setpriv")
        .current_dir(temp.path())
        .args([
            "--reuid",
            "nobody",
            "--regid",
            "nobody",
            "--clear-groups",
            "--",
            binary.to_str().unwrap(),
            "remote",
            "list",
        ])
        .output()
        .unwrap();
    assert!(remote_list.status.success());
    assert!(
        String::from_utf8_lossy(&remote_list.stdout)
            .trim()
            .is_empty(),
        "{}",
        String::from_utf8_lossy(&remote_list.stderr)
    );

    let discombobulator_file = temp.path().join("RootCheck.DiscombobuFile");
    std::fs::write(&discombobulator_file, "FROM scratch for x86_64\n").unwrap();
    let output_blob = temp.path().join("root-check.blob.zst");
    let build = Command::new("setpriv")
        .current_dir(temp.path())
        .args([
            "--reuid",
            "nobody",
            "--regid",
            "nobody",
            "--clear-groups",
            "--",
            binary.to_str().unwrap(),
            "build",
            "--file",
            discombobulator_file.to_str().unwrap(),
            "--output",
            output_blob.to_str().unwrap(),
            "--kind",
            "base",
        ])
        .output()
        .unwrap();
    assert!(!build.status.success());
    assert!(
        String::from_utf8_lossy(&build.stderr).contains("discombobulator must run as root"),
        "{}",
        String::from_utf8_lossy(&build.stderr)
    );
    assert!(!output_blob.exists());
}

#[cfg(unix)]
unsafe fn libc_geteuid() -> u32 {
    unsafe extern "C" {
        fn geteuid() -> u32;
    }

    unsafe { geteuid() }
}
