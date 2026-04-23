#![cfg(target_os = "linux")]

use base64::Engine;
use flate2::write::GzEncoder;
use flate2::Compression;
use rusqlite::{params, Connection};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::io::{Cursor, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Barrier, Mutex};
use std::thread;
use std::time::{Duration, Instant};
use tar::{Builder, EntryType, Header};
use walkdir::WalkDir;

#[test]
fn scratch_build_emits_btrfs_blob_with_private_launch_metadata() {
    let temp = tempfile::tempdir().unwrap();
    let project = temp.path();
    let source_dir = project.join("srcctx");
    fs::create_dir_all(&source_dir).unwrap();

    let c_source = source_dir.join("hello.c");
    fs::write(
        &c_source,
        r#"
      #include <stdio.h>
      #include <stdlib.h>
      #include <math.h>

      int main(int argc, char **argv)
      {
         volatile double input = argc > 1 ? atof(argv[1]) : 0.5;
         printf("%f\n", cos(input));
         return 0;
      }
      "#,
    )
    .unwrap();

    let binary = source_dir.join("hello");
    let compiled = Command::new("clang")
        .arg(&c_source)
        .arg("-O2")
        .arg("-o")
        .arg(&binary)
        .arg("-lm")
        .output()
        .unwrap();
    assert!(
        compiled.status.success(),
        "{}",
        String::from_utf8_lossy(&compiled.stderr)
    );

    let discombobulator_file = project.join("DiscombobuFile");
    fs::write(
        &discombobulator_file,
        r#"
      FROM scratch for x86_64
      COPY {src} ./hello /app/hello
      SURVIVE /app/hello
      EXECUTE ["/app/hello"]
      "#,
    )
    .unwrap();

    let output_blob = project.join("hello.blob.zst");
    let binary_path = env!("CARGO_BIN_EXE_discombobulator");
    let build = Command::new(binary_path)
        .current_dir(project)
        .args([
            "build",
            "--file",
            discombobulator_file.to_str().unwrap(),
            "--context",
            &format!("src={}", source_dir.display()),
            "--output",
            output_blob.to_str().unwrap(),
            "--kind",
            "app",
        ])
        .output()
        .unwrap();
    assert!(
        build.status.success(),
        "{}",
        String::from_utf8_lossy(&build.stderr)
    );
    assert!(output_blob.exists());

    let inspect = tempfile::tempdir().unwrap();
    let image = inspect.path().join("recv.img");
    let mount_point = inspect.path().join("mnt");
    fs::create_dir_all(&mount_point).unwrap();

    assert!(Command::new("truncate")
        .args(["-s", "512M"])
        .arg(&image)
        .status()
        .unwrap()
        .success());
    assert!(Command::new("mkfs.btrfs")
        .arg("-q")
        .arg(&image)
        .status()
        .unwrap()
        .success());
    assert!(Command::new("mount")
        .arg("-o")
        .arg("loop")
        .arg(&image)
        .arg(&mount_point)
        .status()
        .unwrap()
        .success());

    let decoded = Command::new("bash")
        .arg("-lc")
        .arg(format!(
            "set -euo pipefail; zstd -d -q -c '{}' | btrfs receive '{}'",
            output_blob.display(),
            mount_point.display()
        ))
        .output()
        .unwrap();
    assert!(
        decoded.status.success(),
        "{}",
        String::from_utf8_lossy(&decoded.stderr)
    );

    let artifact_root = mount_point.join("artifact");
    assert!(artifact_root
        .join(".prodigy-private/launch.metadata")
        .exists());
    assert!(artifact_root.join("rootfs/app/hello").exists());

    if let Some(interpreter) = read_elf_interpreter(&binary) {
        assert!(
            artifact_root
                .join("rootfs")
                .join(interpreter.trim_start_matches('/'))
                .exists(),
            "missing interpreter {} in rootfs",
            interpreter
        );
    }
    for dependency in read_ldd_dependencies(&binary) {
        assert!(
            artifact_root
                .join("rootfs")
                .join(dependency.strip_prefix("/").unwrap())
                .exists(),
            "missing dependency {} in rootfs",
            dependency.display()
        );
    }

    let metadata =
        fs::read_to_string(artifact_root.join(".prodigy-private/launch.metadata")).unwrap();
    assert!(metadata.contains("\"execute_path\": \"/app/hello\""));

    assert!(Command::new("umount")
        .arg(&mount_point)
        .status()
        .unwrap()
        .success());
}

#[test]
fn app_survive_projection_excludes_undeclared_files_and_keeps_private_metadata_outside_rootfs() {
    let temp = tempfile::tempdir().unwrap();
    let project = temp.path();
    let source_dir = project.join("srcctx");
    fs::create_dir_all(&source_dir).unwrap();

    let c_source = source_dir.join("hello.c");
    fs::write(
        &c_source,
        r#"
      #include <stdio.h>

      int main(void)
      {
         puts("hello");
         return 0;
      }
      "#,
    )
    .unwrap();

    let binary = source_dir.join("hello");
    let compiled = Command::new("clang")
        .arg(&c_source)
        .arg("-O2")
        .arg("-o")
        .arg(&binary)
        .output()
        .unwrap();
    assert!(
        compiled.status.success(),
        "{}",
        String::from_utf8_lossy(&compiled.stderr)
    );

    fs::write(source_dir.join("config.json"), "{\"mode\":\"prod\"}\n").unwrap();
    fs::write(source_dir.join(".secret-env"), "TOKEN=hidden\n").unwrap();
    fs::write(source_dir.join("build-only.txt"), "do not ship\n").unwrap();

    let discombobulator_file = project.join("AppProjection.DiscombobuFile");
    fs::write(
        &discombobulator_file,
        r#"
      FROM scratch for x86_64
      COPY {src} ./hello /app/hello
      COPY {src} ./config.json /app/config.json
      COPY {src} ./.secret-env /app/.secret-env
      COPY {src} ./build-only.txt /build/build-only.txt
      ENV MODE=prod
      WORKDIR /app
      SURVIVE /app/*
      EXECUTE ["/app/hello", "--config", "/app/config.json"]
      "#,
    )
    .unwrap();

    let output_blob = project.join("app-projection.blob.zst");
    build_blob_with_contexts(
        project,
        &discombobulator_file,
        &output_blob,
        "app",
        &[format!("src={}", source_dir.display())],
    );

    let mounted = MountedBlob::receive(&output_blob);
    let artifact_root = mounted.artifact_root();
    assert!(artifact_root
        .join(".prodigy-private/launch.metadata")
        .exists());
    assert!(!artifact_root.join("rootfs/.prodigy-private").exists());
    assert!(artifact_root.join("rootfs/app/hello").exists());
    assert!(artifact_root.join("rootfs/app/config.json").exists());
    assert!(!artifact_root.join("rootfs/app/.secret-env").exists());
    assert!(!artifact_root.join("rootfs/build/build-only.txt").exists());

    let metadata =
        fs::read_to_string(artifact_root.join(".prodigy-private/launch.metadata")).unwrap();
    assert!(metadata.contains("\"execute_path\": \"/app/hello\""));
    assert!(metadata.contains("\"execute_args\": ["));
    assert!(metadata.contains("\"--config\""));
    assert!(metadata.contains("\"/app/config.json\""));
    assert!(metadata.contains("\"execute_cwd\": \"/app\""));
    assert!(metadata.contains("\"execute_arch\": \"x86_64\""));
    assert!(metadata.contains("\"MODE=prod\""));
}

#[test]
fn app_build_rejects_missing_survivor_set() {
    let temp = tempfile::tempdir().unwrap();
    let project = temp.path();
    let source_dir = project.join("srcctx");
    fs::create_dir_all(&source_dir).unwrap();
    let host_true = if Path::new("/bin/true").exists() {
        PathBuf::from("/bin/true")
    } else {
        PathBuf::from("/usr/bin/true")
    };
    fs::copy(&host_true, source_dir.join("true")).unwrap();

    let discombobulator_file = project.join("MissingSurvive.DiscombobuFile");
    fs::write(
        &discombobulator_file,
        r#"
      FROM scratch for x86_64
      COPY {src} ./true /app/true
      EXECUTE ["/app/true"]
      "#,
    )
    .unwrap();

    let output_blob = project.join("missing-survive.blob.zst");
    let stderr = build_failure_with_contexts(
        project,
        &discombobulator_file,
        &output_blob,
        "app",
        &[format!("src={}", source_dir.display())],
    );
    assert!(stderr.contains("app builds require at least one SURVIVE path"), "{stderr}");
    assert!(!output_blob.exists());
}

#[test]
fn app_build_rejects_survivor_sets_that_match_nothing() {
    let temp = tempfile::tempdir().unwrap();
    let project = temp.path();
    let source_dir = project.join("srcctx");
    fs::create_dir_all(&source_dir).unwrap();
    let host_true = if Path::new("/bin/true").exists() {
        PathBuf::from("/bin/true")
    } else {
        PathBuf::from("/usr/bin/true")
    };
    fs::copy(&host_true, source_dir.join("true")).unwrap();

    let discombobulator_file = project.join("SurviveMatchesNothing.DiscombobuFile");
    fs::write(
        &discombobulator_file,
        r#"
      FROM scratch for x86_64
      COPY {src} ./true /app/true
      SURVIVE /app/missing/*
      EXECUTE ["/app/true"]
      "#,
    )
    .unwrap();

    let output_blob = project.join("survive-matches-nothing.blob.zst");
    let stderr = build_failure_with_contexts(
        project,
        &discombobulator_file,
        &output_blob,
        "app",
        &[format!("src={}", source_dir.display())],
    );
    assert!(stderr.contains("SURVIVE matched nothing"), "{stderr}");
    assert!(!output_blob.exists());
}

#[test]
fn app_build_rejects_execute_targets_outside_the_survivor_set() {
    let temp = tempfile::tempdir().unwrap();
    let project = temp.path();
    let source_dir = project.join("srcctx");
    fs::create_dir_all(&source_dir).unwrap();
    let host_true = if Path::new("/bin/true").exists() {
        PathBuf::from("/bin/true")
    } else {
        PathBuf::from("/usr/bin/true")
    };
    fs::copy(&host_true, source_dir.join("true")).unwrap();
    fs::write(source_dir.join("config.json"), "{}\n").unwrap();

    let discombobulator_file = project.join("ExecuteOutsideSurvivors.DiscombobuFile");
    fs::write(
        &discombobulator_file,
        r#"
      FROM scratch for x86_64
      COPY {src} ./true /app/true
      COPY {src} ./config.json /app/config.json
      SURVIVE /app/config.json
      EXECUTE ["/app/true"]
      "#,
    )
    .unwrap();

    let output_blob = project.join("execute-outside-survivors.blob.zst");
    let stderr = build_failure_with_contexts(
        project,
        &discombobulator_file,
        &output_blob,
        "app",
        &[format!("src={}", source_dir.display())],
    );
    assert!(
        stderr.contains("EXECUTE target /app/true is not present in the declared survivor set"),
        "{stderr}"
    );
    assert!(!output_blob.exists());
}

#[test]
fn survive_wildcards_skip_hidden_entries_and_expand_deterministically() {
    let temp = tempfile::tempdir().unwrap();
    let project = temp.path();
    let source_dir = project.join("srcctx");
    fs::create_dir_all(&source_dir).unwrap();

    let c_source = source_dir.join("hello.c");
    fs::write(
        &c_source,
        r#"
      #include <stdio.h>

      int main(void)
      {
         puts("hello");
         return 0;
      }
      "#,
    )
    .unwrap();

    let binary = source_dir.join("hello");
    let compiled = Command::new("clang")
        .arg(&c_source)
        .arg("-O2")
        .arg("-o")
        .arg(&binary)
        .output()
        .unwrap();
    assert!(
        compiled.status.success(),
        "{}",
        String::from_utf8_lossy(&compiled.stderr)
    );

    fs::create_dir_all(source_dir.join("assets/a")).unwrap();
    fs::create_dir_all(source_dir.join("assets/b")).unwrap();
    fs::write(source_dir.join("assets/a/public.txt"), "alpha\n").unwrap();
    fs::write(source_dir.join("assets/b/public.txt"), "beta\n").unwrap();
    fs::write(source_dir.join("assets/.secret.txt"), "hidden\n").unwrap();
    fs::write(source_dir.join("assets/a/.inner-secret"), "hidden-inner\n").unwrap();

    let discombobulator_file = project.join("SurviveWildcard.DiscombobuFile");
    fs::write(
        &discombobulator_file,
        r#"
      FROM scratch for x86_64
      COPY {src} ./hello /app/hello
      COPY {src} ./assets /app/assets
      SURVIVE /app/hello
      SURVIVE /app/assets/*/public.txt
      EXECUTE ["/app/hello"]
      "#,
    )
    .unwrap();

    let output_blob = project.join("survive-wildcard.blob.zst");
    build_blob_with_contexts(
        project,
        &discombobulator_file,
        &output_blob,
        "app",
        &[format!("src={}", source_dir.display())],
    );

    let mounted = MountedBlob::receive(&output_blob);
    let artifact_root = mounted.artifact_root();
    assert!(artifact_root.join("rootfs/app/hello").exists());
    assert_eq!(
        fs::read_to_string(artifact_root.join("rootfs/app/assets/a/public.txt")).unwrap(),
        "alpha\n"
    );
    assert_eq!(
        fs::read_to_string(artifact_root.join("rootfs/app/assets/b/public.txt")).unwrap(),
        "beta\n"
    );
    assert!(!artifact_root.join("rootfs/app/assets/.secret.txt").exists());
    assert!(!artifact_root
        .join("rootfs/app/assets/a/.inner-secret")
        .exists());

    let kept_files = collect_relative_file_paths(&artifact_root.join("rootfs/app/assets"));
    assert_eq!(
        kept_files,
        vec!["a/public.txt".to_string(), "b/public.txt".to_string(),]
    );
}

#[test]
fn published_local_base_can_seed_a_follow_on_build() {
    let temp = tempfile::tempdir().unwrap();
    let project = temp.path();
    let source_dir = project.join("srcctx");
    fs::create_dir_all(&source_dir).unwrap();

    let c_source = source_dir.join("hello.c");
    fs::write(
        &c_source,
        r#"
      #include <stdio.h>

      int main(void)
      {
         puts("hello");
         return 0;
      }
      "#,
    )
    .unwrap();

    let binary = source_dir.join("hello");
    let compiled = Command::new("clang")
        .arg(&c_source)
        .arg("-O2")
        .arg("-o")
        .arg(&binary)
        .output()
        .unwrap();
    assert!(
        compiled.status.success(),
        "{}",
        String::from_utf8_lossy(&compiled.stderr)
    );

    let base_file = project.join("Base.DiscombobuFile");
    fs::write(
        &base_file,
        r#"
      FROM scratch for x86_64
      COPY {src} ./hello /app/hello
      "#,
    )
    .unwrap();

    let base_blob = project.join("hello-base.blob.zst");
    let binary_path = env!("CARGO_BIN_EXE_discombobulator");
    let base_build = Command::new(binary_path)
        .current_dir(project)
        .args([
            "build",
            "--file",
            base_file.to_str().unwrap(),
            "--context",
            &format!("src={}", source_dir.display()),
            "--output",
            base_blob.to_str().unwrap(),
            "--kind",
            "base",
            "--publish-base",
            "hello-base:latest",
        ])
        .output()
        .unwrap();
    assert!(
        base_build.status.success(),
        "{}",
        String::from_utf8_lossy(&base_build.stderr)
    );

    let app_file = project.join("App.DiscombobuFile");
    fs::write(
        &app_file,
        r#"
      FROM hello-base:latest for x86_64
      SURVIVE /app/hello
      EXECUTE ["/app/hello"]
      "#,
    )
    .unwrap();

    let app_blob = project.join("hello-app.blob.zst");
    let app_build = Command::new(binary_path)
        .current_dir(project)
        .args([
            "build",
            "--file",
            app_file.to_str().unwrap(),
            "--output",
            app_blob.to_str().unwrap(),
            "--kind",
            "app",
        ])
        .output()
        .unwrap();
    assert!(
        app_build.status.success(),
        "{}",
        String::from_utf8_lossy(&app_build.stderr)
    );
    assert!(app_blob.exists());

    let connection = open_registry(project);
    let base_row = query_named_artifact(&connection, "base", "hello-base", "latest", "x86_64");
    assert_eq!(base_row.kind, "base");
    assert_eq!(base_row.arch, "x86_64");
    assert_eq!(base_row.name.as_deref(), Some("hello-base"));
    assert_eq!(base_row.tag.as_deref(), Some("latest"));
    let base_cached_path = PathBuf::from(&base_row.path);
    assert!(base_cached_path.exists());
    assert!(base_cached_path.starts_with(project.join(".discombobulator/artifacts/bases/x86_64")));
    assert_eq!(
        base_row.size_bytes,
        fs::metadata(&base_cached_path).unwrap().len() as i64
    );
    assert!(base_row.created_at > 0);
    assert!(base_row.updated_at > 0);
    assert!(base_row.last_used_at > 0);
    assert_eq!(
        fs::read(&base_blob).unwrap(),
        fs::read(&base_cached_path).unwrap()
    );

    let app_rows = query_artifacts_by_kind(&connection, "app");
    assert_eq!(app_rows.len(), 1);
    let app_row = &app_rows[0];
    assert_eq!(app_row.kind, "app");
    assert_eq!(app_row.arch, "x86_64");
    assert!(app_row.name.is_none());
    assert!(app_row.tag.is_none());
    let app_cached_path = PathBuf::from(&app_row.path);
    assert!(app_cached_path.exists());
    assert!(app_cached_path.starts_with(project.join(".discombobulator/artifacts/apps/x86_64")));
    assert_eq!(
        app_row.size_bytes,
        fs::metadata(&app_cached_path).unwrap().len() as i64
    );
    assert!(app_row.created_at > 0);
    assert!(app_row.updated_at > 0);
    assert!(app_row.last_used_at > 0);
    assert_eq!(
        fs::read(&app_blob).unwrap(),
        fs::read(&app_cached_path).unwrap()
    );
}

#[test]
fn repeated_identical_app_build_reuses_cached_local_artifact_blob() {
    let temp = tempfile::tempdir().unwrap();
    let project = temp.path();
    let source_dir = project.join("srcctx");
    fs::create_dir_all(&source_dir).unwrap();

    let c_source = source_dir.join("hello.c");
    fs::write(
        &c_source,
        r#"
      #include <stdio.h>

      int main(void)
      {
         puts("hello");
         return 0;
      }
      "#,
    )
    .unwrap();

    let binary = source_dir.join("hello");
    let compiled = Command::new("clang")
        .arg(&c_source)
        .arg("-O2")
        .arg("-o")
        .arg(&binary)
        .output()
        .unwrap();
    assert!(
        compiled.status.success(),
        "{}",
        String::from_utf8_lossy(&compiled.stderr)
    );

    let discombobulator_file = project.join("AppReuse.DiscombobuFile");
    fs::write(
        &discombobulator_file,
        r#"
      FROM scratch for x86_64
      COPY {src} ./hello /app/hello
      SURVIVE /app/hello
      EXECUTE ["/app/hello"]
      "#,
    )
    .unwrap();

    let first_blob = project.join("app-reuse-first.blob.zst");
    build_blob_with_contexts(
        project,
        &discombobulator_file,
        &first_blob,
        "app",
        &[format!("src={}", source_dir.display())],
    );

    let first_connection = open_registry(project);
    let first_rows = query_artifacts_by_kind(&first_connection, "app");
    assert_eq!(first_rows.len(), 1);
    let first_cached_path = PathBuf::from(&first_rows[0].path);
    assert!(first_cached_path.exists());
    assert!(first_cached_path.starts_with(project.join(".discombobulator/artifacts/apps/x86_64")));
    let first_modified = fs::metadata(&first_cached_path)
        .unwrap()
        .modified()
        .unwrap();
    assert_eq!(
        count_cached_artifacts(project, "app", "x86_64"),
        1,
        "expected one cached app artifact after first build"
    );
    assert_eq!(
        fs::read(&first_blob).unwrap(),
        fs::read(&first_cached_path).unwrap()
    );

    thread::sleep(Duration::from_millis(20));

    let second_blob = project.join("app-reuse-second.blob.zst");
    build_blob_with_contexts(
        project,
        &discombobulator_file,
        &second_blob,
        "app",
        &[format!("src={}", source_dir.display())],
    );

    let second_connection = open_registry(project);
    let second_rows = query_artifacts_by_kind(&second_connection, "app");
    assert_eq!(second_rows.len(), 1);
    let second_cached_path = PathBuf::from(&second_rows[0].path);
    assert_eq!(second_cached_path, first_cached_path);
    let second_modified = fs::metadata(&second_cached_path)
        .unwrap()
        .modified()
        .unwrap();
    assert_eq!(second_modified, first_modified);
    assert_eq!(
        count_cached_artifacts(project, "app", "x86_64"),
        1,
        "expected repeated build to reuse cached app artifact"
    );
    assert_eq!(
        fs::read(&second_blob).unwrap(),
        fs::read(&second_cached_path).unwrap()
    );
}

#[test]
fn concurrent_remote_import_race_downloads_once_and_reuses_cached_import() {
    let registry = FakeRegistry::with_delay(Duration::from_millis(60));
    let temp = tempfile::tempdir().unwrap();
    let project = temp.path();
    let binary = env!("CARGO_BIN_EXE_discombobulator");

    let add_remote = Command::new(binary)
        .current_dir(project)
        .args(["remote", "add", "fixture", &registry.host()])
        .output()
        .unwrap();
    assert!(
        add_remote.status.success(),
        "{}",
        String::from_utf8_lossy(&add_remote.stderr)
    );

    let remote_file = project.join("ConcurrentRemote.DiscombobuFile");
    fs::write(
        &remote_file,
        "FROM remote fixture sample:latest for x86_64\n",
    )
    .unwrap();

    let barrier = Arc::new(Barrier::new(3));
    let mut handles = Vec::new();
    for index in 0..2 {
        let project = project.to_path_buf();
        let file = remote_file.clone();
        let output = project.join(format!("remote-concurrent-{index}.blob.zst"));
        let barrier = barrier.clone();
        handles.push(thread::spawn(move || {
            barrier.wait();
            Command::new(binary)
                .current_dir(&project)
                .args([
                    "build",
                    "--file",
                    file.to_str().unwrap(),
                    "--output",
                    output.to_str().unwrap(),
                    "--kind",
                    "base",
                ])
                .output()
                .unwrap()
        }));
    }
    barrier.wait();

    for handle in handles {
        let build = handle.join().unwrap();
        assert!(
            build.status.success(),
            "{}",
            String::from_utf8_lossy(&build.stderr)
        );
    }

    assert_eq!(
        registry.request_count(),
        4,
        "expected one remote producer worth of registry traffic"
    );
    assert_eq!(count_cached_import_roots(project, "x86_64"), 1);
    let connection = open_registry(project);
    let rows = query_artifacts_by_kind(&connection, "base");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].arch, "x86_64");
    assert!(Path::new(&rows[0].path).exists());
}

#[test]
fn concurrent_step_cache_race_runs_once_and_reuses_cached_step() {
    let server = HitServer::new();
    let temp = tempfile::tempdir().unwrap();
    let project = temp.path();
    let rootfs_context = project.join("rootctx");
    fs::create_dir_all(&rootfs_context).unwrap();

    let runner_source = project.join("hit_runner.c");
    fs::write(
        &runner_source,
        r#"
      #include <arpa/inet.h>
      #include <netinet/in.h>
      #include <stdint.h>
      #include <stdio.h>
      #include <stdlib.h>
      #include <string.h>
      #include <sys/socket.h>
      #include <time.h>
      #include <unistd.h>

      int main(int argc, char **argv)
      {
         if (argc != 4)
         {
            return 2;
         }

         int fd = socket(AF_INET, SOCK_STREAM, 0);
         if (fd < 0)
         {
            return 3;
         }

         struct sockaddr_in address;
         memset(&address, 0, sizeof(address));
         address.sin_family = AF_INET;
         address.sin_port = htons((uint16_t) atoi(argv[2]));
         if (inet_pton(AF_INET, argv[1], &address.sin_addr) != 1)
         {
            close(fd);
            return 4;
         }

         if (connect(fd, (struct sockaddr *) &address, sizeof(address)) != 0)
         {
            close(fd);
            return 5;
         }

         (void) write(fd, "hit\n", 4);
         close(fd);

         struct timespec request;
         request.tv_sec = atoi(argv[3]) / 1000;
         request.tv_nsec = (long) (atoi(argv[3]) % 1000) * 1000000L;
         nanosleep(&request, NULL);
         return 0;
      }
      "#,
    )
    .unwrap();

    let runner_binary = project.join("hit-runner");
    let compiled = Command::new("clang")
        .arg(&runner_source)
        .arg("-O2")
        .arg("-o")
        .arg(&runner_binary)
        .output()
        .unwrap();
    assert!(
        compiled.status.success(),
        "{}",
        String::from_utf8_lossy(&compiled.stderr)
    );

    copy_host_runtime_closure(
        &runner_binary,
        &rootfs_context,
        Path::new("/tool/hit-runner"),
    );

    let mut file_contents = String::from("FROM scratch for x86_64\n");
    for top_level in ["tool", "lib", "lib64", "usr"] {
        if rootfs_context.join(top_level).exists() {
            file_contents.push_str(&format!("COPY {{root}} ./{top_level} /{top_level}\n"));
        }
    }
    file_contents.push_str(&format!(
        "RUN [\"/tool/hit-runner\", \"127.0.0.1\", \"{}\", \"700\"]\n",
        server.port()
    ));

    let discombobulator_file = project.join("ConcurrentStepCache.DiscombobuFile");
    fs::write(&discombobulator_file, file_contents).unwrap();

    let binary = env!("CARGO_BIN_EXE_discombobulator");
    let contexts = vec![format!("root={}", rootfs_context.display())];
    let barrier = Arc::new(Barrier::new(3));
    let mut handles = Vec::new();
    for index in 0..2 {
        let project = project.to_path_buf();
        let file = discombobulator_file.clone();
        let output = project.join(format!("step-concurrent-{index}.blob.zst"));
        let contexts = contexts.clone();
        let barrier = barrier.clone();
        handles.push(thread::spawn(move || {
            barrier.wait();
            let mut command = Command::new(binary);
            command.current_dir(&project);
            command.args(["build", "--file", file.to_str().unwrap()]);
            for context in &contexts {
                command.arg("--context").arg(context);
            }
            command.args(["--output", output.to_str().unwrap(), "--kind", "base"]);
            command.output().unwrap()
        }));
    }
    barrier.wait();

    for handle in handles {
        let build = handle.join().unwrap();
        assert!(
            build.status.success(),
            "{}",
            String::from_utf8_lossy(&build.stderr)
        );
    }

    assert_eq!(
        server.hit_count(),
        1,
        "expected one RUN execution on cache miss"
    );
    assert!(project.join(".discombobulator/cache/steps/x86_64").exists());
    let connection = open_registry(project);
    let rows = query_artifacts_by_kind(&connection, "base");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].arch, "x86_64");
    assert!(Path::new(&rows[0].path).exists());
}

#[test]
fn stale_builder_session_and_tmp_state_are_reaped_on_next_build() {
    let temp = tempfile::tempdir().unwrap();
    let project = temp.path();
    let source_dir = project.join("srcctx");
    fs::create_dir_all(&source_dir).unwrap();
    fs::write(source_dir.join("hello.txt"), "hello\n").unwrap();

    let stale_work = project.join(".discombobulator/work/session-stale");
    let stale_tmp_session = project.join(".discombobulator/tmp/session-stale");
    let stale_tmp_stage = project.join(".discombobulator/tmp/orphan-stage");
    fs::create_dir_all(stale_work.join("workspace")).unwrap();
    fs::create_dir_all(stale_tmp_session.join("staging")).unwrap();
    fs::create_dir_all(&stale_tmp_stage).unwrap();
    fs::write(stale_work.join("workspace/stale.txt"), "stale\n").unwrap();
    fs::write(stale_tmp_session.join("staging/partial.txt"), "partial\n").unwrap();
    fs::write(stale_tmp_stage.join("partial.zst"), "partial\n").unwrap();
    let loop_image = stale_tmp_session.join("artifact.btrfs");
    let loop_mount = stale_tmp_session.join("mount");
    fs::create_dir_all(&loop_mount).unwrap();
    assert!(Command::new("truncate")
        .args(["-s", "256M"])
        .arg(&loop_image)
        .status()
        .unwrap()
        .success());
    assert!(Command::new("mkfs.btrfs")
        .arg("-q")
        .arg(&loop_image)
        .status()
        .unwrap()
        .success());
    assert!(Command::new("mount")
        .arg("-o")
        .arg("loop")
        .arg(&loop_image)
        .arg(&loop_mount)
        .status()
        .unwrap()
        .success());
    assert!(Command::new("btrfs")
        .args(["subvolume", "create"])
        .arg(loop_mount.join("orphaned-subvolume"))
        .status()
        .unwrap()
        .success());
    assert!(Command::new("umount")
        .arg(&loop_mount)
        .status()
        .unwrap()
        .success());
    mark_entry_stale(&stale_work);
    mark_entry_stale(&stale_tmp_session);
    mark_entry_stale(&stale_tmp_stage);

    let discombobulator_file = project.join("Janitor.DiscombobuFile");
    fs::write(
        &discombobulator_file,
        r#"
      FROM scratch for x86_64
      COPY {src} ./hello.txt /app/hello.txt
      "#,
    )
    .unwrap();

    let output_blob = project.join("janitor.blob.zst");
    build_blob_with_contexts(
        project,
        &discombobulator_file,
        &output_blob,
        "base",
        &[format!("src={}", source_dir.display())],
    );

    assert!(!stale_work.exists());
    assert!(!stale_tmp_session.exists());
    assert!(!stale_tmp_stage.exists());
    assert_no_session_entries(&project.join(".discombobulator/work"));
    assert_no_session_entries(&project.join(".discombobulator/tmp"));
}

#[test]
fn stale_unreferenced_cached_imports_and_artifacts_are_reaped_on_startup() {
    let registry = FakeRegistry::new();
    let temp = tempfile::tempdir().unwrap();
    let project = temp.path();
    let binary = env!("CARGO_BIN_EXE_discombobulator");

    let add_remote = Command::new(binary)
        .current_dir(project)
        .args(["remote", "add", "fixture", &registry.host()])
        .output()
        .unwrap();
    assert!(
        add_remote.status.success(),
        "{}",
        String::from_utf8_lossy(&add_remote.stderr)
    );

    let remote_file = project.join("GcRemote.DiscombobuFile");
    fs::write(
        &remote_file,
        "FROM remote fixture sample:latest for x86_64\n",
    )
    .unwrap();

    let first_blob = project.join("gc-first.blob.zst");
    build_blob(project, &remote_file, &first_blob, "base");

    let connection = open_registry(project);
    let referenced_artifact = PathBuf::from(&query_artifacts_by_kind(&connection, "base")[0].path);
    let referenced_import = query_oci_import_paths(&connection)[0].clone();
    assert!(referenced_artifact.exists());
    assert!(referenced_import.exists());

    let orphan_import = project.join(".discombobulator/imports/oci/x86_64/orphan-import");
    fs::create_dir_all(orphan_import.join("rootfs/app")).unwrap();
    fs::write(orphan_import.join("rootfs/app/orphan.txt"), "orphan\n").unwrap();
    mark_entry_stale(&orphan_import);

    let orphan_artifact = project.join(".discombobulator/artifacts/bases/x86_64/orphan.zst");
    fs::create_dir_all(orphan_artifact.parent().unwrap()).unwrap();
    fs::write(&orphan_artifact, "orphan\n").unwrap();
    mark_entry_stale(&orphan_artifact);

    let fetched = Command::new(binary)
        .current_dir(project)
        .args([
            "remote",
            "fetch",
            "fixture",
            "sample:latest",
            "--arch",
            "x86_64",
        ])
        .output()
        .unwrap();
    assert!(
        fetched.status.success(),
        "{}",
        String::from_utf8_lossy(&fetched.stderr)
    );

    assert!(referenced_artifact.exists());
    assert!(referenced_import.exists());
    assert!(!orphan_import.exists());
    assert!(!orphan_artifact.exists());
}

#[test]
fn remote_manifest_fetch_fault_recovers_cleanly_on_next_build() {
    let registry = FakeRegistry::new();
    let temp = tempfile::tempdir().unwrap();
    let project = temp.path();
    add_named_remote(project, "fixture", &registry.host());

    let discombobulator_file = project.join("RemoteManifestFault.DiscombobuFile");
    fs::write(
        &discombobulator_file,
        "FROM remote fixture sample:latest for x86_64\n",
    )
    .unwrap();

    let output_blob = project.join("manifest-fault.blob.zst");
    let failed = build_with_contexts_and_env(
        project,
        &discombobulator_file,
        &output_blob,
        "base",
        &[],
        &[("DISCOMBOBULATOR_TEST_FAULT", "remote-manifest-fetch")],
    );
    assert_fault_injected(&failed, "remote-manifest-fetch");
    assert_eq!(count_cached_import_roots(project, "x86_64"), 0);
    assert_eq!(count_cached_artifacts(project, "base", "x86_64"), 0);

    build_blob(project, &discombobulator_file, &output_blob, "base");

    assert!(output_blob.exists());
    assert_eq!(count_cached_import_roots(project, "x86_64"), 1);
    assert_eq!(count_cached_artifacts(project, "base", "x86_64"), 1);
    assert_no_session_entries(&project.join(".discombobulator/work"));
    assert_no_session_entries(&project.join(".discombobulator/tmp"));
}

#[test]
fn remote_layer_download_fault_recovers_cleanly_on_next_build() {
    let registry = FakeRegistry::new();
    let temp = tempfile::tempdir().unwrap();
    let project = temp.path();
    add_named_remote(project, "fixture", &registry.host());

    let discombobulator_file = project.join("RemoteLayerDownloadFault.DiscombobuFile");
    fs::write(
        &discombobulator_file,
        "FROM remote fixture sample:latest for x86_64\n",
    )
    .unwrap();

    let output_blob = project.join("layer-download-fault.blob.zst");
    let failed = build_with_contexts_and_env(
        project,
        &discombobulator_file,
        &output_blob,
        "base",
        &[],
        &[("DISCOMBOBULATOR_TEST_FAULT", "remote-layer-download")],
    );
    assert_fault_injected(&failed, "remote-layer-download");
    assert_eq!(count_cached_import_roots(project, "x86_64"), 0);
    assert_eq!(count_cached_artifacts(project, "base", "x86_64"), 0);

    build_blob(project, &discombobulator_file, &output_blob, "base");

    assert!(output_blob.exists());
    assert_eq!(count_cached_import_roots(project, "x86_64"), 1);
    assert_eq!(count_cached_artifacts(project, "base", "x86_64"), 1);
    assert_no_session_entries(&project.join(".discombobulator/work"));
    assert_no_session_entries(&project.join(".discombobulator/tmp"));
}

#[test]
fn remote_layer_unpack_fault_recovers_cleanly_on_next_build() {
    let registry = FakeRegistry::new();
    let temp = tempfile::tempdir().unwrap();
    let project = temp.path();
    add_named_remote(project, "fixture", &registry.host());

    let discombobulator_file = project.join("RemoteLayerUnpackFault.DiscombobuFile");
    fs::write(
        &discombobulator_file,
        "FROM remote fixture sample:latest for x86_64\n",
    )
    .unwrap();

    let output_blob = project.join("layer-unpack-fault.blob.zst");
    let failed = build_with_contexts_and_env(
        project,
        &discombobulator_file,
        &output_blob,
        "base",
        &[],
        &[("DISCOMBOBULATOR_TEST_FAULT", "remote-layer-unpack")],
    );
    assert_fault_injected(&failed, "remote-layer-unpack");
    assert_eq!(count_cached_import_roots(project, "x86_64"), 0);
    assert_eq!(count_cached_artifacts(project, "base", "x86_64"), 0);

    build_blob(project, &discombobulator_file, &output_blob, "base");

    assert!(output_blob.exists());
    assert_eq!(count_cached_import_roots(project, "x86_64"), 1);
    assert_eq!(count_cached_artifacts(project, "base", "x86_64"), 1);
    assert_no_session_entries(&project.join(".discombobulator/work"));
    assert_no_session_entries(&project.join(".discombobulator/tmp"));
}

#[test]
fn final_blob_export_fault_recovers_cleanly_on_next_build() {
    let temp = tempfile::tempdir().unwrap();
    let project = temp.path();
    let source_dir = project.join("srcctx");
    fs::create_dir_all(&source_dir).unwrap();
    fs::write(source_dir.join("hello.txt"), "hello\n").unwrap();

    let discombobulator_file = project.join("ExportFault.DiscombobuFile");
    fs::write(
        &discombobulator_file,
        r#"
      FROM scratch for x86_64
      COPY {src} ./hello.txt /app/hello.txt
      "#,
    )
    .unwrap();

    let output_blob = project.join("export-fault.blob.zst");
    let failed = build_with_contexts_and_env(
        project,
        &discombobulator_file,
        &output_blob,
        "base",
        &[format!("src={}", source_dir.display())],
        &[("DISCOMBOBULATOR_TEST_FAULT", "final-blob-export")],
    );
    assert_fault_injected(&failed, "final-blob-export");
    assert!(!output_blob.exists());
    assert_eq!(count_cached_artifacts(project, "base", "x86_64"), 0);
    assert!(query_artifacts_by_kind(&open_registry(project), "base").is_empty());

    build_blob_with_contexts(
        project,
        &discombobulator_file,
        &output_blob,
        "base",
        &[format!("src={}", source_dir.display())],
    );

    assert!(output_blob.exists());
    assert_eq!(count_cached_artifacts(project, "base", "x86_64"), 1);
    assert_eq!(
        query_artifacts_by_kind(&open_registry(project), "base").len(),
        1
    );
    assert_no_session_entries(&project.join(".discombobulator/work"));
    assert_no_session_entries(&project.join(".discombobulator/tmp"));
}

#[test]
fn registry_update_fault_recovers_cleanly_on_next_build() {
    let temp = tempfile::tempdir().unwrap();
    let project = temp.path();
    let source_dir = project.join("srcctx");
    fs::create_dir_all(&source_dir).unwrap();
    fs::write(source_dir.join("hello.txt"), "hello\n").unwrap();

    let discombobulator_file = project.join("RegistryFault.DiscombobuFile");
    fs::write(
        &discombobulator_file,
        r#"
      FROM scratch for x86_64
      COPY {src} ./hello.txt /app/hello.txt
      "#,
    )
    .unwrap();

    let output_blob = project.join("registry-fault.blob.zst");
    let failed = build_with_contexts_and_env(
        project,
        &discombobulator_file,
        &output_blob,
        "base",
        &[format!("src={}", source_dir.display())],
        &[("DISCOMBOBULATOR_TEST_FAULT", "registry-update")],
    );
    assert_fault_injected(&failed, "registry-update");
    assert!(output_blob.exists());
    assert_eq!(count_cached_artifacts(project, "base", "x86_64"), 1);
    assert!(query_artifacts_by_kind(&open_registry(project), "base").is_empty());

    build_blob_with_contexts(
        project,
        &discombobulator_file,
        &output_blob,
        "base",
        &[format!("src={}", source_dir.display())],
    );

    assert!(output_blob.exists());
    assert_eq!(count_cached_artifacts(project, "base", "x86_64"), 1);
    assert_eq!(
        query_artifacts_by_kind(&open_registry(project), "base").len(),
        1
    );
    assert_no_session_entries(&project.join(".discombobulator/work"));
    assert_no_session_entries(&project.join(".discombobulator/tmp"));
}

#[test]
fn local_base_arch_mismatch_is_rejected_before_execution() {
    let temp = tempfile::tempdir().unwrap();
    let project = temp.path();
    let source_dir = project.join("srcctx");
    fs::create_dir_all(&source_dir).unwrap();
    fs::write(source_dir.join("hello.txt"), "hello\n").unwrap();

    let base_file = project.join("BaseMismatchSource.DiscombobuFile");
    fs::write(
        &base_file,
        r#"
      FROM scratch for x86_64
      COPY {src} ./hello.txt /app/hello.txt
      "#,
    )
    .unwrap();

    let base_blob = project.join("hello-base-mismatch.blob.zst");
    let binary = env!("CARGO_BIN_EXE_discombobulator");
    let base_build = Command::new(binary)
        .current_dir(project)
        .args([
            "build",
            "--file",
            base_file.to_str().unwrap(),
            "--context",
            &format!("src={}", source_dir.display()),
            "--output",
            base_blob.to_str().unwrap(),
            "--kind",
            "base",
            "--publish-base",
            "hello-base:latest",
        ])
        .output()
        .unwrap();
    assert!(
        base_build.status.success(),
        "{}",
        String::from_utf8_lossy(&base_build.stderr)
    );

    let mismatch_file = project.join("BaseMismatch.DiscombobuFile");
    fs::write(
        &mismatch_file,
        r#"
      FROM hello-base:latest for arm64
      "#,
    )
    .unwrap();

    let output_blob = project.join("base-arch-mismatch.blob.zst");
    let stderr = build_failure_with_contexts(project, &mismatch_file, &output_blob, "base", &[]);
    assert!(
        stderr.contains("unknown local base hello-base:latest for architecture arm64"),
        "{stderr}"
    );
}

#[test]
fn base_output_preserves_full_final_filesystem() {
    let temp = tempfile::tempdir().unwrap();
    let project = temp.path();
    let source_dir = project.join("srcctx");
    fs::create_dir_all(&source_dir).unwrap();

    fs::write(source_dir.join("visible.txt"), "visible\n").unwrap();
    fs::write(source_dir.join(".hidden.txt"), "hidden\n").unwrap();
    fs::write(source_dir.join("build-only.txt"), "keep me in base\n").unwrap();

    let discombobulator_file = project.join("BasePreserve.DiscombobuFile");
    fs::write(
        &discombobulator_file,
        r#"
      FROM scratch for x86_64
      COPY {src} ./visible.txt /app/visible.txt
      COPY {src} ./.hidden.txt /app/.hidden.txt
      COPY {src} ./build-only.txt /build/build-only.txt
      "#,
    )
    .unwrap();

    let output_blob = project.join("base-preserve.blob.zst");
    build_blob_with_contexts(
        project,
        &discombobulator_file,
        &output_blob,
        "base",
        &[format!("src={}", source_dir.display())],
    );

    let mounted = MountedBlob::receive(&output_blob);
    let artifact_root = mounted.artifact_root();
    assert!(artifact_root.join("app/visible.txt").exists());
    assert!(artifact_root.join("app/.hidden.txt").exists());
    assert!(artifact_root.join("build/build-only.txt").exists());
    assert!(!artifact_root.join(".prodigy-private").exists());
}

#[test]
fn remote_oci_import_uses_cached_imports_and_force_refresh() {
    let registry = FakeRegistry::new();
    let temp = tempfile::tempdir().unwrap();
    let project = temp.path();
    let binary = env!("CARGO_BIN_EXE_discombobulator");

    let add_remote = Command::new(binary)
        .current_dir(project)
        .args(["remote", "add", "fixture", &registry.host()])
        .output()
        .unwrap();
    assert!(
        add_remote.status.success(),
        "{}",
        String::from_utf8_lossy(&add_remote.stderr)
    );

    let remote_file = project.join("Remote.DiscombobuFile");
    fs::write(
        &remote_file,
        "FROM remote fixture sample:latest for x86_64\n",
    )
    .unwrap();
    let force_file = project.join("RemoteForce.DiscombobuFile");
    fs::write(
        &force_file,
        "FROM remote force fixture sample:latest for x86_64\n",
    )
    .unwrap();

    let first_blob = project.join("remote-first.blob.zst");
    build_blob(project, &remote_file, &first_blob, "base");
    {
        let mounted = MountedBlob::receive(&first_blob);
        assert_eq!(
            fs::read_to_string(mounted.artifact_root().join("app/hello")).unwrap(),
            "version-one\n"
        );
        assert_eq!(
            fs::read_link(mounted.artifact_root().join("app/current")).unwrap(),
            PathBuf::from("/app/hello")
        );
        assert!(!mounted.artifact_root().join("app/old.txt").exists());
    }

    let first_request_count = registry.request_count();
    assert!(
        first_request_count >= 4,
        "expected remote fetch traffic, saw {first_request_count}"
    );

    registry.set_version(2);
    let cached_blob = project.join("remote-cached.blob.zst");
    build_blob(project, &remote_file, &cached_blob, "base");
    assert_eq!(registry.request_count(), first_request_count);
    {
        let mounted = MountedBlob::receive(&cached_blob);
        assert_eq!(
            fs::read_to_string(mounted.artifact_root().join("app/hello")).unwrap(),
            "version-one\n"
        );
    }

    let refreshed_blob = project.join("remote-refreshed.blob.zst");
    build_blob(project, &force_file, &refreshed_blob, "base");
    assert!(registry.request_count() > first_request_count);
    {
        let mounted = MountedBlob::receive(&refreshed_blob);
        assert_eq!(
            fs::read_to_string(mounted.artifact_root().join("app/hello")).unwrap(),
            "version-two\n"
        );
        assert_eq!(
            fs::read_link(mounted.artifact_root().join("app/current")).unwrap(),
            PathBuf::from("/app/hello")
        );
        assert!(!mounted.artifact_root().join("app/old.txt").exists());
    }

    let import_root = project.join(".discombobulator/imports/oci/x86_64");
    let import_entries = fs::read_dir(&import_root).unwrap().count();
    assert!(
        import_entries >= 2,
        "expected two cached import roots after forced refresh"
    );
}

#[test]
fn remote_oci_import_rejects_arch_mismatches_before_execution() {
    let registry = FakeRegistry::new();
    let temp = tempfile::tempdir().unwrap();
    let project = temp.path();
    let binary = env!("CARGO_BIN_EXE_discombobulator");

    let add_remote = Command::new(binary)
        .current_dir(project)
        .args(["remote", "add", "fixture", &registry.host()])
        .output()
        .unwrap();
    assert!(
        add_remote.status.success(),
        "{}",
        String::from_utf8_lossy(&add_remote.stderr)
    );

    let remote_file = project.join("RemoteArmMismatch.DiscombobuFile");
    fs::write(
        &remote_file,
        "FROM remote fixture sample:latest for arm64\n",
    )
    .unwrap();

    let output_blob = project.join("remote-arch-mismatch.blob.zst");
    let stderr = build_failure_with_contexts(project, &remote_file, &output_blob, "base", &[]);
    assert!(
        stderr.contains(
            "remote OCI base architecture Some(\"amd64\") does not match requested arm64"
        ),
        "{stderr}"
    );
}

#[test]
fn remote_fetch_uses_cached_imports_and_refreshes_explicitly() {
    let registry = FakeRegistry::new();
    let temp = tempfile::tempdir().unwrap();
    let project = temp.path();
    let binary = env!("CARGO_BIN_EXE_discombobulator");

    let add_remote = Command::new(binary)
        .current_dir(project)
        .args(["remote", "add", "fixture", &registry.host()])
        .output()
        .unwrap();
    assert!(
        add_remote.status.success(),
        "{}",
        String::from_utf8_lossy(&add_remote.stderr)
    );

    let first_fetch = Command::new(binary)
        .current_dir(project)
        .args([
            "remote",
            "fetch",
            "fixture",
            "sample:latest",
            "--arch",
            "x86_64",
        ])
        .output()
        .unwrap();
    assert!(
        first_fetch.status.success(),
        "{}",
        String::from_utf8_lossy(&first_fetch.stderr)
    );
    let first_root = String::from_utf8_lossy(&first_fetch.stdout)
        .trim()
        .to_string();
    assert!(Path::new(&first_root).exists());
    let first_request_count = registry.request_count();
    assert!(
        first_request_count >= 4,
        "expected remote fetch traffic, saw {first_request_count}"
    );

    let second_fetch = Command::new(binary)
        .current_dir(project)
        .args([
            "remote",
            "fetch",
            "fixture",
            "sample:latest",
            "--arch",
            "x86_64",
        ])
        .output()
        .unwrap();
    assert!(
        second_fetch.status.success(),
        "{}",
        String::from_utf8_lossy(&second_fetch.stderr)
    );
    let second_root = String::from_utf8_lossy(&second_fetch.stdout)
        .trim()
        .to_string();
    assert_eq!(second_root, first_root);
    assert_eq!(registry.request_count(), first_request_count);

    registry.set_version(2);
    let refreshed_fetch = Command::new(binary)
        .current_dir(project)
        .args([
            "remote",
            "fetch",
            "fixture",
            "sample:latest",
            "--arch",
            "x86_64",
            "--refresh",
        ])
        .output()
        .unwrap();
    assert!(
        refreshed_fetch.status.success(),
        "{}",
        String::from_utf8_lossy(&refreshed_fetch.stderr)
    );
    let refreshed_root = String::from_utf8_lossy(&refreshed_fetch.stdout)
        .trim()
        .to_string();
    assert!(Path::new(&refreshed_root).exists());
    assert_ne!(refreshed_root, first_root);
    assert!(registry.request_count() > first_request_count);
    assert_eq!(
        fs::read_to_string(Path::new(&refreshed_root).join("app/hello")).unwrap(),
        "version-two\n"
    );
}

#[test]
fn remote_fetch_private_registry_uses_docker_config_basic_auth() {
    let registry = FakeRegistry::with_basic_auth("builder", "s3cret");
    let temp = tempfile::tempdir().unwrap();
    let project = temp.path();
    let binary = env!("CARGO_BIN_EXE_discombobulator");

    let add_remote = Command::new(binary)
        .current_dir(project)
        .args(["remote", "add", "fixture", &registry.host()])
        .output()
        .unwrap();
    assert!(
        add_remote.status.success(),
        "{}",
        String::from_utf8_lossy(&add_remote.stderr)
    );

    let unauthenticated_fetch = Command::new(binary)
        .current_dir(project)
        .args([
            "remote",
            "fetch",
            "fixture",
            "sample:latest",
            "--arch",
            "x86_64",
        ])
        .output()
        .unwrap();
    assert!(!unauthenticated_fetch.status.success());
    let unauthenticated_stderr = String::from_utf8_lossy(&unauthenticated_fetch.stderr);
    assert!(
        unauthenticated_stderr.contains("requires basic auth"),
        "{unauthenticated_stderr}"
    );

    let docker_config = project.join("docker-config");
    write_docker_config_auth(&docker_config, &registry.host(), "builder", "s3cret");
    let authenticated_fetch = Command::new(binary)
        .current_dir(project)
        .env("DOCKER_CONFIG", &docker_config)
        .args([
            "remote",
            "fetch",
            "fixture",
            "sample:latest",
            "--arch",
            "x86_64",
        ])
        .output()
        .unwrap();
    assert!(
        authenticated_fetch.status.success(),
        "{}",
        String::from_utf8_lossy(&authenticated_fetch.stderr)
    );
    let root = String::from_utf8_lossy(&authenticated_fetch.stdout)
        .trim()
        .to_string();
    assert!(Path::new(&root).exists());
    assert_eq!(
        fs::read_to_string(Path::new(&root).join("app/hello")).unwrap(),
        "version-one\n"
    );
}

#[test]
fn remote_oci_import_handles_whiteouts_and_duplicate_entries_deterministically() {
    let registry = FakeRegistry::with_versions(BTreeMap::from([(
        1usize,
        build_registry_image_with_layers(
            vec![
                gzip_tar(&[
                    TarEntry::Directory {
                        path: "app/data",
                        mode: 0o755,
                    },
                    TarEntry::File {
                        path: "app/config.txt",
                        contents: b"old\n",
                        mode: 0o644,
                    },
                    TarEntry::File {
                        path: "app/data/stale.txt",
                        contents: b"stale\n",
                        mode: 0o644,
                    },
                ]),
                gzip_tar(&[
                    TarEntry::File {
                        path: "app/config.txt",
                        contents: b"first\n",
                        mode: 0o644,
                    },
                    TarEntry::File {
                        path: "app/config.txt",
                        contents: b"last\n",
                        mode: 0o644,
                    },
                    TarEntry::File {
                        path: "app/data/.wh..wh..opq",
                        contents: b"",
                        mode: 0o644,
                    },
                    TarEntry::File {
                        path: "app/data/fresh.txt",
                        contents: b"fresh\n",
                        mode: 0o644,
                    },
                ]),
            ],
            "amd64",
        ),
    )]));
    let temp = tempfile::tempdir().unwrap();
    let project = temp.path();
    add_named_remote(project, "fixture", &registry.host());

    let output = remote_fetch(project, "fixture", "sample:latest", "x86_64");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let root = PathBuf::from(String::from_utf8_lossy(&output.stdout).trim());
    assert_eq!(
        fs::read_to_string(root.join("app/config.txt")).unwrap(),
        "last\n"
    );
    assert!(!root.join("app/data/stale.txt").exists());
    assert_eq!(
        fs::read_to_string(root.join("app/data/fresh.txt")).unwrap(),
        "fresh\n"
    );

    let connection = open_registry(project);
    assert_eq!(query_oci_import_paths(&connection).len(), 1);
}

fn assert_remote_oci_import_supports_manifest_and_layer_format(
    manifest_media_type: TestManifestMediaType,
    layer_encoding: TestLayerEncoding,
    expected_contents: &str,
) {
    let registry = FakeRegistry::with_versions(BTreeMap::from([(
        1usize,
        build_registry_image_with_media_types(
            expected_contents,
            "amd64",
            manifest_media_type,
            layer_encoding,
        ),
    )]));
    let temp = tempfile::tempdir().unwrap();
    let project = temp.path();
    add_named_remote(project, "fixture", &registry.host());

    let output = remote_fetch(project, "fixture", "sample:latest", "x86_64");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let root = PathBuf::from(String::from_utf8_lossy(&output.stdout).trim());
    assert_eq!(
        fs::read_to_string(root.join("app/hello")).unwrap(),
        expected_contents
    );
    assert_eq!(
        fs::read_link(root.join("app/current")).unwrap(),
        PathBuf::from("/app/hello")
    );
    assert_eq!(query_oci_import_paths(&open_registry(project)).len(), 1);
}

#[test]
fn remote_oci_import_supports_oci_manifest_with_gzip_layers() {
    assert_remote_oci_import_supports_manifest_and_layer_format(
        TestManifestMediaType::Oci,
        TestLayerEncoding::Gzip,
        "oci-gzip\n",
    );
}

#[test]
fn remote_oci_import_supports_oci_manifest_with_uncompressed_layers() {
    assert_remote_oci_import_supports_manifest_and_layer_format(
        TestManifestMediaType::Oci,
        TestLayerEncoding::Uncompressed,
        "oci-uncompressed\n",
    );
}

#[test]
fn remote_oci_import_supports_oci_manifest_with_zstd_layers() {
    assert_remote_oci_import_supports_manifest_and_layer_format(
        TestManifestMediaType::Oci,
        TestLayerEncoding::Zstd,
        "oci-zstd\n",
    );
}

#[test]
fn remote_oci_import_supports_docker_schema2_manifest_with_gzip_layers() {
    assert_remote_oci_import_supports_manifest_and_layer_format(
        TestManifestMediaType::DockerSchema2,
        TestLayerEncoding::Gzip,
        "docker-gzip\n",
    );
}

#[test]
fn remote_oci_import_supports_docker_schema2_manifest_with_uncompressed_layers() {
    assert_remote_oci_import_supports_manifest_and_layer_format(
        TestManifestMediaType::DockerSchema2,
        TestLayerEncoding::Uncompressed,
        "docker-uncompressed\n",
    );
}

#[test]
fn remote_oci_import_supports_docker_schema2_manifest_with_zstd_layers() {
    assert_remote_oci_import_supports_manifest_and_layer_format(
        TestManifestMediaType::DockerSchema2,
        TestLayerEncoding::Zstd,
        "docker-zstd\n",
    );
}

#[test]
fn remote_oci_import_preserves_hardlinks_and_symlink_chains() {
    let registry = FakeRegistry::with_versions(BTreeMap::from([(
        1usize,
        build_registry_image_with_layers(
            vec![gzip_tar(&[
                TarEntry::Directory {
                    path: "app",
                    mode: 0o755,
                },
                TarEntry::File {
                    path: "app/hello",
                    contents: b"hello\n",
                    mode: 0o644,
                },
                TarEntry::Symlink {
                    path: "app/current",
                    target: "hello",
                    mode: 0o777,
                },
                TarEntry::Symlink {
                    path: "app/latest",
                    target: "current",
                    mode: 0o777,
                },
                TarEntry::Hardlink {
                    path: "app/hello.hard",
                    target: "app/hello",
                    mode: 0o644,
                },
            ])],
            "amd64",
        ),
    )]));
    let temp = tempfile::tempdir().unwrap();
    let project = temp.path();
    add_named_remote(project, "fixture", &registry.host());

    let output = remote_fetch(project, "fixture", "sample:latest", "x86_64");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let root = PathBuf::from(String::from_utf8_lossy(&output.stdout).trim());
    assert_eq!(
        fs::read_link(root.join("app/current")).unwrap(),
        PathBuf::from("hello")
    );
    assert_eq!(
        fs::read_link(root.join("app/latest")).unwrap(),
        PathBuf::from("current")
    );
    assert_eq!(
        fs::read_to_string(root.join("app/hello")).unwrap(),
        "hello\n"
    );
    assert_eq!(
        fs::read_to_string(root.join("app/hello.hard")).unwrap(),
        "hello\n"
    );

    let hello_metadata = fs::metadata(root.join("app/hello")).unwrap();
    let hard_metadata = fs::metadata(root.join("app/hello.hard")).unwrap();
    assert_eq!(hello_metadata.ino(), hard_metadata.ino());
    assert!(hello_metadata.nlink() >= 2);
}

#[test]
fn remote_oci_import_rejects_entry_path_traversal_attempts() {
    let registry = FakeRegistry::with_versions(BTreeMap::from([(
        1usize,
        build_registry_image_with_layers(
            vec![gzip_raw_tar_file("../escape.txt", b"bad\n", 0o644)],
            "amd64",
        ),
    )]));
    let temp = tempfile::tempdir().unwrap();
    let project = temp.path();
    add_named_remote(project, "fixture", &registry.host());

    let output = remote_fetch(project, "fixture", "sample:latest", "x86_64");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("OCI layer entry escapes the rootfs"),
        "{stderr}"
    );
    assert_eq!(count_cached_import_roots(project, "x86_64"), 0);
    assert!(query_oci_import_paths(&open_registry(project)).is_empty());
}

#[test]
fn remote_oci_import_rejects_hardlink_target_traversal_attempts() {
    let registry = FakeRegistry::with_versions(BTreeMap::from([(
        1usize,
        build_registry_image_with_layers(
            vec![gzip_tar(&[
                TarEntry::File {
                    path: "app/hello",
                    contents: b"hello\n",
                    mode: 0o644,
                },
                TarEntry::Hardlink {
                    path: "app/leak",
                    target: "../outside/secret",
                    mode: 0o644,
                },
            ])],
            "amd64",
        ),
    )]));
    let temp = tempfile::tempdir().unwrap();
    let project = temp.path();
    add_named_remote(project, "fixture", &registry.host());

    let output = remote_fetch(project, "fixture", "sample:latest", "x86_64");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("OCI layer entry escapes the rootfs"),
        "{stderr}"
    );
    assert_eq!(count_cached_import_roots(project, "x86_64"), 0);
    assert!(query_oci_import_paths(&open_registry(project)).is_empty());
}

#[test]
fn remote_oci_import_rejects_symlink_chain_parent_escapes() {
    let registry = FakeRegistry::with_versions(BTreeMap::from([(
        1usize,
        build_registry_image_with_layers(
            vec![gzip_tar(&[
                TarEntry::Directory {
                    path: "app",
                    mode: 0o755,
                },
                TarEntry::Symlink {
                    path: "app/current",
                    target: "link-two",
                    mode: 0o777,
                },
                TarEntry::Symlink {
                    path: "app/link-two",
                    target: "../../outside",
                    mode: 0o777,
                },
                TarEntry::File {
                    path: "app/current/pwned.txt",
                    contents: b"bad\n",
                    mode: 0o644,
                },
            ])],
            "amd64",
        ),
    )]));
    let temp = tempfile::tempdir().unwrap();
    let project = temp.path();
    add_named_remote(project, "fixture", &registry.host());

    let output = remote_fetch(project, "fixture", "sample:latest", "x86_64");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("OCI layer entry traverses a symlinked parent path"),
        "{stderr}"
    );
    assert_eq!(count_cached_import_roots(project, "x86_64"), 0);
    assert!(query_oci_import_paths(&open_registry(project)).is_empty());
}

#[test]
fn remote_oci_import_rejects_special_tar_entry_types() {
    let registry = FakeRegistry::with_versions(BTreeMap::from([(
        1usize,
        build_registry_image_with_layers(
            vec![gzip_tar(&[
                TarEntry::Directory {
                    path: "app",
                    mode: 0o755,
                },
                TarEntry::Fifo {
                    path: "app/queue",
                    mode: 0o644,
                },
            ])],
            "amd64",
        ),
    )]));
    let temp = tempfile::tempdir().unwrap();
    let project = temp.path();
    add_named_remote(project, "fixture", &registry.host());

    let output = remote_fetch(project, "fixture", "sample:latest", "x86_64");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("OCI special file entry types are not supported"),
        "{stderr}"
    );
    assert_eq!(count_cached_import_roots(project, "x86_64"), 0);
    assert!(query_oci_import_paths(&open_registry(project)).is_empty());
}

#[test]
fn foreign_arch_build_without_run_succeeds_without_qemu() {
    let Some(foreign_arch) = alternate_test_architecture() else {
        return;
    };

    let temp = tempfile::tempdir().unwrap();
    let project = temp.path();
    let source_dir = project.join("srcctx");
    fs::create_dir_all(&source_dir).unwrap();
    fs::write(source_dir.join("message.txt"), "hello-cross-arch\n").unwrap();

    let discombobulator_file = project.join("ForeignNoRun.DiscombobuFile");
    fs::write(
        &discombobulator_file,
        format!("FROM scratch for {foreign_arch}\nCOPY {{src}} ./message.txt /app/message.txt\n"),
    )
    .unwrap();

    let output_blob = project.join("foreign-no-run.blob.zst");
    build_blob_with_contexts(
        project,
        &discombobulator_file,
        &output_blob,
        "base",
        &[format!("src={}", source_dir.display())],
    );

    let mounted = MountedBlob::receive(&output_blob);
    assert_eq!(
        fs::read_to_string(mounted.artifact_root().join("app/message.txt")).unwrap(),
        "hello-cross-arch\n"
    );
}

#[test]
fn x86_64_host_can_build_arm64_remote_base_without_qemu() {
    if std::env::consts::ARCH != "x86_64" {
        return;
    }

    let registry = FakeRegistry::with_arch("arm64");
    let temp = tempfile::tempdir().unwrap();
    let project = temp.path();
    let binary = env!("CARGO_BIN_EXE_discombobulator");

    let add_remote = Command::new(binary)
        .current_dir(project)
        .args(["remote", "add", "fixture", &registry.host()])
        .output()
        .unwrap();
    assert!(
        add_remote.status.success(),
        "{}",
        String::from_utf8_lossy(&add_remote.stderr)
    );

    let discombobulator_file = project.join("Arm64RemoteBase.DiscombobuFile");
    fs::write(
        &discombobulator_file,
        "FROM remote fixture sample:latest for arm64\n",
    )
    .unwrap();

    let output_blob = project.join("arm64-remote-base.blob.zst");
    build_blob(project, &discombobulator_file, &output_blob, "base");

    let mounted = MountedBlob::receive(&output_blob);
    assert_eq!(
        fs::read_to_string(mounted.artifact_root().join("app/hello")).unwrap(),
        "version-one\n"
    );
    assert_eq!(count_cached_import_roots(project, "arm64"), 1);
    assert_eq!(count_cached_artifacts(project, "base", "arm64"), 1);

    let connection = open_registry(project);
    let rows = query_artifacts_by_kind(&connection, "base");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].arch, "arm64");
}

#[test]
fn foreign_arch_run_fails_clearly_when_required_qemu_is_missing() {
    let Some((foreign_arch, required_qemu)) = alternate_test_architecture_and_qemu() else {
        return;
    };

    let temp = tempfile::tempdir().unwrap();
    let project = temp.path();
    let source_dir = project.join("srcctx");
    fs::create_dir_all(&source_dir).unwrap();
    fs::write(source_dir.join("placeholder"), "placeholder\n").unwrap();
    let discombobulator_file = project.join("ForeignRunMissingQemu.DiscombobuFile");
    fs::write(
        &discombobulator_file,
        format!(
            "FROM scratch for {foreign_arch}\nCOPY {{src}} ./placeholder /tool/does-not-matter\nRUN [\"/tool/does-not-matter\"]\n"
        ),
    )
    .unwrap();

    let output_blob = project.join("foreign-run-missing-qemu.blob.zst");
    let binary = env!("CARGO_BIN_EXE_discombobulator");
    let empty_path = project.join("empty-path");
    fs::create_dir_all(&empty_path).unwrap();
    let build = Command::new(binary)
        .current_dir(project)
        .env("PATH", &empty_path)
        .args([
            "build",
            "--file",
            discombobulator_file.to_str().unwrap(),
            "--context",
            &format!("src={}", source_dir.display()),
            "--output",
            output_blob.to_str().unwrap(),
            "--kind",
            "base",
        ])
        .output()
        .unwrap();
    assert!(!build.status.success());
    let stderr = String::from_utf8_lossy(&build.stderr);
    assert!(
        stderr.contains(&format!(
            "requires {required_qemu} because this build step executes foreign-architecture binaries inside the target rootfs"
        )),
        "{stderr}"
    );
    assert!(stderr.contains("Install qemu-user-static"), "{stderr}");
    assert!(
        stderr.contains("Cross-architecture builds that do not execute foreign-architecture RUN steps do not require QEMU"),
        "{stderr}"
    );
}

#[test]
fn foreign_arch_run_uses_explicit_qemu_invocation() {
    let Some((foreign_arch, required_qemu)) = alternate_test_architecture_and_qemu() else {
        return;
    };

    let temp = tempfile::tempdir().unwrap();
    let project = temp.path();
    let rootfs_context = project.join("rootfs");
    let source_context = project.join("srcctx");
    let helper_dir = project.join("helpers");
    fs::create_dir_all(&rootfs_context).unwrap();
    fs::create_dir_all(&source_context).unwrap();
    fs::create_dir_all(&helper_dir).unwrap();

    copy_host_runtime_closure(Path::new("/bin/sh"), &rootfs_context, Path::new("/bin/sh"));

    let placeholder = source_context.join("placeholder");
    fs::write(&placeholder, fake_foreign_elf_bytes(foreign_arch)).unwrap();
    fs::set_permissions(&placeholder, fs::Permissions::from_mode(0o755)).unwrap();

    let helper = helper_dir.join(required_qemu);
    fs::write(
        &helper,
        "#!/bin/sh\nprintf '%s\\n' \"$@\" > /workspace/qemu.log\n",
    )
    .unwrap();
    fs::set_permissions(&helper, fs::Permissions::from_mode(0o755)).unwrap();

    let mut file_contents = format!("FROM scratch for {foreign_arch}\n");
    for top_level in ["bin", "lib", "lib64", "usr"] {
        if rootfs_context.join(top_level).exists() {
            file_contents.push_str(&format!("COPY {{root}} ./{top_level} /{top_level}\n"));
        }
    }
    file_contents.push_str("COPY {src} ./placeholder /tool/placeholder\n");
    file_contents.push_str("WORKDIR /workspace\n");
    file_contents.push_str("RUN [\"/tool/placeholder\", \"alpha\", \"beta\"]\n");

    let discombobulator_file = project.join("ForeignRunExplicitQemu.DiscombobuFile");
    fs::write(&discombobulator_file, file_contents).unwrap();

    let output_blob = project.join("foreign-run-explicit-qemu.blob.zst");
    let binary = env!("CARGO_BIN_EXE_discombobulator");
    let original_path = std::env::var("PATH").unwrap_or_default();
    let binfmt_rules_before = list_host_binfmt_rules_with_prefix("discombobulator-");
    let build = Command::new(binary)
        .current_dir(project)
        .env("PATH", format!("{}:{original_path}", helper_dir.display()))
        .args([
            "build",
            "--file",
            discombobulator_file.to_str().unwrap(),
            "--context",
            &format!("root={}", rootfs_context.display()),
            "--context",
            &format!("src={}", source_context.display()),
            "--output",
            output_blob.to_str().unwrap(),
            "--kind",
            "base",
        ])
        .output()
        .unwrap();
    assert!(
        build.status.success(),
        "{}",
        String::from_utf8_lossy(&build.stderr)
    );

    let mounted = MountedBlob::receive(&output_blob);
    let qemu_log = fs::read_to_string(mounted.artifact_root().join("workspace/qemu.log")).unwrap();
    assert!(qemu_log.contains("/tool/placeholder"), "{qemu_log}");
    assert!(qemu_log.contains("alpha"), "{qemu_log}");
    assert!(qemu_log.contains("beta"), "{qemu_log}");
    assert!(!mounted
        .artifact_root()
        .join(".discombobulator-run")
        .exists());
    assert_eq!(
        list_host_binfmt_rules_with_prefix("discombobulator-"),
        binfmt_rules_before
    );
}

#[test]
#[ignore = "requires root, qemu-user-static, and live remote registry/package-manager access"]
fn live_x86_64_host_builds_arm64_ubuntu_with_real_qemu_run_steps() {
    if std::env::consts::ARCH != "x86_64" {
        return;
    }

    let qemu = host_command_path("qemu-aarch64-static");
    assert!(
        qemu.exists(),
        "missing qemu-aarch64-static at {}",
        qemu.display()
    );

    let temp = tempfile::tempdir().unwrap();
    let project = temp.path();
    let source_dir = project.join("srcctx");
    fs::create_dir_all(&source_dir).unwrap();
    fs::write(
        source_dir.join("hello.c"),
        r#"
      #include <math.h>
      #include <stdio.h>

      int main(void)
      {
         printf("arm64-build-ok %.6f\n", cos(0.5));
         return 0;
      }
      "#,
    )
    .unwrap();

    let binary = env!("CARGO_BIN_EXE_discombobulator");
    let add_remote = Command::new(binary)
        .current_dir(project)
        .args(["remote", "add", "dockerhub", "docker.io"])
        .output()
        .unwrap();
    assert!(
        add_remote.status.success(),
        "{}",
        String::from_utf8_lossy(&add_remote.stderr)
    );

    let discombobulator_file = project.join("LiveArm64UbuntuQemu.DiscombobuFile");
    fs::write(
        &discombobulator_file,
        r#"
      FROM remote force dockerhub library/ubuntu:24.04 for arm64
      ENV DEBIAN_FRONTEND=noninteractive
      WORKDIR /work
      RUN ["/usr/bin/apt-get", "-o", "Acquire::Retries=3", "update"]
      RUN ["/usr/bin/apt-get", "-o", "Acquire::Retries=3", "install", "-y", "--no-install-recommends", "gcc", "libc6-dev"]
      COPY {src} ./hello.c /work/hello.c
      RUN ["/bin/sh", "-c", "/usr/bin/dpkg --print-architecture > /work/arch.txt"]
      RUN ["/usr/bin/gcc", "-O2", "/work/hello.c", "-o", "/work/hello", "-lm"]
      SURVIVE /work/hello
      SURVIVE /work/arch.txt
      EXECUTE ["/work/hello"]
      "#,
    )
    .unwrap();

    let output_blob = project.join("live-arm64-ubuntu-qemu.blob.zst");
    build_blob_with_contexts(
        project,
        &discombobulator_file,
        &output_blob,
        "app",
        &[format!("src={}", source_dir.display())],
    );

    let mounted = MountedBlob::receive(&output_blob);
    let artifact_root = mounted.artifact_root();
    let rootfs = artifact_root.join("rootfs");
    let built_binary = rootfs.join("work/hello");
    let arch_file = rootfs.join("work/arch.txt");

    assert_eq!(fs::read_to_string(&arch_file).unwrap().trim(), "arm64");

    let elf_header = Command::new("readelf")
        .args(["-h"])
        .arg(&built_binary)
        .output()
        .unwrap();
    assert!(
        elf_header.status.success(),
        "{}",
        String::from_utf8_lossy(&elf_header.stderr)
    );
    let elf_header_stdout = String::from_utf8_lossy(&elf_header.stdout);
    assert!(
        elf_header_stdout.contains("Machine:                           AArch64"),
        "{elf_header_stdout}"
    );

    let execute = Command::new(&qemu)
        .arg("-L")
        .arg(&rootfs)
        .arg(&built_binary)
        .output()
        .unwrap();
    assert!(
        execute.status.success(),
        "{}",
        String::from_utf8_lossy(&execute.stderr)
    );
    let stdout = String::from_utf8_lossy(&execute.stdout);
    assert!(stdout.contains("arm64-build-ok"), "{stdout}");
}

#[test]
fn run_exec_form_mutates_workspace_with_env_and_workdir() {
    let temp = tempfile::tempdir().unwrap();
    let project = temp.path();
    let rootfs_context = project.join("rootfs");
    fs::create_dir_all(&rootfs_context).unwrap();

    let runner_source = project.join("runner.c");
    fs::write(
        &runner_source,
        r#"
      #include <stdio.h>
      #include <stdlib.h>
      #include <string.h>
      #include <unistd.h>

      int main(int argc, char **argv)
      {
         if (argc != 2)
         {
            return 2;
         }

         char cwd[4096];
         if (getcwd(cwd, sizeof(cwd)) == NULL)
         {
            return 3;
         }

         FILE *file = fopen(argv[1], "w");
         if (file == NULL)
         {
            return 4;
         }

         const char *mode = getenv("MODE");
         fprintf(file, "%s:%s\n", mode == NULL ? "" : mode, cwd);
         fclose(file);
         return 0;
      }
      "#,
    )
    .unwrap();

    let runner_binary = project.join("runner");
    let compiled = Command::new("clang")
        .arg(&runner_source)
        .arg("-O2")
        .arg("-o")
        .arg(&runner_binary)
        .output()
        .unwrap();
    assert!(
        compiled.status.success(),
        "{}",
        String::from_utf8_lossy(&compiled.stderr)
    );

    copy_host_runtime_closure(&runner_binary, &rootfs_context, Path::new("/tool/runner"));
    assert!(rootfs_context.join("tool/runner").exists());

    let mut file_contents = String::from("FROM scratch for x86_64\n");
    for top_level in ["tool", "lib", "lib64", "usr"] {
        if rootfs_context.join(top_level).exists() {
            file_contents.push_str(&format!("COPY {{root}} ./{top_level} /{top_level}\n"));
        }
    }
    file_contents.push_str("ENV MODE=smoke\n");
    file_contents.push_str("WORKDIR /workspace\n");
    file_contents.push_str("RUN [\"/tool/runner\", \"/workspace/result.txt\"]\n");

    let discombobulator_file = project.join("Run.DiscombobuFile");
    fs::write(&discombobulator_file, file_contents).unwrap();

    let output_blob = project.join("run-base.blob.zst");
    let binary = env!("CARGO_BIN_EXE_discombobulator");
    let build = Command::new(binary)
        .current_dir(project)
        .args([
            "build",
            "--file",
            discombobulator_file.to_str().unwrap(),
            "--context",
            &format!("root={}", rootfs_context.display()),
            "--output",
            output_blob.to_str().unwrap(),
            "--kind",
            "base",
        ])
        .output()
        .unwrap();
    assert!(
        build.status.success(),
        "{}",
        String::from_utf8_lossy(&build.stderr)
    );

    let mounted = MountedBlob::receive(&output_blob);
    assert_eq!(
        fs::read_to_string(mounted.artifact_root().join("workspace/result.txt")).unwrap(),
        "smoke:/workspace\n"
    );
}

#[test]
fn run_execution_does_not_touch_host_network_bpf_runtime_paths() {
    let temp = tempfile::tempdir().unwrap();
    let project = temp.path();
    let rootfs_context = project.join("rootfs");
    let source_context = project.join("srcctx");
    let helper_dir = project.join("helpers");
    fs::create_dir_all(&rootfs_context).unwrap();
    fs::create_dir_all(&source_context).unwrap();
    fs::create_dir_all(&helper_dir).unwrap();

    copy_host_runtime_closure(Path::new("/bin/sh"), &rootfs_context, Path::new("/bin/sh"));
    fs::write(
        source_context.join("runner.sh"),
        "#!/bin/sh\nprintf 'safe\\n' > /workspace/result.txt\n",
    )
    .unwrap();
    fs::set_permissions(
        source_context.join("runner.sh"),
        fs::Permissions::from_mode(0o755),
    )
    .unwrap();

    let real_unshare = host_command_path("unshare");
    let unshare_log = project.join("unshare.log");
    fs::write(
        helper_dir.join("unshare"),
        format!(
            "#!/bin/sh\nprintf '%s\\n' \"$@\" > '{}'\nexec '{}' \"$@\"\n",
            unshare_log.display(),
            real_unshare.display()
        ),
    )
    .unwrap();
    fs::set_permissions(
        helper_dir.join("unshare"),
        fs::Permissions::from_mode(0o755),
    )
    .unwrap();

    for dangerous_tool in ["bpftool", "tc", "xdp-loader", "xdp", "ip"] {
        let sentinel = project.join(format!("invoked-{dangerous_tool}"));
        fs::write(
            helper_dir.join(dangerous_tool),
            format!(
                "#!/bin/sh\nprintf '{}\\n' > '{}'\nexit 97\n",
                dangerous_tool,
                sentinel.display()
            ),
        )
        .unwrap();
        fs::set_permissions(
            helper_dir.join(dangerous_tool),
            fs::Permissions::from_mode(0o755),
        )
        .unwrap();
    }

    let discombobulator_file = project.join("SafetyRun.DiscombobuFile");
    let mut file_contents = String::from("FROM scratch for x86_64\n");
    for top_level in ["bin", "lib", "lib64", "usr"] {
        if rootfs_context.join(top_level).exists() {
            file_contents.push_str(&format!("COPY {{root}} ./{top_level} /{top_level}\n"));
        }
    }
    file_contents.push_str("COPY {src} ./runner.sh /workspace/runner.sh\n");
    file_contents.push_str("WORKDIR /workspace\n");
    file_contents.push_str("RUN [\"/bin/sh\", \"/workspace/runner.sh\"]\n");
    fs::write(&discombobulator_file, file_contents).unwrap();

    let output_blob = project.join("safety-run.blob.zst");
    let binary = env!("CARGO_BIN_EXE_discombobulator");
    let original_path = std::env::var("PATH").unwrap_or_default();
    let build = Command::new(binary)
        .current_dir(project)
        .env("PATH", format!("{}:{original_path}", helper_dir.display()))
        .args([
            "build",
            "--file",
            discombobulator_file.to_str().unwrap(),
            "--context",
            &format!("root={}", rootfs_context.display()),
            "--context",
            &format!("src={}", source_context.display()),
            "--output",
            output_blob.to_str().unwrap(),
            "--kind",
            "base",
        ])
        .output()
        .unwrap();
    assert!(
        build.status.success(),
        "{}",
        String::from_utf8_lossy(&build.stderr)
    );

    let unshare_args = fs::read_to_string(&unshare_log).unwrap();
    assert!(unshare_args.contains("--fork"));
    assert!(unshare_args.contains("--pid"));
    assert!(unshare_args.contains("--mount"));
    assert!(unshare_args.contains("--uts"));
    assert!(unshare_args.contains("--ipc"));
    assert!(!unshare_args.contains("--net"), "{unshare_args}");

    for dangerous_tool in ["bpftool", "tc", "xdp-loader", "xdp", "ip"] {
        assert!(
            !project.join(format!("invoked-{dangerous_tool}")).exists(),
            "unexpected host-network/BPF tool invocation: {dangerous_tool}"
        );
    }

    let mounted = MountedBlob::receive(&output_blob);
    assert_eq!(
        fs::read_to_string(mounted.artifact_root().join("workspace/result.txt")).unwrap(),
        "safe\n"
    );
}

#[test]
fn run_missing_executable_fails_clearly() {
    let temp = tempfile::tempdir().unwrap();
    let project = temp.path();
    let discombobulator_file = project.join("MissingRun.DiscombobuFile");
    fs::write(
        &discombobulator_file,
        r#"
      FROM scratch for x86_64
      RUN ["/does-not-exist"]
      "#,
    )
    .unwrap();

    let output_blob = project.join("missing-run.blob.zst");
    let binary = env!("CARGO_BIN_EXE_discombobulator");
    let build = Command::new(binary)
        .current_dir(project)
        .args([
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
    let stderr = String::from_utf8_lossy(&build.stderr);
    assert!(stderr.contains("RUN executable /does-not-exist was not found in build root"));
}

#[test]
fn copy_requires_declared_named_context() {
    let temp = tempfile::tempdir().unwrap();
    let project = temp.path();
    let discombobulator_file = project.join("MissingContext.DiscombobuFile");
    fs::write(
        &discombobulator_file,
        r#"
      FROM scratch for x86_64
      COPY {src} ./hello /app/hello
      "#,
    )
    .unwrap();

    let output_blob = project.join("missing-context.blob.zst");
    let stderr =
        build_failure_with_contexts(project, &discombobulator_file, &output_blob, "base", &[]);
    assert!(stderr.contains("undefined context src"), "{stderr}");
}

#[test]
fn copy_wildcards_skip_hidden_entries_and_preserve_metadata() {
    let temp = tempfile::tempdir().unwrap();
    let project = temp.path();
    let source_context = project.join("srcctx");
    fs::create_dir_all(source_context.join("config")).unwrap();

    let visible = source_context.join("visible.sh");
    fs::write(&visible, "#!/bin/sh\nexit 0\n").unwrap();
    fs::set_permissions(&visible, fs::Permissions::from_mode(0o755)).unwrap();

    let hidden = source_context.join(".hidden.sh");
    fs::write(&hidden, "secret\n").unwrap();
    fs::set_permissions(&hidden, fs::Permissions::from_mode(0o700)).unwrap();

    let config_dir = source_context.join("config");
    fs::set_permissions(&config_dir, fs::Permissions::from_mode(0o750)).unwrap();
    let config_file = config_dir.join("settings.txt");
    fs::write(&config_file, "mode=dev\n").unwrap();
    fs::set_permissions(&config_file, fs::Permissions::from_mode(0o640)).unwrap();

    std::os::unix::fs::symlink("visible.sh", source_context.join("current")).unwrap();

    let discombobulator_file = project.join("WildcardCopy.DiscombobuFile");
    fs::write(
        &discombobulator_file,
        r#"
      FROM scratch for x86_64
      COPY {src} ./* /bundle/
      "#,
    )
    .unwrap();

    let output_blob = project.join("wildcard-copy.blob.zst");
    build_blob_with_contexts(
        project,
        &discombobulator_file,
        &output_blob,
        "base",
        &[format!("src={}", source_context.display())],
    );

    let mounted = MountedBlob::receive(&output_blob);
    let bundle_root = mounted.artifact_root().join("bundle");
    let visible_meta = fs::symlink_metadata(bundle_root.join("visible.sh")).unwrap();
    assert_eq!(visible_meta.permissions().mode() & 0o777, 0o755);
    assert_eq!(visible_meta.uid(), 0);
    assert_eq!(visible_meta.gid(), 0);
    assert!(!bundle_root.join(".hidden.sh").exists());

    let config_meta = fs::symlink_metadata(bundle_root.join("config")).unwrap();
    assert!(config_meta.is_dir());
    assert_eq!(config_meta.permissions().mode() & 0o777, 0o750);
    assert_eq!(config_meta.uid(), 0);
    assert_eq!(config_meta.gid(), 0);

    let config_file_meta = fs::symlink_metadata(bundle_root.join("config/settings.txt")).unwrap();
    assert_eq!(config_file_meta.permissions().mode() & 0o777, 0o640);
    assert_eq!(config_file_meta.uid(), 0);
    assert_eq!(config_file_meta.gid(), 0);

    assert_eq!(
        fs::read_link(bundle_root.join("current")).unwrap(),
        PathBuf::from("visible.sh")
    );
}

#[test]
fn copy_wildcard_order_is_deterministic_for_conflicting_matches() {
    let temp = tempfile::tempdir().unwrap();
    let project = temp.path();
    let source_context = project.join("srcctx");
    fs::create_dir_all(source_context.join("a")).unwrap();
    fs::create_dir_all(source_context.join("b")).unwrap();
    fs::write(source_context.join("a/data.txt"), "from-a\n").unwrap();
    fs::write(source_context.join("b/data.txt"), "from-b\n").unwrap();

    let discombobulator_file = project.join("WildcardOrder.DiscombobuFile");
    fs::write(
        &discombobulator_file,
        r#"
      FROM scratch for x86_64
      COPY {src} ./*/data.txt /bundle/
      "#,
    )
    .unwrap();

    let output_blob = project.join("wildcard-order.blob.zst");
    build_blob_with_contexts(
        project,
        &discombobulator_file,
        &output_blob,
        "base",
        &[format!("src={}", source_context.display())],
    );

    let mounted = MountedBlob::receive(&output_blob);
    assert_eq!(
        fs::read_to_string(mounted.artifact_root().join("bundle/data.txt")).unwrap(),
        "from-b\n"
    );
}

#[test]
fn copy_rejects_symlink_escapes_from_wildcards() {
    let temp = tempfile::tempdir().unwrap();
    let project = temp.path();
    let source_context = project.join("srcctx");
    fs::create_dir_all(&source_context).unwrap();
    let outside = project.join("outside.txt");
    fs::write(&outside, "leak\n").unwrap();
    std::os::unix::fs::symlink("../outside.txt", source_context.join("leak")).unwrap();

    let discombobulator_file = project.join("SymlinkEscape.DiscombobuFile");
    fs::write(
        &discombobulator_file,
        r#"
      FROM scratch for x86_64
      COPY {src} ./* /bundle/
      "#,
    )
    .unwrap();

    let output_blob = project.join("symlink-escape.blob.zst");
    let stderr = build_failure_with_contexts(
        project,
        &discombobulator_file,
        &output_blob,
        "base",
        &[format!("src={}", source_context.display())],
    );
    assert!(
        stderr.contains("COPY symlink escapes the named context root"),
        "{stderr}"
    );
}

#[test]
fn copy_rejects_fifo_socket_and_device_nodes() {
    let temp = tempfile::tempdir().unwrap();
    let project = temp.path();
    let binary = env!("CARGO_BIN_EXE_discombobulator");

    for (name, source_path, expected) in [
        ("fifo", "pipe", "COPY rejects special files"),
        ("socket", "sock", "COPY rejects sockets"),
        ("device", "char-device", "COPY rejects special files"),
    ] {
        let source_context = project.join(format!("{name}-ctx"));
        fs::create_dir_all(&source_context).unwrap();

        match name {
            "fifo" => {
                let status = Command::new("mkfifo")
                    .arg(source_context.join(source_path))
                    .status()
                    .unwrap();
                assert!(status.success());
            }
            "socket" => {
                let _listener = UnixListener::bind(source_context.join(source_path)).unwrap();
                let output_blob = project.join(format!("{name}.blob.zst"));
                let file = project.join(format!("{name}.DiscombobuFile"));
                fs::write(
                    &file,
                    format!(
                        "FROM scratch for x86_64\nCOPY {{src}} ./{source_path} /bundle/{source_path}\n"
                    ),
                )
                .unwrap();
                let build = Command::new(binary)
                    .current_dir(project)
                    .args([
                        "build",
                        "--file",
                        file.to_str().unwrap(),
                        "--context",
                        &format!("src={}", source_context.display()),
                        "--output",
                        output_blob.to_str().unwrap(),
                        "--kind",
                        "base",
                    ])
                    .output()
                    .unwrap();
                assert!(!build.status.success());
                let stderr = String::from_utf8_lossy(&build.stderr);
                assert!(stderr.contains(expected), "{stderr}");
                continue;
            }
            "device" => {
                let status = Command::new("mknod")
                    .args([
                        source_context.join(source_path).to_str().unwrap(),
                        "c",
                        "1",
                        "3",
                    ])
                    .status()
                    .unwrap();
                assert!(status.success());
            }
            _ => unreachable!(),
        }

        let discombobulator_file = project.join(format!("{name}.DiscombobuFile"));
        fs::write(
            &discombobulator_file,
            format!(
                "FROM scratch for x86_64\nCOPY {{src}} ./{source_path} /bundle/{source_path}\n"
            ),
        )
        .unwrap();
        let output_blob = project.join(format!("{name}.blob.zst"));
        let stderr = build_failure_with_contexts(
            project,
            &discombobulator_file,
            &output_blob,
            "base",
            &[format!("src={}", source_context.display())],
        );
        assert!(stderr.contains(expected), "{stderr}");
    }
}

#[test]
fn late_step_change_reuses_cached_earlier_run_and_invalidates_downstream() {
    let temp = tempfile::tempdir().unwrap();
    let project = temp.path();
    let rootfs_context = project.join("rootfs");
    let source_context = project.join("srcctx");
    fs::create_dir_all(&rootfs_context).unwrap();
    fs::create_dir_all(&source_context).unwrap();

    let runner_source = project.join("cache_runner.c");
    fs::write(
        &runner_source,
        r#"
      #include <stdio.h>
      #include <stdlib.h>
      #include <string.h>
      #include <time.h>

      static int read_trimmed(const char *path, char *buffer, size_t size)
      {
         FILE *file = fopen(path, "r");
         if (file == NULL)
         {
            return 1;
         }

         size_t count = fread(buffer, 1, size - 1, file);
         fclose(file);
         buffer[count] = '\0';
         while (count > 0 && (buffer[count - 1] == '\n' || buffer[count - 1] == '\r'))
         {
            buffer[--count] = '\0';
         }
         return 0;
      }

      int main(int argc, char **argv)
      {
         if (argc >= 2 && strcmp(argv[1], "stamp") == 0)
         {
            if (argc != 3)
            {
               return 2;
            }

            struct timespec now;
            if (clock_gettime(CLOCK_REALTIME, &now) != 0)
            {
               return 3;
            }

            FILE *file = fopen(argv[2], "w");
            if (file == NULL)
            {
               return 4;
            }

            fprintf(file, "%lld", ((long long) now.tv_sec * 1000000000LL) + now.tv_nsec);
            fclose(file);
            return 0;
         }

         if (argc >= 2 && strcmp(argv[1], "compose") == 0)
         {
            if (argc != 5)
            {
               return 5;
            }

            char early[256];
            char message[256];
            if (read_trimmed(argv[2], early, sizeof(early)) != 0)
            {
               return 6;
            }
            if (read_trimmed(argv[3], message, sizeof(message)) != 0)
            {
               return 7;
            }

            FILE *file = fopen(argv[4], "w");
            if (file == NULL)
            {
               return 8;
            }

            fprintf(file, "%s|%s", early, message);
            fclose(file);
            return 0;
         }

         return 9;
      }
      "#,
    )
    .unwrap();

    let runner_binary = project.join("cache-runner");
    let compiled = Command::new("clang")
        .arg(&runner_source)
        .arg("-O2")
        .arg("-o")
        .arg(&runner_binary)
        .output()
        .unwrap();
    assert!(
        compiled.status.success(),
        "{}",
        String::from_utf8_lossy(&compiled.stderr)
    );

    copy_host_runtime_closure(&runner_binary, &rootfs_context, Path::new("/tool/runner"));
    fs::write(source_context.join("message.txt"), "one").unwrap();

    let mut file_contents = String::from("FROM scratch for x86_64\n");
    for top_level in ["tool", "lib", "lib64", "usr"] {
        if rootfs_context.join(top_level).exists() {
            file_contents.push_str(&format!("COPY {{root}} ./{top_level} /{top_level}\n"));
        }
    }
    file_contents.push_str("WORKDIR /workspace\n");
    file_contents.push_str("RUN [\"/tool/runner\", \"stamp\", \"/workspace/early.txt\"]\n");
    file_contents.push_str("COPY {src} ./message.txt /workspace/message.txt\n");
    file_contents.push_str(
        "RUN [\"/tool/runner\", \"compose\", \"/workspace/early.txt\", \"/workspace/message.txt\", \"/workspace/final.txt\"]\n",
    );

    let discombobulator_file = project.join("CachedSteps.DiscombobuFile");
    fs::write(&discombobulator_file, file_contents).unwrap();

    let first_blob = project.join("cache-first.blob.zst");
    build_blob_with_contexts(
        project,
        &discombobulator_file,
        &first_blob,
        "base",
        &[
            format!("root={}", rootfs_context.display()),
            format!("src={}", source_context.display()),
        ],
    );
    let first_mount = MountedBlob::receive(&first_blob);
    let early_first =
        fs::read_to_string(first_mount.artifact_root().join("workspace/early.txt")).unwrap();
    let final_first =
        fs::read_to_string(first_mount.artifact_root().join("workspace/final.txt")).unwrap();
    assert_eq!(final_first, format!("{early_first}|one"));

    thread::sleep(Duration::from_millis(20));
    fs::write(source_context.join("message.txt"), "two").unwrap();

    let second_blob = project.join("cache-second.blob.zst");
    build_blob_with_contexts(
        project,
        &discombobulator_file,
        &second_blob,
        "base",
        &[
            format!("root={}", rootfs_context.display()),
            format!("src={}", source_context.display()),
        ],
    );
    let second_mount = MountedBlob::receive(&second_blob);
    let early_second =
        fs::read_to_string(second_mount.artifact_root().join("workspace/early.txt")).unwrap();
    let final_second =
        fs::read_to_string(second_mount.artifact_root().join("workspace/final.txt")).unwrap();
    assert_eq!(early_second, early_first);
    assert_eq!(final_second, format!("{early_first}|two"));

    let step_cache_root = project.join(".discombobulator/cache/steps/x86_64");
    assert!(step_cache_root.exists());
    assert!(
        fs::read_dir(&step_cache_root).unwrap().count() >= 4,
        "expected populated step cache under {}",
        step_cache_root.display()
    );
}

#[test]
fn warm_and_late_step_rebuilds_are_materially_faster_than_cold_builds() {
    let temp = tempfile::tempdir().unwrap();
    let project = temp.path();
    let rootfs_context = project.join("rootfs");
    let source_context = project.join("srcctx");
    fs::create_dir_all(&rootfs_context).unwrap();
    fs::create_dir_all(&source_context).unwrap();

    let runner_source = project.join("benchmark_runner.c");
    fs::write(
        &runner_source,
        r#"
      #include <stdio.h>
      #include <stdlib.h>
      #include <string.h>
      #include <time.h>

      static int read_trimmed(const char *path, char *buffer, size_t size)
      {
         FILE *file = fopen(path, "r");
         if (file == NULL)
         {
            return 1;
         }

         size_t count = fread(buffer, 1, size - 1, file);
         fclose(file);
         buffer[count] = '\0';
         while (count > 0 && (buffer[count - 1] == '\n' || buffer[count - 1] == '\r'))
         {
            buffer[--count] = '\0';
         }
         return 0;
      }

      static void sleep_millis(const char *raw)
      {
         struct timespec request;
         request.tv_sec = atoi(raw) / 1000;
         request.tv_nsec = (long) (atoi(raw) % 1000) * 1000000L;
         nanosleep(&request, NULL);
      }

      int main(int argc, char **argv)
      {
         if (argc >= 2 && strcmp(argv[1], "stamp") == 0)
         {
            if (argc != 4)
            {
               return 2;
            }

            sleep_millis(argv[3]);
            FILE *file = fopen(argv[2], "w");
            if (file == NULL)
            {
               return 3;
            }

            fprintf(file, "stamp");
            fclose(file);
            return 0;
         }

         if (argc >= 2 && strcmp(argv[1], "compose") == 0)
         {
            if (argc != 6)
            {
               return 4;
            }

            sleep_millis(argv[5]);

            char early[256];
            char message[256];
            if (read_trimmed(argv[2], early, sizeof(early)) != 0)
            {
               return 5;
            }
            if (read_trimmed(argv[3], message, sizeof(message)) != 0)
            {
               return 6;
            }

            FILE *file = fopen(argv[4], "w");
            if (file == NULL)
            {
               return 7;
            }

            fprintf(file, "%s|%s", early, message);
            fclose(file);
            return 0;
         }

         return 8;
      }
      "#,
    )
    .unwrap();

    let runner_binary = project.join("benchmark-runner");
    let compiled = Command::new("clang")
        .arg(&runner_source)
        .arg("-O2")
        .arg("-o")
        .arg(&runner_binary)
        .output()
        .unwrap();
    assert!(
        compiled.status.success(),
        "{}",
        String::from_utf8_lossy(&compiled.stderr)
    );

    copy_host_runtime_closure(&runner_binary, &rootfs_context, Path::new("/tool/runner"));
    fs::write(source_context.join("message.txt"), "one").unwrap();

    let mut file_contents = String::from("FROM scratch for x86_64\n");
    for top_level in ["tool", "lib", "lib64", "usr"] {
        if rootfs_context.join(top_level).exists() {
            file_contents.push_str(&format!("COPY {{root}} ./{top_level} /{top_level}\n"));
        }
    }
    file_contents.push_str("WORKDIR /workspace\n");
    file_contents
        .push_str("RUN [\"/tool/runner\", \"stamp\", \"/workspace/early.txt\", \"250\"]\n");
    file_contents.push_str("COPY {src} ./message.txt /workspace/message.txt\n");
    file_contents.push_str(
        "RUN [\"/tool/runner\", \"compose\", \"/workspace/early.txt\", \"/workspace/message.txt\", \"/workspace/final.txt\", \"250\"]\n",
    );

    let discombobulator_file = project.join("BenchmarkCachedSteps.DiscombobuFile");
    fs::write(&discombobulator_file, file_contents).unwrap();

    let contexts = [
        format!("root={}", rootfs_context.display()),
        format!("src={}", source_context.display()),
    ];

    let cold_blob = project.join("benchmark-cold.blob.zst");
    let cold = timed_build_blob_with_contexts(
        project,
        &discombobulator_file,
        &cold_blob,
        "base",
        &contexts,
    );

    let warm_blob = project.join("benchmark-warm.blob.zst");
    let warm = timed_build_blob_with_contexts(
        project,
        &discombobulator_file,
        &warm_blob,
        "base",
        &contexts,
    );

    fs::write(source_context.join("message.txt"), "two").unwrap();
    let late_blob = project.join("benchmark-late.blob.zst");
    let late = timed_build_blob_with_contexts(
        project,
        &discombobulator_file,
        &late_blob,
        "base",
        &contexts,
    );

    let cold_ms = cold.as_millis();
    let warm_ms = warm.as_millis();
    let late_ms = late.as_millis();
    println!(
        "benchmark cached steps cold={}ms warm={}ms late={}ms",
        cold_ms, warm_ms, late_ms
    );
    assert!(
        cold_ms >= 450,
        "cold build too small to be meaningful: {cold_ms}ms"
    );
    assert!(
        warm_ms * 4 < cold_ms,
        "expected warm build to be materially faster than cold build; cold={cold_ms}ms warm={warm_ms}ms"
    );
    assert!(
        late_ms * 4 < cold_ms * 3,
        "expected late-step rebuild to be materially faster than cold build; cold={cold_ms}ms late={late_ms}ms"
    );
    assert!(
        warm_ms < late_ms,
        "expected warm build to be faster than late-step rebuild; warm={warm_ms}ms late={late_ms}ms"
    );

    let mounted = MountedBlob::receive(&late_blob);
    assert_eq!(
        fs::read_to_string(mounted.artifact_root().join("workspace/final.txt")).unwrap(),
        "stamp|two"
    );
}

#[test]
fn cached_artifact_export_reuse_is_materially_faster_than_cold_export() {
    let temp = tempfile::tempdir().unwrap();
    let project = temp.path();
    let source_context = project.join("srcctx");
    fs::create_dir_all(&source_context).unwrap();
    fs::write(
        source_context.join("payload.bin"),
        vec![0u8; 32 * 1024 * 1024],
    )
    .unwrap();

    let discombobulator_file = project.join("BenchmarkExport.DiscombobuFile");
    fs::write(
        &discombobulator_file,
        r#"
      FROM scratch for x86_64
      COPY {src} ./payload.bin /bundle/payload.bin
      "#,
    )
    .unwrap();

    let contexts = [format!("src={}", source_context.display())];

    let cold_blob = project.join("export-cold.blob.zst");
    let cold = timed_build_blob_with_contexts(
        project,
        &discombobulator_file,
        &cold_blob,
        "base",
        &contexts,
    );

    let warm_blob = project.join("export-warm.blob.zst");
    let warm = timed_build_blob_with_contexts(
        project,
        &discombobulator_file,
        &warm_blob,
        "base",
        &contexts,
    );

    let cold_ms = cold.as_millis();
    let warm_ms = warm.as_millis();
    println!("benchmark export cold={}ms warm={}ms", cold_ms, warm_ms);
    assert!(
        warm_ms * 4 < cold_ms * 3,
        "expected cached export reuse to be materially faster than cold export; cold={cold_ms}ms warm={warm_ms}ms"
    );
}

#[test]
fn language_matrix_examples_build_and_launch_with_remote_sleeve_and_local_base_reuse() {
    let temp = tempfile::tempdir().unwrap();
    let project = temp.path();
    let arch = current_build_architecture();
    let oci_arch = current_oci_architecture();
    let binary = env!("CARGO_BIN_EXE_discombobulator");
    let shell_target = fs::read_link("/bin/sh")
        .map(|target| {
            if target.is_absolute() {
                target
            } else {
                Path::new("/bin").join(target)
            }
        })
        .unwrap_or_else(|_| PathBuf::from("/bin/sh"));

    let tools_rootfs = project.join("tools-rootfs");
    fs::create_dir_all(&tools_rootfs).unwrap();
    copy_host_runtime_closure(Path::new("/bin/sh"), &tools_rootfs, Path::new("/bin/sh"));

    let python_binary = host_python_binary();
    let python_stdlib = host_python_stdlib();
    copy_host_runtime_closure(&python_binary, &tools_rootfs, &python_binary);
    copy_tree_into_context(&python_stdlib, &tools_rootfs, &python_stdlib);

    let node_binary = host_command_path("node");
    copy_host_runtime_closure(&node_binary, &tools_rootfs, &node_binary);

    let registry = FakeRegistry::with_versions(BTreeMap::from([(
        1usize,
        build_registry_image_from_rootfs(&tools_rootfs, oci_arch),
    )]));

    let add_remote = Command::new(binary)
        .current_dir(project)
        .args(["remote", "add", "fixture", &registry.host()])
        .output()
        .unwrap();
    assert!(
        add_remote.status.success(),
        "{}",
        String::from_utf8_lossy(&add_remote.stderr)
    );

    let base_file = project.join("ExampleTools.DiscombobuFile");
    fs::write(
        &base_file,
        format!("FROM remote fixture sample:latest for {arch}\n"),
    )
    .unwrap();
    let base_blob = project.join("example-tools.blob.zst");
    let base_build = Command::new(binary)
        .current_dir(project)
        .args([
            "build",
            "--file",
            base_file.to_str().unwrap(),
            "--output",
            base_blob.to_str().unwrap(),
            "--kind",
            "base",
            "--publish-base",
            "example-tools:latest",
        ])
        .output()
        .unwrap();
    assert!(
        base_build.status.success(),
        "{}",
        String::from_utf8_lossy(&base_build.stderr)
    );

    let remote_requests_after_base = registry.request_count();
    assert!(
        remote_requests_after_base >= 3,
        "expected one remote OCI import, saw {remote_requests_after_base} requests"
    );
    assert_eq!(count_cached_import_roots(project, arch), 1);
    let connection = open_registry(project);
    let tools_base = query_named_artifact(&connection, "base", "example-tools", "latest", arch);
    assert!(Path::new(&tools_base.path).exists());

    let helper_source = project.join("language_helper.c");
    fs::write(
        &helper_source,
        r#"
      #include <stdio.h>

      int main(int argc, char **argv)
      {
         if (argc != 2)
         {
            return 2;
         }

         printf("helper-%s\n", argv[1]);
         return 0;
      }
      "#,
    )
    .unwrap();
    let helper_binary = project.join("language-helper");
    let helper_compile = Command::new("clang")
        .arg(&helper_source)
        .arg("-O2")
        .arg("-o")
        .arg(&helper_binary)
        .output()
        .unwrap();
    assert!(
        helper_compile.status.success(),
        "{}",
        String::from_utf8_lossy(&helper_compile.stderr)
    );

    let cpp_context = project.join("cppctx");
    fs::create_dir_all(cpp_context.join("bin")).unwrap();
    fs::create_dir_all(cpp_context.join("config")).unwrap();
    fs::create_dir_all(cpp_context.join("data")).unwrap();
    fs::create_dir_all(cpp_context.join("generated")).unwrap();
    fs::write(cpp_context.join("config/app.conf"), "mode=signal\n").unwrap();
    fs::write(cpp_context.join("data/payload.txt"), "nebula\n").unwrap();
    fs::copy(&helper_binary, cpp_context.join("bin/helper")).unwrap();
    fs::set_permissions(
        cpp_context.join("bin/helper"),
        fs::Permissions::from_mode(0o755),
    )
    .unwrap();
    fs::write(
        cpp_context.join("bin/prepare.sh"),
        "#!/bin/sh\nprintf 'prepared-cpp\\n' > /app/generated/note.txt\n",
    )
    .unwrap();
    fs::set_permissions(
        cpp_context.join("bin/prepare.sh"),
        fs::Permissions::from_mode(0o755),
    )
    .unwrap();
    let cpp_source = cpp_context.join("cpp_app.cpp");
    fs::write(
        &cpp_source,
        r#"
      #include <cmath>
      #include <cstdio>
      #include <cstdlib>
      #include <fstream>
      #include <iostream>
      #include <string>

      static std::string read_trimmed(const char *path)
      {
         std::ifstream file(path);
         std::string value;
         std::getline(file, value);
         return value;
      }

      int main()
      {
         std::string config = read_trimmed("/app/config/app.conf");
         std::string payload = read_trimmed("/app/data/payload.txt");
         std::string note = read_trimmed("/app/generated/note.txt");
         FILE *helper = popen("/app/bin/helper cpp", "r");
         if (helper == NULL)
         {
            return 2;
         }

         char helper_buffer[128] = {};
         if (fgets(helper_buffer, sizeof(helper_buffer), helper) == NULL)
         {
            pclose(helper);
            return 3;
         }
         pclose(helper);

         std::string helper_text(helper_buffer);
         if (helper_text.empty() == false && helper_text.back() == '\n')
         {
            helper_text.pop_back();
         }

         long cosine = lround(std::cos(0.25) * 1000.0);
         std::cout << "cpp:" << config.substr(5) << ":" << payload << ":" << note << ":"
                   << helper_text << ":" << cosine << "\n";
         return 0;
      }
      "#,
    )
    .unwrap();
    let cpp_binary = cpp_context.join("bin/cpp-app");
    let cpp_compile = Command::new("clang++")
        .arg("-std=c++23")
        .arg("-O2")
        .arg(&cpp_source)
        .arg("-o")
        .arg(&cpp_binary)
        .output()
        .unwrap();
    assert!(
        cpp_compile.status.success(),
        "{}",
        String::from_utf8_lossy(&cpp_compile.stderr)
    );
    let cpp_file = project.join("CppExample.DiscombobuFile");
    fs::write(
        &cpp_file,
        format!(
            "\
FROM example-tools:latest for {arch}
COPY {{src}} ./bin /app/bin
COPY {{src}} ./config /app/config
COPY {{src}} ./data /app/data
COPY {{src}} ./generated /app/generated
WORKDIR /app
RUN [\"/bin/sh\", \"/app/bin/prepare.sh\"]
SURVIVE /bin/sh
SURVIVE {}
SURVIVE /app/bin/*
SURVIVE /app/config/*
SURVIVE /app/data/*
SURVIVE /app/generated/*
EXECUTE [\"/app/bin/cpp-app\"]
",
            shell_target.display()
        ),
    )
    .unwrap();
    let cpp_blob = project.join("cpp-example.blob.zst");
    build_blob_with_contexts(
        project,
        &cpp_file,
        &cpp_blob,
        "app",
        &[format!("src={}", cpp_context.display())],
    );
    let cpp_mount = MountedBlob::receive(&cpp_blob);
    assert!(cpp_mount
        .artifact_root()
        .join("rootfs/app/bin/helper")
        .exists());
    assert!(cpp_mount
        .artifact_root()
        .join("rootfs/app/generated/note.txt")
        .exists());
    let cpp_output = launch_app_artifact(&cpp_mount);
    assert_eq!(
        String::from_utf8_lossy(&cpp_output.stdout).trim(),
        "cpp:signal:nebula:prepared-cpp:helper-cpp:969"
    );

    let rust_context = project.join("rustctx");
    fs::create_dir_all(rust_context.join("src")).unwrap();
    fs::create_dir_all(rust_context.join("bin")).unwrap();
    fs::create_dir_all(rust_context.join("config")).unwrap();
    fs::create_dir_all(rust_context.join("data")).unwrap();
    fs::create_dir_all(rust_context.join("generated")).unwrap();
    fs::write(
        rust_context.join("Cargo.toml"),
        r#"
[package]
name = "matrix-rust-app"
version = "0.1.0"
edition = "2021"

[dependencies]
serde_json = "1.0"
        "#,
    )
    .unwrap();
    fs::write(
        rust_context.join("src/main.rs"),
        r#"
use std::fs;

fn main() {
   let config = fs::read_to_string("/app/config/config.json").unwrap();
   let value: serde_json::Value = serde_json::from_str(&config).unwrap();
   let mode = value["mode"].as_str().unwrap();
   let asset = fs::read_to_string("/app/data/asset.txt").unwrap();
   let note = fs::read_to_string("/app/generated/note.txt").unwrap();
   print!("rust:{}:{}:{}", mode, asset.trim(), note.trim());
}
        "#,
    )
    .unwrap();
    fs::write(
        rust_context.join("config/config.json"),
        "{\"mode\":\"orion\"}\n",
    )
    .unwrap();
    fs::write(rust_context.join("data/asset.txt"), "comet\n").unwrap();
    fs::write(
        rust_context.join("bin/prepare.sh"),
        "#!/bin/sh\nprintf 'prepared-rust\\n' > /app/generated/note.txt\n",
    )
    .unwrap();
    fs::set_permissions(
        rust_context.join("bin/prepare.sh"),
        fs::Permissions::from_mode(0o755),
    )
    .unwrap();
    let rust_build = Command::new("cargo")
        .current_dir(&rust_context)
        .args(["build", "--release", "--offline"])
        .output()
        .unwrap();
    assert!(
        rust_build.status.success(),
        "{}",
        String::from_utf8_lossy(&rust_build.stderr)
    );
    fs::copy(
        rust_context.join("target/release/matrix-rust-app"),
        rust_context.join("bin/rust-app"),
    )
    .unwrap();
    fs::set_permissions(
        rust_context.join("bin/rust-app"),
        fs::Permissions::from_mode(0o755),
    )
    .unwrap();
    let rust_file = project.join("RustExample.DiscombobuFile");
    fs::write(
        &rust_file,
        format!(
            "\
FROM example-tools:latest for {arch}
COPY {{src}} ./bin /app/bin
COPY {{src}} ./config /app/config
COPY {{src}} ./data /app/data
COPY {{src}} ./generated /app/generated
WORKDIR /app
RUN [\"/bin/sh\", \"/app/bin/prepare.sh\"]
SURVIVE /bin/sh
SURVIVE {}
SURVIVE /app/bin/*
SURVIVE /app/config/*
SURVIVE /app/data/*
SURVIVE /app/generated/*
EXECUTE [\"/app/bin/rust-app\"]
",
            shell_target.display()
        ),
    )
    .unwrap();
    let rust_blob = project.join("rust-example.blob.zst");
    build_blob_with_contexts(
        project,
        &rust_file,
        &rust_blob,
        "app",
        &[format!("src={}", rust_context.display())],
    );
    let rust_mount = MountedBlob::receive(&rust_blob);
    assert!(rust_mount
        .artifact_root()
        .join("rootfs/app/bin/rust-app")
        .exists());
    let rust_output = launch_app_artifact(&rust_mount);
    assert_eq!(
        String::from_utf8_lossy(&rust_output.stdout).trim(),
        "rust:orion:comet:prepared-rust"
    );

    let python_context = project.join("pythonctx");
    fs::create_dir_all(python_context.join("bin")).unwrap();
    fs::create_dir_all(python_context.join("config")).unwrap();
    fs::create_dir_all(python_context.join("data")).unwrap();
    fs::create_dir_all(python_context.join("vendor")).unwrap();
    fs::create_dir_all(python_context.join("generated")).unwrap();
    let packaging_root = host_python_module_root("packaging");
    copy_tree_into_context(
        &packaging_root,
        &python_context,
        Path::new("/vendor/packaging"),
    );
    fs::write(
        python_context.join("main.py"),
        r#"
import json
import subprocess
from pathlib import Path
from packaging.version import Version

config = json.loads(Path("/app/config/config.json").read_text())
asset = Path("/app/data/message.txt").read_text().strip()
note = Path("/app/generated/note.txt").read_text().strip()
helper = subprocess.check_output(["/app/bin/helper", "python"], text=True).strip()
print(f"python:{config['mode']}:{asset}:{note}:{helper}:{Version('1.2.3').major}")
        "#,
    )
    .unwrap();
    fs::write(
        python_context.join("bin/prepare.py"),
        r#"
from pathlib import Path

generated = Path("/app/generated")
(generated / "note.txt").write_text("prepared-python\n")
        "#,
    )
    .unwrap();
    fs::write(
        python_context.join("bin/helper"),
        "#!/bin/sh\nprintf 'helper-python\\n'\n",
    )
    .unwrap();
    fs::set_permissions(
        python_context.join("bin/helper"),
        fs::Permissions::from_mode(0o755),
    )
    .unwrap();
    fs::write(
        python_context.join("config/config.json"),
        "{\"mode\":\"aurora\"}\n",
    )
    .unwrap();
    fs::write(python_context.join("data/message.txt"), "meteor\n").unwrap();
    let python_runtime_survivor = python_stdlib.display().to_string();
    let python_file = project.join("PythonExample.DiscombobuFile");
    fs::write(
        &python_file,
        format!(
            "\
FROM example-tools:latest for {arch}
COPY {{src}} ./bin /app/bin
COPY {{src}} ./config /app/config
COPY {{src}} ./data /app/data
COPY {{src}} ./vendor /app/vendor
COPY {{src}} ./generated /app/generated
COPY {{src}} ./main.py /app/main.py
ENV PYTHONHOME=/usr
ENV PYTHONPATH=/app/vendor
WORKDIR /app
RUN [\"{}\", \"/app/bin/prepare.py\"]
SURVIVE /bin/sh
SURVIVE {}
SURVIVE {}
SURVIVE {}
SURVIVE /app/bin/*
SURVIVE /app/config/*
SURVIVE /app/data/*
SURVIVE /app/generated/*
SURVIVE /app/vendor/*
SURVIVE /app/main.py
EXECUTE [\"{}\", \"/app/main.py\"]
",
            python_binary.display(),
            shell_target.display(),
            python_binary.display(),
            python_runtime_survivor,
            python_binary.display()
        ),
    )
    .unwrap();
    let python_blob = project.join("python-example.blob.zst");
    build_blob_with_contexts(
        project,
        &python_file,
        &python_blob,
        "app",
        &[format!("src={}", python_context.display())],
    );
    let python_mount = MountedBlob::receive(&python_blob);
    assert!(python_mount
        .artifact_root()
        .join("rootfs")
        .join(python_stdlib.strip_prefix("/").unwrap())
        .exists());
    assert!(python_mount
        .artifact_root()
        .join("rootfs/usr/lib/python3.14/encodings/__init__.py")
        .exists());
    assert!(python_mount
        .artifact_root()
        .join("rootfs/app/vendor/packaging")
        .exists());
    let python_output = launch_app_artifact(&python_mount);
    assert_eq!(
        String::from_utf8_lossy(&python_output.stdout).trim(),
        "python:aurora:meteor:prepared-python:helper-python:1"
    );

    let typescript_context = project.join("typescriptctx");
    fs::create_dir_all(typescript_context.join("src")).unwrap();
    fs::create_dir_all(typescript_context.join("bin")).unwrap();
    fs::create_dir_all(typescript_context.join("config")).unwrap();
    fs::create_dir_all(typescript_context.join("data")).unwrap();
    fs::create_dir_all(typescript_context.join("generated")).unwrap();
    let packed_sdk = typescript_context.join("prodigy-neuron-hub.tgz");
    create_local_npm_package_tarball(
        Path::new("/root/prodigy/prodigy/sdk/typescript"),
        &packed_sdk,
    );
    fs::write(
        typescript_context.join("package.json"),
        format!(
            r#"{{
  "name": "matrix-typescript-app",
  "version": "0.1.0",
  "type": "module",
  "dependencies": {{
    "@nametag/prodigy-neuron-hub": "file:./{}"
  }}
}}"#,
            packed_sdk.file_name().unwrap().to_string_lossy()
        ),
    )
    .unwrap();
    let npm_install = Command::new("npm")
        .current_dir(&typescript_context)
        .args(["install", "--no-package-lock", "--ignore-scripts"])
        .output()
        .unwrap();
    assert!(
        npm_install.status.success(),
        "{}",
        String::from_utf8_lossy(&npm_install.stderr)
    );
    fs::write(
        typescript_context.join("src/main.ts"),
        r#"
import fs from 'node:fs';
import { execFileSync } from 'node:child_process';
import { FrameDecoder } from '@nametag/prodigy-neuron-hub';

const config = JSON.parse(fs.readFileSync('/app/config/config.json', 'utf8'));
const asset = fs.readFileSync('/app/data/message.txt', 'utf8').trim();
const note = fs.readFileSync('/app/generated/note.txt', 'utf8').trim();
const helper = execFileSync('/app/bin/helper', ['typescript'], { encoding: 'utf8' }).trim();
const decoder = new FrameDecoder();

console.log(`typescript:${config.mode}:${asset}:${note}:${helper}:${typeof decoder}`);
        "#,
    )
    .unwrap();
    fs::write(
        typescript_context.join("build.mjs"),
        r#"
import fs from 'node:fs';
import { stripTypeScriptTypes } from 'node:module';

fs.mkdirSync('dist', { recursive: true });
const source = fs.readFileSync('src/main.ts', 'utf8');
const transformed = stripTypeScriptTypes(source, { mode: 'transform' });
fs.writeFileSync('dist/main.js', transformed);
        "#,
    )
    .unwrap();
    let ts_compile = Command::new("node")
        .current_dir(&typescript_context)
        .arg("build.mjs")
        .output()
        .unwrap();
    assert!(
        ts_compile.status.success(),
        "{}",
        String::from_utf8_lossy(&ts_compile.stderr)
    );
    fs::write(
        typescript_context.join("bin/helper"),
        "#!/bin/sh\nprintf 'helper-typescript\\n'\n",
    )
    .unwrap();
    fs::set_permissions(
        typescript_context.join("bin/helper"),
        fs::Permissions::from_mode(0o755),
    )
    .unwrap();
    fs::write(
        typescript_context.join("bin/prepare.sh"),
        "#!/bin/sh\nprintf 'prepared-typescript\\n' > /app/generated/note.txt\n",
    )
    .unwrap();
    fs::set_permissions(
        typescript_context.join("bin/prepare.sh"),
        fs::Permissions::from_mode(0o755),
    )
    .unwrap();
    fs::write(
        typescript_context.join("config/config.json"),
        "{\"mode\":\"vector\"}\n",
    )
    .unwrap();
    fs::write(typescript_context.join("data/message.txt"), "asteroid\n").unwrap();
    let typescript_file = project.join("TypeScriptExample.DiscombobuFile");
    fs::write(
        &typescript_file,
        format!(
            "\
FROM example-tools:latest for {arch}
COPY {{src}} ./bin /app/bin
COPY {{src}} ./config /app/config
COPY {{src}} ./data /app/data
COPY {{src}} ./dist /app/dist
COPY {{src}} ./generated /app/generated
COPY {{src}} ./node_modules /app/node_modules
WORKDIR /app
RUN [\"/bin/sh\", \"/app/bin/prepare.sh\"]
SURVIVE /bin/sh
SURVIVE {}
SURVIVE {}
SURVIVE /app/bin/*
SURVIVE /app/config/*
SURVIVE /app/data/*
SURVIVE /app/generated/*
SURVIVE /app/dist/*
SURVIVE /app/node_modules/*
EXECUTE [\"{}\", \"/app/dist/main.js\"]
",
            shell_target.display(),
            node_binary.display(),
            node_binary.display()
        ),
    )
    .unwrap();
    let typescript_blob = project.join("typescript-example.blob.zst");
    build_blob_with_contexts(
        project,
        &typescript_file,
        &typescript_blob,
        "app",
        &[format!("src={}", typescript_context.display())],
    );
    let typescript_mount = MountedBlob::receive(&typescript_blob);
    assert!(typescript_mount
        .artifact_root()
        .join("rootfs/app/node_modules/@nametag/prodigy-neuron-hub/package.json")
        .exists());
    let typescript_output = launch_app_artifact(&typescript_mount);
    assert_eq!(
        String::from_utf8_lossy(&typescript_output.stdout).trim(),
        "typescript:vector:asteroid:prepared-typescript:helper-typescript:object"
    );

    assert_eq!(
        registry.request_count(),
        remote_requests_after_base,
        "expected example app builds to reuse the cached remote-derived local base"
    );

    let cached_apps_before_repeat = count_cached_artifacts(project, "app", arch);
    let repeated_cpp_blob = project.join("cpp-example-repeat.blob.zst");
    build_blob_with_contexts(
        project,
        &cpp_file,
        &repeated_cpp_blob,
        "app",
        &[format!("src={}", cpp_context.display())],
    );
    assert_eq!(
        count_cached_artifacts(project, "app", arch),
        cached_apps_before_repeat,
        "expected identical example rebuild to reuse the cached app artifact"
    );
    let repeated_cpp_mount = MountedBlob::receive(&repeated_cpp_blob);
    let repeated_cpp_output = launch_app_artifact(&repeated_cpp_mount);
    assert_eq!(
        String::from_utf8_lossy(&repeated_cpp_output.stdout).trim(),
        "cpp:signal:nebula:prepared-cpp:helper-cpp:969"
    );
}

fn build_blob(project: &Path, file: &Path, output: &Path, kind: &str) {
    let binary = env!("CARGO_BIN_EXE_discombobulator");
    let build = Command::new(binary)
        .current_dir(project)
        .args([
            "build",
            "--file",
            file.to_str().unwrap(),
            "--output",
            output.to_str().unwrap(),
            "--kind",
            kind,
        ])
        .output()
        .unwrap();
    assert!(
        build.status.success(),
        "{}",
        String::from_utf8_lossy(&build.stderr)
    );
}

fn remote_fetch(project: &Path, remote: &str, image: &str, arch: &str) -> std::process::Output {
    let binary = env!("CARGO_BIN_EXE_discombobulator");
    Command::new(binary)
        .current_dir(project)
        .args(["remote", "fetch", remote, image, "--arch", arch])
        .output()
        .unwrap()
}

fn build_with_contexts_and_env(
    project: &Path,
    file: &Path,
    output: &Path,
    kind: &str,
    contexts: &[String],
    envs: &[(&str, &str)],
) -> std::process::Output {
    let binary = env!("CARGO_BIN_EXE_discombobulator");
    let mut command = Command::new(binary);
    command.current_dir(project);
    command.args(["build", "--file", file.to_str().unwrap()]);
    for context in contexts {
        command.arg("--context").arg(context);
    }
    command.args(["--output", output.to_str().unwrap(), "--kind", kind]);
    for (key, value) in envs {
        command.env(key, value);
    }
    command.output().unwrap()
}

fn build_blob_with_contexts(
    project: &Path,
    file: &Path,
    output: &Path,
    kind: &str,
    contexts: &[String],
) {
    let binary = env!("CARGO_BIN_EXE_discombobulator");
    let mut command = Command::new(binary);
    command.current_dir(project);
    command.args(["build", "--file", file.to_str().unwrap()]);
    for context in contexts {
        command.arg("--context").arg(context);
    }
    command.args(["--output", output.to_str().unwrap(), "--kind", kind]);
    let build = command.output().unwrap();
    assert!(
        build.status.success(),
        "{}",
        String::from_utf8_lossy(&build.stderr)
    );
}

fn assert_fault_injected(output: &std::process::Output, stage: &str) {
    assert!(
        !output.status.success(),
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.status.code(), Some(97));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains(&format!("discombobulator test fault injected at {stage}")),
        "{stderr}"
    );
}

fn timed_build_blob_with_contexts(
    project: &Path,
    file: &Path,
    output: &Path,
    kind: &str,
    contexts: &[String],
) -> Duration {
    let started = Instant::now();
    build_blob_with_contexts(project, file, output, kind, contexts);
    started.elapsed()
}

fn build_failure_with_contexts(
    project: &Path,
    file: &Path,
    output: &Path,
    kind: &str,
    contexts: &[String],
) -> String {
    let binary = env!("CARGO_BIN_EXE_discombobulator");
    let mut command = Command::new(binary);
    command.current_dir(project);
    command.args(["build", "--file", file.to_str().unwrap()]);
    for context in contexts {
        command.arg("--context").arg(context);
    }
    command.args(["--output", output.to_str().unwrap(), "--kind", kind]);
    let build = command.output().unwrap();
    assert!(
        !build.status.success(),
        "{}",
        String::from_utf8_lossy(&build.stderr)
    );
    String::from_utf8_lossy(&build.stderr).to_string()
}

fn add_named_remote(project: &Path, name: &str, host: &str) {
    let binary = env!("CARGO_BIN_EXE_discombobulator");
    let output = Command::new(binary)
        .current_dir(project)
        .args(["remote", "add", name, host])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn collect_relative_file_paths(root: &Path) -> Vec<String> {
    let mut results = Vec::new();
    for entry in WalkDir::new(root).follow_links(false).min_depth(1) {
        let entry = entry.unwrap();
        if entry.file_type().is_file() {
            results.push(path_to_unix(entry.path().strip_prefix(root).unwrap()));
        }
    }
    results.sort();
    results
}

fn path_to_unix(path: &Path) -> String {
    path.components()
        .filter_map(|component| match component {
            std::path::Component::Normal(value) => Some(value.to_string_lossy().to_string()),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join("/")
}

fn current_build_architecture() -> &'static str {
    match std::env::consts::ARCH {
        "x86_64" => "x86_64",
        "aarch64" => "arm64",
        other => panic!("unsupported test architecture {other}"),
    }
}

fn current_oci_architecture() -> &'static str {
    match std::env::consts::ARCH {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        other => panic!("unsupported OCI test architecture {other}"),
    }
}

fn host_python_binary() -> PathBuf {
    if Path::new("/usr/bin/python3.14").exists() {
        PathBuf::from("/usr/bin/python3.14")
    } else {
        host_command_path("python3")
    }
}

fn host_python_stdlib() -> PathBuf {
    let python = host_python_binary();
    let output = Command::new(&python)
        .args([
            "-c",
            "import sysconfig; print(sysconfig.get_paths()['stdlib'])",
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    PathBuf::from(String::from_utf8_lossy(&output.stdout).trim())
}

fn host_python_module_root(module: &str) -> PathBuf {
    let output = Command::new("python3")
        .args([
            "-c",
            &format!("import {module}, os; print(os.path.dirname({module}.__file__))"),
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    PathBuf::from(String::from_utf8_lossy(&output.stdout).trim())
}

fn copy_tree_into_context(source: &Path, context_root: &Path, destination: &Path) {
    let target = context_root.join(destination.strip_prefix("/").unwrap());
    if let Some(parent) = target.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    let copy = Command::new("cp")
        .args(["-a"])
        .arg(source)
        .arg(&target)
        .output()
        .unwrap();
    assert!(
        copy.status.success(),
        "{}",
        String::from_utf8_lossy(&copy.stderr)
    );
}

fn copy_host_runtime_closure(source: &Path, context_root: &Path, destination: &Path) {
    let mut copied = std::collections::BTreeSet::new();
    copy_host_runtime_path(source, context_root, destination, &mut copied);
    if let Some(interpreter) = read_elf_interpreter(source) {
        copy_host_runtime_path(
            Path::new(&interpreter),
            context_root,
            Path::new(&interpreter),
            &mut copied,
        );
    }
    for dependency in read_ldd_dependencies(source) {
        copy_host_runtime_path(&dependency, context_root, &dependency, &mut copied);
    }
}

fn copy_host_runtime_path(
    source: &Path,
    context_root: &Path,
    destination: &Path,
    copied: &mut std::collections::BTreeSet<PathBuf>,
) {
    let normalized = normalize_absolute_path(source);
    if copied.insert(normalized.clone()) == false {
        return;
    }

    let metadata = fs::symlink_metadata(&normalized).unwrap();
    let target = context_root.join(destination.strip_prefix("/").unwrap());
    if metadata.file_type().is_symlink() {
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        let link_target = fs::read_link(&normalized).unwrap();
        let _ = fs::remove_file(&target);
        std::os::unix::fs::symlink(&link_target, &target).unwrap();
        let link_is_absolute = link_target.is_absolute();
        let resolved = if link_is_absolute {
            link_target.clone()
        } else {
            normalized
                .parent()
                .unwrap_or_else(|| Path::new("/"))
                .join(&link_target)
        };
        let resolved_destination = if link_is_absolute {
            link_target
        } else {
            destination
                .parent()
                .unwrap_or_else(|| Path::new("/"))
                .join(&link_target)
        };
        copy_host_runtime_path(&resolved, context_root, &resolved_destination, copied);
        return;
    }

    if metadata.is_dir() {
        fs::create_dir_all(&target).unwrap();
        fs::set_permissions(
            &target,
            fs::Permissions::from_mode(metadata.permissions().mode()),
        )
        .unwrap();
        return;
    }

    if let Some(parent) = target.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    fs::copy(&normalized, &target).unwrap();
    fs::set_permissions(
        &target,
        fs::Permissions::from_mode(metadata.permissions().mode()),
    )
    .unwrap();
}

fn read_elf_interpreter(path: &Path) -> Option<String> {
    let output = Command::new("readelf")
        .arg("-l")
        .arg(path)
        .output()
        .unwrap();
    if output.status.success() == false {
        return None;
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.lines() {
        if let Some(start) = line.find("Requesting program interpreter: ") {
            let value = &line[start + "Requesting program interpreter: ".len()..];
            let value = value.trim().trim_start_matches('[').trim_end_matches(']');
            return Some(value.to_string());
        }
    }
    None
}

fn read_ldd_dependencies(path: &Path) -> Vec<PathBuf> {
    let output = Command::new("ldd").arg(path).output().unwrap();
    if output.status.success() == false {
        return Vec::new();
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut dependencies = Vec::new();
    for line in stdout.lines() {
        if let Some((_, right)) = line.split_once("=>") {
            let trimmed = right.trim();
            if let Some(path) = trimmed.split_whitespace().next() {
                if path.starts_with('/') {
                    dependencies.push(PathBuf::from(path));
                }
            }
        } else {
            let trimmed = line.trim();
            if trimmed.starts_with('/') {
                if let Some(path) = trimmed.split_whitespace().next() {
                    dependencies.push(PathBuf::from(path));
                }
            }
        }
    }
    dependencies.sort();
    dependencies.dedup();
    dependencies
}

fn normalize_absolute_path(path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        Path::new("/").join(path)
    }
}

fn host_command_path(command: &str) -> PathBuf {
    let output = Command::new("bash")
        .args(["-lc", &format!("command -v -- {command}")])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    PathBuf::from(String::from_utf8_lossy(&output.stdout).trim())
}

fn alternate_test_architecture() -> Option<&'static str> {
    match std::env::consts::ARCH {
        "x86_64" => Some("arm64"),
        "aarch64" => Some("x86_64"),
        _ => None,
    }
}

fn alternate_test_architecture_and_qemu() -> Option<(&'static str, &'static str)> {
    match std::env::consts::ARCH {
        "x86_64" => Some(("arm64", "qemu-aarch64-static")),
        "aarch64" => Some(("x86_64", "qemu-x86_64-static")),
        _ => None,
    }
}

fn fake_foreign_elf_bytes(arch: &str) -> Vec<u8> {
    let machine = match arch {
        "arm64" => [0xb7, 0x00],
        "x86_64" => [0x3e, 0x00],
        "riscv64" => [0xf3, 0x00],
        other => panic!("unsupported test architecture {other}"),
    };
    let mut bytes = vec![
        0x7f, b'E', b'L', b'F', 0x02, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x02, 0x00, machine[0], machine[1], 0x01, 0x00, 0x00, 0x00,
    ];
    bytes.resize(128, 0);
    bytes
}

fn list_host_binfmt_rules_with_prefix(prefix: &str) -> Vec<String> {
    let root = Path::new("/proc/sys/fs/binfmt_misc");
    if root.exists() == false {
        return Vec::new();
    }

    let mut names = fs::read_dir(root)
        .unwrap()
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .filter(|name| name.starts_with(prefix))
        .collect::<Vec<_>>();
    names.sort();
    names
}

struct MountedBlob {
    temp: tempfile::TempDir,
    mount_point: PathBuf,
}

impl MountedBlob {
    fn receive(blob: &Path) -> Self {
        let temp = tempfile::tempdir().unwrap();
        let image = temp.path().join("recv.img");
        let mount_point = temp.path().join("mnt");
        fs::create_dir_all(&mount_point).unwrap();

        assert!(Command::new("truncate")
            .args(["-s", "512M"])
            .arg(&image)
            .status()
            .unwrap()
            .success());
        assert!(Command::new("mkfs.btrfs")
            .arg("-q")
            .arg(&image)
            .status()
            .unwrap()
            .success());
        assert!(Command::new("mount")
            .arg("-o")
            .arg("loop")
            .arg(&image)
            .arg(&mount_point)
            .status()
            .unwrap()
            .success());

        let decoded = Command::new("bash")
            .arg("-lc")
            .arg(format!(
                "set -euo pipefail; zstd -d -q -c '{}' | btrfs receive '{}'",
                blob.display(),
                mount_point.display()
            ))
            .output()
            .unwrap();
        assert!(
            decoded.status.success(),
            "{}",
            String::from_utf8_lossy(&decoded.stderr)
        );

        Self { temp, mount_point }
    }

    fn artifact_root(&self) -> PathBuf {
        self.mount_point.join("artifact")
    }
}

#[derive(Deserialize)]
struct LaunchMetadataFixture {
    execute_path: String,
    execute_args: Vec<String>,
    execute_env: Vec<String>,
    execute_cwd: String,
}

fn launch_app_artifact(mounted: &MountedBlob) -> std::process::Output {
    let metadata: LaunchMetadataFixture = serde_json::from_slice(
        &fs::read(
            mounted
                .artifact_root()
                .join(".prodigy-private/launch.metadata"),
        )
        .unwrap(),
    )
    .unwrap();
    let rootfs = mounted.artifact_root().join("rootfs");
    assert!(
        rootfs.join("bin/sh").exists(),
        "launch helper requires /bin/sh in the survivor set"
    );

    let mut script = String::new();
    if metadata.execute_cwd.is_empty() == false && metadata.execute_cwd != "/" {
        script.push_str("cd ");
        script.push_str(&shell_quote(&metadata.execute_cwd));
        script.push_str(" && ");
    }
    for assignment in &metadata.execute_env {
        let (name, value) = assignment.split_once('=').unwrap();
        script.push_str(name);
        script.push('=');
        script.push_str(&shell_quote(value));
        script.push(' ');
    }
    script.push_str("exec ");
    script.push_str(&shell_quote(&metadata.execute_path));
    for argument in &metadata.execute_args {
        script.push(' ');
        script.push_str(&shell_quote(argument));
    }

    let launched = Command::new("chroot")
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .arg(&rootfs)
        .args(["/bin/sh", "-lc", &script])
        .output()
        .unwrap();
    assert!(
        launched.status.success(),
        "{}",
        String::from_utf8_lossy(&launched.stderr)
    );
    launched
}

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\"'\"'"))
}

struct ArtifactRow {
    kind: String,
    arch: String,
    name: Option<String>,
    tag: Option<String>,
    path: String,
    size_bytes: i64,
    created_at: i64,
    updated_at: i64,
    last_used_at: i64,
}

fn open_registry(project: &Path) -> Connection {
    Connection::open(project.join(".discombobulator/registry/registry.sqlite")).unwrap()
}

fn query_named_artifact(
    connection: &Connection,
    kind: &str,
    name: &str,
    tag: &str,
    arch: &str,
) -> ArtifactRow {
    connection
        .query_row(
            "SELECT kind, arch, name, tag, path, size_bytes, created_at, updated_at, last_used_at
             FROM artifacts
             WHERE kind=?1 AND name=?2 AND tag=?3 AND arch=?4",
            params![kind, name, tag, arch],
            |row| {
                Ok(ArtifactRow {
                    kind: row.get(0)?,
                    arch: row.get(1)?,
                    name: row.get(2)?,
                    tag: row.get(3)?,
                    path: row.get(4)?,
                    size_bytes: row.get(5)?,
                    created_at: row.get(6)?,
                    updated_at: row.get(7)?,
                    last_used_at: row.get(8)?,
                })
            },
        )
        .unwrap()
}

fn query_artifacts_by_kind(connection: &Connection, kind: &str) -> Vec<ArtifactRow> {
    let mut statement = connection
        .prepare(
            "SELECT kind, arch, name, tag, path, size_bytes, created_at, updated_at, last_used_at
             FROM artifacts
             WHERE kind=?1
             ORDER BY path ASC",
        )
        .unwrap();
    let rows = statement
        .query_map(params![kind], |row| {
            Ok(ArtifactRow {
                kind: row.get(0)?,
                arch: row.get(1)?,
                name: row.get(2)?,
                tag: row.get(3)?,
                path: row.get(4)?,
                size_bytes: row.get(5)?,
                created_at: row.get(6)?,
                updated_at: row.get(7)?,
                last_used_at: row.get(8)?,
            })
        })
        .unwrap();
    rows.map(|row| row.unwrap()).collect()
}

fn query_oci_import_paths(connection: &Connection) -> Vec<PathBuf> {
    let mut statement = connection
        .prepare("SELECT path FROM oci_imports ORDER BY path ASC")
        .unwrap();
    let rows = statement
        .query_map([], |row| row.get::<_, String>(0))
        .unwrap();
    rows.map(|row| PathBuf::from(row.unwrap())).collect()
}

fn count_cached_artifacts(project: &Path, kind: &str, arch: &str) -> usize {
    let directory = match kind {
        "app" => project.join(format!(".discombobulator/artifacts/apps/{arch}")),
        "base" => project.join(format!(".discombobulator/artifacts/bases/{arch}")),
        other => panic!("unsupported artifact kind {other}"),
    };
    if directory.exists() == false {
        return 0;
    }
    fs::read_dir(directory).unwrap().count()
}

fn count_cached_import_roots(project: &Path, arch: &str) -> usize {
    let directory = project.join(format!(".discombobulator/imports/oci/{arch}"));
    if directory.exists() == false {
        return 0;
    }
    fs::read_dir(directory).unwrap().count()
}

fn mark_entry_stale(path: &Path) {
    let touched = Command::new("touch")
        .args(["-d", "3 days ago"])
        .arg(path)
        .output()
        .unwrap();
    assert!(
        touched.status.success(),
        "{}",
        String::from_utf8_lossy(&touched.stderr)
    );
}

fn assert_no_session_entries(root: &Path) {
    if root.exists() == false {
        return;
    }
    let entries = fs::read_dir(root)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().to_string())
        .collect::<Vec<_>>();
    assert!(
        entries
            .iter()
            .all(|entry| entry.starts_with("session-") == false),
        "expected no lingering builder sessions under {} but found {:?}",
        root.display(),
        entries
    );
}

fn write_docker_config_auth(
    docker_config_dir: &Path,
    registry_host: &str,
    username: &str,
    password: &str,
) {
    fs::create_dir_all(docker_config_dir).unwrap();
    let auth = base64::engine::general_purpose::STANDARD.encode(format!("{username}:{password}"));
    fs::write(
        docker_config_dir.join("config.json"),
        format!("{{\"auths\":{{\"{registry_host}\":{{\"auth\":\"{auth}\"}}}}}}\n"),
    )
    .unwrap();
}

impl Drop for MountedBlob {
    fn drop(&mut self) {
        let _ = Command::new("umount").arg(&self.mount_point).status();
        let _ = self.temp.path();
    }
}

struct FakeRegistry {
    address: SocketAddr,
    requests: Arc<AtomicUsize>,
    shutdown: Arc<AtomicBool>,
    current_version: Arc<Mutex<usize>>,
    thread: Option<thread::JoinHandle<()>>,
}

struct HitServer {
    address: SocketAddr,
    hits: Arc<AtomicUsize>,
    shutdown: Arc<AtomicBool>,
    thread: Option<thread::JoinHandle<()>>,
}

impl HitServer {
    fn new() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let hits = Arc::new(AtomicUsize::new(0));
        let shutdown = Arc::new(AtomicBool::new(false));

        let thread_hits = hits.clone();
        let thread_shutdown = shutdown.clone();
        let thread = thread::spawn(move || loop {
            let Ok((mut stream, _)) = listener.accept() else {
                break;
            };
            if thread_shutdown.load(Ordering::SeqCst) {
                break;
            }
            thread_hits.fetch_add(1, Ordering::SeqCst);
            let _ = stream.read(&mut [0u8; 32]);
        });

        Self {
            address,
            hits,
            shutdown,
            thread: Some(thread),
        }
    }

    fn port(&self) -> u16 {
        self.address.port()
    }

    fn hit_count(&self) -> usize {
        self.hits.load(Ordering::SeqCst)
    }
}

impl Drop for HitServer {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect(self.address);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

impl FakeRegistry {
    fn new() -> Self {
        Self::with_arch("amd64")
    }

    fn with_versions(versions: BTreeMap<usize, RegistryImageVersion>) -> Self {
        Self::spawn_versions(versions, None, Duration::ZERO)
    }

    fn with_basic_auth(username: &str, password: &str) -> Self {
        let encoded =
            base64::engine::general_purpose::STANDARD.encode(format!("{username}:{password}"));
        Self::spawn("amd64", Some(format!("Basic {encoded}")), Duration::ZERO)
    }

    fn with_arch(architecture: &str) -> Self {
        Self::spawn(architecture, None, Duration::ZERO)
    }

    fn with_delay(response_delay: Duration) -> Self {
        Self::spawn("amd64", None, response_delay)
    }

    fn spawn(
        architecture: &str,
        expected_authorization: Option<String>,
        response_delay: Duration,
    ) -> Self {
        Self::spawn_versions(
            BTreeMap::from([
                (1usize, build_registry_image("version-one\n", architecture)),
                (2usize, build_registry_image("version-two\n", architecture)),
            ]),
            expected_authorization,
            response_delay,
        )
    }

    fn spawn_versions(
        versions: BTreeMap<usize, RegistryImageVersion>,
        expected_authorization: Option<String>,
        response_delay: Duration,
    ) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let requests = Arc::new(AtomicUsize::new(0));
        let shutdown = Arc::new(AtomicBool::new(false));
        let current_version = Arc::new(Mutex::new(1usize));
        let versions = Arc::new(versions);

        let thread_shutdown = shutdown.clone();
        let thread_requests = requests.clone();
        let thread_current_version = current_version.clone();
        let thread_versions = versions.clone();
        let thread_expected_authorization = expected_authorization.clone();
        let thread = thread::spawn(move || loop {
            let Ok((mut stream, _)) = listener.accept() else {
                break;
            };
            if thread_shutdown.load(Ordering::SeqCst) {
                break;
            }
            thread_requests.fetch_add(1, Ordering::SeqCst);
            if response_delay.is_zero() == false {
                thread::sleep(response_delay);
            }
            serve_registry_request(
                &mut stream,
                &thread_versions,
                *thread_current_version.lock().unwrap(),
                thread_expected_authorization.as_deref(),
            );
        });

        Self {
            address,
            requests,
            shutdown,
            current_version,
            thread: Some(thread),
        }
    }

    fn host(&self) -> String {
        format!("http://{}", self.address)
    }

    fn request_count(&self) -> usize {
        self.requests.load(Ordering::SeqCst)
    }

    fn set_version(&self, version: usize) {
        *self.current_version.lock().unwrap() = version;
    }
}

impl Drop for FakeRegistry {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect(self.address);
        if let Some(handle) = self.thread.take() {
            let _ = handle.join();
        }
    }
}

#[derive(Clone)]
struct RegistryImageVersion {
    manifest_json: Vec<u8>,
    manifest_digest: String,
    manifest_media_type: &'static str,
    blobs: BTreeMap<String, Vec<u8>>,
}

#[derive(Clone, Copy)]
enum TestManifestMediaType {
    Oci,
    DockerSchema2,
}

impl TestManifestMediaType {
    fn manifest_media_type(self) -> &'static str {
        match self {
            Self::Oci => "application/vnd.oci.image.manifest.v1+json",
            Self::DockerSchema2 => "application/vnd.docker.distribution.manifest.v2+json",
        }
    }

    fn config_media_type(self) -> &'static str {
        match self {
            Self::Oci => "application/vnd.oci.image.config.v1+json",
            Self::DockerSchema2 => "application/vnd.docker.container.image.v1+json",
        }
    }
}

#[derive(Clone, Copy)]
enum TestLayerEncoding {
    Gzip,
    Uncompressed,
    Zstd,
}

impl TestLayerEncoding {
    fn archive(self, entries: &[TarEntry<'_>]) -> Vec<u8> {
        match self {
            Self::Gzip => gzip_tar(entries),
            Self::Uncompressed => raw_tar(entries),
            Self::Zstd => zstd_tar(entries),
        }
    }

    fn media_type(self, manifest: TestManifestMediaType) -> &'static str {
        match self {
            Self::Gzip => match manifest {
                TestManifestMediaType::Oci => "application/vnd.oci.image.layer.v1.tar+gzip",
                TestManifestMediaType::DockerSchema2 => {
                    "application/vnd.docker.image.rootfs.diff.tar.gzip"
                }
            },
            Self::Uncompressed => match manifest {
                TestManifestMediaType::Oci => "application/vnd.oci.image.layer.v1.tar",
                TestManifestMediaType::DockerSchema2 => {
                    "application/vnd.docker.image.rootfs.diff.tar"
                }
            },
            Self::Zstd => "application/vnd.oci.image.layer.v1.tar+zstd",
        }
    }
}

struct RegistryLayerBlob {
    bytes: Vec<u8>,
    media_type: &'static str,
}

fn build_registry_image(version_text: &str, architecture: &str) -> RegistryImageVersion {
    build_registry_image_with_media_types(
        version_text,
        architecture,
        TestManifestMediaType::Oci,
        TestLayerEncoding::Gzip,
    )
}

fn build_registry_image_with_media_types(
    version_text: &str,
    architecture: &str,
    manifest_media_type: TestManifestMediaType,
    layer_encoding: TestLayerEncoding,
) -> RegistryImageVersion {
    let config = format!(
        r#"{{"architecture":"{architecture}","os":"linux","rootfs":{{"type":"layers","diff_ids":[]}}}}"#
    )
    .into_bytes();
    let config_digest = sha256_prefixed(&config);

    let layer_one = layer_encoding.archive(&[TarEntry::File {
        path: "app/old.txt",
        contents: b"stale\n",
        mode: 0o644,
    }]);
    let layer_one_digest = sha256_prefixed(&layer_one);
    let layer_two = layer_encoding.archive(&[
        TarEntry::File {
            path: "app/.wh.old.txt",
            contents: b"",
            mode: 0o644,
        },
        TarEntry::File {
            path: "app/hello",
            contents: version_text.as_bytes(),
            mode: 0o755,
        },
        TarEntry::Symlink {
            path: "app/current",
            target: "/app/hello",
            mode: 0o777,
        },
    ]);
    let layer_two_digest = sha256_prefixed(&layer_two);

    let manifest_json = format!(
        r#"{{
  "schemaVersion": 2,
  "mediaType": "{}",
  "config": {{
    "mediaType": "{}",
    "digest": "{config_digest}",
    "size": {}
  }},
  "layers": [
    {{
      "mediaType": "{}",
      "digest": "{layer_one_digest}",
      "size": {}
    }},
    {{
      "mediaType": "{}",
      "digest": "{layer_two_digest}",
      "size": {}
    }}
  ]
}}"#,
        manifest_media_type.manifest_media_type(),
        manifest_media_type.config_media_type(),
        config.len(),
        layer_encoding.media_type(manifest_media_type),
        layer_one.len(),
        layer_encoding.media_type(manifest_media_type),
        layer_two.len()
    )
    .into_bytes();
    let manifest_digest = sha256_prefixed(&manifest_json);

    RegistryImageVersion {
        manifest_json,
        manifest_digest,
        manifest_media_type: manifest_media_type.manifest_media_type(),
        blobs: BTreeMap::from([
            (config_digest, config),
            (layer_one_digest, layer_one),
            (layer_two_digest, layer_two),
        ]),
    }
}

fn build_registry_image_with_layers(
    layers: Vec<Vec<u8>>,
    architecture: &str,
) -> RegistryImageVersion {
    build_registry_image_with_manifest_and_layers(
        layers
            .into_iter()
            .map(|bytes| RegistryLayerBlob {
                bytes,
                media_type: "application/vnd.oci.image.layer.v1.tar+gzip",
            })
            .collect(),
        architecture,
        TestManifestMediaType::Oci,
    )
}

fn build_registry_image_with_manifest_and_layers(
    layers: Vec<RegistryLayerBlob>,
    architecture: &str,
    manifest_media_type: TestManifestMediaType,
) -> RegistryImageVersion {
    let config = format!(
        r#"{{"architecture":"{architecture}","os":"linux","rootfs":{{"type":"layers","diff_ids":[]}}}}"#
    )
    .into_bytes();
    let config_digest = sha256_prefixed(&config);

    let mut manifest_layers = Vec::new();
    let mut blobs = BTreeMap::from([(config_digest.clone(), config)]);
    for layer in layers {
        let digest = sha256_prefixed(&layer.bytes);
        manifest_layers.push(format!(
            r#"{{
      "mediaType": "{}",
      "digest": "{digest}",
      "size": {}
    }}"#,
            layer.media_type,
            layer.bytes.len()
        ));
        blobs.insert(digest, layer.bytes);
    }
    let manifest_json = format!(
        r#"{{
  "schemaVersion": 2,
  "mediaType": "{}",
  "config": {{
    "mediaType": "{}",
    "digest": "{config_digest}",
    "size": {}
  }},
  "layers": [
    {}
  ]
}}"#,
        manifest_media_type.manifest_media_type(),
        manifest_media_type.config_media_type(),
        blobs[&config_digest].len(),
        manifest_layers.join(",\n")
    )
    .into_bytes();
    let manifest_digest = sha256_prefixed(&manifest_json);

    RegistryImageVersion {
        manifest_json,
        manifest_digest,
        manifest_media_type: manifest_media_type.manifest_media_type(),
        blobs,
    }
}

fn build_registry_image_from_rootfs(rootfs: &Path, architecture: &str) -> RegistryImageVersion {
    let layer = gzip_tar_directory(rootfs);
    build_registry_image_with_manifest_and_layers(
        vec![RegistryLayerBlob {
            bytes: layer,
            media_type: "application/vnd.oci.image.layer.v1.tar+gzip",
        }],
        architecture,
        TestManifestMediaType::Oci,
    )
}

fn raw_tar(entries: &[TarEntry<'_>]) -> Vec<u8> {
    let mut builder = Builder::new(Vec::new());
    append_tar_entries(&mut builder, entries);
    builder.into_inner().unwrap()
}

fn zstd_tar(entries: &[TarEntry<'_>]) -> Vec<u8> {
    zstd::stream::encode_all(Cursor::new(raw_tar(entries)), 0).unwrap()
}

enum TarEntry<'a> {
    Directory {
        path: &'a str,
        mode: u32,
    },
    File {
        path: &'a str,
        contents: &'a [u8],
        mode: u32,
    },
    Symlink {
        path: &'a str,
        target: &'a str,
        mode: u32,
    },
    Hardlink {
        path: &'a str,
        target: &'a str,
        mode: u32,
    },
    Fifo {
        path: &'a str,
        mode: u32,
    },
}

fn gzip_tar(entries: &[TarEntry<'_>]) -> Vec<u8> {
    let encoder = GzEncoder::new(Vec::new(), Compression::default());
    let mut builder = Builder::new(encoder);
    append_tar_entries(&mut builder, entries);
    let encoder = builder.into_inner().unwrap();
    encoder.finish().unwrap()
}

fn append_tar_entries<W: Write>(builder: &mut Builder<W>, entries: &[TarEntry<'_>]) {
    for entry in entries {
        match entry {
            TarEntry::Directory { path, mode } => {
                let mut header = Header::new_gnu();
                header.set_entry_type(EntryType::Directory);
                header.set_path(path).unwrap();
                header.set_size(0);
                header.set_mode(*mode);
                header.set_cksum();
                builder.append(&header, std::io::empty()).unwrap();
            }
            TarEntry::File {
                path,
                contents,
                mode,
            } => {
                let mut header = Header::new_gnu();
                header.set_path(path).unwrap();
                header.set_size(contents.len() as u64);
                header.set_mode(*mode);
                header.set_cksum();
                builder
                    .append_data(&mut header, path, Cursor::new(*contents))
                    .unwrap();
            }
            TarEntry::Symlink { path, target, mode } => {
                let mut header = Header::new_gnu();
                header.set_entry_type(EntryType::Symlink);
                header.set_path(path).unwrap();
                header.set_link_name(target).unwrap();
                header.set_size(0);
                header.set_mode(*mode);
                header.set_cksum();
                builder.append(&header, std::io::empty()).unwrap();
            }
            TarEntry::Hardlink { path, target, mode } => {
                let mut header = Header::new_gnu();
                header.set_entry_type(EntryType::Link);
                header.set_path(path).unwrap();
                header.set_link_name(target).unwrap();
                header.set_size(0);
                header.set_mode(*mode);
                header.set_cksum();
                builder.append(&header, std::io::empty()).unwrap();
            }
            TarEntry::Fifo { path, mode } => {
                let mut header = Header::new_gnu();
                header.set_entry_type(EntryType::Fifo);
                header.set_path(path).unwrap();
                header.set_size(0);
                header.set_mode(*mode);
                header.set_cksum();
                builder.append(&header, std::io::empty()).unwrap();
            }
        }
    }
}

fn gzip_raw_tar_file(path: &str, contents: &[u8], mode: u32) -> Vec<u8> {
    let mut archive = Vec::new();
    append_raw_tar_file(&mut archive, path.as_bytes(), contents, mode);
    archive.extend(std::iter::repeat_n(0u8, 1024));
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(&archive).unwrap();
    encoder.finish().unwrap()
}

fn append_raw_tar_file(archive: &mut Vec<u8>, path: &[u8], contents: &[u8], mode: u32) {
    assert!(
        path.len() <= 100,
        "raw tar helper only supports 100-byte names"
    );
    let mut header = [0u8; 512];
    write_tar_bytes(&mut header[0..100], path);
    write_tar_octal(&mut header[100..108], mode as u64);
    write_tar_octal(&mut header[108..116], 0);
    write_tar_octal(&mut header[116..124], 0);
    write_tar_octal(&mut header[124..136], contents.len() as u64);
    write_tar_octal(&mut header[136..148], 0);
    header[148..156].fill(b' ');
    header[156] = b'0';
    write_tar_bytes(&mut header[257..263], b"ustar\0");
    write_tar_bytes(&mut header[263..265], b"00");
    let checksum: u32 = header.iter().map(|byte| *byte as u32).sum();
    write_tar_checksum(&mut header[148..156], checksum);
    archive.extend_from_slice(&header);
    archive.extend_from_slice(contents);
    let padding = (512 - (contents.len() % 512)) % 512;
    archive.extend(std::iter::repeat_n(0u8, padding));
}

fn write_tar_bytes(field: &mut [u8], value: &[u8]) {
    assert!(value.len() <= field.len());
    field.fill(0);
    field[..value.len()].copy_from_slice(value);
}

fn write_tar_octal(field: &mut [u8], value: u64) {
    let width = field.len() - 1;
    let encoded = format!("{value:0width$o}\0");
    assert_eq!(encoded.len(), field.len());
    field.copy_from_slice(encoded.as_bytes());
}

fn write_tar_checksum(field: &mut [u8], checksum: u32) {
    let encoded = format!("{checksum:06o}\0 ");
    assert_eq!(encoded.len(), field.len());
    field.copy_from_slice(encoded.as_bytes());
}

fn gzip_tar_directory(root: &Path) -> Vec<u8> {
    let encoder = GzEncoder::new(Vec::new(), Compression::default());
    let mut builder = Builder::new(encoder);
    let mut entries: Vec<_> = WalkDir::new(root)
        .follow_links(false)
        .min_depth(1)
        .into_iter()
        .map(|entry| entry.unwrap())
        .collect();
    entries.sort_by_key(|entry| path_to_unix(entry.path().strip_prefix(root).unwrap()));

    for entry in entries {
        let source = entry.path();
        let relative = path_to_unix(source.strip_prefix(root).unwrap());
        let metadata = fs::symlink_metadata(source).unwrap();
        let mut header = Header::new_gnu();
        header.set_mode(metadata.permissions().mode());
        header.set_mtime(0);
        header.set_uid(0);
        header.set_gid(0);
        if metadata.file_type().is_dir() {
            header.set_entry_type(EntryType::Directory);
            header.set_size(0);
            header.set_cksum();
            builder
                .append_data(&mut header, relative, std::io::empty())
                .unwrap();
            continue;
        }

        if metadata.file_type().is_symlink() {
            header.set_entry_type(EntryType::Symlink);
            header.set_size(0);
            header
                .set_link_name(fs::read_link(source).unwrap())
                .unwrap();
            header.set_cksum();
            builder
                .append_data(&mut header, relative, std::io::empty())
                .unwrap();
            continue;
        }

        let mut file = fs::File::open(source).unwrap();
        header.set_entry_type(EntryType::Regular);
        header.set_size(metadata.len());
        header.set_cksum();
        builder
            .append_data(&mut header, relative, &mut file)
            .unwrap();
    }

    let encoder = builder.into_inner().unwrap();
    encoder.finish().unwrap()
}

fn create_local_npm_package_tarball(package_root: &Path, output: &Path) {
    let file = fs::File::create(output).unwrap();
    let encoder = GzEncoder::new(file, Compression::default());
    let mut builder = Builder::new(encoder);
    append_tree_to_tarball(
        &mut builder,
        &package_root.join("package.json"),
        Path::new("package/package.json"),
    );
    append_tree_to_tarball(
        &mut builder,
        &package_root.join("README.md"),
        Path::new("package/README.md"),
    );
    append_tree_to_tarball(
        &mut builder,
        &package_root.join("dist"),
        Path::new("package/dist"),
    );
    builder.finish().unwrap();
    let encoder = builder.into_inner().unwrap();
    encoder.finish().unwrap();
}

fn append_tree_to_tarball<W: Write>(builder: &mut Builder<W>, source: &Path, archive_path: &Path) {
    let metadata = fs::symlink_metadata(source).unwrap();
    let archive_name = path_to_unix(archive_path);
    let mut header = Header::new_gnu();
    header.set_mode(metadata.permissions().mode());
    header.set_mtime(0);
    header.set_uid(0);
    header.set_gid(0);
    if metadata.file_type().is_dir() {
        header.set_entry_type(EntryType::Directory);
        header.set_size(0);
        header.set_cksum();
        builder
            .append_data(&mut header, &archive_name, std::io::empty())
            .unwrap();
        let mut children: Vec<_> = fs::read_dir(source)
            .unwrap()
            .map(|entry| entry.unwrap())
            .collect();
        children.sort_by_key(|entry| entry.file_name());
        for child in children {
            append_tree_to_tarball(
                builder,
                &child.path(),
                &archive_path.join(child.file_name()),
            );
        }
        return;
    }

    if metadata.file_type().is_symlink() {
        header.set_entry_type(EntryType::Symlink);
        header.set_size(0);
        header
            .set_link_name(fs::read_link(source).unwrap())
            .unwrap();
        header.set_cksum();
        builder
            .append_data(&mut header, &archive_name, std::io::empty())
            .unwrap();
        return;
    }

    let mut file = fs::File::open(source).unwrap();
    header.set_entry_type(EntryType::Regular);
    header.set_size(metadata.len());
    header.set_cksum();
    builder
        .append_data(&mut header, &archive_name, &mut file)
        .unwrap();
}

fn serve_registry_request(
    stream: &mut TcpStream,
    versions: &BTreeMap<usize, RegistryImageVersion>,
    current_version: usize,
    expected_authorization: Option<&str>,
) {
    let mut buffer = [0u8; 4096];
    let read = stream.read(&mut buffer).unwrap_or(0);
    if read == 0 {
        return;
    }

    let request = String::from_utf8_lossy(&buffer[..read]);
    let path = request
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .unwrap_or("/");
    let authorization = request.lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        if name.eq_ignore_ascii_case("Authorization") {
            Some(value.trim())
        } else {
            None
        }
    });

    if let Some(expected_authorization) = expected_authorization {
        if authorization != Some(expected_authorization) {
            write_http_response_with_headers(
                stream,
                401,
                "text/plain",
                None,
                &[("WWW-Authenticate", "Basic realm=\"fake-registry\"")],
                b"authorization required",
            );
            return;
        }
    }

    let version = versions.get(&current_version).unwrap();
    match path {
        "/v2/sample/manifests/latest" => {
            write_http_response(
                stream,
                200,
                version.manifest_media_type,
                Some(&version.manifest_digest),
                &version.manifest_json,
            );
        }
        _ if path.starts_with("/v2/sample/blobs/") => {
            let digest = path.trim_start_matches("/v2/sample/blobs/");
            if let Some(blob) = version.blobs.get(digest) {
                write_http_response(stream, 200, "application/octet-stream", None, blob);
            } else {
                write_http_response(stream, 404, "text/plain", None, b"missing blob");
            }
        }
        _ => {
            write_http_response(stream, 404, "text/plain", None, b"missing path");
        }
    }
}

fn write_http_response(
    stream: &mut TcpStream,
    status: u16,
    content_type: &str,
    digest: Option<&str>,
    body: &[u8],
) {
    write_http_response_with_headers(stream, status, content_type, digest, &[], body);
}

fn write_http_response_with_headers(
    stream: &mut TcpStream,
    status: u16,
    content_type: &str,
    digest: Option<&str>,
    headers: &[(&str, &str)],
    body: &[u8],
) {
    let reason = match status {
        200 => "OK",
        401 => "Unauthorized",
        404 => "Not Found",
        _ => "Error",
    };
    let mut response = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Length: {}\r\nContent-Type: {content_type}\r\nConnection: close\r\n",
        body.len()
    );
    if let Some(digest) = digest {
        response.push_str(&format!("Docker-Content-Digest: {digest}\r\n"));
    }
    for (name, value) in headers {
        response.push_str(&format!("{name}: {value}\r\n"));
    }
    response.push_str("\r\n");
    stream.write_all(response.as_bytes()).unwrap();
    stream.write_all(body).unwrap();
    stream.flush().unwrap();
}

fn sha256_prefixed(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}
