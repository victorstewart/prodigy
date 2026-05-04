#![cfg(target_os = "linux")]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Command, Output};

use tar::Archive;
use tempfile::TempDir;
use zstd::stream::read::Decoder as ZstdDecoder;

#[test]
fn flat_bundle_packages_binary_tools_and_ebpf_objects() {
    let temp = TempDir::new().unwrap();
    let project = temp.path();
    let build_dir = project.join("build");
    let inspect_dir = project.join("inspect");
    fs::create_dir_all(&build_dir).unwrap();
    fs::create_dir_all(&inspect_dir).unwrap();

    let source = build_dir.join("hello.c");
    fs::write(
        &source,
        "#include <stdio.h>\nint main(void) { puts(\"hello\"); return 0; }\n",
    )
    .unwrap();
    let binary = build_dir.join("hello");
    run_checked(
        Command::new("clang")
            .arg(&source)
            .arg("-O2")
            .arg("-o")
            .arg(&binary),
        "compile hello bundle binary",
    );

    let tool = project.join("helper-tool");
    fs::write(&tool, "#!/usr/bin/env bash\necho helper\n").unwrap();
    fs::set_permissions(&tool, fs::Permissions::from_mode(0o755)).unwrap();

    let ebpf_object = build_dir.join("latency.ebpf.o");
    fs::write(&ebpf_object, b"fake-ebpf-object").unwrap();

    let output = project.join("prodigy.bundle.tar.zst");
    run_checked(
        bundle_command(&binary, &build_dir, &output)
            .arg("--tool-binary")
            .arg(&tool),
        "build flat bundle",
    );

    extract_bundle(&output, &inspect_dir);

    assert!(inspect_dir.join("hello").is_file());
    assert!(inspect_dir.join("lib").is_dir());
    assert!(inspect_dir.join("tools/helper-tool").is_file());
    assert!(inspect_dir.join("latency.ebpf.o").is_file());
    assert_ne!(
        fs::metadata(inspect_dir.join("hello"))
            .unwrap()
            .permissions()
            .mode()
            & 0o111,
        0
    );
}

#[test]
fn flat_bundle_resolves_needed_library_from_library_search_dir() {
    let temp = TempDir::new().unwrap();
    let project = temp.path();
    let build_dir = project.join("build");
    let lib_dir = project.join("libdir");
    let inspect_dir = project.join("inspect");
    fs::create_dir_all(&build_dir).unwrap();
    fs::create_dir_all(&lib_dir).unwrap();
    fs::create_dir_all(&inspect_dir).unwrap();

    let library_source = lib_dir.join("custom.c");
    fs::write(
        &library_source,
        "#include <stdio.h>\nvoid custom_message(void) { puts(\"custom\"); }\n",
    )
    .unwrap();
    let library_binary = lib_dir.join("libcustom.so");
    run_checked(
        Command::new("clang")
            .arg("-shared")
            .arg("-fPIC")
            .arg(&library_source)
            .arg("-o")
            .arg(&library_binary),
        "compile shared library for flat bundle",
    );

    let source = build_dir.join("main.c");
    fs::write(
        &source,
        "void custom_message(void);\nint main(void) { custom_message(); return 0; }\n",
    )
    .unwrap();
    let binary = build_dir.join("main");
    run_checked(
        Command::new("clang")
            .arg(&source)
            .arg("-L")
            .arg(&lib_dir)
            .arg("-lcustom")
            .arg("-o")
            .arg(&binary),
        "compile bundle binary with external shared library",
    );

    let ldd_output = Command::new("ldd").arg(&binary).output().unwrap();
    assert!(String::from_utf8_lossy(&ldd_output.stdout).contains("libcustom.so => not found"));

    let output = project.join("prodigy.bundle.tar.zst");
    run_checked(
        bundle_command(&binary, &build_dir, &output)
            .arg("--library-search-dir")
            .arg(&lib_dir),
        "build flat bundle with library search dir",
    );

    extract_bundle(&output, &inspect_dir);
    assert!(inspect_dir.join("main").is_file());
    assert!(inspect_dir.join("lib/libcustom.so").is_file());
}

#[test]
fn flat_bundle_fails_clearly_when_needed_library_cannot_be_resolved() {
    let temp = TempDir::new().unwrap();
    let project = temp.path();
    let build_dir = project.join("build");
    let lib_dir = project.join("libdir");
    fs::create_dir_all(&build_dir).unwrap();
    fs::create_dir_all(&lib_dir).unwrap();

    let library_source = lib_dir.join("custom.c");
    fs::write(
        &library_source,
        "#include <stdio.h>\nvoid custom_message(void) { puts(\"custom\"); }\n",
    )
    .unwrap();
    let library_binary = lib_dir.join("libcustom.so");
    run_checked(
        Command::new("clang")
            .arg("-shared")
            .arg("-fPIC")
            .arg(&library_source)
            .arg("-o")
            .arg(&library_binary),
        "compile unresolved shared library fixture",
    );

    let source = build_dir.join("main.c");
    fs::write(
        &source,
        "void custom_message(void);\nint main(void) { custom_message(); return 0; }\n",
    )
    .unwrap();
    let binary = build_dir.join("main");
    run_checked(
        Command::new("clang")
            .arg(&source)
            .arg("-L")
            .arg(&lib_dir)
            .arg("-lcustom")
            .arg("-o")
            .arg(&binary),
        "compile binary with unresolved shared library",
    );

    let ldd_output = Command::new("ldd").arg(&binary).output().unwrap();
    assert!(String::from_utf8_lossy(&ldd_output.stdout).contains("libcustom.so => not found"));

    let output = project.join("prodigy.bundle.tar.zst");
    let failure = bundle_command(&binary, &build_dir, &output).output().unwrap();
    assert!(!failure.status.success());
    let stderr = String::from_utf8_lossy(&failure.stderr);
    assert!(stderr.contains("libcustom.so"), "{stderr}");
    assert!(!output.exists());
}

fn bundle_command(binary: &Path, build_dir: &Path, output: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_discombobulator"));
    command
        .arg("bundle")
        .arg("flat")
        .arg("--binary")
        .arg(binary)
        .arg("--build-dir")
        .arg(build_dir)
        .arg("--output")
        .arg(output);
    command
}

fn extract_bundle(bundle: &Path, destination: &Path) {
    let bundle_file = fs::File::open(bundle).unwrap();
    let decoder = ZstdDecoder::new(bundle_file).unwrap();
    let mut archive = Archive::new(decoder);
    archive.unpack(destination).unwrap();
}

fn run_checked(command: &mut Command, description: &str) -> Output {
    let output = command.output().unwrap_or_else(|error| {
        panic!("{description}: failed to spawn command: {error}");
    });
    if output.status.success() == false {
        panic!(
            "{description}: command failed\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    output
}
