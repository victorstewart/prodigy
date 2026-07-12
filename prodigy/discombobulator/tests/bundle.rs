#![cfg(target_os = "linux")]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Command, Output};

use tar::Archive;
use tempfile::TempDir;
use zstd::stream::read::Decoder as ZstdDecoder;

fn app_container_blob(payload: &[u8]) -> Vec<u8> {
    let mut blob = b"PRODIGY-DISCOMBOBULATOR-APP-CONTAINER\ncontract=prodigy-container-artifact\ncontract_version=1\n\n".to_vec();
    blob.extend_from_slice(payload);
    blob
}

fn tunnel_provider_blob(payload: &[u8]) -> Vec<u8> {
    let mut blob = b"PRODIGY-DISCOMBOBULATOR-MOTHERSHIP-TUNNEL-PROVIDER\ncontract=prodigy-mothership-tunnel-provider\ncontract_version=1\ncontainer_kind=mothershipTunnelProvider\nrequires_standard_neuron_socket=false\nrequires_mothership_tunnel_gateway=true\nnetwork_policy=tcpEgressOnly\n\n".to_vec();
    blob.extend_from_slice(payload);
    blob
}

#[test]
fn flat_bundle_packages_binary_tools_ebpf_and_exact_container_artifacts() {
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

    let app_artifact = project.join("resolver.container.zst");
    let app_artifact_bytes = app_container_blob(b"app-payload");
    fs::write(&app_artifact, &app_artifact_bytes).unwrap();
    fs::set_permissions(&app_artifact, fs::Permissions::from_mode(0o755)).unwrap();
    let tunnel_artifact = build_dir.join("tunnel.container.zst");
    let tunnel_artifact_bytes = tunnel_provider_blob(b"tunnel-payload");
    fs::write(&tunnel_artifact, &tunnel_artifact_bytes).unwrap();
    fs::write(
        project.join("libresolver-neighbor.so"),
        b"must-not-be-chased",
    )
    .unwrap();
    let resolver_plan = project.join("resolver.deployment.plan.v1.json");
    let resolver_plan_bytes = br#"{"config":{"applicationID":"${application:Resolver}"}}"#;
    fs::write(&resolver_plan, resolver_plan_bytes).unwrap();

    let output = project.join("prodigy.bundle.tar.zst");
    run_checked(
        bundle_command(&binary, &build_dir, &output)
            .current_dir(project)
            .arg("--tool-binary")
            .arg(&tool)
            .arg("--container-artifact")
            .arg("./resolver.container.zst")
            .arg("--container-artifact")
            .arg(&tunnel_artifact)
            .arg("--container-plan")
            .arg(&resolver_plan),
        "build flat bundle",
    );

    extract_bundle(&output, &inspect_dir);

    assert!(inspect_dir.join("hello").is_file());
    assert!(inspect_dir.join("lib").is_dir());
    assert!(inspect_dir.join("tools/helper-tool").is_file());
    assert!(inspect_dir.join("latency.ebpf.o").is_file());
    assert_eq!(
        fs::read(inspect_dir.join("containers/resolver.container.zst")).unwrap(),
        app_artifact_bytes
    );
    assert_eq!(
        fs::read(inspect_dir.join("containers/tunnel.container.zst")).unwrap(),
        tunnel_artifact_bytes
    );
    assert_eq!(
        fs::read(inspect_dir.join("containers/plans/resolver.deployment.plan.v1.json")).unwrap(),
        resolver_plan_bytes
    );
    assert_eq!(
        fs::metadata(inspect_dir.join("containers/resolver.container.zst"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o644
    );
    assert_eq!(
        fs::metadata(inspect_dir.join("containers/tunnel.container.zst"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o644
    );
    assert_eq!(
        fs::metadata(inspect_dir.join("containers/plans/resolver.deployment.plan.v1.json"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o644
    );
    let mut container_entries = fs::read_dir(inspect_dir.join("containers"))
        .unwrap()
        .filter_map(|entry| {
            let entry = entry.unwrap();
            entry
                .file_type()
                .unwrap()
                .is_file()
                .then(|| entry.file_name())
        })
        .collect::<Vec<_>>();
    container_entries.sort();
    assert_eq!(
        container_entries,
        vec![
            std::ffi::OsString::from("resolver.container.zst"),
            std::ffi::OsString::from("tunnel.container.zst"),
        ]
    );
    let plan_entries = fs::read_dir(inspect_dir.join("containers/plans"))
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect::<Vec<_>>();
    assert_eq!(
        plan_entries,
        vec![std::ffi::OsString::from("resolver.deployment.plan.v1.json")]
    );
    assert!(!inspect_dir
        .join("containers/libresolver-neighbor.so")
        .exists());
    assert!(!inspect_dir.join("lib/libresolver-neighbor.so").exists());
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
fn flat_bundle_rejects_invalid_container_artifact_inputs() {
    let temp = TempDir::new().unwrap();
    let project = temp.path();
    let build_dir = project.join("build");
    fs::create_dir_all(&build_dir).unwrap();
    let binary = build_dir.join("prodigy");
    fs::copy("/bin/true", &binary).unwrap();

    let malformed = project.join("malformed.container.zst");
    fs::write(&malformed, b"not-a-discombobulator-blob").unwrap();
    let malformed_output = project.join("malformed.bundle.tar.zst");
    let malformed_result = bundle_command(&binary, &build_dir, &malformed_output)
        .arg("--container-artifact")
        .arg(&malformed)
        .output()
        .unwrap();
    assert!(!malformed_result.status.success());
    assert!(String::from_utf8_lossy(&malformed_result.stderr)
        .contains("not a supported Discombobulator-built blob"));
    assert!(!malformed_output.exists());

    let first_dir = project.join("first");
    let second_dir = project.join("second");
    fs::create_dir_all(&first_dir).unwrap();
    fs::create_dir_all(&second_dir).unwrap();
    let first = first_dir.join("duplicate.container.zst");
    let second = second_dir.join("duplicate.container.zst");
    fs::write(&first, app_container_blob(b"first")).unwrap();
    fs::write(&second, app_container_blob(b"second")).unwrap();
    let duplicate_output = project.join("duplicate.bundle.tar.zst");
    let duplicate_result = bundle_command(&binary, &build_dir, &duplicate_output)
        .arg("--container-artifact")
        .arg(&first)
        .arg("--container-artifact")
        .arg(&second)
        .output()
        .unwrap();
    assert!(!duplicate_result.status.success());
    assert!(
        String::from_utf8_lossy(&duplicate_result.stderr).contains("must have unique basenames")
    );
    assert!(!duplicate_output.exists());

    let parent_relative = first_dir
        .join("..")
        .join("second")
        .join("duplicate.container.zst");
    let parent_relative_output = project.join("parent-relative.bundle.tar.zst");
    run_checked(
        bundle_command(&binary, &build_dir, &parent_relative_output)
            .arg("--container-artifact")
            .arg(parent_relative),
        "accept parent-relative container artifact source",
    );

    let injection_output = project.join("injection.bundle.tar.zst");
    let injection_result = bundle_command(&binary, &build_dir, &injection_output)
        .current_dir(project)
        .arg("--container-artifact")
        .arg("..")
        .output()
        .unwrap();
    assert!(!injection_result.status.success());
    assert!(String::from_utf8_lossy(&injection_result.stderr)
        .contains("must have a normal nonempty basename"));
    assert!(!injection_output.exists());

    let directory_output = project.join("directory.bundle.tar.zst");
    let directory_result = bundle_command(&binary, &build_dir, &directory_output)
        .arg("--container-artifact")
        .arg(&first_dir)
        .output()
        .unwrap();
    assert!(!directory_result.status.success());
    assert!(String::from_utf8_lossy(&directory_result.stderr).contains("is not a regular file"));
    assert!(!directory_output.exists());
}

#[test]
fn flat_bundle_rejects_invalid_container_plan_inputs() {
    let temp = TempDir::new().unwrap();
    let project = temp.path();
    let build_dir = project.join("build");
    fs::create_dir_all(&build_dir).unwrap();
    let binary = build_dir.join("prodigy");
    fs::copy("/bin/true", &binary).unwrap();

    let malformed = project.join("malformed.json");
    fs::write(&malformed, b"not-json").unwrap();
    let malformed_result = bundle_command(
        &binary,
        &build_dir,
        &project.join("malformed.bundle.tar.zst"),
    )
    .arg("--container-plan")
    .arg(&malformed)
    .output()
    .unwrap();
    assert!(!malformed_result.status.success());
    assert!(String::from_utf8_lossy(&malformed_result.stderr).contains("not valid JSON"));

    let array = project.join("array.json");
    fs::write(&array, b"[]").unwrap();
    let array_result = bundle_command(&binary, &build_dir, &project.join("array.bundle.tar.zst"))
        .arg("--container-plan")
        .arg(&array)
        .output()
        .unwrap();
    assert!(!array_result.status.success());
    assert!(String::from_utf8_lossy(&array_result.stderr).contains("root must be an object"));

    let oversized = project.join("oversized.json");
    fs::write(&oversized, vec![b' '; 1024 * 1024 + 1]).unwrap();
    let oversized_result = bundle_command(
        &binary,
        &build_dir,
        &project.join("oversized.bundle.tar.zst"),
    )
    .arg("--container-plan")
    .arg(&oversized)
    .output()
    .unwrap();
    assert!(!oversized_result.status.success());
    assert!(String::from_utf8_lossy(&oversized_result.stderr).contains("1048576-byte limit"));
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
    let failure = bundle_command(&binary, &build_dir, &output)
        .output()
        .unwrap();
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
