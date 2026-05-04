use crate::cli::{
    parse_key_value, BuildCommand, BundleFlatCommand, InternalRunCommand, OutputKindArg,
};
use crate::plan::{
    normalize_absolute_path, parse_build_spec, resolve_build_spec, resolve_container_path,
    Architecture, FromSource, OutputKind, ResolvedBuildSpec, ResolvedBuildStep, ResolvedRun,
};
use crate::registry::{
    sha256_file, ArtifactRecord, OciImportRecord, Registry, RemoteRecord, StorageRoot,
};
use anyhow::{bail, Context, Result};
use base64::Engine;
use flate2::read::GzDecoder;
use metalor::runtime::{
    build_unshare_reexec_command, helper_binary_path, run_isolated_container_command,
    ContainerRunCommand, RUN_HELPER_DIR,
};
use reqwest::blocking::Client as HttpClient;
use reqwest::header::{ACCEPT, AUTHORIZATION, WWW_AUTHENTICATE};
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsStr;
use std::fs;
use std::fs::OpenOptions;
use std::io::{Cursor, Read};
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tar::Archive;
use tempfile::TempDir;
use walkdir::WalkDir;
use zstd::stream::read::Decoder as ZstdDecoder;

const STEP_CACHE_VERSION: &str = "discombobulator-step-cache-v1";
const ARTIFACT_CACHE_VERSION: &str = "discombobulator-artifact-cache-v1";
const METALOR_RUNTIME_DIR_NAME: &str = ".metalor-runtime";
const SESSION_STALE_AFTER: Duration = Duration::from_secs(6 * 60 * 60);
const LOCK_EXCLUSIVE: i32 = 2;
const LOCK_UNLOCK: i32 = 8;
const TEST_FAULT_ENV: &str = "DISCOMBOBULATOR_TEST_FAULT";

struct MaterializedBase {
    root: PathBuf,
    identity: String,
}

struct BuildSession {
    work_root: PathBuf,
    tmp_root: PathBuf,
}

#[derive(Deserialize, Serialize)]
struct SessionLease {
    pid: u32,
    started_at: u64,
    boot_id: Option<String>,
}

impl BuildSession {
    fn start(storage: &StorageRoot) -> Result<Self> {
        let session_id = format!(
            "session-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        );
        let work_root = storage.work_dir().join(&session_id);
        let tmp_root = storage.tmp_dir().join(&session_id);
        fs::create_dir_all(&work_root)?;
        fs::create_dir_all(&tmp_root)?;
        let lease = SessionLease {
            pid: std::process::id(),
            started_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            boot_id: current_boot_id(),
        };
        let lease_bytes = serde_json::to_vec_pretty(&lease)?;
        fs::write(work_root.join("lease.json"), &lease_bytes)?;
        fs::write(tmp_root.join("lease.json"), &lease_bytes)?;
        Ok(Self {
            work_root,
            tmp_root,
        })
    }

    fn work_root(&self) -> &Path {
        &self.work_root
    }

    fn tmp_root(&self) -> &Path {
        &self.tmp_root
    }
}

impl Drop for BuildSession {
    fn drop(&mut self) {
        let _ = remove_existing_path(&self.work_root);
        let _ = remove_existing_path(&self.tmp_root);
    }
}

struct FileLockGuard {
    file: fs::File,
}

impl FileLockGuard {
    fn acquire(storage: &StorageRoot, namespace: &str, key: &str) -> Result<Self> {
        let lock_path = storage.lock_path(namespace, key);
        if let Some(parent) = lock_path.parent() {
            fs::create_dir_all(parent)?;
        }
        let file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(&lock_path)
            .with_context(|| format!("failed to open lock file {}", lock_path.display()))?;
        let result = unsafe { libc_flock(file.as_raw_fd(), LOCK_EXCLUSIVE) };
        if result != 0 {
            return Err(std::io::Error::last_os_error())
                .with_context(|| format!("failed to lock {}", lock_path.display()));
        }
        Ok(Self { file })
    }
}

impl Drop for FileLockGuard {
    fn drop(&mut self) {
        let _ = unsafe { libc_flock(self.file.as_raw_fd(), LOCK_UNLOCK) };
    }
}

pub fn run(command: BuildCommand) -> Result<()> {
    ensure_root()?;
    let cwd = std::env::current_dir()?;
    let storage = StorageRoot::discover(cwd);
    storage.ensure_layout()?;
    reap_stale_builder_state(&storage)?;
    let registry = Registry::open(&storage)?;

    let contexts = parse_contexts(&command.context)?;
    let build_args = parse_build_args(&command.build_arg)?;
    let contents = fs::read_to_string(&command.file)
        .with_context(|| format!("failed to read {}", command.file.display()))?;
    let spec = parse_build_spec(&contents)?;
    let output_kind = match command.kind {
        OutputKindArg::App => OutputKind::App,
        OutputKindArg::Base => OutputKind::Base,
    };
    let resolved = resolve_build_spec(&spec, output_kind, &build_args)?;

    execute_supported_subset(
        &registry,
        &storage,
        output_kind,
        command.publish_base.as_deref(),
        &resolved,
        &contexts,
        &command.output,
    )?;
    Ok(())
}

pub fn bundle_flat(command: BundleFlatCommand) -> Result<()> {
    if command.binary.is_file() == false {
        bail!(
            "bundle binary path does not exist: {}",
            command.binary.display()
        );
    }
    if command.build_dir.is_dir() == false {
        bail!(
            "bundle build dir does not exist: {}",
            command.build_dir.display()
        );
    }

    let output_parent = command
        .output
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or(std::env::current_dir()?);
    fs::create_dir_all(&output_parent)?;

    let stage = TempDir::new_in(&output_parent)?;
    let stage_root = stage.path();
    let library_dir = stage_root.join("lib");
    fs::create_dir_all(&library_dir)?;

    install_bundle_executable(
        &command.binary,
        &stage_root.join(bundle_entry_name(&command.binary)?),
    )?;
    copy_bundle_runtime_dependencies(
        &command.binary,
        &library_dir,
        &command.library_search_dir,
        false,
    )?;
    copy_bundle_ebpf_objects(stage_root, &command.build_dir, &command.ebpf)?;

    if command.tool_binary.is_empty() == false {
        let tools_dir = stage_root.join("tools");
        fs::create_dir_all(&tools_dir)?;
        for tool_binary in &command.tool_binary {
            if tool_binary.is_file() == false {
                bail!(
                    "bundle tool binary path does not exist: {}",
                    tool_binary.display()
                );
            }
            install_bundle_executable(
                tool_binary,
                &tools_dir.join(bundle_entry_name(tool_binary)?),
            )?;
            copy_bundle_runtime_dependencies(
                tool_binary,
                &library_dir,
                &command.library_search_dir,
                false,
            )?;
        }
    }

    emit_flat_bundle(stage_root, &command.output)?;
    println!("{}", command.output.display());
    Ok(())
}

pub fn fetch_remote(
    registry: &Registry,
    storage: &StorageRoot,
    remote_name: &str,
    image: &str,
    arch: Architecture,
    refresh: bool,
) -> Result<PathBuf> {
    ensure_root()?;
    reap_stale_builder_state(storage)?;
    let session = BuildSession::start(storage)?;
    let materialized = materialize_remote_base_root(
        registry,
        storage,
        &session,
        remote_name,
        image,
        arch,
        refresh,
    )?;
    Ok(materialized.root)
}

pub fn run_internal(command: InternalRunCommand) -> Result<()> {
    ensure_root()?;
    let env = command
        .env
        .iter()
        .map(|entry| parse_key_value(entry, "--env"))
        .collect::<Result<Vec<_>>>()?;
    let request = ContainerRunCommand {
        root: command.root,
        cwd: command.cwd,
        mounts: Vec::new(),
        env,
        emulator: command.emulator,
        executable: command.executable,
        argv: command.argv,
    };
    run_isolated_container_command(&request)
}

fn ensure_root() -> Result<()> {
    if unsafe { libc_geteuid() } != 0 {
        bail!("discombobulator must run as root");
    }

    Ok(())
}

unsafe fn libc_geteuid() -> u32 {
    unsafe extern "C" {
        fn geteuid() -> u32;
    }

    unsafe { geteuid() }
}

fn execute_supported_subset(
    registry: &Registry,
    storage: &StorageRoot,
    output_kind: OutputKind,
    publish_base: Option<&str>,
    resolved: &ResolvedBuildSpec,
    contexts: &BTreeMap<String, PathBuf>,
    output_path: &Path,
) -> Result<()> {
    let published_base = parse_named_base_ref(publish_base)?;
    if output_kind != OutputKind::Base && published_base.is_some() {
        bail!("--publish-base is only valid with --kind base");
    }

    match &resolved.from.source {
        FromSource::Scratch => {
            ensure_publishable_arch_matches_source(output_kind, published_base.as_ref(), resolved)?;
        }
        FromSource::LocalBase(_) => {}
        FromSource::Remote { remote, image, .. } => {
            registry
                .lookup_remote(remote)?
                .with_context(|| format!("unknown remote {remote}"))?;
            if image.trim().is_empty() {
                bail!("remote image reference must not be empty");
            }
        }
    }

    if output_kind == OutputKind::Base {
        if let Some((artifact_path, digest, size_bytes)) =
            try_reuse_fully_cached_base_artifact(storage, resolved, contexts)?
        {
            if let Some(parent) = output_path.parent() {
                fs::create_dir_all(parent)?;
            }
            materialize_output_blob(&artifact_path, output_path)?;
            maybe_inject_test_fault("registry-update");
            registry.upsert_artifact(&ArtifactRecord {
                kind: "base".to_string(),
                arch: resolved.from.arch.as_str().to_string(),
                name: published_base.as_ref().map(|(name, _)| name.clone()),
                tag: published_base.as_ref().map(|(_, tag)| tag.clone()),
                digest,
                path: artifact_path.display().to_string(),
                size_bytes,
            })?;
            println!("built {}", output_path.display());
            return Ok(());
        }
    }

    let session = BuildSession::start(storage)?;

    let runtime_root = session.work_root().join(METALOR_RUNTIME_DIR_NAME);
    let workspace_root = runtime_root.join("workspace");
    fs::create_dir_all(&workspace_root)?;

    let base_identity =
        materialize_base_into_workspace(registry, storage, &session, &workspace_root, resolved)?;

    let final_step_key = execute_steps(
        storage,
        &session,
        &workspace_root,
        &base_identity,
        resolved,
        contexts,
    )?;

    let artifact_root = match output_kind {
        OutputKind::App => {
            let projected_root = session.work_root().join("final");
            assemble_app_tree(&workspace_root, &projected_root, resolved)?;

            let artifact_root = session.work_root().join("artifact");
            fs::create_dir_all(artifact_root.join(".prodigy-private"))?;
            fs::rename(&projected_root, artifact_root.join("rootfs"))?;
            write_launch_metadata(
                &artifact_root.join(".prodigy-private/launch.metadata"),
                resolved,
            )?;
            artifact_root
        }
        OutputKind::Base => workspace_root.clone(),
    };

    if let Some(parent) = output_path.parent() {
        fs::create_dir_all(parent)?;
    }

    let artifact_kind = output_kind_name(output_kind);
    let (artifact_path, digest, size_bytes) = publish_cached_artifact(
        storage,
        &session,
        artifact_kind,
        resolved.from.arch,
        artifact_root.as_path(),
        if output_kind == OutputKind::Base {
            Some(base_artifact_cache_key_from_step_key(
                &final_step_key,
                resolved.from.arch,
            ))
        } else {
            None
        },
    )?;
    materialize_output_blob(&artifact_path, output_path)?;
    maybe_inject_test_fault("registry-update");
    registry.upsert_artifact(&ArtifactRecord {
        kind: artifact_kind.to_string(),
        arch: resolved.from.arch.as_str().to_string(),
        name: published_base.as_ref().map(|(name, _)| name.clone()),
        tag: published_base.as_ref().map(|(_, tag)| tag.clone()),
        digest,
        path: artifact_path.display().to_string(),
        size_bytes,
    })?;

    println!("built {}", output_path.display());
    Ok(())
}

fn output_kind_name(output_kind: OutputKind) -> &'static str {
    match output_kind {
        OutputKind::App => "app",
        OutputKind::Base => "base",
    }
}

fn reap_stale_builder_state(storage: &StorageRoot) -> Result<()> {
    let _lock = FileLockGuard::acquire(storage, "janitor", "global")?;
    remove_stale_entries_in_dir(&storage.work_dir(), true)?;
    remove_stale_entries_in_dir(&storage.tmp_dir(), false)?;
    reap_stale_unreferenced_cached_state(storage)?;
    Ok(())
}

fn remove_stale_entries_in_dir(root: &Path, session_only: bool) -> Result<()> {
    if root.exists() == false {
        return Ok(());
    }

    let now = SystemTime::now();
    let boot_id = current_boot_id();
    let mut entries =
        fs::read_dir(root)?.collect::<std::result::Result<Vec<_>, std::io::Error>>()?;
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        let path = entry.path();
        let file_name = entry.file_name();
        let file_name = file_name.to_string_lossy();
        let is_session_entry = file_name.starts_with("session-");
        if session_only && is_session_entry == false {
            continue;
        }
        let should_reap = if is_session_entry {
            is_stale_entry(&path, now)? || session_entry_process_is_dead(&path, boot_id.as_deref())?
        } else {
            is_stale_entry(&path, now)?
        };
        if should_reap {
            remove_existing_path(&path)?;
        }
    }

    Ok(())
}

fn is_stale_entry(path: &Path, now: SystemTime) -> Result<bool> {
    let metadata = fs::metadata(path)?;
    let modified = metadata.modified().unwrap_or(now);
    let age = now.duration_since(modified).unwrap_or_default();
    Ok(age >= SESSION_STALE_AFTER)
}

fn current_boot_id() -> Option<String> {
    fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| value.is_empty() == false)
}

fn session_entry_process_is_dead(path: &Path, current_boot_id: Option<&str>) -> Result<bool> {
    let lease_path = path.join("lease.json");
    if lease_path.exists() == false {
        return Ok(false);
    }
    let lease: SessionLease = serde_json::from_slice(&fs::read(&lease_path)?)
        .with_context(|| format!("failed to parse session lease {}", lease_path.display()))?;
    if let (Some(expected), Some(current)) = (lease.boot_id.as_deref(), current_boot_id) {
        if expected != current {
            return Ok(true);
        }
    }
    if lease.pid == std::process::id() {
        return Ok(false);
    }
    Ok(Path::new("/proc").join(lease.pid.to_string()).exists() == false)
}

fn reap_stale_unreferenced_cached_state(storage: &StorageRoot) -> Result<()> {
    let registry = Registry::open(storage)?;
    let referenced_artifacts: BTreeSet<PathBuf> =
        registry.list_artifact_paths()?.into_iter().collect();
    let referenced_imports: BTreeSet<PathBuf> =
        registry.list_oci_import_paths()?.into_iter().collect();
    remove_stale_unreferenced_artifacts(storage, &referenced_artifacts)?;
    remove_stale_unreferenced_imports(storage, &referenced_imports)?;
    Ok(())
}

fn remove_stale_unreferenced_artifacts(
    storage: &StorageRoot,
    referenced_artifacts: &BTreeSet<PathBuf>,
) -> Result<()> {
    for kind in ["apps", "bases"] {
        let kind_root = storage.root().join("artifacts").join(kind);
        remove_stale_unreferenced_leaf_entries(&kind_root, referenced_artifacts)?;
    }
    Ok(())
}

fn remove_stale_unreferenced_imports(
    storage: &StorageRoot,
    referenced_imports: &BTreeSet<PathBuf>,
) -> Result<()> {
    remove_stale_unreferenced_leaf_entries(&storage.imports_dir(), referenced_imports)
}

fn remove_stale_unreferenced_leaf_entries(
    root: &Path,
    referenced_paths: &BTreeSet<PathBuf>,
) -> Result<()> {
    if root.exists() == false {
        return Ok(());
    }

    let now = SystemTime::now();
    let mut arch_entries =
        fs::read_dir(root)?.collect::<std::result::Result<Vec<_>, std::io::Error>>()?;
    arch_entries.sort_by_key(|entry| entry.file_name());
    for arch_entry in arch_entries {
        if arch_entry.file_type()?.is_dir() == false {
            continue;
        }
        let mut entries = fs::read_dir(arch_entry.path())?
            .collect::<std::result::Result<Vec<_>, std::io::Error>>()?;
        entries.sort_by_key(|entry| entry.file_name());
        for entry in entries {
            let path = entry.path();
            if referenced_paths.contains(&path) {
                continue;
            }
            if is_stale_entry(&path, now)? {
                remove_existing_path(&path)?;
            }
        }
    }

    Ok(())
}

fn parse_contexts(raw_contexts: &[String]) -> Result<BTreeMap<String, PathBuf>> {
    let mut contexts = BTreeMap::new();
    for raw in raw_contexts {
        let (name, value) = parse_key_value(raw, "--context")?;
        let path = PathBuf::from(value);
        let absolute = if path.is_absolute() {
            path
        } else {
            std::env::current_dir()?.join(path)
        };
        if absolute.is_dir() == false {
            bail!("context {} is not a directory", absolute.display());
        }
        contexts.insert(name, absolute);
    }
    Ok(contexts)
}

fn bundle_entry_name(path: &Path) -> Result<&OsStr> {
    path.file_name()
        .with_context(|| format!("bundle path has no file name: {}", path.display()))
}

fn install_bundle_executable(source: &Path, destination: &Path) -> Result<()> {
    if let Some(parent) = destination.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::copy(source, destination).with_context(|| {
        format!(
            "failed to install bundle executable {} to {}",
            source.display(),
            destination.display()
        )
    })?;
    fs::set_permissions(destination, fs::Permissions::from_mode(0o755))?;
    Ok(())
}

fn copy_bundle_runtime_dependencies(
    binary_path: &Path,
    output_dir: &Path,
    library_search_dirs: &[PathBuf],
    copy_builder_toolchain_runtimes: bool,
) -> Result<()> {
    let mut copied_names = BTreeSet::new();
    for dependency in read_ldd_dependencies(binary_path)? {
        let Some(dep_name) = dependency.file_name().and_then(OsStr::to_str) else {
            continue;
        };
        if should_skip_bundle_dependency(dep_name, copy_builder_toolchain_runtimes) {
            continue;
        }
        if copied_names.insert(dep_name.to_string()) == false {
            continue;
        }
        copy_bundle_file_following_symlinks(&dependency, &output_dir.join(dep_name))?;
    }

    if is_elf(binary_path)? == false {
        return Ok(());
    }

    let mut unresolved = Vec::new();
    for dependency_name in read_elf_needed_libraries(binary_path)? {
        if should_skip_bundle_dependency(&dependency_name, copy_builder_toolchain_runtimes) {
            continue;
        }
        if copied_names.contains(&dependency_name) {
            continue;
        }
        if let Some(resolved_path) =
            resolve_bundle_dependency_by_name(library_search_dirs, &dependency_name)
        {
            copy_bundle_file_following_symlinks(
                &resolved_path,
                &output_dir.join(&dependency_name),
            )?;
            copied_names.insert(dependency_name);
        } else {
            unresolved.push(dependency_name);
        }
    }

    if unresolved.is_empty() == false {
        bail!(
            "unable to resolve bundle runtime dependencies for {}: {}",
            binary_path.display(),
            unresolved.join(" ")
        );
    }

    Ok(())
}

fn should_skip_bundle_dependency(
    dependency_name: &str,
    copy_builder_toolchain_runtimes: bool,
) -> bool {
    if dependency_name.starts_with("ld-linux-")
        || dependency_name.starts_with("libnss_")
        || matches!(
            dependency_name,
            "libc.so.6"
                | "libm.so.6"
                | "libresolv.so.2"
                | "libdl.so.2"
                | "libpthread.so.0"
                | "librt.so.1"
                | "libutil.so.1"
                | "libanl.so.1"
                | "libmemusage.so"
                | "libBrokenLocale.so.1"
        )
    {
        return true;
    }

    if copy_builder_toolchain_runtimes == false
        && matches!(dependency_name, "libstdc++.so.6" | "libgcc_s.so.1")
    {
        return true;
    }

    false
}

fn resolve_bundle_dependency_by_name(
    library_search_dirs: &[PathBuf],
    dependency_name: &str,
) -> Option<PathBuf> {
    for search_dir in library_search_dirs {
        if search_dir.is_dir() == false {
            continue;
        }
        let candidate = search_dir.join(dependency_name);
        if candidate.exists() {
            return Some(candidate);
        }
    }
    None
}

fn copy_bundle_file_following_symlinks(source: &Path, destination: &Path) -> Result<()> {
    let resolved = source
        .canonicalize()
        .unwrap_or_else(|_| source.to_path_buf());
    if let Some(parent) = destination.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::copy(&resolved, destination).with_context(|| {
        format!(
            "failed to copy bundle dependency {} to {}",
            resolved.display(),
            destination.display()
        )
    })?;
    let permissions = fs::metadata(&resolved)?.permissions();
    fs::set_permissions(destination, permissions)?;
    Ok(())
}

fn copy_bundle_ebpf_objects(
    stage_root: &Path,
    build_dir: &Path,
    ebpf_files: &[PathBuf],
) -> Result<()> {
    for ebpf_file in ebpf_files {
        if ebpf_file.as_os_str().is_empty() {
            continue;
        }
        let destination = stage_root.join(bundle_entry_name(ebpf_file)?);
        fs::copy(ebpf_file, &destination).with_context(|| {
            format!(
                "failed to copy bundle eBPF object {} to {}",
                ebpf_file.display(),
                destination.display()
            )
        })?;
    }

    let mut entries =
        fs::read_dir(build_dir)?.collect::<std::result::Result<Vec<_>, std::io::Error>>()?;
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        let path = entry.path();
        if entry.file_type()?.is_file() == false {
            continue;
        }
        if path
            .file_name()
            .and_then(OsStr::to_str)
            .map(|name| name.ends_with(".ebpf.o"))
            .unwrap_or(false)
            == false
        {
            continue;
        }
        let destination = stage_root.join(bundle_entry_name(&path)?);
        fs::copy(&path, &destination).with_context(|| {
            format!(
                "failed to copy generated bundle eBPF object {} to {}",
                path.display(),
                destination.display()
            )
        })?;
    }
    Ok(())
}

fn emit_flat_bundle(stage_root: &Path, output_path: &Path) -> Result<()> {
    let output_parent = output_path
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or(std::env::current_dir()?);
    fs::create_dir_all(&output_parent)?;
    let output_temp = output_path.with_extension("tmp");
    let mut command = Command::new("tar");
    command
        .arg("--zstd")
        .arg("--sort=name")
        .arg("--mtime=UTC 2024-01-01")
        .arg("--owner=0")
        .arg("--group=0")
        .arg("--numeric-owner")
        .arg("--pax-option=delete=atime,delete=ctime")
        .arg("-cf")
        .arg(&output_temp)
        .arg("-C")
        .arg(stage_root)
        .arg(".");
    run_command(&mut command, "flat bundle archive creation")?;
    fs::rename(&output_temp, output_path)?;
    Ok(())
}

fn parse_build_args(raw_build_args: &[String]) -> Result<BTreeMap<String, String>> {
    let mut build_args = BTreeMap::new();
    for raw in raw_build_args {
        let (name, value) = parse_key_value(raw, "--build-arg")?;
        build_args.insert(name, value);
    }
    Ok(build_args)
}

fn materialize_base_into_workspace(
    registry: &Registry,
    storage: &StorageRoot,
    session: &BuildSession,
    workspace_root: &Path,
    resolved: &ResolvedBuildSpec,
) -> Result<String> {
    match &resolved.from.source {
        FromSource::Scratch => Ok(format!("scratch:{}", resolved.from.arch.as_str())),
        FromSource::LocalBase(reference) => {
            let (base_name, base_tag) = split_named_base_ref(reference)?;
            let artifact = registry
                .lookup_named_base(&base_name, &base_tag, resolved.from.arch.as_str())?
                .with_context(|| {
                    format!(
                        "unknown local base {reference} for architecture {}",
                        resolved.from.arch.as_str()
                    )
                })?;
            let import_mount =
                LoopbackBtrfs::from_blob_in(session.tmp_root(), Path::new(&artifact.path))?;
            let imported_root = import_mount.receive_blob(Path::new(&artifact.path))?;
            copy_tree(&imported_root, workspace_root)?;
            Ok(format!("local-base:{}", artifact.digest))
        }
        FromSource::Remote {
            remote,
            image,
            force_refresh,
        } => {
            let materialized = materialize_remote_base_root(
                registry,
                storage,
                session,
                remote,
                image,
                resolved.from.arch,
                *force_refresh,
            )?;
            copy_tree(&materialized.root, workspace_root)?;
            Ok(materialized.identity)
        }
    }
}

fn execute_steps(
    storage: &StorageRoot,
    session: &BuildSession,
    workspace_root: &Path,
    base_identity: &str,
    resolved: &ResolvedBuildSpec,
    contexts: &BTreeMap<String, PathBuf>,
) -> Result<String> {
    let host_arch = host_architecture()?;
    let mut parent_key = seed_step_cache_key(base_identity, resolved.from.arch);
    for step in &resolved.steps {
        let step_key = compute_step_cache_key(&parent_key, resolved.from.arch, step, contexts)?;
        let cache_root = storage.step_cache_root(resolved.from.arch.as_str(), &step_key);
        let cached_rootfs = cache_root.join("rootfs");
        if cached_rootfs.exists() {
            restore_workspace_from_cache(&cached_rootfs, workspace_root)?;
            parent_key = step_key;
            continue;
        }

        let _lock = FileLockGuard::acquire(
            storage,
            "step-cache",
            &format!("{}:{step_key}", resolved.from.arch.as_str()),
        )?;
        if cached_rootfs.exists() {
            restore_workspace_from_cache(&cached_rootfs, workspace_root)?;
            parent_key = step_key;
            continue;
        }

        match step {
            ResolvedBuildStep::Copy(copy) => apply_copy(workspace_root, copy, contexts)?,
            ResolvedBuildStep::Run(run) => {
                execute_run_step(workspace_root, host_arch, resolved.from.arch, run)?
            }
        }
        publish_step_cache(
            storage,
            session,
            resolved.from.arch,
            &step_key,
            workspace_root,
        )?;
        parent_key = step_key;
    }
    Ok(parent_key)
}

fn execute_run_step(
    workspace_root: &Path,
    host_arch: Architecture,
    target_arch: Architecture,
    run: &ResolvedRun,
) -> Result<()> {
    let env_pairs = build_run_env_pairs(&run.env);
    fs::create_dir_all(workspace_root.join(run.workdir.trim_start_matches('/')))?;
    let executable =
        resolve_run_executable(workspace_root, &run.workdir, &run.argv[0], &env_pairs)?;
    let emulator = install_run_emulator(workspace_root, host_arch, target_arch)?;
    let current_exe =
        std::env::current_exe().context("failed to locate discombobulator executable")?;
    let request = ContainerRunCommand {
        root: workspace_root.to_path_buf(),
        cwd: run.workdir.clone(),
        mounts: Vec::new(),
        env: env_pairs,
        emulator,
        executable,
        argv: run.argv[1..].to_vec(),
    };
    let mut command = build_unshare_reexec_command(
        &current_exe,
        "internal-run",
        workspace_root.parent().with_context(|| {
            format!(
                "missing metalor runtime root for workspace {}",
                workspace_root.display()
            )
        })?,
        &request,
    )?;
    let result = run_command(&mut command, "RUN execution");
    cleanup_run_emulator(workspace_root)?;
    result
}

fn seed_step_cache_key(base_identity: &str, arch: Architecture) -> String {
    let mut hasher = Sha256::new();
    hasher.update(STEP_CACHE_VERSION.as_bytes());
    hasher.update(b"\nbase\n");
    hasher.update(base_identity.as_bytes());
    hasher.update(b"\narch\n");
    hasher.update(arch.as_str().as_bytes());
    hex::encode(hasher.finalize())
}

fn base_artifact_cache_key_from_step_key(step_key: &str, arch: Architecture) -> String {
    let mut hasher = Sha256::new();
    hasher.update(ARTIFACT_CACHE_VERSION.as_bytes());
    hasher.update(b"\nbase-step\n");
    hasher.update(arch.as_str().as_bytes());
    hasher.update(b"\n");
    hasher.update(step_key.as_bytes());
    hex::encode(hasher.finalize())
}

fn try_reuse_fully_cached_base_artifact(
    storage: &StorageRoot,
    resolved: &ResolvedBuildSpec,
    contexts: &BTreeMap<String, PathBuf>,
) -> Result<Option<(PathBuf, String, i64)>> {
    if matches!(&resolved.from.source, FromSource::Scratch) == false {
        return Ok(None);
    }

    let mut parent_key = seed_step_cache_key(
        &format!("scratch:{}", resolved.from.arch.as_str()),
        resolved.from.arch,
    );
    for step in &resolved.steps {
        let step_key = compute_step_cache_key(&parent_key, resolved.from.arch, step, contexts)?;
        let cached_rootfs = storage
            .step_cache_root(resolved.from.arch.as_str(), &step_key)
            .join("rootfs");
        if cached_rootfs.exists() == false {
            return Ok(None);
        }
        parent_key = step_key;
    }

    let artifact_key = base_artifact_cache_key_from_step_key(&parent_key, resolved.from.arch);
    let cached_artifact =
        storage.artifact_blob_path("base", resolved.from.arch.as_str(), &artifact_key);
    if cached_artifact.exists() {
        return Ok(Some(cached_artifact_metadata(cached_artifact)?));
    }

    Ok(None)
}

fn compute_step_cache_key(
    parent_key: &str,
    arch: Architecture,
    step: &ResolvedBuildStep,
    contexts: &BTreeMap<String, PathBuf>,
) -> Result<String> {
    let mut hasher = Sha256::new();
    hasher.update(STEP_CACHE_VERSION.as_bytes());
    hasher.update(b"\nparent\n");
    hasher.update(parent_key.as_bytes());
    hasher.update(b"\narch\n");
    hasher.update(arch.as_str().as_bytes());
    match step {
        ResolvedBuildStep::Copy(copy) => {
            let context_root = contexts
                .get(&copy.context)
                .with_context(|| format!("undefined context {}", copy.context))?;
            let matches = resolve_context_matches(context_root, &copy.source)?;
            if matches.is_empty() {
                bail!(
                    "COPY source {} matched nothing in context {}",
                    copy.source,
                    copy.context
                );
            }
            hasher.update(b"\nstep\nCOPY\n");
            hasher.update(serde_json::to_vec(copy)?);
            for source in matches {
                hash_copy_source(&mut hasher, context_root, &source)?;
            }
        }
        ResolvedBuildStep::Run(run) => {
            hasher.update(b"\nstep\nRUN\n");
            hasher.update(serde_json::to_vec(run)?);
            hasher.update(b"\nnetwork\nenabled\n");
        }
    }
    Ok(hex::encode(hasher.finalize()))
}

fn hash_copy_source(hasher: &mut Sha256, context_root: &Path, source: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(source)?;
    let relative = source.strip_prefix(context_root).with_context(|| {
        format!(
            "COPY source escapes the named context root: {}",
            source.display()
        )
    })?;
    let relative = path_to_unix(relative);
    hasher.update(b"\npath\n");
    hasher.update(relative.as_bytes());
    hasher.update(b"\nmode\n");
    hasher.update(metadata.permissions().mode().to_le_bytes());

    if metadata.file_type().is_socket() {
        bail!("COPY rejects sockets: {}", source.display());
    }
    if metadata.file_type().is_block_device()
        || metadata.file_type().is_char_device()
        || metadata.file_type().is_fifo()
    {
        bail!("COPY rejects special files: {}", source.display());
    }

    if metadata.file_type().is_symlink() {
        let target = fs::read_link(source)?;
        ensure_context_symlink_target(context_root, source, &target)?;
        hasher.update(b"\ntype\nsymlink\n");
        hasher.update(target.as_os_str().as_bytes());
        return Ok(());
    }

    if metadata.is_dir() {
        hasher.update(b"\ntype\ndir\n");
        let mut children =
            fs::read_dir(source)?.collect::<std::result::Result<Vec<_>, std::io::Error>>()?;
        children.sort_by_key(|entry| entry.file_name());
        for child in children {
            hash_copy_source(hasher, context_root, &child.path())?;
        }
        return Ok(());
    }

    hasher.update(b"\ntype\nfile\n");
    let bytes = fs::read(source)?;
    hasher.update(sha256_prefixed(&bytes).as_bytes());
    Ok(())
}

fn ensure_context_symlink_target(context_root: &Path, source: &Path, target: &Path) -> Result<()> {
    let resolved_target = if target.is_absolute() {
        PathBuf::from(target)
    } else {
        source.parent().unwrap_or(context_root).join(target)
    };
    let canonical_root = context_root
        .canonicalize()
        .unwrap_or_else(|_| context_root.to_path_buf());
    let canonical_target = resolved_target.canonicalize().unwrap_or(resolved_target);
    if canonical_target.starts_with(&canonical_root) == false {
        bail!(
            "COPY symlink escapes the named context root: {}",
            source.display()
        );
    }
    Ok(())
}

fn restore_workspace_from_cache(cached_rootfs: &Path, workspace_root: &Path) -> Result<()> {
    clear_directory(workspace_root)?;
    copy_tree(cached_rootfs, workspace_root)
}

fn publish_step_cache(
    storage: &StorageRoot,
    session: &BuildSession,
    arch: Architecture,
    step_key: &str,
    workspace_root: &Path,
) -> Result<()> {
    let cache_root = storage.step_cache_root(arch.as_str(), step_key);
    if cache_root.exists() {
        return Ok(());
    }

    let staging = TempDir::new_in(session.tmp_root())?;
    let staged_cache_root = staging.path().join("step-cache");
    let staged_rootfs = staged_cache_root.join("rootfs");
    copy_tree(workspace_root, &staged_rootfs)?;
    fs::write(
        staged_cache_root.join("metadata.json"),
        serde_json::to_vec_pretty(&serde_json::json!({
            "version": STEP_CACHE_VERSION,
            "arch": arch.as_str(),
            "step_key": step_key,
        }))?,
    )?;

    if let Some(parent) = cache_root.parent() {
        fs::create_dir_all(parent)?;
    }
    match fs::rename(&staged_cache_root, &cache_root) {
        Ok(()) => Ok(()),
        Err(error) if cache_root.exists() => {
            let _ = error;
            Ok(())
        }
        Err(error) => Err(error)
            .with_context(|| format!("failed to publish step cache {}", cache_root.display())),
    }
}

fn build_run_env_pairs(env: &[(String, String)]) -> Vec<(String, String)> {
    let mut pairs = env.to_vec();
    if env.iter().any(|(key, _)| key == "PATH") == false {
        pairs.push((
            "PATH".to_string(),
            "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".to_string(),
        ));
    }
    pairs
}

fn resolve_run_executable(
    workspace_root: &Path,
    workdir: &str,
    executable: &str,
    env_pairs: &[(String, String)],
) -> Result<String> {
    let candidate = if executable.contains('/') {
        resolve_container_path(workdir, executable)?
    } else {
        let path_value = env_pairs
            .iter()
            .rev()
            .find(|(key, _)| key == "PATH")
            .map(|(_, value)| value.as_str())
            .unwrap_or("/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin");
        find_executable_in_path(workspace_root, path_value, executable)?
            .with_context(|| format!("RUN executable {executable} was not found in build root"))?
    };

    let host_path = workspace_root.join(candidate.trim_start_matches('/'));
    if host_path.exists() == false {
        bail!(
            "RUN executable {candidate} was not found in build root at {}",
            host_path.display()
        );
    }
    Ok(candidate)
}

fn find_executable_in_path(
    workspace_root: &Path,
    path_value: &str,
    executable: &str,
) -> Result<Option<String>> {
    for directory in path_value.split(':') {
        if directory.is_empty() {
            continue;
        }
        let candidate = normalize_absolute_path(&Path::new(directory).join(executable))?;
        let host_path = workspace_root.join(candidate.trim_start_matches('/'));
        if host_path.is_file() {
            return Ok(Some(candidate));
        }
    }
    Ok(None)
}

fn host_architecture() -> Result<Architecture> {
    match std::env::consts::ARCH {
        "x86_64" => Ok(Architecture::X86_64),
        "aarch64" => Ok(Architecture::Arm64),
        "riscv64" => Ok(Architecture::Riscv64),
        other => bail!("unsupported host architecture {other}"),
    }
}

fn required_qemu_binary(arch: Architecture) -> &'static str {
    match arch {
        Architecture::X86_64 => "qemu-x86_64-static",
        Architecture::Arm64 => "qemu-aarch64-static",
        Architecture::Riscv64 => "qemu-riscv64-static",
    }
}

fn find_tool_in_path(tool: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    for directory in std::env::split_paths(&path) {
        let candidate = directory.join(tool);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

fn install_run_emulator(
    workspace_root: &Path,
    host_arch: Architecture,
    target_arch: Architecture,
) -> Result<Option<String>> {
    if host_arch == target_arch {
        return Ok(None);
    }

    let required_qemu = required_qemu_binary(target_arch);
    let host_qemu_path = find_tool_in_path(required_qemu).with_context(|| {
        format!(
            "RUN execution for target architecture {} on host {} requires {} because this build step executes foreign-architecture binaries inside the target rootfs. Install qemu-user-static or otherwise make {} available in PATH. Cross-architecture builds that do not execute foreign-architecture RUN steps do not require QEMU.",
            target_arch.as_str(),
            host_arch.as_str(),
            required_qemu,
            required_qemu
        )
    })?;
    let resolved_host_qemu = host_qemu_path.canonicalize().unwrap_or(host_qemu_path);
    let emulator_path = helper_binary_path(required_qemu);
    let host_destination = workspace_root.join(emulator_path.trim_start_matches('/'));
    if let Some(parent) = host_destination.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::copy(&resolved_host_qemu, &host_destination).with_context(|| {
        format!(
            "failed to install {} into build root at {}",
            required_qemu,
            host_destination.display()
        )
    })?;
    let mode = fs::metadata(&resolved_host_qemu)?.permissions().mode();
    fs::set_permissions(&host_destination, fs::Permissions::from_mode(mode))?;
    Ok(Some(emulator_path))
}

fn cleanup_run_emulator(workspace_root: &Path) -> Result<()> {
    let helper_root = workspace_root.join(RUN_HELPER_DIR.trim_start_matches('/'));
    if helper_root.exists() {
        remove_existing_path(&helper_root)?;
    }
    Ok(())
}

fn materialize_remote_base_root(
    registry: &Registry,
    storage: &StorageRoot,
    session: &BuildSession,
    remote_name: &str,
    image: &str,
    arch: Architecture,
    force_refresh: bool,
) -> Result<MaterializedBase> {
    if force_refresh == false {
        if let Some(import_record) =
            registry.lookup_oci_import(remote_name, image, arch.as_str())?
        {
            let rootfs = Path::new(&import_record.path).join("rootfs");
            if rootfs.exists() {
                registry.touch_remote_last_used(remote_name)?;
                registry.touch_oci_import_last_used(remote_name, image, arch.as_str())?;
                return Ok(MaterializedBase {
                    root: rootfs,
                    identity: format!("remote-manifest:{}", import_record.manifest_digest),
                });
            }
        }
    }

    let remote = registry
        .lookup_remote(remote_name)?
        .with_context(|| format!("unknown remote {remote_name}"))?;
    let _lock = FileLockGuard::acquire(
        storage,
        "oci-import",
        &format!("{}:{remote_name}:{image}", arch.as_str()),
    )?;
    if force_refresh == false {
        if let Some(import_record) =
            registry.lookup_oci_import(remote_name, image, arch.as_str())?
        {
            let rootfs = Path::new(&import_record.path).join("rootfs");
            if rootfs.exists() {
                registry.touch_remote_last_used(remote_name)?;
                registry.touch_oci_import_last_used(remote_name, image, arch.as_str())?;
                return Ok(MaterializedBase {
                    root: rootfs,
                    identity: format!("remote-manifest:{}", import_record.manifest_digest),
                });
            }
        }
    }
    let client = RegistryHttpClient::new(&remote)?;
    let image_reference = parse_remote_image_reference(image)?;
    let resolved_image = resolve_remote_image(&client, &remote, &image_reference, arch)?;
    let import_root = storage.import_root(arch.as_str(), &resolved_image.manifest_digest);
    let rootfs = import_root.join("rootfs");
    if rootfs.exists() {
        let identity = format!("remote-manifest:{}", resolved_image.manifest_digest);
        maybe_inject_test_fault("registry-update");
        registry.upsert_oci_import(&OciImportRecord {
            remote_name: remote_name.to_string(),
            image: image.to_string(),
            arch: arch.as_str().to_string(),
            manifest_digest: resolved_image.manifest_digest,
            path: import_root.display().to_string(),
        })?;
        registry.touch_remote_last_used(remote_name)?;
        return Ok(MaterializedBase {
            root: rootfs,
            identity,
        });
    }

    let import_staging = TempDir::new_in(session.tmp_root())?;
    let staged_import_root = import_staging.path().join("import");
    let staged_rootfs = staged_import_root.join("rootfs");
    fs::create_dir_all(&staged_rootfs)?;

    for layer in &resolved_image.layers {
        let bytes = client.fetch_blob(&resolved_image.repository, &layer.digest)?;
        unpack_oci_layer(&bytes, layer.media_type.as_deref(), &staged_rootfs)?;
        maybe_inject_test_fault("remote-layer-unpack");
    }

    fs::write(
        staged_import_root.join("metadata.json"),
        serde_json::to_vec_pretty(&ImportedOciMetadata {
            remote_name: remote_name.to_string(),
            image: image.to_string(),
            arch: arch.as_str().to_string(),
            repository: resolved_image.repository.clone(),
            manifest_digest: resolved_image.manifest_digest.clone(),
        })?,
    )?;

    if let Some(parent) = import_root.parent() {
        fs::create_dir_all(parent)?;
    }
    match fs::rename(&staged_import_root, &import_root) {
        Ok(()) => {}
        Err(error) if import_root.exists() => {
            let _ = error;
        }
        Err(error) => {
            return Err(error).with_context(|| {
                format!(
                    "failed to publish cached OCI import {}",
                    import_root.display()
                )
            });
        }
    }

    let identity = format!("remote-manifest:{}", resolved_image.manifest_digest);
    maybe_inject_test_fault("registry-update");
    registry.upsert_oci_import(&OciImportRecord {
        remote_name: remote_name.to_string(),
        image: image.to_string(),
        arch: arch.as_str().to_string(),
        manifest_digest: resolved_image.manifest_digest,
        path: import_root.display().to_string(),
    })?;
    registry.touch_remote_last_used(remote_name)?;
    Ok(MaterializedBase {
        root: import_root.join("rootfs"),
        identity,
    })
}

#[derive(Clone, Debug)]
struct ParsedRemoteImage {
    repository: String,
    reference: String,
}

#[derive(Clone, Debug)]
struct ResolvedRemoteImage {
    repository: String,
    manifest_digest: String,
    layers: Vec<OciBlobDescriptor>,
}

#[derive(Clone, Debug, Deserialize)]
struct OciManifestList {
    manifests: Vec<OciPlatformDescriptor>,
}

#[derive(Clone, Debug, Deserialize)]
struct OciPlatformDescriptor {
    #[serde(rename = "mediaType")]
    media_type: Option<String>,
    digest: String,
    platform: Option<OciPlatform>,
}

#[derive(Clone, Debug, Deserialize)]
struct OciManifest {
    config: OciBlobDescriptor,
    layers: Vec<OciBlobDescriptor>,
}

#[derive(Clone, Debug, Deserialize)]
struct OciBlobDescriptor {
    #[serde(rename = "mediaType")]
    media_type: Option<String>,
    digest: String,
}

#[derive(Clone, Debug, Deserialize)]
struct OciPlatform {
    architecture: Option<String>,
    os: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
struct OciConfigBlob {
    architecture: Option<String>,
    os: Option<String>,
}

#[derive(Serialize)]
struct ImportedOciMetadata {
    remote_name: String,
    image: String,
    arch: String,
    repository: String,
    manifest_digest: String,
}

struct HttpBytesResponse {
    bytes: Vec<u8>,
    digest: Option<String>,
}

struct RegistryHttpClient {
    client: HttpClient,
    base_url: String,
    basic_auth: Option<(String, String)>,
    bearer_token: RefCell<Option<String>>,
}

impl RegistryHttpClient {
    fn new(remote: &RemoteRecord) -> Result<Self> {
        Ok(Self {
            client: HttpClient::builder().build()?,
            base_url: registry_base_url(&remote.registry_host),
            basic_auth: load_registry_basic_auth(&remote.registry_host),
            bearer_token: RefCell::new(None),
        })
    }

    fn fetch_manifest(&self, repository: &str, reference: &str) -> Result<HttpBytesResponse> {
        let response = self.get_bytes(
            &format!("/v2/{repository}/manifests/{reference}"),
            Some(
                "application/vnd.oci.image.index.v1+json,\
                 application/vnd.docker.distribution.manifest.list.v2+json,\
                 application/vnd.oci.image.manifest.v1+json,\
                 application/vnd.docker.distribution.manifest.v2+json",
            ),
        )?;
        maybe_inject_test_fault("remote-manifest-fetch");
        Ok(response)
    }

    fn fetch_blob(&self, repository: &str, digest: &str) -> Result<Vec<u8>> {
        let bytes = self
            .get_bytes(&format!("/v2/{repository}/blobs/{digest}"), None)?
            .bytes;
        maybe_inject_test_fault("remote-layer-download");
        Ok(bytes)
    }

    fn get_bytes(&self, path: &str, accept: Option<&str>) -> Result<HttpBytesResponse> {
        let url = format!("{}{}", self.base_url, path);
        let first = self.issue_request(&url, accept, self.bearer_token.borrow().as_deref())?;
        if first.status() == StatusCode::UNAUTHORIZED {
            let challenge = first
                .headers()
                .get(WWW_AUTHENTICATE)
                .context("registry returned 401 without WWW-Authenticate")?
                .to_str()
                .context("registry returned invalid WWW-Authenticate header")?
                .to_string();
            let (scheme, _) = parse_www_authenticate(&challenge)?;
            if scheme.eq_ignore_ascii_case("Basic") {
                if self.basic_auth.is_some() {
                    bail!(
                        "registry request to {url} failed: configured DOCKER_CONFIG basic auth was rejected"
                    );
                }
                bail!(
                    "registry request to {url} requires basic auth and no matching DOCKER_CONFIG credentials were found"
                );
            }
            let token = self.obtain_bearer_token(&challenge)?;
            self.bearer_token.replace(Some(token.clone()));
            let retry = self.issue_request(&url, accept, Some(&token))?;
            return self.finish_response(retry, &url);
        }

        self.finish_response(first, &url)
    }

    fn issue_request(
        &self,
        url: &str,
        accept: Option<&str>,
        bearer_token: Option<&str>,
    ) -> Result<reqwest::blocking::Response> {
        let mut request = self.client.get(url);
        if let Some(value) = accept {
            request = request.header(ACCEPT, value);
        }
        if let Some((username, password)) = &self.basic_auth {
            request = request.basic_auth(username, Some(password));
        }
        if let Some(token) = bearer_token {
            request = request.header(AUTHORIZATION, format!("Bearer {token}"));
        }
        request
            .send()
            .with_context(|| format!("failed to fetch {url}"))
    }

    fn finish_response(
        &self,
        response: reqwest::blocking::Response,
        url: &str,
    ) -> Result<HttpBytesResponse> {
        let status = response.status();
        let digest = response
            .headers()
            .get("Docker-Content-Digest")
            .and_then(|value| value.to_str().ok())
            .map(|value| value.to_string());
        let bytes = response
            .bytes()
            .with_context(|| format!("failed to read registry response body from {url}"))?;
        if status.is_success() == false {
            bail!(
                "registry request to {url} failed with {}: {}",
                status,
                String::from_utf8_lossy(&bytes)
            );
        }
        Ok(HttpBytesResponse {
            bytes: bytes.to_vec(),
            digest,
        })
    }

    fn obtain_bearer_token(&self, challenge: &str) -> Result<String> {
        let (scheme, parameters) = parse_www_authenticate(challenge)?;
        if scheme.eq_ignore_ascii_case("Bearer") == false {
            bail!("unsupported registry auth challenge: {challenge}");
        }

        let realm = parameters
            .get("realm")
            .context("registry auth challenge missing realm")?;
        let mut url = reqwest::Url::parse(realm)?;
        {
            let mut query = url.query_pairs_mut();
            if let Some(service) = parameters.get("service") {
                query.append_pair("service", service);
            }
            if let Some(scope) = parameters.get("scope") {
                query.append_pair("scope", scope);
            }
        }

        let mut request = self.client.get(url);
        if let Some((username, password)) = &self.basic_auth {
            request = request.basic_auth(username, Some(password));
        }
        let response = request
            .send()
            .context("failed to request registry bearer token")?;
        let status = response.status();
        let body = response
            .bytes()
            .context("failed to read registry token body")?;
        if status.is_success() == false {
            bail!(
                "registry token request failed with {}: {}",
                status,
                String::from_utf8_lossy(&body)
            );
        }
        let value: serde_json::Value = serde_json::from_slice(&body)?;
        value
            .get("token")
            .or_else(|| value.get("access_token"))
            .and_then(|token| token.as_str())
            .map(|token| token.to_string())
            .context("registry token response missing token")
    }
}

fn resolve_remote_image(
    client: &RegistryHttpClient,
    remote: &RemoteRecord,
    image: &ParsedRemoteImage,
    arch: Architecture,
) -> Result<ResolvedRemoteImage> {
    let repository =
        apply_remote_repository_prefix(remote.repository_prefix.as_deref(), &image.repository);
    let manifest_response = client.fetch_manifest(&repository, &image.reference)?;
    let manifest_value: serde_json::Value = serde_json::from_slice(&manifest_response.bytes)?;

    if manifest_value.get("manifests").is_some() {
        let manifest_list: OciManifestList = serde_json::from_value(manifest_value)?;
        let selected = manifest_list
            .manifests
            .into_iter()
            .find(|descriptor| platform_matches_target(descriptor.platform.as_ref(), arch))
            .with_context(|| {
                format!(
                    "no linux/{} manifest found for remote image {}",
                    arch.as_str(),
                    image.reference
                )
            })?;
        if let Some(media_type) = selected.media_type.as_deref() {
            let supported = media_type.contains("manifest");
            if supported == false {
                bail!("unsupported manifest descriptor media type {media_type}");
            }
        }
        let child_response = client.fetch_manifest(&repository, &selected.digest)?;
        let child_digest = child_response
            .digest
            .unwrap_or_else(|| selected.digest.clone());
        return resolve_remote_manifest(
            client,
            &repository,
            &child_response.bytes,
            &child_digest,
            arch,
        );
    }

    let manifest_digest = manifest_response
        .digest
        .unwrap_or_else(|| sha256_prefixed(&manifest_response.bytes));
    resolve_remote_manifest(
        client,
        &repository,
        &manifest_response.bytes,
        &manifest_digest,
        arch,
    )
}

fn resolve_remote_manifest(
    client: &RegistryHttpClient,
    repository: &str,
    manifest_bytes: &[u8],
    manifest_digest: &str,
    arch: Architecture,
) -> Result<ResolvedRemoteImage> {
    let manifest: OciManifest = serde_json::from_slice(manifest_bytes)?;
    let config_bytes = client.fetch_blob(repository, &manifest.config.digest)?;
    let config: OciConfigBlob = serde_json::from_slice(&config_bytes)?;
    validate_remote_platform(config.os.as_deref(), config.architecture.as_deref(), arch)?;
    Ok(ResolvedRemoteImage {
        repository: repository.to_string(),
        manifest_digest: manifest_digest.to_string(),
        layers: manifest.layers,
    })
}

fn parse_remote_image_reference(image: &str) -> Result<ParsedRemoteImage> {
    let trimmed = image.trim();
    if trimmed.is_empty() {
        bail!("remote image reference must not be empty");
    }
    if let Some((repository, digest)) = trimmed.split_once('@') {
        if repository.is_empty() || digest.is_empty() {
            bail!("remote image reference is invalid: {image}");
        }
        return Ok(ParsedRemoteImage {
            repository: repository.to_string(),
            reference: digest.to_string(),
        });
    }

    let last_slash = trimmed.rfind('/');
    let last_colon = trimmed.rfind(':');
    if let Some(index) = last_colon {
        if last_slash.map(|slash| index > slash).unwrap_or(true) {
            let repository = &trimmed[..index];
            let tag = &trimmed[index + 1..];
            if repository.is_empty() || tag.is_empty() {
                bail!("remote image reference is invalid: {image}");
            }
            return Ok(ParsedRemoteImage {
                repository: repository.to_string(),
                reference: tag.to_string(),
            });
        }
    }

    Ok(ParsedRemoteImage {
        repository: trimmed.to_string(),
        reference: "latest".to_string(),
    })
}

fn apply_remote_repository_prefix(prefix: Option<&str>, repository: &str) -> String {
    match prefix {
        Some(prefix)
            if prefix.is_empty() == false
                && repository.starts_with(&(prefix.to_string() + "/")) == false =>
        {
            format!("{prefix}/{repository}")
        }
        _ => repository.to_string(),
    }
}

fn registry_base_url(registry_host: &str) -> String {
    let trimmed = registry_host.trim().trim_end_matches('/');
    let normalized = trimmed
        .trim_start_matches("https://")
        .trim_start_matches("http://");
    if normalized == "docker.io" || normalized == "index.docker.io" {
        return "https://registry-1.docker.io".to_string();
    }
    if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
        trimmed.to_string()
    } else {
        format!("https://{trimmed}")
    }
}

fn load_registry_basic_auth(registry_host: &str) -> Option<(String, String)> {
    let docker_config = std::env::var_os("DOCKER_CONFIG")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".docker")));
    let config_path = docker_config?.join("config.json");
    let bytes = fs::read(config_path).ok()?;
    let value: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    let auths = value.get("auths")?.as_object()?;
    let normalized = registry_host
        .trim()
        .trim_end_matches('/')
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .to_string();
    let mut candidates = vec![
        normalized.clone(),
        format!("https://{normalized}"),
        format!("http://{normalized}"),
    ];
    if normalized == "docker.io"
        || normalized == "index.docker.io"
        || normalized == "registry-1.docker.io"
    {
        candidates.push("https://index.docker.io/v1/".to_string());
        candidates.push("https://registry-1.docker.io".to_string());
    }
    for candidate in candidates {
        if let Some(auth) = auths
            .get(&candidate)
            .and_then(|entry| entry.get("auth"))
            .and_then(|value| value.as_str())
        {
            let decoded = base64::engine::general_purpose::STANDARD
                .decode(auth)
                .ok()?;
            let decoded = String::from_utf8(decoded).ok()?;
            let (username, password) = decoded.split_once(':')?;
            return Some((username.to_string(), password.to_string()));
        }
    }
    None
}

fn parse_www_authenticate(value: &str) -> Result<(String, BTreeMap<String, String>)> {
    let (scheme, rest) = value
        .split_once(' ')
        .with_context(|| format!("invalid WWW-Authenticate header: {value}"))?;
    let mut parameters = BTreeMap::new();
    for raw_pair in rest.split(',') {
        let (key, raw_value) = raw_pair
            .trim()
            .split_once('=')
            .with_context(|| format!("invalid WWW-Authenticate parameter: {raw_pair}"))?;
        parameters.insert(
            key.to_string(),
            raw_value.trim().trim_matches('"').to_string(),
        );
    }
    Ok((scheme.to_string(), parameters))
}

fn platform_matches_target(platform: Option<&OciPlatform>, arch: Architecture) -> bool {
    let Some(platform) = platform else {
        return false;
    };
    platform.os.as_deref().unwrap_or("linux") == "linux"
        && oci_architecture_matches(platform.architecture.as_deref(), arch)
}

fn validate_remote_platform(
    os: Option<&str>,
    architecture: Option<&str>,
    target_arch: Architecture,
) -> Result<()> {
    if os.unwrap_or("linux") != "linux" {
        bail!("remote OCI base is not a linux image");
    }
    if oci_architecture_matches(architecture, target_arch) == false {
        bail!(
            "remote OCI base architecture {:?} does not match requested {}",
            architecture,
            target_arch.as_str()
        );
    }
    Ok(())
}

fn oci_architecture_matches(value: Option<&str>, target_arch: Architecture) -> bool {
    let Some(value) = value else {
        return false;
    };
    match target_arch {
        Architecture::X86_64 => value == "amd64" || value == "x86_64",
        Architecture::Arm64 => value == "arm64" || value == "aarch64",
        Architecture::Riscv64 => value == "riscv64" || value == "riscv",
    }
}

fn sha256_prefixed(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

fn unpack_oci_layer(bytes: &[u8], media_type: Option<&str>, rootfs: &Path) -> Result<()> {
    let zstd = media_type
        .map(|value| value.contains("zstd") || value.contains("+zstd"))
        .unwrap_or_else(|| bytes.starts_with(&[0x28, 0xB5, 0x2F, 0xFD]));
    if zstd {
        let decoder = ZstdDecoder::new(Cursor::new(bytes))
            .context("failed to decode zstd-compressed OCI layer")?;
        let mut archive = Archive::new(decoder);
        return apply_oci_archive(&mut archive, rootfs);
    }

    let gzip = media_type
        .map(|value| value.contains("+gzip") || value.contains(".gzip"))
        .unwrap_or_else(|| bytes.starts_with(&[0x1f, 0x8b]));
    if gzip {
        let decoder = GzDecoder::new(Cursor::new(bytes));
        let mut archive = Archive::new(decoder);
        apply_oci_archive(&mut archive, rootfs)
    } else {
        let mut archive = Archive::new(Cursor::new(bytes));
        apply_oci_archive(&mut archive, rootfs)
    }
}

fn apply_oci_archive<R: Read>(archive: &mut Archive<R>, rootfs: &Path) -> Result<()> {
    for entry in archive.entries()? {
        let mut entry = entry?;
        let relative = normalize_archive_entry_path(&entry.path()?)?;
        if relative.as_os_str().is_empty() {
            continue;
        }

        if let Some(action) = classify_whiteout(&relative) {
            apply_whiteout(rootfs, action)?;
            continue;
        }

        let entry_type = entry.header().entry_type();
        if entry_type.is_dir() {
            let destination = prepare_rootfs_destination(rootfs, &relative)?;
            match fs::symlink_metadata(&destination) {
                Ok(metadata) => {
                    if metadata.file_type().is_symlink() || metadata.is_dir() == false {
                        remove_existing_path(&destination)?;
                        fs::create_dir(&destination)?;
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    fs::create_dir(&destination)?;
                }
                Err(error) => return Err(error.into()),
            }
            fs::set_permissions(
                &destination,
                fs::Permissions::from_mode(entry.header().mode().unwrap_or(0o755)),
            )?;
            continue;
        }

        let destination = prepare_rootfs_destination(rootfs, &relative)?;
        remove_existing_path(&destination)?;

        if entry_type.is_symlink() {
            let target = entry
                .link_name()?
                .context("OCI symlink entry missing target")?;
            symlink(target, &destination)?;
            continue;
        }

        if entry_type.is_hard_link() {
            let target = entry
                .link_name()?
                .context("OCI hardlink entry missing target")?;
            let target = normalize_archive_entry_path(&target)?;
            let target = resolve_existing_rootfs_path(rootfs, &target, "OCI hardlink target")?;
            fs::hard_link(&target, &destination)?;
            continue;
        }

        if entry_type.is_character_special()
            || entry_type.is_block_special()
            || entry_type.is_fifo()
        {
            bail!(
                "OCI special file entry types are not supported: {}",
                relative.display()
            );
        }

        if entry_type.is_file() == false {
            continue;
        }

        entry.unpack(&destination)?;
        fs::set_permissions(
            &destination,
            fs::Permissions::from_mode(entry.header().mode().unwrap_or(0o644)),
        )?;
    }

    Ok(())
}

fn prepare_rootfs_destination(rootfs: &Path, relative: &Path) -> Result<PathBuf> {
    ensure_safe_rootfs_parents(rootfs, relative)?;
    Ok(rootfs.join(relative))
}

fn ensure_safe_rootfs_parents(rootfs: &Path, relative: &Path) -> Result<()> {
    let mut current = rootfs.to_path_buf();
    let Some(parent) = relative.parent() else {
        return Ok(());
    };
    if parent.as_os_str().is_empty() {
        return Ok(());
    }
    for component in parent.components() {
        let std::path::Component::Normal(part) = component else {
            bail!(
                "OCI layer entry has invalid normalized parent path: {}",
                relative.display()
            );
        };
        current.push(part);
        match fs::symlink_metadata(&current) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() {
                    bail!(
                        "OCI layer entry traverses a symlinked parent path: {}",
                        relative.display()
                    );
                }
                if metadata.is_dir() == false {
                    bail!(
                        "OCI layer entry parent is not a directory: {}",
                        relative.display()
                    );
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                fs::create_dir(&current)?;
            }
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

fn resolve_existing_rootfs_path(
    rootfs: &Path,
    relative: &Path,
    description: &str,
) -> Result<PathBuf> {
    let path = prepare_rootfs_destination(rootfs, relative)?;
    match fs::symlink_metadata(&path) {
        Ok(_) => Ok(path),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            bail!("{description} is missing: {}", relative.display());
        }
        Err(error) => Err(error.into()),
    }
}

fn normalize_archive_entry_path(path: &Path) -> Result<PathBuf> {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            std::path::Component::CurDir => {}
            std::path::Component::Normal(part) => normalized.push(part),
            std::path::Component::RootDir
            | std::path::Component::ParentDir
            | std::path::Component::Prefix(_) => {
                bail!("OCI layer entry escapes the rootfs: {}", path.display());
            }
        }
    }
    Ok(normalized)
}

enum WhiteoutAction {
    Remove(PathBuf),
    Opaque(PathBuf),
}

fn classify_whiteout(path: &Path) -> Option<WhiteoutAction> {
    let file_name = path.file_name()?.to_str()?;
    if file_name == ".wh..wh..opq" {
        let parent = path.parent().map(Path::to_path_buf).unwrap_or_default();
        return Some(WhiteoutAction::Opaque(parent));
    }
    let removed = file_name.strip_prefix(".wh.")?;
    let parent = path.parent().map(Path::to_path_buf).unwrap_or_default();
    Some(WhiteoutAction::Remove(parent.join(removed)))
}

fn apply_whiteout(rootfs: &Path, action: WhiteoutAction) -> Result<()> {
    match action {
        WhiteoutAction::Remove(path) => {
            let target = prepare_rootfs_destination(rootfs, &path)?;
            remove_existing_path(&target)
        }
        WhiteoutAction::Opaque(path) => {
            let directory = prepare_rootfs_destination(rootfs, &path)?;
            match fs::symlink_metadata(&directory) {
                Ok(metadata) => {
                    if metadata.file_type().is_symlink() || metadata.is_dir() == false {
                        bail!(
                            "OCI opaque whiteout target is not a directory: {}",
                            path.display()
                        );
                    }
                    for entry in fs::read_dir(&directory)? {
                        let entry = entry?;
                        remove_existing_path(&entry.path())?;
                    }
                    Ok(())
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
                Err(error) => Err(error.into()),
            }
        }
    }
}

fn remove_existing_path(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_dir() && metadata.file_type().is_symlink() == false {
                fs::remove_dir_all(path)?;
            } else {
                fs::remove_file(path)?;
            }
            Ok(())
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn apply_copy(
    workspace_root: &Path,
    copy: &crate::plan::ResolvedCopy,
    contexts: &BTreeMap<String, PathBuf>,
) -> Result<()> {
    let context_root = contexts
        .get(&copy.context)
        .with_context(|| format!("undefined context {}", copy.context))?;
    let matches = resolve_context_matches(context_root, &copy.source)?;
    if matches.is_empty() {
        bail!(
            "COPY source {} matched nothing in context {}",
            copy.source,
            copy.context
        );
    }

    let destination = workspace_root.join(copy.destination.trim_start_matches('/'));
    let destination_is_directory =
        matches.len() > 1 || destination.to_string_lossy().ends_with('/');
    if destination_is_directory {
        fs::create_dir_all(&destination)?;
    }

    for source in matches {
        let metadata = fs::symlink_metadata(&source)?;
        if metadata.file_type().is_socket() {
            bail!("COPY rejects sockets: {}", source.display());
        }
        if metadata.file_type().is_block_device()
            || metadata.file_type().is_char_device()
            || metadata.file_type().is_fifo()
        {
            bail!("COPY rejects special files: {}", source.display());
        }

        let target = if destination_is_directory {
            destination.join(source.file_name().unwrap_or_else(|| OsStr::new("copy")))
        } else {
            destination.clone()
        };

        copy_context_entry(context_root, &source, &target)?;
    }

    Ok(())
}

fn resolve_context_matches(context_root: &Path, pattern: &str) -> Result<Vec<PathBuf>> {
    if pattern.contains('*') {
        let mut matches = Vec::new();
        for entry in WalkDir::new(context_root).follow_links(false).min_depth(1) {
            let entry = entry?;
            let relative = entry.path().strip_prefix(context_root)?;
            let relative = path_to_unix(relative);
            if match_pattern(pattern, &relative)? {
                matches.push(entry.path().to_path_buf());
            }
        }
        matches.sort();
        Ok(matches)
    } else {
        let candidate = context_root.join(pattern);
        let canonical = candidate
            .canonicalize()
            .with_context(|| format!("COPY source {} does not exist", candidate.display()))?;
        let canonical_root = context_root.canonicalize()?;
        if canonical.starts_with(&canonical_root) == false {
            bail!("COPY source escapes the named context root");
        }
        Ok(vec![candidate])
    }
}

fn assemble_app_tree(
    workspace_root: &Path,
    final_tree: &Path,
    resolved: &ResolvedBuildSpec,
) -> Result<()> {
    fs::create_dir_all(final_tree)?;
    if resolved.survives.is_empty() {
        bail!("app builds require at least one SURVIVE path");
    }

    let matched = resolve_survivors(workspace_root, &resolved.survives)?;
    if matched.is_empty() {
        bail!("SURVIVE matched nothing");
    }

    for source in &matched {
        let relative = source.strip_prefix(workspace_root)?;
        let destination = final_tree.join(relative);
        copy_internal_entry(source, &destination)?;
    }

    let execute = resolved
        .execute
        .as_ref()
        .context("app builds require EXECUTE")?;
    let execute_path = final_tree.join(execute[0].trim_start_matches('/'));
    if execute_path.exists() == false {
        bail!(
            "EXECUTE target {} is not present in the declared survivor set",
            execute[0]
        );
    }

    copy_elf_runtime_closure(workspace_root, final_tree, &matched)?;
    Ok(())
}

fn resolve_survivors(workspace_root: &Path, patterns: &[String]) -> Result<Vec<PathBuf>> {
    let mut results = BTreeSet::new();
    for pattern in patterns {
        let relative_pattern = pattern.trim_start_matches('/');
        if relative_pattern.contains('*') {
            for entry in WalkDir::new(workspace_root)
                .follow_links(false)
                .min_depth(1)
            {
                let entry = entry?;
                let relative = entry.path().strip_prefix(workspace_root)?;
                let relative = path_to_unix(relative);
                if match_pattern(relative_pattern, &relative)? {
                    results.insert(entry.path().to_path_buf());
                }
            }
        } else {
            let source = workspace_root.join(relative_pattern);
            if source.exists() {
                results.insert(source);
            }
        }
    }

    Ok(results.into_iter().collect())
}

fn write_launch_metadata(path: &Path, resolved: &ResolvedBuildSpec) -> Result<()> {
    let execute = resolved
        .execute
        .as_ref()
        .context("app builds require EXECUTE")?;
    let payload = LaunchMetadata {
        execute_path: execute[0].clone(),
        execute_args: execute[1..].to_vec(),
        execute_env: resolved
            .env
            .iter()
            .map(|(key, value)| format!("{key}={value}"))
            .collect(),
        execute_cwd: resolved.workdir.clone(),
        execute_arch: resolved.from.arch.as_str().to_string(),
    };
    fs::write(path, serde_json::to_vec_pretty(&payload)?)?;
    Ok(())
}

fn publish_cached_artifact(
    storage: &StorageRoot,
    session: &BuildSession,
    kind: &str,
    arch: Architecture,
    artifact_root: &Path,
    artifact_key_override: Option<String>,
) -> Result<(PathBuf, String, i64)> {
    let artifact_key = match artifact_key_override {
        Some(value) => value,
        None => compute_artifact_cache_key(artifact_root)?,
    };
    let cached_artifact = storage.artifact_blob_path(kind, arch.as_str(), &artifact_key);
    if cached_artifact.exists() {
        return cached_artifact_metadata(cached_artifact);
    }

    let _lock = FileLockGuard::acquire(
        storage,
        "artifact",
        &format!("{kind}:{}:{artifact_key}", arch.as_str()),
    )?;
    if cached_artifact.exists() {
        return cached_artifact_metadata(cached_artifact);
    }

    let staging = TempDir::new_in(session.tmp_root())?;
    let staged_blob = staging.path().join(format!("{artifact_key}.zst"));
    emit_btrfs_blob(session.tmp_root(), artifact_root, &staged_blob)?;
    maybe_inject_test_fault("final-blob-export");

    if let Some(parent) = cached_artifact.parent() {
        fs::create_dir_all(parent)?;
    }
    match fs::rename(&staged_blob, &cached_artifact) {
        Ok(()) => {}
        Err(error) if cached_artifact.exists() => {
            let _ = error;
        }
        Err(error) => {
            return Err(error).with_context(|| {
                format!(
                    "failed to publish cached artifact {}",
                    cached_artifact.display()
                )
            });
        }
    }

    cached_artifact_metadata(cached_artifact)
}

fn cached_artifact_metadata(path: PathBuf) -> Result<(PathBuf, String, i64)> {
    let digest = sha256_file(&path)?;
    let size_bytes = fs::metadata(&path)?.len() as i64;
    Ok((path, digest, size_bytes))
}

fn compute_artifact_cache_key(root: &Path) -> Result<String> {
    let mut entries = WalkDir::new(root)
        .follow_links(false)
        .min_depth(1)
        .into_iter()
        .collect::<std::result::Result<Vec<_>, walkdir::Error>>()?;
    entries.sort_by_key(|entry| path_to_unix(entry.path().strip_prefix(root).unwrap()));

    let mut hasher = Sha256::new();
    hasher.update(ARTIFACT_CACHE_VERSION.as_bytes());
    for entry in entries {
        let relative = entry.path().strip_prefix(root)?;
        let relative = path_to_unix(relative);
        let metadata = fs::symlink_metadata(entry.path())?;
        hasher.update(b"\npath\n");
        hasher.update(relative.as_bytes());
        hasher.update(b"\nmode\n");
        hasher.update((metadata.permissions().mode() & 0o7777).to_le_bytes());

        if metadata.file_type().is_symlink() {
            hasher.update(b"\ntype\nsymlink\n");
            hasher.update(fs::read_link(entry.path())?.as_os_str().as_bytes());
            continue;
        }

        if metadata.is_dir() {
            hasher.update(b"\ntype\ndir\n");
            continue;
        }

        hasher.update(b"\ntype\nfile\n");
        let mut file = fs::File::open(entry.path())?;
        let mut buffer = [0u8; 64 * 1024];
        loop {
            let read = file.read(&mut buffer)?;
            if read == 0 {
                break;
            }
            hasher.update(&buffer[..read]);
        }
    }

    Ok(hex::encode(hasher.finalize()))
}

fn emit_btrfs_blob(temp_root: &Path, artifact_root: &Path, output_path: &Path) -> Result<()> {
    let output_temp = output_path.with_extension("tmp");
    let mount = LoopbackBtrfs::new_in(temp_root, artifact_root)?;
    let subvolume = mount.create_subvolume("artifact")?;
    copy_tree(artifact_root, &subvolume)?;
    mount.send_subvolume(&subvolume, &output_temp)?;
    fs::rename(&output_temp, output_path)?;
    Ok(())
}

fn materialize_output_blob(cached_artifact: &Path, output_path: &Path) -> Result<()> {
    if cached_artifact == output_path {
        return Ok(());
    }

    let output_parent = output_path
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or(std::env::current_dir()?);
    fs::create_dir_all(&output_parent)?;
    let staging = TempDir::new_in(&output_parent)?;
    let staged_output = staging.path().join(
        output_path
            .file_name()
            .unwrap_or_else(|| OsStr::new("artifact.zst")),
    );
    copy_blob_file(cached_artifact, &staged_output)?;
    fs::rename(&staged_output, output_path)?;
    Ok(())
}

fn copy_blob_file(source: &Path, destination: &Path) -> Result<()> {
    let copy_attempt = Command::new("cp")
        .arg("--reflink=auto")
        .arg("--")
        .arg(source)
        .arg(destination)
        .output();
    match copy_attempt {
        Ok(output) if output.status.success() => Ok(()),
        Ok(_) | Err(_) => {
            fs::copy(source, destination).with_context(|| {
                format!(
                    "failed to copy cached artifact {} to {}",
                    source.display(),
                    destination.display()
                )
            })?;
            let permissions = fs::metadata(source)?.permissions();
            fs::set_permissions(destination, permissions)?;
            Ok(())
        }
    }
}

fn copy_elf_runtime_closure(
    workspace_root: &Path,
    final_tree: &Path,
    matched: &[PathBuf],
) -> Result<()> {
    let mut copied = BTreeSet::new();
    for source in matched {
        let relative = source.strip_prefix(workspace_root)?;
        let projected = final_tree.join(relative);
        if projected.is_file() == false {
            continue;
        }

        if is_elf(&projected)? {
            if let Some(interpreter) = read_elf_interpreter(&projected)? {
                copy_runtime_path(
                    workspace_root,
                    Path::new(&interpreter),
                    final_tree,
                    &mut copied,
                )?;
            }
            let mut dependencies = read_ldd_dependencies(&projected)?;
            if dependencies.is_empty() {
                dependencies = resolve_needed_libraries_from_workspace(
                    workspace_root,
                    &read_elf_needed_libraries(&projected)?,
                )?;
            }
            for dependency in dependencies {
                copy_runtime_path(workspace_root, &dependency, final_tree, &mut copied)?;
            }
        }
    }

    Ok(())
}

fn is_elf(path: &Path) -> Result<bool> {
    let output = Command::new("readelf").arg("-h").arg(path).output()?;
    Ok(output.status.success())
}

fn read_elf_interpreter(path: &Path) -> Result<Option<String>> {
    let output = Command::new("readelf").arg("-l").arg(path).output()?;
    if output.status.success() == false {
        return Ok(None);
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.lines() {
        if let Some(start) = line.find("Requesting program interpreter: ") {
            let value = &line[start + "Requesting program interpreter: ".len()..];
            let value = value.trim().trim_start_matches('[').trim_end_matches(']');
            return Ok(Some(value.to_string()));
        }
    }

    Ok(None)
}

fn read_ldd_dependencies(path: &Path) -> Result<Vec<PathBuf>> {
    let output = Command::new("ldd").arg(path).output()?;
    if output.status.success() == false {
        return Ok(Vec::new());
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
    Ok(dependencies)
}

fn read_elf_needed_libraries(path: &Path) -> Result<Vec<String>> {
    let output = Command::new("readelf").arg("-d").arg(path).output()?;
    if output.status.success() == false {
        return Ok(Vec::new());
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut needed = Vec::new();
    for line in stdout.lines() {
        if line.contains("(NEEDED)") == false {
            continue;
        }
        let Some(start) = line.find('[') else {
            continue;
        };
        let Some(end) = line[start + 1..].find(']') else {
            continue;
        };
        needed.push(line[start + 1..start + 1 + end].to_string());
    }
    needed.sort();
    needed.dedup();
    Ok(needed)
}

fn resolve_needed_libraries_from_workspace(
    workspace_root: &Path,
    needed: &[String],
) -> Result<Vec<PathBuf>> {
    let mut resolved = Vec::new();
    for library in needed {
        resolved.push(resolve_needed_library(workspace_root, library)?);
    }
    resolved.sort();
    resolved.dedup();
    Ok(resolved)
}

fn resolve_needed_library(workspace_root: &Path, library: &str) -> Result<PathBuf> {
    for prefix in ["lib", "lib64", "usr/lib", "usr/lib64"] {
        let root = workspace_root.join(prefix);
        if root.exists() == false {
            continue;
        }
        for entry in WalkDir::new(&root).follow_links(false) {
            let entry = entry?;
            if entry.file_name() == OsStr::new(library) {
                return Ok(Path::new("/").join(entry.path().strip_prefix(workspace_root)?));
            }
        }
    }

    bail!(
        "failed to resolve ELF dependency {} inside {}",
        library,
        workspace_root.display()
    )
}

fn copy_runtime_path(
    workspace_root: &Path,
    path: &Path,
    final_tree: &Path,
    copied: &mut BTreeSet<PathBuf>,
) -> Result<()> {
    let normalized = PathBuf::from(normalize_absolute_path(path)?);
    if copied.insert(normalized.clone()) == false {
        return Ok(());
    }

    let source_root = if workspace_root.join(normalized.strip_prefix("/")?).exists() {
        workspace_root
    } else {
        Path::new("/")
    };
    let source_path = source_root.join(normalized.strip_prefix("/")?);
    let source_metadata = fs::symlink_metadata(&source_path)?;
    let destination = final_tree.join(normalized.strip_prefix("/")?);
    if source_metadata.file_type().is_symlink() {
        if let Some(parent) = destination.parent() {
            fs::create_dir_all(parent)?;
        }
        let target = fs::read_link(&source_path)?;
        let _ = fs::remove_file(&destination);
        symlink(&target, &destination)?;
        let resolved_target = if target.is_absolute() {
            target
        } else {
            normalized
                .parent()
                .unwrap_or_else(|| Path::new("/"))
                .join(target)
        };
        copy_runtime_path(workspace_root, &resolved_target, final_tree, copied)?;
        return Ok(());
    }

    if source_metadata.is_dir() {
        fs::create_dir_all(&destination)?;
        return Ok(());
    }

    if let Some(parent) = destination.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::copy(&source_path, &destination)?;
    fs::set_permissions(
        &destination,
        fs::Permissions::from_mode(source_metadata.permissions().mode()),
    )?;
    Ok(())
}

fn copy_context_entry(context_root: &Path, source: &Path, destination: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(source)?;
    if metadata.file_type().is_symlink() {
        let target = fs::read_link(source)?;
        ensure_context_symlink_target(context_root, source, &target)?;
        if let Some(parent) = destination.parent() {
            fs::create_dir_all(parent)?;
        }
        let _ = fs::remove_file(destination);
        symlink(target, destination)?;
        return Ok(());
    }

    if metadata.is_dir() {
        fs::create_dir_all(destination)?;
        fs::set_permissions(
            destination,
            fs::Permissions::from_mode(metadata.permissions().mode()),
        )?;
        for entry in fs::read_dir(source)? {
            let entry = entry?;
            copy_context_entry(
                context_root,
                &entry.path(),
                &destination.join(entry.file_name()),
            )?;
        }
        return Ok(());
    }

    if let Some(parent) = destination.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::copy(source, destination)?;
    fs::set_permissions(
        destination,
        fs::Permissions::from_mode(metadata.permissions().mode()),
    )?;
    Ok(())
}

fn copy_internal_entry(source: &Path, destination: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(source)?;
    if metadata.file_type().is_symlink() {
        if let Some(parent) = destination.parent() {
            fs::create_dir_all(parent)?;
        }
        let target = fs::read_link(source)?;
        remove_existing_path(destination)?;
        symlink(target, destination)?;
        return Ok(());
    }

    if metadata.is_dir() {
        fs::create_dir_all(destination)?;
        fs::set_permissions(
            destination,
            fs::Permissions::from_mode(metadata.permissions().mode()),
        )?;
        for entry in fs::read_dir(source)? {
            let entry = entry?;
            copy_internal_entry(&entry.path(), &destination.join(entry.file_name()))?;
        }
        return Ok(());
    }

    if let Some(parent) = destination.parent() {
        fs::create_dir_all(parent)?;
    }
    remove_existing_path(destination)?;
    fs::copy(source, destination)?;
    fs::set_permissions(
        destination,
        fs::Permissions::from_mode(metadata.permissions().mode()),
    )?;
    Ok(())
}

fn copy_tree(source: &Path, destination: &Path) -> Result<()> {
    fs::create_dir_all(destination)?;
    for entry in WalkDir::new(source).follow_links(false).min_depth(1) {
        let entry = entry?;
        let relative = entry.path().strip_prefix(source)?;
        let target = destination.join(relative);
        copy_internal_entry(entry.path(), &target)?;
    }
    Ok(())
}

fn clear_directory(path: &Path) -> Result<()> {
    fs::create_dir_all(path)?;
    let mut entries =
        fs::read_dir(path)?.collect::<std::result::Result<Vec<_>, std::io::Error>>()?;
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        remove_existing_path(&entry.path())?;
    }
    Ok(())
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

fn match_pattern(pattern: &str, candidate: &str) -> Result<bool> {
    let pattern_parts: Vec<&str> = pattern.trim_start_matches("./").split('/').collect();
    let candidate_parts: Vec<&str> = candidate.split('/').collect();
    if pattern_parts.len() != candidate_parts.len() {
        return Ok(false);
    }

    for (pattern_part, candidate_part) in pattern_parts.iter().zip(candidate_parts.iter()) {
        if candidate_part.starts_with('.') && pattern_part.starts_with('.') == false {
            return Ok(false);
        }
        if component_matches(pattern_part, candidate_part) == false {
            return Ok(false);
        }
    }

    Ok(true)
}

fn component_matches(pattern: &str, candidate: &str) -> bool {
    if pattern == "*" {
        return true;
    }

    let mut parts = pattern.split('*').peekable();
    let mut offset = 0usize;
    let mut first = true;
    while let Some(part) = parts.next() {
        if part.is_empty() {
            first = false;
            continue;
        }

        if first {
            if candidate[offset..].starts_with(part) == false {
                return false;
            }
            offset += part.len();
            first = false;
            continue;
        }

        if let Some(index) = candidate[offset..].find(part) {
            offset += index + part.len();
        } else {
            return false;
        }
    }

    pattern.ends_with('*') || offset == candidate.len()
}

#[derive(Serialize)]
struct LaunchMetadata {
    execute_path: String,
    execute_args: Vec<String>,
    execute_env: Vec<String>,
    execute_cwd: String,
    execute_arch: String,
}

struct LoopbackBtrfs {
    image_dir: TempDir,
    mount_dir: TempDir,
}

impl LoopbackBtrfs {
    fn new_in(parent: &Path, seed_path: &Path) -> Result<Self> {
        Self::with_size_in(parent, estimate_size(seed_path)?)
    }

    fn from_blob_in(parent: &Path, blob_path: &Path) -> Result<Self> {
        let compressed_size = fs::metadata(blob_path)
            .with_context(|| format!("failed to stat {}", blob_path.display()))?
            .len();
        let estimated = (compressed_size.saturating_mul(64)).max(256 * 1024 * 1024);
        Self::with_size_in(parent, estimated.next_power_of_two())
    }

    fn with_size_in(parent: &Path, size: u64) -> Result<Self> {
        let image_dir = tempfile::tempdir_in(parent)?;
        let mount_dir = tempfile::tempdir_in(parent)?;
        Self::with_prepared_dirs(image_dir, mount_dir, size)
    }

    fn with_prepared_dirs(image_dir: TempDir, mount_dir: TempDir, size: u64) -> Result<Self> {
        let image_path = image_dir.path().join("artifact.btrfs");
        run_command(
            Command::new("truncate")
                .arg("-s")
                .arg(format!("{size}"))
                .arg(&image_path),
            "truncate",
        )?;
        run_command(
            Command::new("mkfs.btrfs").arg("-q").arg(&image_path),
            "mkfs.btrfs",
        )?;
        run_command(
            Command::new("mount")
                .arg("-o")
                .arg("loop")
                .arg(&image_path)
                .arg(mount_dir.path()),
            "mount loopback btrfs",
        )?;
        Ok(Self {
            image_dir,
            mount_dir,
        })
    }

    fn create_subvolume(&self, name: &str) -> Result<PathBuf> {
        let path = self.mount_dir.path().join(name);
        run_command(
            Command::new("btrfs")
                .args(["subvolume", "create"])
                .arg(&path),
            "btrfs subvolume create",
        )?;
        Ok(path)
    }

    fn send_subvolume(&self, path: &Path, output_path: &Path) -> Result<()> {
        run_command(
            Command::new("btrfs")
                .args(["property", "set", "-ts"])
                .arg(path)
                .arg("ro")
                .arg("true"),
            "btrfs property set ro=true",
        )?;
        let command = format!(
            "set -euo pipefail; btrfs send '{}' | zstd -T0 -q -o '{}'",
            path.display(),
            output_path.display()
        );
        run_command(Command::new("bash").arg("-lc").arg(command), "btrfs send")?;
        Ok(())
    }

    fn receive_blob(&self, blob_path: &Path) -> Result<PathBuf> {
        let command = format!(
            "set -euo pipefail; zstd -d -q -c '{}' | btrfs receive '{}'",
            blob_path.display(),
            self.mount_dir.path().display()
        );
        run_command(
            Command::new("bash").arg("-lc").arg(command),
            "btrfs receive",
        )?;
        let received = self.mount_dir.path().join("artifact");
        if received.exists() == false {
            bail!(
                "received base artifact did not materialize expected subvolume {}",
                received.display()
            );
        }
        Ok(received)
    }
}

impl Drop for LoopbackBtrfs {
    fn drop(&mut self) {
        let _ = Command::new("umount").arg(self.mount_dir.path()).status();
        let _ = self.image_dir.path();
    }
}

fn estimate_size(path: &Path) -> Result<u64> {
    let mut bytes = 16u64 * 1024 * 1024;
    for entry in WalkDir::new(path).follow_links(false) {
        let entry = entry?;
        if entry.file_type().is_file() {
            bytes = bytes.saturating_add(entry.metadata()?.len());
        }
    }

    let padded = bytes.saturating_mul(4).max(256 * 1024 * 1024);
    Ok(padded.next_power_of_two())
}

fn parse_named_base_ref(raw: Option<&str>) -> Result<Option<(String, String)>> {
    match raw {
        Some(value) => {
            let (name, tag) = split_named_base_ref(value)?;
            Ok(Some((name, tag)))
        }
        None => Ok(None),
    }
}

fn split_named_base_ref(raw: &str) -> Result<(String, String)> {
    let (name, tag) = raw
        .split_once(':')
        .with_context(|| format!("base reference must use name:tag syntax: {raw}"))?;
    if name.is_empty() || tag.is_empty() {
        bail!("base reference must use name:tag syntax: {raw}");
    }
    Ok((name.to_string(), tag.to_string()))
}

fn ensure_publishable_arch_matches_source(
    _output_kind: OutputKind,
    _published_base: Option<&(String, String)>,
    _resolved: &ResolvedBuildSpec,
) -> Result<()> {
    Ok(())
}

fn run_command(command: &mut Command, description: &str) -> Result<()> {
    let output = command
        .output()
        .with_context(|| format!("failed to spawn {description}"))?;
    if output.status.success() == false {
        bail!(
            "{} failed: {}{}",
            description,
            String::from_utf8_lossy(&output.stderr),
            String::from_utf8_lossy(&output.stdout)
        );
    }
    Ok(())
}

trait FileTypeExt {
    fn is_socket(&self) -> bool;
    fn is_block_device(&self) -> bool;
    fn is_char_device(&self) -> bool;
    fn is_fifo(&self) -> bool;
}

impl FileTypeExt for std::fs::FileType {
    fn is_socket(&self) -> bool {
        std::os::unix::fs::FileTypeExt::is_socket(self)
    }

    fn is_block_device(&self) -> bool {
        std::os::unix::fs::FileTypeExt::is_block_device(self)
    }

    fn is_char_device(&self) -> bool {
        std::os::unix::fs::FileTypeExt::is_char_device(self)
    }

    fn is_fifo(&self) -> bool {
        std::os::unix::fs::FileTypeExt::is_fifo(self)
    }
}

unsafe extern "C" {
    fn flock(fd: i32, operation: i32) -> i32;
}

unsafe fn libc_flock(fd: i32, operation: i32) -> i32 {
    unsafe { flock(fd, operation) }
}

fn should_inject_test_fault(stage: &str) -> bool {
    let configured = match std::env::var(TEST_FAULT_ENV) {
        Ok(value) => value,
        Err(_) => return false,
    };
    configured
        .split([',', ';'])
        .map(str::trim)
        .any(|candidate| candidate == stage)
}

fn maybe_inject_test_fault(stage: &str) {
    if should_inject_test_fault(stage) {
        eprintln!("discombobulator test fault injected at {stage}");
        std::process::exit(97);
    }
}
