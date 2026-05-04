use crate::cli::{
    parse_key_value, BuildCommand, BundleFlatCommand, InternalRunCommand, OutputKindArg,
};
use crate::plan::Architecture;
use crate::registry::{Registry, StorageRoot};
use anyhow::{bail, Context, Result};
use metalor::runtime::linux_provider::{
    LocalLinuxProviderKind, ProviderRuntimeLayout, ProviderSession,
};
#[cfg(target_os = "macos")]
use metalor::runtime::macos::{AppleLinuxProvider, DEFAULT_APPLE_LINUX_BUNDLE};
#[cfg(target_os = "windows")]
use metalor::runtime::windows::{resolve_wsl_distro, WslProvider};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Component, Path, PathBuf};

const DISCOMBOBULATOR_PROVIDER_RUNTIME_ROOT_ENV: &str = "DISCOMBOBULATOR_PROVIDER_RUNTIME_ROOT";
#[cfg(target_os = "macos")]
const DISCOMBOBULATOR_APPLE_LINUX_HELPER_ENV: &str = "DISCOMBOBULATOR_APPLE_LINUX_HELPER";
#[cfg(target_os = "macos")]
const DISCOMBOBULATOR_APPLE_LINUX_VM_ENV: &str = "DISCOMBOBULATOR_APPLE_LINUX_VM";
#[cfg(target_os = "macos")]
const DISCOMBOBULATOR_APPLE_LINUX_BUNDLE_ENV: &str = "DISCOMBOBULATOR_APPLE_LINUX_BUNDLE";
#[cfg(target_os = "windows")]
const DISCOMBOBULATOR_WSL_DISTRO_ENV: &str = "DISCOMBOBULATOR_WSL_DISTRO";
const DEFAULT_PROVIDER_RUNTIME_ROOT: &str = "/var/tmp/discombobulator-provider/v1";
const PROVIDER_BOOTSTRAP_VERSION: &str = "2026-04-04-v1";

#[cfg(target_os = "macos")]
type HostProvider = AppleLinuxProvider;
#[cfg(target_os = "windows")]
type HostProvider = WslProvider;

#[derive(Clone, Debug)]
struct PortableProvider {
    shell: HostProvider,
    kind: LocalLinuxProviderKind,
    identity: String,
    #[cfg(target_os = "macos")]
    bundle: String,
    #[cfg(target_os = "windows")]
    auto_install: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct StagedHostRoot {
    host_root: PathBuf,
    remote_root: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct PortableBuildPlan {
    project_root: String,
    job_root: String,
    remote_file: String,
    remote_output: String,
    local_output: PathBuf,
    remote_contexts: Vec<String>,
    staged_roots: Vec<StagedHostRoot>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RemoteTooling {
    manifest_path: String,
    cargo_home: String,
    rustup_home: String,
    target_dir: String,
    release_binary: String,
}

pub fn run(command: BuildCommand) -> Result<()> {
    let cwd = std::env::current_dir()?;
    let provider = PortableProvider::resolve()?;
    let layout = ProviderRuntimeLayout::new(resolve_provider_runtime_root()?)?;
    let mut log = String::new();

    provider.ensure_available(&mut log)?;
    let session = provider.session();
    let metadata = layout.metadata(
        provider.kind,
        provider.identity.clone(),
        PROVIDER_BOOTSTRAP_VERSION,
    )?;
    session.write_runtime_metadata(&metadata, &mut log)?;
    let tooling = ensure_remote_tooling(&session, &layout, &mut log)?;
    let plan = prepare_build_plan(&session, &layout, &cwd, &command, &mut log)?;

    let build_result = run_remote_build(&session, &tooling, &plan, &command, &mut log)
        .and_then(|_| collect_remote_output(&session, &plan, &mut log));

    if build_result.is_err() {
        return build_result.with_context(|| {
         format!(
            "portable discombobulator build failed\nprovider={}\nprovider identity={}\nprovider job root={}\nprovider log:\n{}",
            provider.kind.as_str(),
            provider.identity,
            plan.job_root,
            log
         )
      });
    }

    session.remove_path(&plan.job_root, &mut log)?;
    println!("{}", plan.local_output.display());
    Ok(())
}

pub fn bundle_flat(_command: BundleFlatCommand) -> Result<()> {
    bail!("discombobulator bundle flat currently requires a Linux host; macOS and Windows build support goes through a local Linux provider with `discombobulator build`")
}

pub fn fetch_remote(
    _registry: &Registry,
    _storage: &StorageRoot,
    _remote_name: &str,
    _image: &str,
    _arch: Architecture,
    _refresh: bool,
) -> Result<PathBuf> {
    bail!("discombobulator remote fetch currently requires a Linux host; use `discombobulator build` with a remote FROM on macOS or Windows")
}

pub fn run_internal(_command: InternalRunCommand) -> Result<()> {
    bail!("discombobulator internal-run is Linux-only")
}

impl PortableProvider {
    fn session(&self) -> ProviderSession<HostProvider> {
        ProviderSession::new(self.shell.clone())
    }

    #[cfg(target_os = "macos")]
    fn resolve() -> Result<Self> {
        let helper = std::env::var(DISCOMBOBULATOR_APPLE_LINUX_HELPER_ENV)
         .with_context(|| {
            format!(
               "macOS portable discombobulator builds require {} to point at the Metalor Apple Linux helper",
               DISCOMBOBULATOR_APPLE_LINUX_HELPER_ENV
            )
         })?;
        let vm_name = optional_trimmed_env(DISCOMBOBULATOR_APPLE_LINUX_VM_ENV)
            .unwrap_or_else(|| "prodigy".to_string());
        let bundle = optional_trimmed_env(DISCOMBOBULATOR_APPLE_LINUX_BUNDLE_ENV)
            .unwrap_or_else(|| DEFAULT_APPLE_LINUX_BUNDLE.to_string());
        let shell = AppleLinuxProvider::new(PathBuf::from(helper), vm_name.clone())?;
        Ok(Self {
            shell,
            kind: LocalLinuxProviderKind::MacLocal,
            identity: vm_name,
            bundle,
        })
    }

    #[cfg(target_os = "windows")]
    fn resolve() -> Result<Self> {
        let resolution =
            resolve_wsl_distro(optional_trimmed_env(DISCOMBOBULATOR_WSL_DISTRO_ENV).as_deref())?;
        let shell = WslProvider::new(resolution.distro.clone())?;
        Ok(Self {
            shell,
            kind: LocalLinuxProviderKind::Wsl2,
            identity: resolution.distro,
            auto_install: resolution.auto_install,
        })
    }

    #[cfg(target_os = "macos")]
    fn ensure_available(&self, log: &mut String) -> Result<()> {
        self.shell.ensure_available(&self.bundle, log)
    }

    #[cfg(target_os = "windows")]
    fn ensure_available(&self, log: &mut String) -> Result<()> {
        self.shell.ensure_available(self.auto_install, log)
    }
}

fn resolve_provider_runtime_root() -> Result<String> {
    let runtime_root = optional_trimmed_env(DISCOMBOBULATOR_PROVIDER_RUNTIME_ROOT_ENV)
        .unwrap_or_else(|| DEFAULT_PROVIDER_RUNTIME_ROOT.to_string());
    Ok(runtime_root)
}

fn ensure_remote_tooling<S>(
    session: &ProviderSession<S>,
    layout: &ProviderRuntimeLayout,
    log: &mut String,
) -> Result<RemoteTooling>
where
    S: metalor::runtime::linux_provider::ProviderShell,
{
    let cargo_home = layout.join("toolchain/cargo-home")?;
    let rustup_home = layout.join("toolchain/rustup-home")?;
    let cargo_bin = provider_join(&cargo_home, "bin/cargo");
    let bootstrap_stamp = layout.stamp_path("bootstrap", PROVIDER_BOOTSTRAP_VERSION)?;
    session.ensure_warm_state(
        "discombobulator bootstrap",
        &bootstrap_stamp,
        &[&cargo_bin],
        log,
        |session, log| {
            session.run(
                &bootstrap_script(&cargo_home, &rustup_home, &cargo_bin),
                log,
            )
        },
    )?;

    let source_fingerprint = discombobulator_source_fingerprint()?;
    let source_root = layout.join(&format!("tool-source/{source_fingerprint}"))?;
    let source_stamp = layout.stamp_path("tool-source", &source_fingerprint)?;
    let manifest_path = provider_join(&source_root, "discombobulator/Cargo.toml");
    session.ensure_warm_state(
        "discombobulator source sync",
        &source_stamp,
        &[&manifest_path],
        log,
        |session, log| {
            session.run(
                &format!(
                    "rm -rf {source_root} && mkdir -p {source_root}",
                    source_root = shell_quote(&source_root),
                ),
                log,
            )?;
            session.stage_host_path(discombobulator_source_dir(), &source_root, false, log)?;
            Ok(())
        },
    )?;

    let target_dir = layout.join(&format!("tool-build/{source_fingerprint}"))?;
    let release_binary = provider_join(&target_dir, "release/discombobulator");
    Ok(RemoteTooling {
        manifest_path,
        cargo_home,
        rustup_home,
        target_dir,
        release_binary,
    })
}

fn bootstrap_script(cargo_home: &str, rustup_home: &str, cargo_bin: &str) -> String {
    format!(
      "set -euo pipefail\n\
if ! command -v apt-get >/dev/null 2>&1; then\n\
   echo 'portable discombobulator builds currently require an apt-based Linux provider image' >&2\n\
   exit 1\n\
fi\n\
export DEBIAN_FRONTEND=noninteractive\n\
apt-get update\n\
apt-get install -y --no-install-recommends btrfs-progs zstd qemu-user-static build-essential curl ca-certificates pkg-config tar util-linux\n\
mkdir -p {cargo_home} {rustup_home}\n\
export CARGO_HOME={cargo_home}\n\
export RUSTUP_HOME={rustup_home}\n\
if [ ! -x {cargo_bin} ]; then\n\
   curl https://sh.rustup.rs -sSf | sh -s -- -y --profile minimal --default-toolchain stable\n\
fi\n\
{cargo_bin} --version\n",
      cargo_home = shell_quote(cargo_home),
      rustup_home = shell_quote(rustup_home),
      cargo_bin = shell_quote(cargo_bin),
   )
}

fn discombobulator_source_fingerprint() -> Result<String> {
    let mut hasher = Sha256::new();
    let cargo_toml = discombobulator_source_dir().join("Cargo.toml");
    let cargo_lock = discombobulator_source_dir().join("Cargo.lock");
    let source_dir = discombobulator_source_dir().join("src");
    for path in [&cargo_toml, &cargo_lock, &source_dir] {
        fingerprint_path(path, &mut hasher)?;
    }
    Ok(hex::encode(hasher.finalize()))
}

fn discombobulator_source_dir() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

fn fingerprint_path(path: &Path, hasher: &mut Sha256) -> Result<()> {
    let metadata =
        fs::metadata(path).with_context(|| format!("failed to read {}", path.display()))?;
    hasher.update(path.to_string_lossy().as_bytes());
    if metadata.is_file() {
        hasher.update(b"\0file\0");
        hasher
            .update(&fs::read(path).with_context(|| format!("failed to read {}", path.display()))?);
        return Ok(());
    }
    if metadata.is_dir() {
        hasher.update(b"\0dir\0");
        let mut entries =
            fs::read_dir(path)?.collect::<std::result::Result<Vec<_>, std::io::Error>>()?;
        entries.sort_by_key(|entry| entry.file_name());
        for entry in entries {
            fingerprint_path(&entry.path(), hasher)?;
        }
        return Ok(());
    }
    bail!(
        "unsupported source path for fingerprinting: {}",
        path.display()
    )
}

fn prepare_build_plan<S>(
    session: &ProviderSession<S>,
    layout: &ProviderRuntimeLayout,
    cwd: &Path,
    command: &BuildCommand,
    log: &mut String,
) -> Result<PortableBuildPlan>
where
    S: metalor::runtime::linux_provider::ProviderShell,
{
    let project_root = layout.join(&format!("projects/{}", project_key(cwd)))?;
    session.run(&format!("mkdir -p {}", shell_quote(&project_root)), log)?;
    let job = session.prepare_job_root(layout, "discombobulator-build", log)?;
    let local_output = resolve_output_path(cwd, &command.output)?;
    let remote_output_dir = provider_join(&job.root, "output");
    let remote_output = provider_join(
        &remote_output_dir,
        output_file_name(&local_output)?
            .to_str()
            .context("output path must have a normal file name")?,
    );

    let build_file = resolve_existing_file(cwd, &command.file)?;
    let contexts = parse_context_dirs(cwd, &command.context)?;
    let mut requests = Vec::<(String, PathBuf)>::new();
    add_stage_request(
        &mut requests,
        "build-file".to_string(),
        build_file
            .parent()
            .context("build file must have a parent directory")?
            .to_path_buf(),
    );
    for (name, path) in &contexts {
        add_stage_request(
            &mut requests,
            format!("context-{}", sanitize_label(name)),
            path.clone(),
        );
    }

    let mut staged_roots = Vec::new();
    for (label, host_root) in requests {
        let remote_parent = provider_join(&job.root, &format!("inputs/{label}"));
        let remote_root = session.stage_host_path(&host_root, &remote_parent, false, log)?;
        staged_roots.push(StagedHostRoot {
            host_root,
            remote_root,
        });
    }
    staged_roots.sort_by(|left, right| {
        right
            .host_root
            .components()
            .count()
            .cmp(&left.host_root.components().count())
    });

    let remote_file = translate_host_path(&build_file, &staged_roots)?;
    let mut remote_contexts = Vec::new();
    for (name, host_root) in contexts {
        remote_contexts.push(format!(
            "{}={}",
            name,
            translate_host_path(&host_root, &staged_roots)?
        ));
    }

    Ok(PortableBuildPlan {
        project_root,
        job_root: job.root,
        remote_file,
        remote_output,
        local_output,
        remote_contexts,
        staged_roots,
    })
}

fn run_remote_build<S>(
    session: &ProviderSession<S>,
    tooling: &RemoteTooling,
    plan: &PortableBuildPlan,
    command: &BuildCommand,
    log: &mut String,
) -> Result<()>
where
    S: metalor::runtime::linux_provider::ProviderShell,
{
    let cargo_build = shell_join(&[
        "cargo".to_string(),
        "build".to_string(),
        "--release".to_string(),
        "--manifest-path".to_string(),
        tooling.manifest_path.clone(),
    ]);
    let build_command = shell_join(&build_command_argv(tooling, command, plan));
    let script = format!(
        "set -euo pipefail\n\
mkdir -p {project_root} {output_dir}\n\
export CARGO_HOME={cargo_home}\n\
export RUSTUP_HOME={rustup_home}\n\
export CARGO_TARGET_DIR={target_dir}\n\
export PATH={cargo_bin_dir}:\"$PATH\"\n\
{cargo_build}\n\
cd {project_root}\n\
{build_command}\n",
        project_root = shell_quote(&plan.project_root),
        output_dir = shell_quote(
            Path::new(&plan.remote_output)
                .parent()
                .context("remote output path must have a parent")?
                .to_str()
                .context("remote output parent must be valid UTF-8")?
        ),
        cargo_home = shell_quote(&tooling.cargo_home),
        rustup_home = shell_quote(&tooling.rustup_home),
        target_dir = shell_quote(&tooling.target_dir),
        cargo_bin_dir = shell_quote(&provider_join(&tooling.cargo_home, "bin")),
        cargo_build = cargo_build,
        build_command = build_command,
    );
    session.run(&script, log)
}

fn collect_remote_output<S>(
    session: &ProviderSession<S>,
    plan: &PortableBuildPlan,
    log: &mut String,
) -> Result<()>
where
    S: metalor::runtime::linux_provider::ProviderShell,
{
    let output_parent = plan
        .local_output
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or(std::env::current_dir()?);
    session.collect_path(&plan.remote_output, &output_parent, log)
}

fn build_command_argv(
    tooling: &RemoteTooling,
    command: &BuildCommand,
    plan: &PortableBuildPlan,
) -> Vec<String> {
    let mut argv = vec![];
    argv.push(tooling.release_binary.clone());
    argv.push("build".to_string());
    argv.push("--file".to_string());
    argv.push(plan.remote_file.clone());
    for context in &plan.remote_contexts {
        argv.push("--context".to_string());
        argv.push(context.clone());
    }
    for build_arg in &command.build_arg {
        argv.push("--build-arg".to_string());
        argv.push(build_arg.clone());
    }
    argv.push("--output".to_string());
    argv.push(plan.remote_output.clone());
    argv.push("--kind".to_string());
    argv.push(output_kind_name(command.kind).to_string());
    if let Some(publish_base) = &command.publish_base {
        argv.push("--publish-base".to_string());
        argv.push(publish_base.clone());
    }
    argv
}

fn output_kind_name(kind: OutputKindArg) -> &'static str {
    match kind {
        OutputKindArg::App => "app",
        OutputKindArg::Base => "base",
    }
}

fn resolve_existing_file(cwd: &Path, path: &Path) -> Result<PathBuf> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        cwd.join(path)
    };
    let canonical = fs::canonicalize(&absolute)
        .with_context(|| format!("failed to access {}", absolute.display()))?;
    if canonical.is_file() == false {
        bail!("build file does not exist: {}", canonical.display());
    }
    Ok(canonical)
}

fn resolve_output_path(cwd: &Path, output: &Path) -> Result<PathBuf> {
    let absolute = if output.is_absolute() {
        output.to_path_buf()
    } else {
        cwd.join(output)
    };
    if let Some(parent) = absolute.parent() {
        fs::create_dir_all(parent)?;
    }
    Ok(absolute)
}

fn parse_context_dirs(cwd: &Path, raw_contexts: &[String]) -> Result<BTreeMap<String, PathBuf>> {
    let mut contexts = BTreeMap::new();
    for raw in raw_contexts {
        let (name, value) = parse_key_value(raw, "--context")?;
        let candidate = PathBuf::from(value);
        let absolute = if candidate.is_absolute() {
            candidate
        } else {
            cwd.join(candidate)
        };
        let canonical = fs::canonicalize(&absolute)
            .with_context(|| format!("failed to access {}", absolute.display()))?;
        if canonical.is_dir() == false {
            bail!("context {} is not a directory", canonical.display());
        }
        contexts.insert(name, canonical);
    }
    Ok(contexts)
}

fn add_stage_request(requests: &mut Vec<(String, PathBuf)>, label: String, host_root: PathBuf) {
    if requests
        .iter()
        .any(|(_, existing)| path_is_within(&host_root, existing))
    {
        return;
    }
    requests.retain(|(_, existing)| path_is_within(existing, &host_root) == false);
    requests.push((label, host_root));
}

fn translate_host_path(path: &Path, staged_roots: &[StagedHostRoot]) -> Result<String> {
    let canonical =
        fs::canonicalize(path).with_context(|| format!("failed to access {}", path.display()))?;
    for staged_root in staged_roots {
        if !path_is_within(&canonical, &staged_root.host_root) {
            continue;
        }
        let relative = canonical
            .strip_prefix(&staged_root.host_root)
            .with_context(|| {
                format!(
                    "failed to compute relative path from {} to {}",
                    staged_root.host_root.display(),
                    canonical.display()
                )
            })?;
        return remote_join_path(&staged_root.remote_root, relative);
    }

    bail!(
        "path was not staged for provider build: {}",
        canonical.display()
    )
}

fn remote_join_path(base: &str, relative: &Path) -> Result<String> {
    let mut remote = base.trim_end_matches('/').to_string();
    for component in relative.components() {
        match component {
            Component::CurDir => {}
            Component::Normal(value) => {
                if remote != "/" {
                    remote.push('/');
                }
                remote.push_str(&value.to_string_lossy());
            }
            Component::RootDir => {}
            Component::ParentDir => bail!("provider relative paths must not contain '..'"),
            Component::Prefix(_) => bail!("provider relative paths must not contain prefixes"),
        }
    }
    Ok(remote)
}

fn path_is_within(path: &Path, root: &Path) -> bool {
    path == root || path.starts_with(root)
}

fn project_key(cwd: &Path) -> String {
    let mut hasher = Sha256::new();
    hasher.update(cwd.to_string_lossy().as_bytes());
    hex::encode(hasher.finalize())
}

fn output_file_name(path: &Path) -> Result<&std::ffi::OsStr> {
    path.file_name()
        .with_context(|| format!("output path has no file name: {}", path.display()))
}

fn shell_join(argv: &[String]) -> String {
    argv.iter()
        .map(|value| shell_quote(value))
        .collect::<Vec<_>>()
        .join(" ")
}

fn shell_quote(value: &str) -> String {
    let escaped = value.replace('\'', "'\"'\"'");
    format!("'{escaped}'")
}

fn provider_join(parent: &str, child: &str) -> String {
    if parent.is_empty() {
        return child.to_string();
    }
    if child.is_empty() {
        return parent.to_string();
    }
    if parent == "/" {
        format!("/{child}")
    } else {
        format!("{}/{}", parent.trim_end_matches('/'), child)
    }
}

fn sanitize_label(value: &str) -> String {
    let sanitized: String = value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.') {
                ch
            } else {
                '-'
            }
        })
        .collect();
    if sanitized.is_empty() {
        "input".to_string()
    } else {
        sanitized
    }
}

fn optional_trimmed_env(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| value.is_empty() == false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn stage_requests_prefer_outer_roots() {
        let root = PathBuf::from("/tmp/example");
        let nested = root.join("nested");
        let mut requests = Vec::new();
        add_stage_request(&mut requests, "nested".to_string(), nested.clone());
        add_stage_request(&mut requests, "root".to_string(), root.clone());
        assert_eq!(requests, vec![("root".to_string(), root)]);
    }

    #[test]
    fn translated_path_uses_the_most_specific_stage_root() {
        let temp = tempfile::tempdir().unwrap();
        let outer = temp.path().join("project");
        let inner = outer.join("contexts").join("src");
        let binary = inner.join("bin").join("app");
        fs::create_dir_all(binary.parent().unwrap()).unwrap();
        fs::write(&binary, "ok").unwrap();
        let staged = vec![
            StagedHostRoot {
                host_root: inner.clone(),
                remote_root: "/provider/inner/src".to_string(),
            },
            StagedHostRoot {
                host_root: outer.clone(),
                remote_root: "/provider/outer/project".to_string(),
            },
        ];
        let translated = translate_host_path(&binary, &staged).unwrap();
        assert_eq!(translated, "/provider/inner/src/bin/app");
    }

    #[test]
    fn build_command_arguments_use_remote_binary_and_translated_inputs() {
        let command = BuildCommand {
            file: PathBuf::from("DiscombobuFile"),
            context: vec!["src=/tmp/source".to_string()],
            build_arg: vec!["MODE=dev".to_string()],
            output: PathBuf::from("bundle.blob.zst"),
            kind: OutputKindArg::App,
            publish_base: None,
        };
        let tooling = RemoteTooling {
            manifest_path: "/provider/source/discombobulator/Cargo.toml".to_string(),
            cargo_home: "/provider/cargo-home".to_string(),
            rustup_home: "/provider/rustup-home".to_string(),
            target_dir: "/provider/target".to_string(),
            release_binary: "/provider/target/release/discombobulator".to_string(),
        };
        let plan = PortableBuildPlan {
            project_root: "/provider/project".to_string(),
            job_root: "/provider/jobs/example".to_string(),
            remote_file: "/provider/jobs/example/inputs/build-file/DiscombobuFile".to_string(),
            remote_output: "/provider/jobs/example/output/bundle.blob.zst".to_string(),
            local_output: PathBuf::from("/tmp/bundle.blob.zst"),
            remote_contexts: vec![
                "src=/provider/jobs/example/inputs/context-src/source".to_string()
            ],
            staged_roots: Vec::new(),
        };

        let argv = build_command_argv(&tooling, &command, &plan);
        assert_eq!(argv[0], "/provider/target/release/discombobulator");
        assert!(argv.contains(&"--context".to_string()));
        assert!(argv.contains(&"src=/provider/jobs/example/inputs/context-src/source".to_string()));
        assert!(argv.contains(&"--build-arg".to_string()));
        assert!(argv.contains(&"MODE=dev".to_string()));
        assert!(argv.contains(&"/provider/jobs/example/output/bundle.blob.zst".to_string()));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_provider_requires_helper_env() {
        std::env::remove_var(DISCOMBOBULATOR_APPLE_LINUX_HELPER_ENV);
        let error = PortableProvider::resolve().unwrap_err();
        assert!(
            format!("{error:#}").contains(DISCOMBOBULATOR_APPLE_LINUX_HELPER_ENV),
            "{error:#}"
        );
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn windows_provider_accepts_explicit_distro_without_querying_wsl() {
        std::env::set_var(DISCOMBOBULATOR_WSL_DISTRO_ENV, "Ubuntu-24.04");
        let provider = PortableProvider::resolve().unwrap();
        assert_eq!(provider.identity, "Ubuntu-24.04");
        assert!(!provider.auto_install);
        std::env::remove_var(DISCOMBOBULATOR_WSL_DISTRO_ENV);
    }
}
