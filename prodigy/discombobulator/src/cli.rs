use crate::build;
use crate::plan::Architecture;
use crate::registry::{Registry, StorageRoot};
use anyhow::{bail, Context, Result};
use clap::{Args, Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "discombobulator")]
#[command(about = "Prodigy-native container builder")]
pub struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Build(BuildCommand),
    Bundle(BundleCommand),
    Remote(RemoteCommand),
    #[command(hide = true)]
    InternalRun(InternalRunCommand),
}

#[derive(Args)]
pub struct BundleCommand {
    #[command(subcommand)]
    pub subcommand: BundleSubcommand,
}

#[derive(Subcommand)]
pub enum BundleSubcommand {
    Flat(BundleFlatCommand),
}

#[derive(Args)]
pub struct BundleFlatCommand {
    #[arg(long)]
    pub binary: PathBuf,

    #[arg(long)]
    pub build_dir: PathBuf,

    #[arg(long)]
    pub output: PathBuf,

    #[arg(long)]
    pub ebpf: Vec<PathBuf>,

    #[arg(long = "tool-binary")]
    pub tool_binary: Vec<PathBuf>,

    #[arg(long = "library-search-dir")]
    pub library_search_dir: Vec<PathBuf>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub enum OutputKindArg {
    App,
    Base,
}

#[derive(Args)]
pub struct BuildCommand {
    #[arg(long)]
    pub file: PathBuf,

    #[arg(long, value_name = "name=dir")]
    pub context: Vec<String>,

    #[arg(long, value_name = "name=value")]
    pub build_arg: Vec<String>,

    #[arg(long)]
    pub output: PathBuf,

    #[arg(long, value_enum)]
    pub kind: OutputKindArg,

    #[arg(long, value_name = "name:tag")]
    pub publish_base: Option<String>,
}

#[derive(Args)]
pub struct InternalRunCommand {
    #[arg(long)]
    pub root: PathBuf,

    #[arg(long)]
    pub cwd: String,

    #[arg(long, value_name = "key=value")]
    pub env: Vec<String>,

    #[arg(long)]
    pub emulator: Option<String>,

    #[arg(long)]
    pub executable: String,

    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    pub argv: Vec<String>,
}

#[derive(Args)]
struct RemoteCommand {
    #[command(subcommand)]
    subcommand: RemoteSubcommand,
}

#[derive(Subcommand)]
enum RemoteSubcommand {
    Add(RemoteAddCommand),
    Fetch(RemoteFetchCommand),
    List,
    Remove(RemoteRemoveCommand),
}

#[derive(Args)]
struct RemoteAddCommand {
    name: String,
    registry_host: String,

    #[arg(long)]
    prefix: Option<String>,
}

#[derive(Args)]
struct RemoteFetchCommand {
    name: String,
    image: String,

    #[arg(long)]
    arch: String,

    #[arg(long)]
    refresh: bool,
}

#[derive(Args)]
struct RemoteRemoveCommand {
    name: String,
}

pub fn run() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Build(command) => build::run(command),
        Commands::Bundle(command) => run_bundle(command),
        Commands::Remote(command) => run_remote(command),
        Commands::InternalRun(command) => build::run_internal(command),
    }
}

fn run_bundle(command: BundleCommand) -> Result<()> {
    match command.subcommand {
        BundleSubcommand::Flat(command) => build::bundle_flat(command),
    }
}

fn run_remote(command: RemoteCommand) -> Result<()> {
    let storage = StorageRoot::discover(std::env::current_dir()?);
    storage.ensure_layout()?;
    let registry = Registry::open(&storage)?;

    match command.subcommand {
        RemoteSubcommand::Add(add) => {
            registry.upsert_remote(&add.name, &add.registry_host, add.prefix.as_deref())?;
            println!("registered remote {}", add.name);
        }
        RemoteSubcommand::Fetch(fetch) => {
            let arch = Architecture::parse(&fetch.arch)?;
            if registry.lookup_remote(&fetch.name)?.is_none() {
                bail!("unknown remote {}", fetch.name);
            }
            let path = build::fetch_remote(
                &registry,
                &storage,
                &fetch.name,
                &fetch.image,
                arch,
                fetch.refresh,
            )?;
            println!("{}", path.display());
        }
        RemoteSubcommand::List => {
            for remote in registry.list_remotes()? {
                let prefix = remote.repository_prefix.unwrap_or_default();
                println!("{}\t{}\t{}", remote.name, remote.registry_host, prefix);
            }
        }
        RemoteSubcommand::Remove(remove) => {
            if registry.remove_remote(&remove.name)? {
                println!("removed remote {}", remove.name);
            } else {
                bail!("unknown remote {}", remove.name);
            }
        }
    }

    Ok(())
}

pub fn parse_key_value(argument: &str, what: &str) -> Result<(String, String)> {
    let (name, value) = argument
        .split_once('=')
        .with_context(|| format!("{what} must use name=value syntax: {argument}"))?;
    if name.is_empty() || value.is_empty() {
        bail!("{what} must use name=value syntax: {argument}");
    }

    Ok((name.to_string(), value.to_string()))
}
