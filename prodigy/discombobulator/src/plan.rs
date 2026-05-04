use anyhow::{bail, Context, Result};
use metalor::parser::{
    interpolate_braced_variables, parse_exec_array, significant_lines, valid_identifier,
};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path, PathBuf};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OutputKind {
    App,
    Base,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct BuildSpec {
    pub from: FromSpec,
    pub instructions: Vec<Instruction>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct FromSpec {
    pub source: FromSource,
    pub arch: Architecture,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub enum FromSource {
    Scratch,
    LocalBase(String),
    Remote {
        remote: String,
        image: String,
        force_refresh: bool,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub enum Instruction {
    Arg {
        name: String,
    },
    Env {
        key: String,
        value: String,
    },
    Workdir {
        path: String,
    },
    Copy {
        context: String,
        source: String,
        destination: String,
    },
    Run {
        argv: Vec<String>,
    },
    Survive {
        pattern: String,
    },
    Execute {
        argv: Vec<String>,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize)]
pub enum Architecture {
    X86_64,
    Arm64,
    Riscv64,
}

impl Architecture {
    pub fn parse(raw: &str) -> Result<Self> {
        match raw {
            "x86_64" | "amd64" => Ok(Self::X86_64),
            "arm64" | "aarch64" => Ok(Self::Arm64),
            "riscv64" | "riscv" => Ok(Self::Riscv64),
            _ => bail!("unsupported architecture {raw}"),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::X86_64 => "x86_64",
            Self::Arm64 => "arm64",
            Self::Riscv64 => "riscv64",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ResolvedBuildSpec {
    pub from: FromSpec,
    pub declared_args: BTreeSet<String>,
    pub env: Vec<(String, String)>,
    pub workdir: String,
    pub steps: Vec<ResolvedBuildStep>,
    pub copies: Vec<ResolvedCopy>,
    pub runs: Vec<ResolvedRun>,
    pub survives: Vec<String>,
    pub execute: Option<Vec<String>>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ResolvedCopy {
    pub context: String,
    pub source: String,
    pub destination: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ResolvedRun {
    pub argv: Vec<String>,
    pub env: Vec<(String, String)>,
    pub workdir: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub enum ResolvedBuildStep {
    Copy(ResolvedCopy),
    Run(ResolvedRun),
}

pub fn parse_build_spec(contents: &str) -> Result<BuildSpec> {
    let mut from: Option<FromSpec> = None;
    let mut instructions = Vec::new();

    for line in significant_lines(contents) {
        let instruction = parse_instruction(line.text)
            .with_context(|| format!("line {}: {}", line.number, line.text))?;
        match instruction {
            ParsedInstruction::From(parsed_from) => {
                if from.is_some() {
                    bail!(
                        "line {}: multiple FROM instructions are not allowed",
                        line.number
                    );
                }
                from = Some(parsed_from);
            }
            ParsedInstruction::Instruction(instruction) => instructions.push(instruction),
        }
    }

    let from = from.context("DiscombobuFile must contain exactly one FROM instruction")?;
    Ok(BuildSpec { from, instructions })
}

pub fn resolve_build_spec(
    spec: &BuildSpec,
    output_kind: OutputKind,
    build_args: &BTreeMap<String, String>,
) -> Result<ResolvedBuildSpec> {
    let mut declared_args = BTreeSet::new();
    let mut env = Vec::new();
    let mut workdir = "/".to_string();
    let mut steps = Vec::new();
    let mut copies = Vec::new();
    let mut runs = Vec::new();
    let mut survives = Vec::new();
    let mut execute = None;

    for instruction in &spec.instructions {
        match instruction {
            Instruction::Arg { name } => {
                declared_args.insert(name.clone());
            }
            Instruction::Env { key, value } => {
                let resolved_key = interpolate(key, build_args)?;
                let resolved_value = interpolate(value, build_args)?;
                env.push((resolved_key, resolved_value));
            }
            Instruction::Workdir { path } => {
                let resolved = interpolate(path, build_args)?;
                workdir = resolve_container_path(&workdir, &resolved)?;
            }
            Instruction::Copy {
                context,
                source,
                destination,
            } => {
                let resolved_context = interpolate(context, build_args)?;
                let resolved_source = interpolate(source, build_args)?;
                let resolved_destination = interpolate(destination, build_args)?;
                let destination = resolve_container_path(&workdir, &resolved_destination)?;
                let copy = ResolvedCopy {
                    context: resolved_context,
                    source: normalize_relative_pattern(&resolved_source)?,
                    destination,
                };
                copies.push(copy.clone());
                steps.push(ResolvedBuildStep::Copy(copy));
            }
            Instruction::Run { argv } => {
                let mut resolved = Vec::with_capacity(argv.len());
                for token in argv {
                    resolved.push(interpolate(token, build_args)?);
                }
                if resolved.is_empty() {
                    bail!("RUN requires at least one argv element");
                }
                let run = ResolvedRun {
                    argv: resolved,
                    env: env.clone(),
                    workdir: workdir.clone(),
                };
                runs.push(run.clone());
                steps.push(ResolvedBuildStep::Run(run));
            }
            Instruction::Survive { pattern } => {
                survives.push(normalize_container_pattern(&interpolate(
                    pattern, build_args,
                )?)?);
            }
            Instruction::Execute { argv } => {
                if execute.is_some() {
                    bail!("multiple EXECUTE instructions are not allowed");
                }

                let mut resolved = Vec::with_capacity(argv.len());
                for token in argv {
                    resolved.push(interpolate(token, build_args)?);
                }
                if resolved.is_empty() {
                    bail!("EXECUTE requires at least one argv element");
                }
                if resolved[0].starts_with('/') == false {
                    bail!("EXECUTE requires an absolute executable path");
                }
                execute = Some(resolved);
            }
        }
    }

    for name in build_args.keys() {
        if declared_args.contains(name) == false {
            bail!("undefined ARG {name}");
        }
    }

    match output_kind {
        OutputKind::App => {
            if execute.is_none() {
                bail!("app builds require EXECUTE");
            }
        }
        OutputKind::Base => {
            if execute.is_some() {
                bail!("base builds reject EXECUTE");
            }
        }
    }

    Ok(ResolvedBuildSpec {
        from: spec.from.clone(),
        declared_args,
        env,
        workdir,
        steps,
        copies,
        runs,
        survives,
        execute,
    })
}

fn interpolate(value: &str, build_args: &BTreeMap<String, String>) -> Result<String> {
    interpolate_braced_variables(value, build_args, "ARG")
}

enum ParsedInstruction {
    From(FromSpec),
    Instruction(Instruction),
}

fn parse_instruction(line: &str) -> Result<ParsedInstruction> {
    if let Some(rest) = line.strip_prefix("FROM ") {
        return Ok(ParsedInstruction::From(parse_from(rest)?));
    }
    if let Some(rest) = line.strip_prefix("ARG ") {
        let name = rest.trim();
        if valid_identifier(name) == false {
            bail!("ARG requires a valid identifier");
        }
        return Ok(ParsedInstruction::Instruction(Instruction::Arg {
            name: name.to_string(),
        }));
    }
    if let Some(rest) = line.strip_prefix("ENV ") {
        let (key, value) = rest
            .split_once('=')
            .context("ENV must use KEY=value syntax")?;
        if valid_identifier(key.trim()) == false {
            bail!("ENV requires a valid identifier");
        }
        return Ok(ParsedInstruction::Instruction(Instruction::Env {
            key: key.trim().to_string(),
            value: value.trim().to_string(),
        }));
    }
    if let Some(rest) = line.strip_prefix("WORKDIR ") {
        return Ok(ParsedInstruction::Instruction(Instruction::Workdir {
            path: rest.trim().to_string(),
        }));
    }
    if let Some(rest) = line.strip_prefix("COPY ") {
        return Ok(ParsedInstruction::Instruction(parse_copy(rest)?));
    }
    if let Some(rest) = line.strip_prefix("RUN ") {
        return Ok(ParsedInstruction::Instruction(Instruction::Run {
            argv: parse_exec_array(rest)?,
        }));
    }
    if let Some(rest) = line.strip_prefix("SURVIVE ") {
        return Ok(ParsedInstruction::Instruction(Instruction::Survive {
            pattern: rest.trim().to_string(),
        }));
    }
    if let Some(rest) = line.strip_prefix("EXECUTE ") {
        return Ok(ParsedInstruction::Instruction(Instruction::Execute {
            argv: parse_exec_array(rest)?,
        }));
    }

    bail!("unsupported instruction");
}

fn parse_from(rest: &str) -> Result<FromSpec> {
    let tokens: Vec<&str> = rest.split_whitespace().collect();
    if tokens.len() < 3 {
        bail!("FROM requires a base and architecture");
    }

    if tokens[0] == "remote" {
        match tokens.as_slice() {
            ["remote", name, image, "for", arch] => Ok(FromSpec {
                source: FromSource::Remote {
                    remote: (*name).to_string(),
                    image: (*image).to_string(),
                    force_refresh: false,
                },
                arch: Architecture::parse(arch)?,
            }),
            ["remote", "force", name, image, "for", arch] => Ok(FromSpec {
                source: FromSource::Remote {
                    remote: (*name).to_string(),
                    image: (*image).to_string(),
                    force_refresh: true,
                },
                arch: Architecture::parse(arch)?,
            }),
            _ => bail!(
                "FROM remote must use `FROM remote <name> <image> for <arch>` or `FROM remote force <name> <image> for <arch>`"
            ),
        }
    } else {
        match tokens.as_slice() {
            [base, "for", arch] => {
                let source = if *base == "scratch" {
                    FromSource::Scratch
                } else {
                    FromSource::LocalBase((*base).to_string())
                };

                Ok(FromSpec {
                    source,
                    arch: Architecture::parse(arch)?,
                })
            }
            _ => bail!("FROM must use `FROM <base> for <arch>`"),
        }
    }
}

fn parse_copy(rest: &str) -> Result<Instruction> {
    let mut parts = rest.split_whitespace();
    let context = parts.next().context("COPY requires a named context")?;
    let source = parts.next().context("COPY requires a source path")?;
    let destination = parts.next().context("COPY requires a destination path")?;
    if parts.next().is_some() {
        bail!("COPY accepts exactly one context, one source, and one destination");
    }
    let context = context
        .strip_prefix('{')
        .and_then(|value| value.strip_suffix('}'))
        .context("COPY requires `{name}` context syntax")?;
    if context.is_empty() {
        bail!("COPY requires `{{name}}` context syntax");
    }

    Ok(Instruction::Copy {
        context: context.to_string(),
        source: source.to_string(),
        destination: destination.to_string(),
    })
}

pub fn resolve_container_path(workdir: &str, raw: &str) -> Result<String> {
    let joined = if raw.starts_with('/') {
        PathBuf::from(raw)
    } else {
        PathBuf::from(workdir).join(raw)
    };

    normalize_absolute_path(&joined)
}

pub fn normalize_absolute_path(path: &Path) -> Result<String> {
    if path.is_absolute() == false {
        bail!("expected an absolute path");
    }

    let mut parts = Vec::new();
    for component in path.components() {
        match component {
            Component::RootDir => {}
            Component::Normal(value) => parts.push(value.to_string_lossy().to_string()),
            Component::CurDir => {}
            Component::ParentDir => {
                if parts.pop().is_none() {
                    bail!("path escapes root");
                }
            }
            Component::Prefix(_) => bail!("unsupported path prefix"),
        }
    }

    if parts.is_empty() {
        Ok("/".to_string())
    } else {
        Ok(format!("/{}", parts.join("/")))
    }
}

pub fn normalize_relative_pattern(raw: &str) -> Result<String> {
    if raw.starts_with('/') || raw.contains("..") {
        bail!("COPY source paths must stay relative to their named context");
    }
    if raw.contains('?') || raw.contains('[') || raw.contains(']') || raw.contains("**") {
        bail!("only `*` wildcard expansion is supported in v1");
    }

    let normalized = raw.trim_start_matches("./").trim().to_string();
    if normalized.is_empty() {
        bail!("COPY source path must not be empty");
    }
    Ok(normalized)
}

pub fn normalize_container_pattern(raw: &str) -> Result<String> {
    if raw.starts_with('/') == false {
        bail!("SURVIVE paths must be absolute");
    }
    if raw.contains('?') || raw.contains('[') || raw.contains(']') || raw.contains("**") {
        bail!("only `*` wildcard expansion is supported in v1");
    }

    normalize_absolute_path(Path::new(raw))
}
