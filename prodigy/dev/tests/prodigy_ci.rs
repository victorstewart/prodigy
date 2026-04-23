use std::env;
use std::ffi::OsString;
use std::path::PathBuf;
use std::process::{Command, ExitCode, Stdio};

const PRODIGY_TARGET_ALL_FILTER: &str =
   "^(prodigy_dev_[a-z0-9_]+|prodigy_[a-z0-9_]+)$";
const PRODIGY_TARGET_MESH_FILTER: &str =
   "^(prodigy_dev_mesh_unit|prodigy_dev_service_mesh_matrix_smoke|prodigy_dev_service_mesh_matrix_ci)$";
const PRODIGY_TARGET_DEPLOYMENTS_FILTER: &str =
   "^(prodigy_dev_deployments_unit|prodigy_dev_deployments_matrix_smoke|prodigy_dev_deployments_matrix_ci)$";
const PRODIGY_TARGET_CLUSTER_FILTER: &str = "^prodigy_dev_deployments_matrix_ci$";
const PRODIGY_TARGET_FUZZ_FILTER: &str =
   "^(prodigy_[a-z0-9_]+_fuzz_smoke|prodigy_[a-z0-9_]+_sanitizer_gate)$";

struct Options
{
   build_dir: PathBuf,
   ctest_filter: String,
   ctest_filter_explicit: bool,
   target: String,
   build_jobs: String,
   skip_build: bool,
   keep_tmp: bool,
}

fn usage(program: &str)
{
   eprintln!(
      "usage: {program} [--build-dir=PATH] [--ctest-filter=REGEX] [--target=all|mesh|deployments|cluster|fuzz] [--build-jobs=N] [--skip-build] [--keep-tmp]"
   );
}

fn parse_args() -> Result<Options, String>
{
   let mut options = Options {
      build_dir: PathBuf::from("build/prodigy-dev"),
      ctest_filter: PRODIGY_TARGET_ALL_FILTER.to_string(),
      ctest_filter_explicit: false,
      target: "all".to_string(),
      build_jobs: "8".to_string(),
      skip_build: false,
      keep_tmp: false,
   };

   let mut args = env::args_os();
   let program = args.next().unwrap_or_else(|| OsString::from("prodigy_ci"));

   for raw in args
   {
      let Some(arg) = raw.to_str() else {
         return Err(format!("invalid non-utf8 argument: {:?}", raw));
      };

      if let Some(v) = arg.strip_prefix("--build-dir=")
      {
         options.build_dir = PathBuf::from(v);
      }
      else if let Some(v) = arg.strip_prefix("--ctest-filter=")
      {
         options.ctest_filter = v.to_string();
         options.ctest_filter_explicit = true;
      }
      else if let Some(v) = arg.strip_prefix("--target=")
      {
         options.target = v.to_string();
      }
      else if let Some(v) = arg.strip_prefix("--build-jobs=")
      {
         options.build_jobs = v.to_string();
      }
      else if arg == "--skip-build"
      {
         options.skip_build = true;
      }
      else if arg == "--keep-tmp"
      {
         options.keep_tmp = true;
      }
      else if arg == "--help" || arg == "-h"
      {
         usage(&program.to_string_lossy());
         std::process::exit(0);
      }
      else
      {
         return Err(format!("unknown argument: {arg}"));
      }
   }

   if options.target != "all"
      && options.target != "mesh"
      && options.target != "deployments"
      && options.target != "cluster"
      && options.target != "fuzz"
   {
      return Err(format!("invalid --target value: {}", options.target));
   }

   if !options.ctest_filter_explicit && options.target == "all"
   {
      options.ctest_filter = PRODIGY_TARGET_ALL_FILTER.to_string();
   }

   if !options.ctest_filter_explicit && options.target == "mesh"
   {
      options.ctest_filter = PRODIGY_TARGET_MESH_FILTER.to_string();
   }

   if !options.ctest_filter_explicit && options.target == "deployments"
   {
      options.ctest_filter = PRODIGY_TARGET_DEPLOYMENTS_FILTER.to_string();
   }

   if !options.ctest_filter_explicit && options.target == "cluster"
   {
      options.ctest_filter = PRODIGY_TARGET_CLUSTER_FILTER.to_string();
   }

   if !options.ctest_filter_explicit && options.target == "fuzz"
   {
      options.ctest_filter = PRODIGY_TARGET_FUZZ_FILTER.to_string();
   }

   Ok(options)
}

fn run_step(step_name: &str, cmd: &mut Command) -> Result<(), String>
{
   eprintln!("==> {step_name}");
   eprintln!("    {:?}", cmd);
   let status = cmd.status().map_err(|e| format!("{step_name} failed to start: {e}"))?;
   if status.success()
   {
      Ok(())
   }
   else
   {
      Err(format!("{step_name} failed with status {status}"))
   }
}

fn enforce_fake_public_boundary_ci(cmd: &mut Command)
{
   cmd.env("PRODIGY_DEV_ENABLE_FAKE_IPV4_BOUNDARY", "1");
   cmd.env("PRODIGY_DEV_REQUIRE_FAKE_IPV4_BOUNDARY", "1");
}

fn ensure_root() -> Result<(), String>
{
   let output = Command::new("id")
      .arg("-u")
      .stdout(Stdio::piped())
      .stderr(Stdio::inherit())
      .output()
      .map_err(|e| format!("unable to execute id -u: {e}"))?;

   if !output.status.success()
   {
      return Err(format!("id -u exited with status {}", output.status));
   }

   let uid_text = String::from_utf8(output.stdout).map_err(|e| format!("invalid uid output: {e}"))?;
   let uid_trimmed = uid_text.trim();
   if uid_trimmed == "0"
   {
      Ok(())
   }
   else
   {
      Err(format!(
         "prodigy netns tests require root; current uid={uid_trimmed}"
      ))
   }
}

fn main() -> ExitCode
{
   let options = match parse_args()
   {
      Ok(opts) => opts,
      Err(err) =>
      {
         eprintln!("error: {err}");
         let program = env::args().next().unwrap_or_else(|| "prodigy_ci".to_string());
         usage(&program);
         return ExitCode::from(2);
      }
   };

   if let Err(err) = ensure_root()
   {
      eprintln!("error: {err}");
      return ExitCode::from(1);
   }

   if !options.skip_build
   {
      let mut build = Command::new("cmake");
      build
         .arg("--build")
         .arg(&options.build_dir)
         .arg("-j")
         .arg(&options.build_jobs)
         .stdout(Stdio::inherit())
         .stderr(Stdio::inherit());

      if let Err(err) = run_step("build", &mut build)
      {
         eprintln!("{err}");
         return ExitCode::from(1);
      }
   }

   let mut ctest = Command::new("ctest");
   ctest
      .arg("--test-dir")
      .arg(&options.build_dir)
      .arg("--output-on-failure")
      .arg("-R")
      .arg(&options.ctest_filter)
      .stdout(Stdio::inherit())
      .stderr(Stdio::inherit());

   if options.keep_tmp
   {
      ctest.env("PRODIGY_DEV_KEEP_TMP", "1");
   }
   enforce_fake_public_boundary_ci(&mut ctest);

   if let Err(err) = run_step("ctest", &mut ctest)
   {
      eprintln!("{err}");
      return ExitCode::from(1);
   }

   eprintln!("PASS: Prodigy CI suite is green");
   ExitCode::SUCCESS
}
