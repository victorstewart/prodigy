use discombobulator::plan::{
    parse_build_spec, resolve_build_spec, Architecture, FromSource, OutputKind,
};
use std::collections::BTreeMap;

#[test]
fn parses_remote_force_and_executes_absolute_binary() {
    let spec = parse_build_spec(
        r#"
      FROM remote force dockerhub library/ubuntu:24.04 for arm64
      ARG CHANNEL
      ENV MODE=${CHANNEL}
      WORKDIR /app
      COPY {src} ./bin/server /app/server
      SURVIVE /app/server
      EXECUTE ["/app/server", "--mode", "${CHANNEL}"]
      "#,
    )
    .unwrap();

    match spec.from.source {
        FromSource::Remote {
            ref remote,
            ref image,
            force_refresh,
        } => {
            assert_eq!(remote, "dockerhub");
            assert_eq!(image, "library/ubuntu:24.04");
            assert!(force_refresh);
        }
        other => panic!("unexpected FROM source: {other:?}"),
    }
    assert_eq!(spec.from.arch, Architecture::Arm64);

    let mut build_args = BTreeMap::new();
    build_args.insert("CHANNEL".to_string(), "stable".to_string());
    let resolved = resolve_build_spec(&spec, OutputKind::App, &build_args).unwrap();
    assert_eq!(resolved.env[0], ("MODE".to_string(), "stable".to_string()));
    assert_eq!(resolved.execute.unwrap()[0], "/app/server");
}

#[test]
fn parses_local_base_from_form() {
    let spec = parse_build_spec(
        r#"
      FROM build-sleeve:latest for x86_64
      EXECUTE ["/app/server"]
      "#,
    )
    .unwrap();

    match spec.from.source {
        FromSource::LocalBase(ref reference) => assert_eq!(reference, "build-sleeve:latest"),
        other => panic!("unexpected FROM source: {other:?}"),
    }
    assert_eq!(spec.from.arch, Architecture::X86_64);
}

#[test]
fn rejects_undefined_arg_interpolation() {
    let spec = parse_build_spec(
        r#"
      FROM scratch for x86_64
      ARG MODE
      EXECUTE ["/app/server", "${MISSING}"]
      "#,
    )
    .unwrap();

    let error = resolve_build_spec(&spec, OutputKind::App, &BTreeMap::new()).unwrap_err();
    assert!(format!("{error:#}").contains("undefined ARG MISSING"));
}

#[test]
fn rejects_non_absolute_execute_paths() {
    let spec = parse_build_spec(
        r#"
      FROM scratch for x86_64
      EXECUTE ["server"]
      "#,
    )
    .unwrap();

    let error = resolve_build_spec(&spec, OutputKind::App, &BTreeMap::new()).unwrap_err();
    assert!(format!("{error:#}").contains("absolute executable path"));
}

#[test]
fn rejects_unsupported_legacy_instructions() {
    let error = parse_build_spec(
        r#"
      FROM scratch for x86_64
      ENTRYPOINT ["/app/server"]
      "#,
    )
    .unwrap_err();
    assert!(format!("{error:#}").contains("unsupported instruction"));

    let error = parse_build_spec(
        r#"
      FROM scratch for x86_64
      CMD ["--port", "8080"]
      "#,
    )
    .unwrap_err();
    assert!(format!("{error:#}").contains("unsupported instruction"));
}

#[test]
fn rejects_copy_without_named_context_syntax() {
    let error = parse_build_spec(
        r#"
      FROM scratch for x86_64
      COPY src ./server /app/server
      EXECUTE ["/app/server"]
      "#,
    )
    .unwrap_err();
    assert!(format!("{error:#}").contains("COPY requires `{name}` context syntax"));
}

#[test]
fn rejects_shell_form_run() {
    let error = parse_build_spec(
        r#"
      FROM scratch for x86_64
      RUN echo hello
      "#,
    )
    .unwrap_err();

    assert!(format!("{error:#}").contains("exec-form arrays"));
}

#[test]
fn output_kind_validation_requires_execute_for_apps_and_rejects_it_for_bases() {
    let app_spec = parse_build_spec(
        r#"
      FROM scratch for x86_64
      SURVIVE /app/server
      "#,
    )
    .unwrap();
    let app_error = resolve_build_spec(&app_spec, OutputKind::App, &BTreeMap::new()).unwrap_err();
    assert!(format!("{app_error:#}").contains("app builds require EXECUTE"));

    let base_spec = parse_build_spec(
        r#"
      FROM scratch for x86_64
      EXECUTE ["/app/server"]
      "#,
    )
    .unwrap();
    let base_error =
        resolve_build_spec(&base_spec, OutputKind::Base, &BTreeMap::new()).unwrap_err();
    assert!(format!("{base_error:#}").contains("base builds reject EXECUTE"));
}

#[test]
fn rejects_copy_sources_that_use_parent_dir_escape() {
    let spec = parse_build_spec(
        r#"
      FROM scratch for x86_64
      COPY {src} ../secret /app/secret
      EXECUTE ["/app/server"]
      "#,
    )
    .unwrap();

    let error = resolve_build_spec(&spec, OutputKind::App, &BTreeMap::new()).unwrap_err();
    assert!(format!("{error:#}").contains("COPY source paths must stay relative"));
}

#[test]
fn run_captures_env_and_workdir_state_at_each_step() {
    let spec = parse_build_spec(
        r#"
      FROM scratch for x86_64
      ENV MODE=alpha
      WORKDIR /first
      RUN ["/bin/one"]
      ENV MODE=beta
      WORKDIR /second
      RUN ["/bin/two"]
      EXECUTE ["/bin/three"]
      "#,
    )
    .unwrap();

    let resolved = resolve_build_spec(&spec, OutputKind::App, &BTreeMap::new()).unwrap();
    assert_eq!(resolved.runs.len(), 2);
    assert_eq!(resolved.runs[0].workdir, "/first");
    assert_eq!(
        resolved.runs[0].env,
        vec![("MODE".to_string(), "alpha".to_string())]
    );
    assert_eq!(resolved.runs[1].workdir, "/second");
    assert_eq!(
        resolved.runs[1].env,
        vec![
            ("MODE".to_string(), "alpha".to_string()),
            ("MODE".to_string(), "beta".to_string())
        ]
    );
}
