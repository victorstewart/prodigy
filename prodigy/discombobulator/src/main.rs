fn main() -> std::process::ExitCode {
    match discombobulator::run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("discombobulator: {error:#}");
            std::process::ExitCode::FAILURE
        }
    }
}
