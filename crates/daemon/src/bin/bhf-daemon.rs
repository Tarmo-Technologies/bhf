// SPDX-License-Identifier: Apache-2.0

const USAGE: &str = "Usage: bhf-daemon [--mcp | [--security-config FILE] [--jobs-dir DIR]]

Default: deterministic JSON-RPC over stdio, local single-user (no token)
  --security-config FILE  JSON-RPC with workspace-scoped security: the tenants,
                          token files, workspace roots and roles in FILE
                          (see docs/site/daemon.md)
  --jobs-dir DIR          Run the continuous fuzzing scheduler, its jobs kept
                          in DIR, behind the submitJob, listJobs and cancelJob
                          methods
  --job-workers N         Jobs run at once (default 1)
  --bhf PATH              The bhf a job runs (default: the bhf beside
                          bhf-daemon, else bhf on PATH)
  --mcp                   MCP over newline-delimited stdio
  --help                  Show this help
  --version               Show the version";

fn main() {
    let mut mcp = false;
    let mut security_config: Option<std::path::PathBuf> = None;
    let mut jobs_dir: Option<std::path::PathBuf> = None;
    let mut job_workers: u32 = 1;
    let mut bhf: Option<std::path::PathBuf> = None;
    let mut args = std::env::args_os().skip(1);
    let value = |args: &mut std::iter::Skip<std::env::ArgsOs>, flag: &str| match args.next() {
        Some(value) => value,
        None => {
            eprintln!("bhf-daemon: {flag} needs a value; use --help");
            std::process::exit(2);
        }
    };
    while let Some(arg) = args.next() {
        let text = arg.to_str();
        if let Some(path) = text.and_then(|text| text.strip_prefix("--security-config=")) {
            security_config = Some(path.into());
            continue;
        }
        match text {
            Some("--mcp") if !mcp => mcp = true,
            Some("--security-config") if security_config.is_none() => {
                security_config = Some(value(&mut args, "--security-config").into());
            }
            Some("--jobs-dir") if jobs_dir.is_none() => {
                jobs_dir = Some(value(&mut args, "--jobs-dir").into());
            }
            Some("--bhf") if bhf.is_none() => bhf = Some(value(&mut args, "--bhf").into()),
            Some("--job-workers") => {
                let workers = value(&mut args, "--job-workers");
                match workers.to_str().and_then(|text| text.parse::<u32>().ok()) {
                    Some(workers) if workers > 0 => job_workers = workers,
                    _ => {
                        eprintln!("bhf-daemon: --job-workers takes a positive number");
                        std::process::exit(2);
                    }
                }
            }
            Some("--help" | "-h") => {
                println!("bhf-daemon {}\n\n{USAGE}", env!("CARGO_PKG_VERSION"));
                return;
            }
            Some("--version" | "-V") => {
                println!(
                    "bhf-daemon {}\ncommit: {}",
                    env!("CARGO_PKG_VERSION"),
                    cli::BUILD_COMMIT
                );
                return;
            }
            _ => {
                eprintln!("bhf-daemon: unknown option {:?}; use --help", arg);
                std::process::exit(2);
            }
        }
    }
    if mcp && security_config.is_some() {
        eprintln!(
            "bhf-daemon: --security-config applies to JSON-RPC; MCP over stdio has no \
             authentication, so it serves one local user"
        );
        std::process::exit(2);
    }
    if mcp && jobs_dir.is_some() {
        eprintln!("bhf-daemon: --jobs-dir serves the JSON-RPC job methods; MCP has none");
        std::process::exit(2);
    }
    // Read before the first request: a config the daemon cannot use stops it
    // at start, with the reason.
    let security = match security_config.as_deref() {
        Some(path) => match daemon::load_security_config(path) {
            Ok(security) => security,
            Err(error) => {
                eprintln!("bhf-daemon: --security-config: {error}");
                std::process::exit(2);
            }
        },
        None => daemon::DaemonSecurityConfig::local_single_user(),
    };

    let mut services = daemon::DaemonServices::default();
    if let Some(dir) = jobs_dir {
        let name = format!("bhf{}", std::env::consts::EXE_SUFFIX);
        let bhf = bhf.unwrap_or_else(|| {
            let beside = std::env::current_exe()
                .ok()
                .and_then(|exe| exe.parent().map(|dir| dir.join(&name)));
            let on_path = std::env::var_os("PATH")
                .into_iter()
                .flat_map(|path| std::env::split_paths(&path).collect::<Vec<_>>())
                .map(|dir| dir.join(&name));
            beside
                .into_iter()
                .chain(on_path)
                .find(|bhf| bhf.is_file())
                .unwrap_or_else(|| name.clone().into())
        });
        if let Err(error) = std::fs::create_dir_all(&dir) {
            eprintln!("bhf-daemon: --jobs-dir {}: {error}", dir.display());
            std::process::exit(2);
        }
        let config = continuous_daemon::DaemonConfig {
            data_dir: dir.clone(),
            max_concurrent_jobs: job_workers,
            bhf_bin: bhf,
            webhook_url: None,
            poll_interval: std::time::Duration::from_millis(200),
        };
        match continuous_daemon::Scheduler::start(&config) {
            Ok(scheduler) => services.jobs = Some(scheduler),
            Err(error) => {
                eprintln!("bhf-daemon: --jobs-dir {}: {error}", dir.display());
                std::process::exit(2);
            }
        }
    }

    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let result = if mcp {
        daemon::run_mcp(stdin.lock(), stdout.lock())
    } else {
        daemon::run_json_rpc_with_services(stdin.lock(), stdout.lock(), security, &services)
    };
    if let Err(error) = result {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
