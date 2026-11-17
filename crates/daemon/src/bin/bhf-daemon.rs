// SPDX-License-Identifier: Apache-2.0

const USAGE: &str = "Usage: bhf-daemon [--mcp | --security-config FILE]

Default: deterministic JSON-RPC over stdio, local single-user (no token)
  --security-config FILE  JSON-RPC with workspace-scoped security: the tenants,
                          token files, workspace roots and roles in FILE
                          (see docs/site/daemon.md)
  --mcp                   MCP over newline-delimited stdio
  --help                  Show this help
  --version               Show the version";

fn main() {
    let mut mcp = false;
    let mut security_config: Option<std::path::PathBuf> = None;
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

    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let result = if mcp {
        daemon::run_mcp(stdin.lock(), stdout.lock())
    } else {
        daemon::run_json_rpc_with_security(stdin.lock(), stdout.lock(), security)
    };
    if let Err(error) = result {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
