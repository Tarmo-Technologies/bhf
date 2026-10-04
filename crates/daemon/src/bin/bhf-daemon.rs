// SPDX-License-Identifier: Apache-2.0

fn main() {
    let mut mcp = false;
    for arg in std::env::args_os().skip(1) {
        match arg.to_str() {
            Some("--mcp") if !mcp => mcp = true,
            Some("--help" | "-h") => {
                println!("bhf-daemon {}\n\nUsage: bhf-daemon [--mcp]\n\nDefault: deterministic JSON-RPC over stdio\n  --mcp      MCP over newline-delimited stdio\n  --help     Show this help\n  --version  Show the version", env!("CARGO_PKG_VERSION"));
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

    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let result = if mcp {
        daemon::run_mcp(stdin.lock(), stdout.lock())
    } else {
        daemon::run_json_rpc(stdin.lock(), stdout.lock())
    };
    if let Err(error) = result {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
