//! `aska-drop serve` — the Aska Dead Drop relay binary.
//!
//! Binds 127.0.0.1 only (Tor publishes the onion service and forwards to it), locks memory,
//! disables core dumps, and serves ADP/1 until killed. It writes nothing to disk and prints
//! nothing while running; the only output is a one-line reason on a fatal start-up error.
#![deny(unsafe_code)]

use aska_drop::{harden, serve, Config, Store};
use aska_proto::{DEFAULT_MAX_TTL_HOURS, DEFAULT_PORT, RELAY_READ_TIMEOUT_SECS};
use clap::{Parser, Subcommand};
use std::net::{Ipv4Addr, SocketAddr};
use std::process::ExitCode;
use std::sync::{Arc, Mutex};
use std::time::Duration;

#[derive(Parser)]
#[command(name = "aska-drop", version, about = "Aska Dead Drop relay (ADP/1)")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run the relay on loopback (Tor forwards the onion service to it).
    Serve(ServeArgs),
}

/// The complete configuration surface (§9.3, Table 4) plus one development-only switch.
#[derive(clap::Args)]
struct ServeArgs {
    /// Loopback port Tor forwards to.
    #[arg(long, default_value_t = DEFAULT_PORT)]
    port: u16,
    /// Longest TTL a client may request (hard ceiling 168 = 7 days).
    #[arg(long, default_value_t = DEFAULT_MAX_TTL_HOURS, value_parser = clap::value_parser!(u16).range(1..=168))]
    max_ttl_hours: u16,
    /// Capacity in Blocks for size class 1 (4 KiB); 0 = do not serve the class.
    #[arg(long, default_value_t = 2000)]
    cap_1: usize,
    /// Capacity in Blocks for size class 2 (16 KiB); 0 = do not serve the class.
    #[arg(long, default_value_t = 800)]
    cap_2: usize,
    /// Capacity in Blocks for size class 3 (64 KiB); 0 = do not serve the class.
    #[arg(long, default_value_t = 200)]
    cap_3: usize,
    /// Base proof-of-work difficulty in bits (adaptive bits are added on top).
    #[arg(long, default_value_t = 0, value_parser = clap::value_parser!(u8).range(0..=64))]
    pow_base: u8,
    /// DEVELOPMENT ONLY: start even if memory cannot be locked against swapping.
    /// Never use on a relay that serves real Blocks.
    #[arg(long, hide = true)]
    insecure_no_mlock: bool,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let Cmd::Serve(a) = cli.cmd;

    let cfg = Config {
        caps: [a.cap_1, a.cap_2, a.cap_3],
        max_ttl_hours: a.max_ttl_hours,
        pow_base_difficulty: a.pow_base,
    };

    if let Err(e) = harden::no_core_dumps() {
        eprintln!("aska-drop: {e}");
        return ExitCode::from(3);
    }
    // Fail now, with a reason, rather than abort hours later when the store outgrows the
    // lock limit (see harden.rs). Skipped only in the development mode that does not lock.
    if !a.insecure_no_mlock {
        if let Err(e) = harden::check_memlock_limit(&cfg) {
            eprintln!("aska-drop: {e}");
            return ExitCode::from(3);
        }
    }
    if let Err(e) = harden::lock_memory() {
        if a.insecure_no_mlock {
            eprintln!("aska-drop: WARNING: memory is NOT locked ({e}); development use only");
        } else {
            eprintln!("aska-drop: {e}");
            return ExitCode::from(3);
        }
    }
    let store = Arc::new(Mutex::new(Store::new(cfg)));
    let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, a.port));

    let rt = match tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_io()
        .enable_time()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("aska-drop: runtime: {e}");
            return ExitCode::from(2);
        }
    };
    rt.block_on(async move {
        let listener = match tokio::net::TcpListener::bind(addr).await {
            Ok(l) => l,
            Err(e) => {
                eprintln!("aska-drop: cannot bind {addr}: {e}");
                return ExitCode::from(2);
            }
        };
        serve(
            listener,
            store,
            Duration::from_secs(RELAY_READ_TIMEOUT_SECS),
        )
        .await;
        ExitCode::SUCCESS
    })
}
