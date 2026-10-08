//! `aska` — the Aska command-line client (Client Design §4, Table 3).
//!
//! A thin layer over `aska-core`: argument parsing, terminal I/O, QR rendering, exit codes.
//! It holds no secret of its own; everything sensitive lives in the core's `Session`. Nothing
//! is written to disk unless the user names a file (`--out`, `--out-keycard`, `profile create`),
//! and secrets are never accepted on the command line or from the environment — only from the
//! terminal prompt, a camera helper, or `--stdin`.
#![deny(unsafe_code)]

/// `println!` that reports a failed write instead of panicking: evaluates to `io::Result<()>`,
/// so call sites use `out!(…)?`. A reader that goes away early (`aska verify | head -1`) turns
/// into `BrokenPipe`, which `Fail` maps to a quiet exit with code 141 — the command unwinds
/// normally, so the `Session` and every buffer are still wiped on the way out.
macro_rules! out {
    ($($arg:tt)*) => {{
        use std::io::Write as _;
        writeln!(std::io::stdout().lock(), $($arg)*)
    }};
}

/// `eprintln!` that never panics: diagnostics on a closed or full stderr are dropped.
macro_rules! note {
    ($($arg:tt)*) => {{
        use std::io::Write as _;
        let _ = writeln!(std::io::stderr().lock(), $($arg)*);
    }};
}

mod cmd_misc;
mod cmd_receive;
mod cmd_send;
mod ctx;
mod files;
mod handover;
mod term;

use clap::{Args, Parser, Subcommand};
use ctx::{exit, parse_shares, parse_ttl, Ctx, Fail, Globals, QrStyle};
use std::path::PathBuf;
use std::process::ExitCode;

const LONG_ABOUT: &str = "\
Aska — secure notes that leave nothing behind.

Nothing is stored: no history, no contacts, no cache, no log. A note exists on the relay as
ciphertext until it expires, and on screen while you look at it. Every command first runs the
environment checks of `aska doctor` and shows their warnings.

Exit codes: 0 success · 2 success after acknowledged warnings · 3 you declined ·
4 relay unreachable or full · 5 nothing found or opened · 6 refused (not through Tor, or a
relay that is not a .onion) · 141 standard output closed early (e.g. `| head`) · 1 other error.

If the local network blocks Tor, Aska cannot work around it by itself (it uses the system Tor
and writes no configuration): the doctor says so when it can tell, and every failed network
attempt ends with the same advice — connect Tor through a bridge with your platform's own tool
(Tails: Tor Connection; Whonix: Anon Connection Wizard; elsewhere Tor Browser, then --tor-browser).

--stdin (scripting) reads every input from standard input, in this order, one per line:
  send / seal:  [passphrase] [decoy text] [decoy passphrase] [distress text]
                [distress passphrase] — only those you asked for — then the note until EOF.
  receive / open / share combine / key / share split:
                key material lines, then an EMPTY line, then the passphrase line (may be empty).
  receive --receiving-seed: the seed line is 24 words, the check of a seed stored in the
                --profile (xxxx-xxxx-xxxx), or empty for the only stored seed.
  profile create: the passphrase.  profile add-seed: the passphrase, then the 24 words
                (none with --new).  profile remove-seed: the passphrase.
Hand-over material is then printed as `KEYCARD …`, `WORDS …`, `SHARE i/n …`, `RELAYS …` lines.";

#[derive(Parser)]
#[command(name = "aska", version, about = "Aska secure notes — command-line client", long_about = LONG_ABOUT)]
struct Cli {
    #[command(flatten)]
    g: GlobalArgs,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Args)]
struct GlobalArgs {
    /// Tor SOCKS5 port (loopback only; on a Whonix Workstation the gateway, 10.152.152.10)
    #[arg(long, global = true, value_name = "HOST:PORT")]
    socks: Option<String>,
    /// Tor control port; needed only for relays that require a circle key
    #[arg(long, global = true, value_name = "HOST:PORT")]
    control: Option<String>,
    /// Control-port cookie file (CookieAuthentication 1)
    #[arg(long, global = true, value_name = "FILE")]
    control_cookie: Option<PathBuf>,
    /// Prompt for the control-port password (HashedControlPassword)
    #[arg(long, global = true)]
    control_password: bool,
    /// Encrypted profile with relays (and circle key); prompts for its passphrase
    #[arg(long, global = true, value_name = "FILE")]
    profile: Option<PathBuf>,
    /// Relay .onion address (repeatable; added to the profile's relays)
    #[arg(long = "relay", global = true, value_name = "ONION")]
    relays: Vec<String>,
    /// Acknowledge doctor warnings without asking (success then exits 2)
    #[arg(short = 'y', long, global = true)]
    yes: bool,
    /// Proceed even if secrets cannot be locked in RAM (see `aska doctor`)
    #[arg(long, global = true)]
    accept_unlocked_memory: bool,
    /// Skip the random 0–90 s delay before network requests (weakens cover; for tests)
    #[arg(long, global = true)]
    fast: bool,
    /// QR rendering [default: half on a terminal, none otherwise]
    #[arg(long, global = true, value_enum)]
    qr: Option<QrStyle>,
    /// Idle timeout in seconds before the Session closes itself
    #[arg(long, global = true, default_value_t = 300)]
    idle: u64,
    /// Camera helper, used only when no camera can be read in-process (or always, with
    /// --scan-helper): a command that prints the decoded QR text on stdout
    #[arg(
        long,
        global = true,
        default_value = "zbarcam --raw --oneshot -Sdisable -Sqrcode.enable",
        value_name = "CMD"
    )]
    scan_cmd: String,
    /// Scan with the external helper instead of the in-process camera reader
    #[arg(long, global = true)]
    scan_helper: bool,
    /// Scripting mode: all inputs from standard input in the documented order; no prompts
    #[arg(long, global = true)]
    stdin: bool,
    /// Use Tor Browser's Tor (127.0.0.1:9150) — e.g. after connecting it through a bridge
    #[arg(long, global = true, conflicts_with = "socks")]
    tor_browser: bool,
}

#[derive(Args, Clone)]
struct SendArgs {
    /// Protection level
    #[arg(long, value_enum, default_value_t = LevelArg::Quick)]
    level: LevelArg,
    /// Guarded threshold, e.g. 2of3 or 3of5 (implies --level guarded)
    #[arg(long, value_parser = parse_shares)]
    shares: Option<(u8, u8)>,
    /// Pin the size class (1 = 4 KiB, 2 = 16 KiB, 3 = 64 KiB); default: smallest that fits
    #[arg(long, value_parser = clap::value_parser!(u8).range(1..=3))]
    class: Option<u8>,
    /// How long the relay keeps the Block: 1h … 7d
    #[arg(long, default_value = "24h", value_parser = parse_ttl)]
    ttl: u16,
    /// Also require a passphrase to open the real note (prompted)
    #[arg(long)]
    passphrase: bool,
    /// Add a decoy note behind its own passphrase (prompted)
    #[arg(long)]
    decoy: bool,
    /// Add a distress note: its passphrase shows it and destroys the real one (prompted)
    #[arg(long)]
    distress: bool,
    /// Write the Key Card text to this new file (normally it is only shown)
    #[arg(long, value_name = "FILE")]
    out_keycard: Option<PathBuf>,
    /// "for:" name shown with each Share, in order (repeatable; displayed only, never stored)
    #[arg(long = "for", value_name = "NAME")]
    for_labels: Vec<String>,
    /// Posting attempts on fresh circuits before giving up
    #[arg(long, default_value_t = 3)]
    attempts: u32,
    /// Seal for a Receiving Key (askar1…, DC-02): nothing to hand over afterwards
    #[arg(long, value_name = "ASKAR", conflicts_with_all = ["level", "shares", "for_labels", "out_keycard"])]
    to: Option<String>,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, clap::ValueEnum)]
enum LevelArg {
    /// The key travels whole: Key Card QR + 24 words
    Quick,
    /// The key is split into Shares for different people
    Guarded,
}

#[derive(Args, Clone)]
struct ReceiveArgs {
    /// Fetch only this size class. Default: the Key Card's class; for 24 words or Shares, which carry no class, all three
    #[arg(long, value_parser = clap::value_parser!(u8).range(1..=3))]
    class: Option<u8>,
    /// Seconds the note stays on screen before it is burned (any key closes it sooner)
    #[arg(long, default_value_t = 300)]
    view_seconds: u64,
    /// Fetch attempts (the Block may not be posted yet)
    #[arg(long, default_value_t = 3)]
    attempts: u32,
    /// Seconds between attempts
    #[arg(long, default_value_t = 30)]
    interval: u64,
    /// Receive with a receiving seed (24 words, prompted) instead of key material (DC-02)
    #[arg(long)]
    receiving_seed: bool,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run the environment checks and exit (0 clean, 2 warnings, 6 refusals)
    Doctor,
    /// Write a note, seal it, post it through Tor, then hand over the key
    Send(SendArgs),
    /// Split mode, offline side: seal a note into a Block file instead of posting it
    Seal {
        #[command(flatten)]
        args: SendArgs,
        /// New file to write the Block (and its label) to
        #[arg(long, value_name = "FILE")]
        out: PathBuf,
    },
    /// Split mode, networked side: post a Block file to the relays
    Post {
        file: PathBuf,
        /// How long the relay keeps the Block: 1h … 7d
        #[arg(long, default_value = "24h", value_parser = parse_ttl)]
        ttl: u16,
    },
    /// Collect key material, fetch the drop through Tor, open and show the note
    Receive(ReceiveArgs),
    /// Split mode, offline side: match and open a note from a bucket file (see `drop get`)
    Open {
        bucket: PathBuf,
        #[command(flatten)]
        args: ReceiveArgs,
    },
    /// Shares of a key (Guarded level)
    Share {
        #[command(subcommand)]
        cmd: ShareCmd,
    },
    /// Re-encode key material for another hand-over
    Key {
        #[command(subcommand)]
        cmd: KeyCmd,
    },
    /// Raw Dead Drop operations (operators and tests)
    Drop {
        #[command(subcommand)]
        cmd: DropCmd,
    },
    /// Show this binary's fingerprint and how to check it (contacts nothing)
    Verify,
    /// Optional encrypted profile holding relays and a circle key
    Profile {
        #[command(subcommand)]
        cmd: ProfileCmd,
    },
}

#[derive(Subcommand)]
enum ShareCmd {
    /// Split key material (words or Key Card) into k-of-n Shares, shown one at a time
    Split {
        #[arg(long, value_parser = clap::value_parser!(u8).range(2..=16))]
        k: u8,
        #[arg(long, value_parser = clap::value_parser!(u8).range(2..=16))]
        n: u8,
        /// "for:" name shown with each Share, in order (repeatable)
        #[arg(long = "for", value_name = "NAME")]
        for_labels: Vec<String>,
    },
    /// Collect k Shares, verify they reconstruct, then continue as `receive`
    Combine {
        #[command(flatten)]
        args: ReceiveArgs,
        /// Stop after the Shares are verified; fetch and show nothing
        #[arg(long)]
        check_only: bool,
    },
}

#[derive(Subcommand)]
enum KeyCmd {
    /// Show the key as 24 words
    Words,
    /// New receiving key (DC-02): a 24-word seed to keep and a public askar1… key to give out
    Receive {
        /// Re-derive the public key from an existing seed (prompted) instead of a new one
        #[arg(long, conflicts_with = "stored")]
        from_words: bool,
        /// Show the public key of a seed stored in the --profile, named by its check
        /// (xxxx-xxxx-xxxx); with one stored seed the check may be omitted
        #[arg(long, value_name = "CHECK", num_args = 0..=1, default_missing_value = "")]
        stored: Option<String>,
    },
    /// Show the key as a Key Card carrying the given relays (and circle key)
    Card {
        /// Prompt for a circle auth key to put in the card (applies to every relay)
        #[arg(long)]
        auth_key: bool,
    },
}

#[derive(Subcommand)]
enum DropCmd {
    /// Ask a relay for its limits
    Info { onion: String },
    /// Put a Block file (from `seal`) on one relay
    Put {
        onion: String,
        file: PathBuf,
        #[arg(long, default_value = "24h", value_parser = parse_ttl)]
        ttl: u16,
    },
    /// Fetch a whole bucket; write it to a file only with --out (for `aska open`)
    Get {
        onion: String,
        #[arg(long, value_parser = clap::value_parser!(u8).range(1..=3))]
        class: u8,
        #[arg(long, value_name = "FILE")]
        out: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
enum ProfileCmd {
    /// Create a profile from the --relay addresses given (prompts for a passphrase)
    Create {
        #[arg(long, value_name = "FILE")]
        file: PathBuf,
        /// Prompt for a circle auth key to store with the relays
        #[arg(long)]
        auth_key: bool,
    },
    /// Open a profile and list its relays and stored receiving keys (secrets are never shown)
    Open {
        #[arg(long, value_name = "FILE")]
        file: PathBuf,
    },
    /// Store a receiving seed in the profile: an existing one (24 words, prompted) or --new
    AddSeed {
        #[arg(long, value_name = "FILE")]
        file: PathBuf,
        /// Create a fresh seed and store it (its words are shown once, for a paper backup)
        #[arg(long)]
        new: bool,
    },
    /// Remove a stored receiving seed, named by its check (xxxx-xxxx-xxxx)
    RemoveSeed {
        #[arg(long, value_name = "FILE")]
        file: PathBuf,
        #[arg(value_name = "CHECK")]
        check: String,
    },
    /// Overwrite the profile with random bytes and delete it
    Forget {
        #[arg(long, value_name = "FILE")]
        file: PathBuf,
    },
}

fn send_opts(a: &SendArgs) -> cmd_send::SendOpts {
    cmd_send::SendOpts {
        guarded: a.level == LevelArg::Guarded,
        shares: a.shares,
        class: a.class,
        ttl: a.ttl,
        decoy: a.decoy,
        distress: a.distress,
        passphrase: a.passphrase,
        out_keycard: a.out_keycard.clone(),
        for_labels: a.for_labels.clone(),
        attempts: a.attempts,
        to: a.to.clone(),
    }
}

fn receive_opts(a: &ReceiveArgs, shares_only: bool, check_only: bool) -> cmd_receive::ReceiveOpts {
    cmd_receive::ReceiveOpts {
        class: a.class,
        view_seconds: a.view_seconds,
        attempts: a.attempts,
        interval_secs: a.interval,
        shares_only,
        check_only,
        receiving_seed: a.receiving_seed,
    }
}

fn doctor_only(ctx: &mut Ctx) -> Result<(), Fail> {
    use aska_core::doctor::{self, DoctorConfig, Severity};
    let findings = doctor::run(&DoctorConfig {
        tor: ctx.tor.clone(),
        relay_addresses: ctx.relays.iter().map(|r| r.onion()).collect(),
        probe_tor: true,
    });
    let mut worst = exit::OK;
    for f in &findings {
        let tag = match f.severity {
            Severity::Refuse => {
                worst = exit::DOCTOR_REFUSED;
                "REFUSE"
            }
            Severity::Warn => {
                if worst == exit::OK {
                    worst = exit::WARNED;
                }
                "WARN"
            }
            Severity::Info => "INFO",
        };
        out!("[{tag}] {}{}", f.message, crate::ctx::cli_hint_for(f))?;
    }
    if findings.is_empty() {
        out!("No findings.")?;
    }
    if worst == exit::OK {
        Ok(())
    } else {
        Err(Fail(worst, String::new()))
    }
}

fn run(cli: Cli) -> Result<i32, Fail> {
    aska_core::platform::disable_core_dumps();
    let g = cli.g;
    let mut ctx = Ctx::build(Globals {
        socks: g.socks,
        control: g.control,
        control_cookie: g.control_cookie,
        control_password: g.control_password,
        profile: g.profile,
        relays: g.relays,
        yes: g.yes,
        accept_unlocked_memory: g.accept_unlocked_memory,
        fast: g.fast,
        qr: g.qr,
        idle: g.idle,
        scan_cmd: g.scan_cmd,
        scan_helper: g.scan_helper,
        stdin: g.stdin,
        tor_browser: g.tor_browser,
    })?;
    match cli.cmd {
        Cmd::Doctor => doctor_only(&mut ctx)?,
        Cmd::Send(a) => cmd_send::run(&mut ctx, &send_opts(&a), None)?,
        Cmd::Seal { args, out } => cmd_send::run(&mut ctx, &send_opts(&args), Some(&out))?,
        Cmd::Post { file, ttl } => cmd_misc::post(&mut ctx, &file, ttl)?,
        Cmd::Receive(a) => cmd_receive::run(&mut ctx, &receive_opts(&a, false, false), None)?,
        Cmd::Open { bucket, args } => {
            cmd_receive::run(&mut ctx, &receive_opts(&args, false, false), Some(&bucket))?
        }
        Cmd::Share { cmd } => match cmd {
            ShareCmd::Split { k, n, for_labels } => {
                if n < k {
                    return Err(Fail::new(exit::ERROR, "n must be at least k"));
                }
                cmd_misc::share_split(&mut ctx, k, n, &for_labels)?
            }
            ShareCmd::Combine { args, check_only } => {
                cmd_receive::run(&mut ctx, &receive_opts(&args, true, check_only), None)?
            }
        },
        Cmd::Key { cmd } => match cmd {
            KeyCmd::Words => cmd_misc::key(&mut ctx, false, false)?,
            KeyCmd::Receive { from_words, stored } => {
                cmd_misc::key_receive(&mut ctx, from_words, stored.as_deref())?
            }
            KeyCmd::Card { auth_key } => cmd_misc::key(&mut ctx, true, auth_key)?,
        },
        Cmd::Drop { cmd } => match cmd {
            DropCmd::Info { onion } => cmd_misc::drop_info(&mut ctx, &onion)?,
            DropCmd::Put { onion, file, ttl } => cmd_misc::drop_put(&mut ctx, &onion, &file, ttl)?,
            DropCmd::Get { onion, class, out } => {
                cmd_misc::drop_get(&mut ctx, &onion, class, out.as_deref())?
            }
        },
        Cmd::Verify => cmd_misc::verify(&mut ctx)?,
        Cmd::Profile { cmd } => match cmd {
            ProfileCmd::Create { file, auth_key } => {
                cmd_misc::profile_create(&mut ctx, &file, auth_key)?
            }
            ProfileCmd::Open { file } => cmd_misc::profile_open(&mut ctx, &file)?,
            ProfileCmd::AddSeed { file, new } => cmd_misc::profile_add_seed(&mut ctx, &file, new)?,
            ProfileCmd::RemoveSeed { file, check } => {
                cmd_misc::profile_remove_seed(&mut ctx, &file, &check)?
            }
            ProfileCmd::Forget { file } => cmd_misc::profile_forget(&mut ctx, &file)?,
        },
    }
    Ok(ctx.success_code())
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli) {
        Ok(code) => ExitCode::from(code as u8),
        Err(Fail(code, msg)) => {
            if !msg.is_empty() {
                note!("aska: {msg}");
            }
            ExitCode::from(code as u8)
        }
    }
}
