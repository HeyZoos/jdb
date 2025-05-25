use clap::ArgGroup;
use clap::Parser;
use nix::sys::ptrace;
use nix::unistd::Pid;
use nix::{sys::wait::waitpid, unistd::{fork, ForkResult}};
use tracing::{info};
use std::str::FromStr;

/// ```sh
/// cargo run -- --program /bin/echo
/// ```
fn main() {
    // Install a global tracing subscriber that listens for events and filters based on the value of
    // the RUST_LOG environment variable. This is a quick and easy way to get the loggers to just
    // **do stuff**.
    tracing_subscriber::fmt::init();

    // Get the program invocation arguments.
    let args = Args::parse();

    // Attach to running program or spawn program.
    if let Some(pid) = args.pid {
        info!(target=pid, pid=std::process::id(), "Attaching to target process");
        ptrace::attach(Pid::from_raw(pid)).unwrap();
    }

    if let Some(program) = args.program {
        match unsafe{fork()} {
            Ok(ForkResult::Parent { child, .. }) => {
                info!(child=child.as_raw(), pid=std::process::id(), "Created child process");
                waitpid(child, None).unwrap();
            }
            Ok(ForkResult::Child) => {
                // Indicates that this process is to be traced by its parent.
                // This is the only ptrace request to be issued by the tracee.
                // https://docs.rs/nix/latest/nix/sys/ptrace/fn.traceme.html
                info!(pid=std::process::id(), "Asking to be traced");
                ptrace::traceme().unwrap();
                info!(pid=std::process::id(), program, "Calling exec");
                let program_cstring = std::ffi::CString::from_str(program.as_str()).unwrap();
                // Conventionally, argv[0] is the program name.
                nix::unistd::execv::<_>(&program_cstring, &vec![program_cstring.clone()]).unwrap();
            }
            Err(_) => println!("Fork failed"),
        }
    }
}

#[derive(Debug, Parser)]
#[command(about, version, group(
    ArgGroup::new("target")
        .required(true)  // Something must be provided for this argument group
        .multiple(false)  // Only one argument can be provided
        .args(["program", "pid"])
))]
struct Args {
    // We can possibly kick off this child as a subprocess i.e. `jdb --program <program>`
    #[arg(long)]
    program: Option<String>,

    // Or we can attach to a running PID `jdb --pid <pid>`
    #[arg(long)]
    pid: Option<i32>,
}
