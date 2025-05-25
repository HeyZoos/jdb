use clap::ArgGroup;
use clap::Parser;
use nix::sys::ptrace;
use nix::unistd::Pid;
use nix::{
    sys::wait::waitpid,
    unistd::{ForkResult, fork},
};
use std::str::FromStr;
use tracing::info;

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

    let mut target: Option<Pid> = None;

    // Attach to running program.
    if let Some(pid) = args.pid {
        info!(
            target = pid,
            pid = std::process::id(),
            "Attaching to target process"
        );
        target = Some(Pid::from_raw(pid));
        ptrace::attach(target.unwrap()).unwrap();
    }

    // Or attempt to create and attach to a child program.
    if let Some(program) = args.program {
        match unsafe { fork() } {
            Ok(ForkResult::Parent { child, .. }) => {
                info!(
                    child = child.as_raw(),
                    pid = std::process::id(),
                    "Created child process"
                );
                target = Some(child);
            }
            Ok(ForkResult::Child) => {
                // Indicates that this process is to be traced by its parent.
                // This is the only ptrace request to be issued by the tracee.
                // https://docs.rs/nix/latest/nix/sys/ptrace/fn.traceme.html
                info!(pid = std::process::id(), "Asking to be traced");
                ptrace::traceme().unwrap();
                info!(pid = std::process::id(), program, "Calling exec");
                let program_cstring = std::ffi::CString::from_str(program.as_str()).unwrap();
                // Conventionally, argv[0] is the program name.
                // TODO: We need to imitate the path aware behavior of `execlp`
                nix::unistd::execv::<_>(&program_cstring, &vec![program_cstring.clone()]).unwrap();
            }
            Err(_) => println!("Fork failed"),
        }
    }

    info!(
        child = target.unwrap().as_raw(),
        pid = std::process::id(),
        "Waiting for child process to pause"
    );
    waitpid(target.unwrap(), None).unwrap();
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
