use clap::ArgGroup;
use clap::Parser;
use nix::sys::ptrace;
use nix::unistd::Pid;
use nix::{
    sys::wait::waitpid,
    unistd::{ForkResult, fork},
};
use rustyline::DefaultEditor;
use rustyline::error::ReadlineError;
use std::process::id;
use std::str::FromStr;
use tracing::{error, info};
use which::which;

/// ```sh
/// cargo run -- --program /bin/echo
/// ```
/// We allow this warning because the child process which calls `exec` does not terminate.
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
        info!(target = pid, pid = id(), "Attaching to target process");
        target = Some(Pid::from_raw(pid));
        ptrace::attach(target.unwrap()).unwrap();
    }

    // Or attempt to create and attach to a child program.
    if let Some(program) = args.program {
        match unsafe { fork() } {
            Ok(ForkResult::Parent { child, .. }) => {
                info!(child = child.as_raw(), pid = id(), "Created child process");
                target = Some(child);
            }
            Ok(ForkResult::Child) => {
                // Indicates that this process is to be traced by its parent.
                // This is the only ptrace request to be issued by the tracee.
                // https://docs.rs/nix/latest/nix/sys/ptrace/fn.traceme.html
                info!(pid = id(), "Asking to be traced");
                ptrace::traceme().unwrap();
                info!(pid = id(), program, "Calling exec");
                let absolute_program = which(&program).unwrap();
                let absolute_program_str = absolute_program.to_str().unwrap();
                info!(
                    pid = id(),
                    program = &program,
                    absolute = absolute_program_str,
                    "Resolved program to absolute path"
                );
                let program_cstring = std::ffi::CString::from_str(absolute_program_str).unwrap();
                // Conventionally, argv[0] is the program name.
                // This does not terminate and is the reason for the `#[allow(unreachable_code)]`.
                nix::unistd::execv::<_>(&program_cstring, &vec![program_cstring.clone()]).unwrap();
            }
            Err(_) => println!("Fork failed"),
        }
    }

    #[allow(unreachable_code)]
    {
        info!(
            child = target.unwrap().as_raw(),
            pid = id(),
            "Waiting for child process to pause"
        );
    }

    waitpid(target.unwrap(), None).unwrap();

    let mut rl = DefaultEditor::new().unwrap();
    if rl.load_history("history.txt").is_err() {
        error!(pid = id(), "No previous history.");
    }

    loop {
        let readline = rl.readline(">> ");
        match readline {
            Ok(line) => {
                rl.add_history_entry(line.as_str()).unwrap();
                info!(pid = id(), line, "Add history entry");
            }
            Err(ReadlineError::Interrupted) => {
                info!(pid = id(), "CTRL-C");
                break;
            }
            Err(ReadlineError::Eof) => {
                info!(pid = id(), "CTRL-D");
                break;
            }
            Err(err) => {
                info!(pid = id(), "Error: {:?}", err);
                break;
            }
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
