use bon::Builder;
use clap::ArgGroup;
use clap::Parser;
use nix::errno::Errno;
use nix::sys::ptrace;
use nix::sys::ptrace::{cont, detach};
use nix::sys::signal::{SIGCONT, SIGKILL, SIGSTOP, kill};
use nix::sys::wait::WaitStatus;
use nix::unistd::Pid;
use nix::{
    sys::wait::waitpid,
    unistd::{ForkResult, fork},
};
use rustyline::DefaultEditor;
use rustyline::error::ReadlineError;
use std::cmp::PartialEq;
use std::fmt::{Display, Formatter};
use std::path::PathBuf;
use std::process::id;
use std::str::FromStr;
use tracing::{error, info};
use which::which;

/// ```sh
/// cargo run -- --program /bin/echo
/// ```
fn main() -> anyhow::Result<()> {
    // Install a global tracing subscriber that listens for events and filters based on the value of
    // the RUST_LOG environment variable. This is a quick and easy way to get the loggers to just
    // **do stuff**.
    tracing_subscriber::fmt::init();

    // Get the program invocation arguments.
    let args = Args::parse();

    let mut process = if let Some(pid) = args.pid {
        Process::attach(Pid::from_raw(pid))?
    } else if let Some(program) = args.program {
        Process::launch(program)?
    } else {
        error!("This should not be reachable, somehow neither --pid nor --program were provided");
        std::process::exit(1);
    };

    info!(
        child = process.pid.as_raw(),
        "[{}] Waiting for child process",
        id()
    );

    process.wait()?;

    let mut rl = DefaultEditor::new()?;
    if rl.load_history(".history").is_err() {
        error!("[{}] No previous history", id());
    }

    loop {
        let readline = rl.readline("jdb> ");
        match readline {
            Ok(line) => {
                if line == "continue" || line == "c" {
                    process.resume()?;
                }
                rl.add_history_entry(line.as_str())?;
                info!(line, "[{}] Add history entry", id());
            }
            Err(ReadlineError::Interrupted) => {
                info!("[{}] Calling interrupt", id());
                break;
            }
            Err(ReadlineError::Eof) => {
                info!(pid = id(), "CTRL-D");
            }
            Err(err) => {
                info!(pid = id(), "Error: {:?}", err);
            }
        }
    }

    info!(
        state = process.state.to_string(),
        "[{}] Process exited",
        id()
    );
    Ok(())
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
    program: Option<PathBuf>,

    // Or we can attach to a running PID `jdb --pid <pid>`
    #[arg(long)]
    pid: Option<i32>,
}

#[derive(Builder)]
struct Process {
    pid: Pid,
    terminate_on_end: bool,
    state: ProcessState,
}

impl Process {
    fn attach(pid: Pid) -> Result<Process, Errno> {
        info!(
            target = pid.as_raw(),
            "[{}] Attaching to target process",
            id()
        );
        ptrace::attach(pid)?;
        Ok(Process::builder()
            .pid(pid)
            .terminate_on_end(false)
            .state(ProcessState::Stopped)
            .build())
    }

    fn launch(path: PathBuf) -> Result<Process, Errno> {
        match unsafe { fork() } {
            Ok(ForkResult::Parent { child, .. }) => {
                info!(child = child.as_raw(), "[{}] Created child process", id());
                Ok(Process::builder()
                    .pid(child)
                    .state(ProcessState::Stopped)
                    .terminate_on_end(true)
                    .build())
            }
            Ok(ForkResult::Child) => {
                // Indicates that this process is to be traced by its parent.
                // This is the only ptrace request to be issued by the tracee.
                // https://docs.rs/nix/latest/nix/sys/ptrace/fn.traceme.html
                info!("[{}] Asking to be traced", id());
                ptrace::traceme()?;
                info!(program = path.to_str().unwrap(), "[{}] Calling exec", id());
                let program = which(&path).unwrap();
                let program = program.to_str().unwrap();
                info!(
                    program = &program,
                    "[{}] Resolved program to absolute path",
                    id()
                );
                let program_cstring = std::ffi::CString::from_str(program).unwrap();
                // Conventionally, argv[0] is the program name.
                nix::unistd::execv::<_>(&program_cstring, &vec![program_cstring.clone()])?;
                Ok(Process::builder()
                    .pid(Pid::from_raw(id() as i32))
                    .state(ProcessState::Stopped)
                    .terminate_on_end(true)
                    .build())
            }
            Err(errno) => {
                error!(errno = errno as i32, "Fork failed");
                Err(errno)
            }
        }
    }

    fn resume(&mut self) -> anyhow::Result<()> {
        cont(self.pid, None)?;
        self.wait()?;
        self.state = ProcessState::Running;
        Ok(())
    }

    fn wait(&mut self) -> anyhow::Result<()> {
        // This call blocks until the child changes state (such as being
        // stopped by a signal)
        let status = waitpid(self.pid, None)?;
        info!(
            signal = format!("{:?}", status),
            "[{}] Received signal after waiting",
            id()
        );
        match status {
            WaitStatus::Exited(_, _) => {
                self.state = ProcessState::Exited;
            }
            WaitStatus::Signaled(_, _, _) => {
                self.state = ProcessState::Terminated;
            }
            WaitStatus::Stopped(_, _) => {
                self.state = ProcessState::Stopped;
            }
            _ => {}
        }

        Ok(())
    }
}

impl Drop for Process {
    fn drop(&mut self) {
        info!(
            child = self.pid.as_raw(),
            "[{}] Entering drop logic for child process",
            id()
        );
        if self.state == ProcessState::Running {
            info!(
                child = self.pid.as_raw(),
                "[{}] Calling SIGSTOP on child process",
                id()
            );
            kill(self.pid, SIGSTOP).unwrap();
            self.wait().unwrap();
        }

        info!(
            child = self.pid.as_raw(),
            "[{}] Detaching from the child process",
            id()
        );
        match detach(self.pid, None) {
            Ok(_) => info!(
                child = self.pid.as_raw(),
                "[{}] Successfully detached from child process",
                id()
            ),
            Err(errno) => error!(
                child = self.pid.as_raw(),
                errno = errno as i32,
                "[{}] Failed to detach from child process",
                id(),
            ),
        }

        info!(
            child = self.pid.as_raw(),
            "[{}] Calling SIGCONT on child process",
            id()
        );
        kill(self.pid, SIGCONT).unwrap();

        if self.terminate_on_end {
            info!(
                child = self.pid.as_raw(),
                "[{}] Calling SIGKILL on child process",
                id()
            );
            kill(self.pid, SIGKILL).unwrap();
            self.wait().unwrap();
        }
    }
}

#[derive(PartialEq, Debug)]
enum ProcessState {
    Stopped,
    Running,
    Exited,
    Terminated,
}

impl Display for ProcessState {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_process_launch() {
        let process = Process::launch(PathBuf::from("/bin/echo")).unwrap();
        assert!(process_exists(process.pid));
    }

    #[test]
    fn test_process_launch_non_existent_program() {
        let result = Process::launch(PathBuf::from("/nonexistent/program"));
        assert!(result.is_err());
    }

    /// If you call kill with a signal of 0, it doesn’t send a signal to the
    /// process but still carries out the existence and permission checks it
    /// would make when actually sending a signal
    fn process_exists(pid: Pid) -> bool {
        // Send a signal to a process, if signal is None, error checking is
        // performed but no signal is actually sent
        kill(pid, None).is_ok()
    }
}
