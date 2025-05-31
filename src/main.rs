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
use std::os::fd::{AsFd, OwnedFd};
use std::path::PathBuf;
use std::process::id;
use std::str::FromStr;
use tracing::{error, info, info_span, span};
use which::which;

/// ```sh
/// cargo run -- --program /bin/echo
/// ```
fn main() -> anyhow::Result<()> {
    // Install a global tracing subscriber that listens for events and filters based on the value of
    // the RUST_LOG environment variable. This is a quick and easy way to get the loggers to just
    // **do stuff**.
    tracing_subscriber::fmt::init();

    let _span = span!(tracing::Level::INFO, "main", pid = id()).entered();

    // Get the program invocation arguments.
    let args = Args::parse();

    let mut process = if let Some(pid) = args.pid {
        Process::attach(Pid::from_raw(pid))?
    } else if let Some(program) = args.program {
        Process::launch(program, true)?
    } else {
        error!("This should not be reachable, somehow neither --pid nor --program were provided");
        std::process::exit(1);
    };

    info!(child=%process.pid, "Waiting for child process",);

    process.wait()?;

    let mut rl = DefaultEditor::new()?;
    if rl.load_history(".history").is_err() {
        error!("No previous history");
    }

    loop {
        let readline = rl.readline("jdb> ");
        match readline {
            Ok(line) => {
                if line == "continue" || line == "c" {
                    process.resume()?;
                }
                rl.add_history_entry(line.as_str())?;
                info!(line, "Add history entry");
            }
            Err(ReadlineError::Interrupted) => {
                info!("Calling interrupt");
                break;
            }
            Err(ReadlineError::Eof) => {
                info!("CTRL-D");
            }
            Err(err) => {
                info!(?err);
            }
        }
    }

    info!(?process.state, "Process exited");
    Ok(())
}

fn exit_with_pipe_error(pipe: Pipe, prefix: &str) -> ! {
    let error = std::io::Error::last_os_error();
    let message = format!("{prefix}: {error}");
    pipe.write(message.as_bytes()).unwrap();
    std::process::exit(-1);
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

struct Pipe {
    // `OwnedFd` closes the file descriptor on drop.
    // It is guaranteed that nobody else will close the file descriptor.
    read: Option<OwnedFd>,
    write: Option<OwnedFd>,
}

impl Pipe {
    fn new(close_on_exec: bool) -> Result<Pipe, Errno> {
        let (read, write) = nix::unistd::pipe2(if close_on_exec {
            // We pass O_CLOEXEC to pipe2 if `close_on_exec` is true, to
            // ensure that the pipe gets closed when we call `execlp`.
            // Otherwise, the process will hang while trying to read from
            // the pipe due to the duplicated file descriptors.
            nix::fcntl::OFlag::O_CLOEXEC
        } else {
            nix::fcntl::OFlag::empty()
        })?;

        Ok(Pipe {
            read: Some(OwnedFd::from(read)),
            write: Some(OwnedFd::from(write)),
        })
    }

    fn read(&self) -> Result<Vec<u8>, Errno> {
        let mut buffer = [0u8; 1024];
        let fd = self.read.as_ref().unwrap().as_fd();
        match nix::unistd::read(fd, &mut buffer) {
            Ok(n) => {
                info!(n_bytes = n, "Read from pipe");
                Ok(buffer[..n].to_vec())
            }
            Err(errno) => {
                error!(errno = errno.to_string(), "Failed to read from pipe",);
                Err(errno)
            }
        }
    }

    fn write(&self, bytes: &[u8]) -> Result<(), Errno> {
        match nix::unistd::write(self.write.as_ref().unwrap().as_fd(), bytes) {
            Ok(n) => {
                info!(n_bytes = n, "[{}] Wrote to pipe", id());
                Ok(())
            }
            Err(errno) => {
                error!(
                    errno = errno.to_string(),
                    "[{}] Failed to write to pipe",
                    id()
                );
                Err(errno)
            }
        }
    }

    fn close_read(&mut self) {
        // By taking ownership of the `OwnedFd` value, we cause it to drop
        self.read.take();
    }

    fn close_write(&mut self) {
        // By taking ownership of the `OwnedFd` value, we cause it to drop
        self.write.take();
    }
}

#[derive(Builder)]
struct Process {
    pid: Pid,
    terminate_on_end: bool,
    is_attached: bool,
    state: ProcessState,
}

impl Process {
    fn attach(pid: Pid) -> anyhow::Result<Process> {
        let _span = span!(tracing::Level::INFO, "attach", pid = id()).entered();

        info!(target = %pid, "Attaching to target process");

        ptrace::attach(pid).map_err(|error| {
            error!(%error, "Failed to attach to process");
            error
        })?;

        let mut process = Process::builder()
            .pid(pid)
            .terminate_on_end(false)
            .state(ProcessState::Stopped)
            .is_attached(true)
            .build();

        process.wait()?;

        Ok(process)
    }

    fn launch(path: PathBuf, attach: bool) -> anyhow::Result<Process> {
        let _span = info_span!("launch", pid = id()).entered();

        info!(?path, attach, "Attempting to launch program");
        // It’s important to call pipe before fork, or the pipes won’t function;
        // the pipes in the two processes would be completely distinct
        let mut pipe = Pipe::new(true)?;

        match unsafe { fork() } {
            Ok(ForkResult::Parent { child, .. }) => {
                let _span = info_span!("parent", %child).entered();

                pipe.close_write();
                let data = pipe.read()?;

                if data.len() > 0 {
                    let chars = String::from_utf8(data)?;
                    error!(error = chars, "Received an error from the child process");
                    return Err(Errno::UnknownErrno.into());
                }

                info!(%child, "Created child process");
                Ok(Process::builder()
                    .pid(child)
                    .state(ProcessState::Stopped)
                    .terminate_on_end(true)
                    .is_attached(attach)
                    .build())
            }
            Ok(ForkResult::Child) => {
                let _span = info_span!("child", pid = id()).entered();

                pipe.close_read();

                if attach {
                    info!("Asking to be traced");
                    // Indicates that this process is to be traced by its parent.
                    // This is the only ptrace request to be issued by the tracee.
                    // https://docs.rs/nix/latest/nix/sys/ptrace/fn.traceme.html
                    if ptrace::traceme().is_err() {
                        exit_with_pipe_error(pipe, "Tracing failed");
                    }
                }

                let program = match which(&path) {
                    Ok(program) => program,
                    Err(_) => {
                        error!("Failed to resolve program to absolute path");
                        exit_with_pipe_error(pipe, "Failed to resolve program to absolute path");
                    }
                };

                info!(?program, "Resolved program to absolute path");
                let program_cstring = std::ffi::CString::from_str(program.to_str().unwrap())?;

                info!(?program, "Calling exec");
                // Conventionally, argv[0] is the program name.
                let args = vec![program_cstring.clone()];
                if nix::unistd::execv::<_>(&program_cstring, &args).is_err() {
                    exit_with_pipe_error(pipe, "Exec failed");
                }

                unreachable!();
            }
            Err(errno) => {
                error!(errno = errno as i32, "Fork failed");
                Err(errno.into())
            }
        }
    }

    fn resume(&mut self) -> anyhow::Result<()> {
        info!(target=%self.pid, "Resuming the inferior process");
        cont(self.pid, None)?;
        self.state = ProcessState::Running;
        Ok(())
    }

    fn wait(&mut self) -> anyhow::Result<()> {
        // This call blocks until the child changes state (such as being
        // stopped by a signal)
        let status = waitpid(self.pid, None)?;
        info!(?status, "Received signal after waiting");
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
        let _span = info_span!("drop", %self.pid, is_attached=?self.is_attached, terminate_on_end=?self.terminate_on_end).entered();

        if self.is_attached {
            if self.state == ProcessState::Running {
                info!("Calling SIGSTOP on child process");
                kill(self.pid, SIGSTOP).unwrap();
                self.wait().unwrap();
            }

            info!("Detaching from the child process");
            match detach(self.pid, None) {
                Ok(_) => info!("Successfully detached from child process"),
                Err(errno) => {
                    error!(%errno, "Failed to detach from child process")
                }
            }

            info!("Calling SIGCONT on child process",);
            // Rust forcing me to handle the case where sending the signal fails :)
            if let Err(err) = kill(self.pid, SIGCONT) {
                error!(%err, "Failed to send SIGCONT to child process");
            }
        }

        if self.terminate_on_end {
            info!("Calling SIGKILL on child process");
            if let Err(err) = kill(self.pid, SIGKILL) {
                error!(%err, "Failed to send SIGKILL to child process");
            } else {
                self.wait().unwrap();
            }
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
    use std::io::BufRead;

    #[test]
    fn test_process_launch_successfully() {
        info!("test_process_launch");
        let process = Process::launch(PathBuf::from("/bin/echo"), true).unwrap();
        assert!(process_exists(process.pid));
    }

    #[test]
    fn test_process_launch_non_existent_program() {
        info!("test_process_launch_non_existent_program");
        let result = Process::launch(PathBuf::from("/nonexistent/program"), true);
        assert!(result.is_err());
    }

    #[test]
    fn test_process_attach_successfully() {
        // Bind process to variable to keep it alive so the `drop` logic runs after `attach`
        let target = Process::launch("tail".parse().unwrap(), false).unwrap();
        let pid = target.pid;
        let process = Process::attach(pid);
        // The status 't' indicates that the process is stopped
        assert_eq!(get_process_status(process.unwrap().pid).unwrap(), 't');
    }

    #[test]
    fn test_process_attach_invalid_pid() {
        let process = Process::attach(Pid::from_raw(0));
        assert!(process.is_err());
    }

    #[test]
    fn test_process_resume_successfully() {
        {
            // Bind process to variable to keep it alive so the `drop` logic runs after `attach`
            let mut target = Process::launch("tail".parse().unwrap(), true).unwrap();
            target.resume().unwrap();
            assert!(vec!['R', 'S'].contains(&get_process_status(target.pid).unwrap()))
        }
        {
            // Bind process to variable to keep it alive so the `drop` logic runs after `attach`
            let target = Process::launch("tail".parse().unwrap(), false).unwrap();
            let mut attached = Process::attach(target.pid).unwrap();
            attached.resume().unwrap();
            assert!(vec!['R', 'S'].contains(&get_process_status(target.pid).unwrap()))
        }
    }

    #[test]
    fn test_process_resume_already_terminated() {
        tracing_subscriber::fmt::init();
        let mut target = Process::launch("echo".parse().unwrap(), true).unwrap();
        target.resume().unwrap();
        target.wait().unwrap();
        assert!(target.resume().is_err());
    }

    /// If you call kill with a signal of 0, it doesn’t send a signal to the
    /// process but still carries out the existence and permission checks it
    /// would make when actually sending a signal
    fn process_exists(pid: Pid) -> bool {
        // Send a signal to a process, if signal is None, error checking is
        // performed but no signal is actually sent
        kill(pid, None).is_ok()
    }

    fn get_process_status(pid: Pid) -> anyhow::Result<char> {
        let process = std::fs::File::open(format!("/proc/{pid}/stat"));
        if let Ok(file) = process {
            let mut buffer = String::new();
            let mut reader = std::io::BufReader::new(file);
            reader.read_line(&mut buffer)?;
            if let Some(i) = buffer.rfind(')') {
                let status_i = i + 2;
                if let Some(status) = buffer.chars().nth(status_i) {
                    return Ok(status);
                }
            }
        }

        Err(anyhow::anyhow!(
            "Failed to read process status for PID {}",
            pid
        ))
    }
}
