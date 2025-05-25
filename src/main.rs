use clap::ArgGroup;
use clap::Parser;
use tracing::error;

fn main() {
    // Install a global tracing subscriber that listens for events and filters based on the value of
    // the RUST_LOG environment variable. This is a quick and easy way to get the loggers to just
    // **do stuff**.
    tracing_subscriber::fmt::init();

    // Get the program invocation arguments.
    let args = Args::parse();
}

#[derive(Debug, Parser)]
#[command(about, version, group(
    ArgGroup::new("target")
        .required(true)
        .multiple(false)
        .args(["program", "pid"])
))]
struct Args {
    // We can possibly kick off this child as a subprocess i.e. `jdb --program <program>`
    #[arg(long)]
    program: Option<String>,

    // Or we can attach to a running PID `jdb --pid <pid>`
    #[arg(long)]
    pid: Option<u32>,
}
