use tracing::error;

fn main() {
    tracing_subscriber::fmt::init();
    
    let args = std::env::args();

    if args.len() == 1 {
        error!("No arguments provided");
        std::process::exit(-1);
    }
}
