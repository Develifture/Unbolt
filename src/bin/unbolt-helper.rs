#![windows_subsystem = "windows"]
fn main() {
    if unbolt::broker::worker::main_from_args().is_err() {
        std::process::exit(1);
    }
}
