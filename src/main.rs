mod meta;
use log::*;
use std::process;
use std::env::consts;
use meta::watcher::Watcher;


fn main() -> ! {
    pretty_env_logger::init();
    unsafe {
        if libc::geteuid() != 0 {
            error!("Application must run as root");
            process::exit(1);
        }
    }
    if consts::OS != "linux" {
        error!("Application can only run on Linux");
        process::exit(2);
    }
    info!("monitoring started processes...");
    let mut watcher = Watcher::new().unwrap();
    
    watcher.main_loop()
}