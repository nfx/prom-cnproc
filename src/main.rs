use std::collections::HashMap;
use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::path::PathBuf;
use std::process;

use cnproc::PidMonitor;
use cnproc::PidEvent;
use log::*;
use std::io::Result;
use std::time::Instant;
use std::env::consts;

use epimetheus::metric;


#[derive(Debug)]
struct Process {
    pid: i32,
    ppid: i32,
    argv: Vec<String>,
    exe: PathBuf
}

impl Process {
    fn new(pid: i32) -> Result<Self> {
        let start = Instant::now();

        let mut buf = String::new();
        let mut c = File::open(format!("/proc/{}/cmdline", pid))?;
        c.read_to_string(&mut buf)?;
        let argv = buf.split('\0').map(String::from).collect();
        
        let mut buf2 = String::new();
        let mut s = File::open(format!("/proc/{}/stat", pid))?;
        s.read_to_string(&mut buf2)?;
        let ppid = match buf2.split_whitespace().into_iter()
            .collect::<Vec<&str>>().get(3) {
                Some(ppid) => (*ppid).parse().unwrap(),
                None => 0,
        };
    
        let exe = Path::new(&format!("/proc/{}/exe", pid)).read_link()?;
        // for now the absolute path is not needed
        //let exe = exe.canonicalize()?;

        debug!("discovery pid={} took={:.2?}", pid, start.elapsed());
        Ok(Process{pid, ppid, argv, exe}) 
    }

    fn label(&self) -> String {
        // TODO: more logic for python stuff
        if let Some(os_str) = self.exe.file_name() {
            os_str.to_string_lossy().into_owned()
        } else {
            String::from("unknown")
        }
    }
}

struct Watcher {
    pids: HashMap<i32,Process>,
    monitor: PidMonitor,
    short: bool,
    ignores: Vec<String>
}

impl Watcher {
    fn new() -> Result<Self> { 
        let monitor = PidMonitor::new()?;
        Ok(Self{monitor, 
            pids: HashMap::new(),
            ignores: vec![String::from("systemd")],
            short: true
        })
    }

    /// Return chained path to the process
    fn chain(&self, pid: i32) -> String {
        let mut curr = pid;
        let mut chain = vec![];
        while curr != 0 {
            if let Some(prc) = self.pids.get(&curr) {
                curr = prc.ppid;
                let mut label = prc.label();

                // remove common arch labels
                label = label.replace("aarch64-unknown-linux-gnu", "");
                label = label.replace("arm-unknown-linux-gnu", "");
                label = label.replace("x86-unknown-linux-gnu", "");
                label = label.replace("x86_64-unknown-linux-gnu", "");
                
                label = label.replace("aarch64-linux-gnu", "");
                label = label.replace("arm-linux-gnu", "");
                label = label.replace("x86-linux-gnu", "");
                label = label.replace("x86_64-linux-gnu", "");

                if chain.last() == Some(&label) && self.short {
                    continue;
                }
                if self.ignores.contains(&label) {
                    continue;
                }
                chain.push(label);
            } else {
                curr = 0
            }
        }
        chain.reverse();
        return format!("/{}", chain.join("/"));
    }

    fn start(&mut self, pid: i32) {
        let mut curr = pid;
        while curr != 0 {
            if self.pids.contains_key(&curr) {
                // eagerly break the cycle if parents 
                // were already discovered
                break;
            }
            let prc = match Process::new(curr) {
                Ok(it) => it,
                _ => continue,
            };
            curr = prc.ppid;
            self.pids.insert(prc.pid, prc);
        }
        let tree = self.chain(pid);
        metric!(processes{tree=tree.clone(), state="RUNNING"}).add(1.0);
        debug!("started pid={} tree={}", pid, tree)
    }

    fn stop(&mut self, pid: i32) {
        if !self.pids.contains_key(&pid) {
            // don't trigger for before unknown processes
            return;
        }
        let tree = self.chain(pid);
        metric!(processes{tree=tree.clone(), state="STOPPED"}).add(-1.0);
        self.pids.remove(&pid);
        debug!("stopped pid={} tree={}", pid, tree)
    }

    pub fn main_loop(&mut self) -> ! {
        loop {
            if let Some(e) = self.monitor.recv() {
                match e {
                    PidEvent::Exec(pid) => self.start(pid),
                    PidEvent::Exit(pid) => self.stop(pid),
                    _ => continue
                }
            }
        }
    }
}

#[cfg(target_os = "linux")]
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
    epimetheus::spawn_http_server();
    watcher.main_loop()
}