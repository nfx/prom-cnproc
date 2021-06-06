use std::{collections::HashMap};
use cnproc::{PidMonitor, PidEvent};
use log::*;
use metrics_exporter_prometheus::PrometheusBuilder;
use super::info::Process;
use std::io::Result;
use metrics::{gauge, histogram};


#[cfg(target_os = "linux")]
pub struct Watcher {
    pids: HashMap<i32,Process>,
    monitor: PidMonitor,
    short: bool
}

impl Watcher {
    pub fn new() -> Result<Self> { 
        let monitor = PidMonitor::new()?;
        let builder = PrometheusBuilder::new();
        builder.install().expect("failed to install Prometheus recorder.");
        Ok(Self{monitor, 
            pids: HashMap::new(),
            short: true
        })
    }

    /// Compacts the name for presentation in monitoring
    fn chain(&self, pid: i32) -> String {
        let mut curr = pid;
        let mut chain = vec![];
        // tree entropy is minumum entropy of any paths of binaries executed in this process tree
        let mut tree_entropy = std::f32::MAX;
        while curr != 0 {
            trace!("chain curr={} {}", curr, chain.join("<"));
            if let Some(prc) = self.pids.get(&curr) {
                curr = prc.ppid;
                let label = prc.label();

                let path_entropy = prc.entropy();
                if path_entropy < tree_entropy {
                    tree_entropy = path_entropy;
                }
                if chain.last() == Some(&label) && self.short {
                    continue;
                }
                if label == "systemd" {
                    continue;
                }
                if label == "python3.8" {
                    warn!("py> {}", prc.argv.join(" "))
                }
                chain.push(label);
            } else {
                curr = 0
            }
        }
        if tree_entropy < 0.01 {
            // random prefix means that folder with binary was in random location
            chain.push("random");
        }
        chain.reverse();
        let username = self.pids.get(&pid).map(Process::user).unwrap_or("unknown");
        return format!("/{}:{}", chain.join("/"), username);
    }

    fn start(&mut self, pid: i32) {
        let mut curr = pid;
        while curr != 0 {
            trace!("pid {} > curr {}", pid, curr);
            if self.pids.contains_key(&curr) {
                // eagerly break the cycle if parents 
                // were already discovered
                break;
            }
            let prc = match Process::new(curr) {
                Ok(it) => it,
                Err(e) => {
                    warn!("pid {} > {}", curr, e);
                    break; // or continue?..
                }
            };
            curr = prc.ppid;
            self.pids.insert(prc.pid, prc);
        }
        let tree = self.chain(pid);
        gauge!("process", 1.0, "tree" => tree.clone(), "state" => "RUNNING");
        gauge!("process", 0., "tree" => tree.clone(), "state" => "STOPPED");
        debug!("started pid={} tree={}", pid, tree)
    }

    fn stop(&mut self, pid: i32) {
        if !self.pids.contains_key(&pid) {
            // don't trigger for before unknown processes
            return;
        }
        let prc = self.pids.remove(&pid).unwrap();
        let tree = self.chain(pid);
        let elapsed = prc.start.elapsed();
        let seconds = elapsed.as_secs_f64();

        gauge!("process", 0., "tree" => tree.clone(), "state" => "RUNNING");
        gauge!("process", 1., "tree" => tree.clone(), "state" => "STOPPED");
        histogram!("process_seconds", seconds, "tree" => tree.clone());
        debug!("stopped pid={} tree={} duration={:?}", pid, tree, elapsed);
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