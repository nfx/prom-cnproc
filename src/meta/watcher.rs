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
    monitor: PidMonitor
}

/// Compacts the name for presentation in monitoring
fn tree(pids: &HashMap<i32,Process>, pid: i32) -> String {
    let mut curr = pid;
    let mut tree = vec![];
    let mut pos = 0;
    let mut sshd_pos = std::usize::MAX;
    // tree entropy is minumum entropy of any paths of binaries executed in this process tree
    let mut tree_entropy = std::f32::MAX;

    while curr != 0 {
        trace!("tree curr={} {}", curr, tree.join("<"));
        if let Some(prc) = pids.get(&curr) {
            curr = prc.ppid;
            // possible optimization: cache label and entropy per pid
            let label = prc.label();

            let path_entropy = prc.entropy();
            if path_entropy < tree_entropy {
                tree_entropy = path_entropy;
            }
            if tree.last() == Some(&label) {
                continue;
            }
            if label == "systemd" {
                continue;
            }
            if label == "sshd" {
                // save the position of SSH process
                sshd_pos = pos;
            }
            tree.push(label);
            pos = pos + 1;
        } else {
            curr = 0
        }
    }
    if tree_entropy < 0.022 {
        // random prefix means that folder with binary was in random location
        tree.push("random");
    }
    let mut ssh_prefix = "ssh:".to_owned();
    if sshd_pos < std::usize::MAX {
        let username = pids.get(&pid).map(Process::user).unwrap_or("unknown");
        if let Some(x) = tree.get_mut(sshd_pos) {
            ssh_prefix.push_str(username);
            *x = &ssh_prefix;
        }
    }
    tree.reverse();
    
    return format!("/{}", tree.join("/"));
}

impl Watcher {
    pub fn new() -> Result<Self> { 
        let monitor = PidMonitor::new()?;
        let builder = PrometheusBuilder::new();
        builder.install().expect("failed to install Prometheus recorder.");
        Ok(Self{monitor, pids: HashMap::new()})
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
                    break;
                }
            };
            curr = prc.ppid;
            self.pids.insert(prc.pid, prc);
        }
        let tree = tree(&self.pids, pid);
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
        let tree = tree(&self.pids, pid);
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::vec;

    #[test]
    fn cmdline_parses() {
        let mut pids = HashMap::new();

        pids.insert(1, Process::from(1, 0, "/usr/bin/bash", vec![]));
        pids.insert(2, Process::from(2, 1, "/usr/sbin/sshd", vec![]));
        pids.insert(3, Process::from(3, 2, "/bin/bash", vec![
            String::from("sh"),
            String::from("/etc/init.d/hwclock.sh"),
            String::from("-a"),
            String::from("-b"),
        ]));
        let t = tree(&pids, 3);

        // unknown is the default username for pid "2", that is not likely to exist
        assert_eq!("/base/ssh:unknown/hwclock.sh", t)
    }
}