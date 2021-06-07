use std::ffi::CStr;
use std::fs;
use std::io::Read;
use std::fs::File;
use std::os::linux::fs::MetadataExt;
use std::path::Path;
use std::path::PathBuf;
use std::io::Result;
use std::time::Instant;
use entropy::metric_entropy;
use super::known::is_base;
use log::trace;
use std::collections::HashSet;
use lazy_static::lazy_static;

lazy_static! {
    static ref PYTHONS: HashSet<&'static str> = {
        let mut pythons = HashSet::new();
        pythons.insert("/usr/bin/python2.6"); // hello, centOS...
        pythons.insert("/usr/bin/python2.7");
        pythons.insert("/usr/bin/python3.0");
        pythons.insert("/usr/bin/python3.1");
        pythons.insert("/usr/bin/python3.2");
        pythons.insert("/usr/bin/python3.3");
        pythons.insert("/usr/bin/python3.4");
        pythons.insert("/usr/bin/python3.5");
        pythons.insert("/usr/bin/python3.6");
        pythons.insert("/usr/bin/python3.8");
        pythons.insert("/usr/bin/python3.9");
        pythons.insert("/usr/bin/python3.10");
        pythons.insert("/usr/bin/python3.11");
        pythons
    };
    static ref SHELLS: HashSet<&'static str> = {
        let mut shells = HashSet::new();
        shells.insert("/usr/bin/bash"); 
        shells.insert("/bin/bash"); 
        shells.insert("/usr/bin/chsh"); 
        shells.insert("/bin/chsh"); 
        shells.insert("/usr/bin/csh"); 
        shells.insert("/bin/csh"); 
        shells.insert("/usr/bin/dash"); 
        shells.insert("/bin/dash"); 
        shells.insert("/usr/bin/ksh"); 
        shells.insert("/bin/ksh"); 
        shells.insert("/usr/bin/rbash"); 
        shells.insert("/bin/rbash"); 
        shells.insert("/usr/bin/sh"); 
        shells.insert("/bin/sh"); 
        shells.insert("/usr/bin/tcsh"); 
        shells.insert("/bin/tcsh"); 
        shells.insert("/usr/bin/zsh"); 
        shells.insert("/bin/zsh"); 
        shells
    };
}

#[derive(Debug)]
pub struct Process {
    pub pid: i32,
    pub ppid: i32,
    pub argv: Vec<String>,
    exe: PathBuf,
    pub start: Instant,
}

fn cmdline(pid: i32) -> Result<Vec<String>> {
    let mut buf = String::new();
    let mut c = File::open(format!("/proc/{}/cmdline", pid))?;
    c.read_to_string(&mut buf)?;
    let argv = buf.split('\0').map(String::from).collect();
    Ok(argv)
}

fn ppid(pid: i32) -> Result<i32> {
    let mut buf2 = String::new();
    let mut s = File::open(format!("/proc/{}/stat", pid))?;
    s.read_to_string(&mut buf2)?;
    let ppid = match buf2.split_whitespace().into_iter()
        .collect::<Vec<&str>>().get(3) {
            Some(ppid) => (*ppid).parse().unwrap(),
            None => 0,
    };
    Ok(ppid)
}

impl Process {
    pub fn new(pid: i32) -> Result<Self> {
        let start = Instant::now();
        let argv = cmdline(pid)?;
        let ppid = ppid(pid)?;
        let exe = Path::new(&format!("/proc/{}/exe", pid)).read_link()?;
        let exe = exe.canonicalize()?;
        trace!("{} pid={} ppid={} took={:.2?}", 
            exe.to_str().unwrap_or("..."), pid, ppid, start.elapsed());
        Ok(Process{pid, ppid, argv, exe, start}) 
    }

    /// Returns minimum metric entropy of any path element
    pub fn entropy(&self) -> f32 {
        let mut path_entropy = std::f32::MAX;
        let actual = self.actual_runnable();
        let mut elems = actual.split("/");
        for chunk in &mut elems {
            let entropy = metric_entropy(chunk.as_bytes());
            trace!("entropy {}={}", chunk, entropy);
            if entropy < path_entropy {
                path_entropy = entropy;
            }
        }
        path_entropy
    }

    /// Determines actual runnable file - binary or script
    fn actual_runnable(&self) -> &str {
        let sh  = self.is_shell();
        let py  = self.is_python();
        let has_args = self.argv.len() > 1;
        if (sh || py) && has_args {
            let maybe_script = self.argv[1].as_str();
            // or should it be just regex?..
            let path = Path::new(maybe_script);
            if path.is_file() {
                return maybe_script;
            }
        }
        self.exe.to_str().unwrap_or("/")
    }

    fn is_python(&self) -> bool {
        match self.exe.to_str() {
            Some(path) => PYTHONS.contains(path),
            None => false,
        }
    }

    fn is_shell(&self) -> bool {
        match self.exe.to_str() {
            Some(path) => SHELLS.contains(path),
            None => false,
        }
    }
    
    /// Determines short label to include in process tree
    pub fn label(&self) -> &str {
        let path = self.actual_runnable();
        if is_base(path) {
            // base system may have plenty of scripts
            return "base";
        }
        // maybe this will be improved
        let filename = path.split("/").last().unwrap_or("/");
        filename
    }

    /// Returns owner name of this process
    pub fn user(&self) -> &str {
        let default = "unknown";
        let path = &format!("/proc/{}", self.pid);
        let task = Path::new(path);
        match fs::metadata(task) {
            Ok(meta) => {
                let uid = meta.st_uid();
                unsafe {
                    let pw = libc::getpwuid(uid);
                    let name_ptr = (*pw).pw_name;
                    let cstr = CStr::from_ptr(name_ptr);
                    let username = cstr.to_str().unwrap_or(default);
                    username
                }
            }
            Err(_) => default,
        }
    }
}

#[cfg(test)]
mod tests {
    // Note this useful idiom: importing names from outer (for mod tests) scope.
    use super::*;

    #[test]
    fn cmdline_parses() {
        let pid = std::process::id() as i32;
        let cmd = cmdline(pid).unwrap();
        assert_eq!(true, cmd.len() > 1);
    }

    #[test]
    fn ppid_parses() {
        let pid = std::process::id() as i32;
        let parent = ppid(pid).unwrap();
        assert_ne!(0, parent);
    }

    #[test]
    fn process_inits() {
        let pid = std::process::id() as i32;
        let this = Process::new(pid).unwrap();
        assert_ne!(0, this.ppid);
        assert_ne!("unknown", this.user());
    }

    fn dummy_path(exe: &str) -> Process {
        Process{
            argv: vec![],
            pid: 0,
            ppid: 0,
            start: Instant::now(),
            exe: PathBuf::from(exe)
        }
    }

    #[test]
    fn labels() {
        let t = dummy_path("/usr/bin/dd");
        assert_eq!("base", t.label());

        let t = dummy_path("/usr/bin/dd-outer");
        assert_eq!("dd-outer", t.label());
    }

    #[test]
    fn entropies() {
        let t = dummy_path("/tmp/target/debug/deps/prom_cnproc-0883569a23a4bd16");
        assert_eq!(0.15128307, t.entropy());

        let t = dummy_path("/tmp/target/debug/deps/prom_cnproc");
        assert_eq!(0.24837805, t.entropy());

        let t = dummy_path("/tmp/ZW50cm9weQo/any-shady-process");
        assert_eq!(0.20322484, t.entropy());
    }

    #[test]
    fn shell_script_label() {
        let p = Process{
            pid: 0,
            ppid: 0,
            start: Instant::now(),
            argv: vec![
                String::from("sh"),
                String::from("/etc/init.d/hwclock.sh"),
                String::from("-a"),
                String::from("-b"),
            ],
            exe: PathBuf::from("/bin/bash")
        };
        assert_eq!("hwclock.sh", p.label())
    }
}