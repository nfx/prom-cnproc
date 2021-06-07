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

#[derive(Debug)]
pub struct Process {
    pub pid: i32,
    pub ppid: i32,
    pub argv: Vec<String>,
    exe: PathBuf,
    pub start: Instant
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
        let mut elems = self.exe.to_str().unwrap_or("/").split("/");
        for chunk in &mut elems {
            let entropy = metric_entropy(chunk.as_bytes());
            trace!("entropy {}={}", chunk, entropy);
            if entropy < path_entropy {
                path_entropy = entropy;
            }
        }
        path_entropy
    }
    
    pub fn label(&self) -> &str {
        if let Some(path) = self.exe.to_str() {
            if is_base(path) {
                return "base";
            }
        }
        // TODO: more logic for python stuff
        if let Some(os_str) = self.exe.file_name() {
            return os_str.to_str().unwrap_or("unknown");
        }
        return "unknown"
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
}