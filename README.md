prom-cnproc
---

Prometheus exporter for process trees started on Linux. One may wonder what processes are started on Linux machines and if things are expected. Generally it's difficult to see if process is intended to be run or not. This utility aims at making low-overhead monitoring of every process launch with intention to remove noisy parts of process trees. Events are provided through Linux kernel [Process Events Connector](https://lwn.net/Articles/157150/). This small utility is the attempt to mine useful information about process trees in a consice and low-overhead method, running a Rust application in the user-space. Resulting 500kb binary has no dependencies and runs almost without an overhead. Main logic depends on [cnproc](https://crates.io/crates/cnproc) Rust crate. All the work is only the initial prototype and you should use it at your own risk. 

Let's take a typical SystemD process tree and try to find `prom-cnproc` in it:

```bash
serge@satyricon:~$ pstree
systemd─┬─accounts-daemon───2*[{accounts-daemon}]
        │ .. omitted for brevity
        └─sh───node─┬─node─┬─bash
                    │      ├─bash───sudo───bash───prom-cnproc───2*[{prom-cnproc}]
                    │      └─12*[{node}]
                    └─node─┬─node───6*[{node}]
```

... and Prometheus exporter will present it as `/sshd/base/server.sh/sudo/base/prom-cnproc` tree in `process` gauge. Double-nesting of `node` processes is rolled up. `systemd` is omitted, because it is the mother of all dragons. This tool also exposes `process_seconds` histogram.

```bash
serge@satyricon:~$ curl http://localhost:9501/
process{state="RUNNING",tree="/sshd/base/pstree"} 1
process{state="STOPPED",tree="/sshd/base/pstree"} 0
process{state="RUNNING",tree="/sshd/base/server.sh/sudo/base/prom-cnproc"} 1
process{state="STOPPED",tree="/sshd/base/server.sh/sudo/base/prom-cnproc"} 0
```

Some practical challenges already solved:

* Whenever we launch a Python or Bash script, we're interested in the name of the script, not the fact that `/bin/sh` is called. This means that cron job `python /tmp/ZW50cm9weQo/top.py` should appear as `/random/crond/top.py`, where `/random` would mean a high-entropy folder name, where script is located.
* Whenever [a basic Linux binary](src/meta/known.rs) is called, it'll be aliased as `base` in the tree name.

Process has to be run as root, because it seems to be no other way to listen for a corresponding NetLink socket. If there's a way to improve it - i'd be happy to get a pull request to this.

Releasing:

- `apt-get install libc6-dev-i386`
- `cargo install cargo-deb`
- `cargo deb --target=aarch64-unknown-linux-gnu`
- `cargo deb --target=x86_64-unknown-linux-gnu`