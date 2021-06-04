prom-cnproc
---

Prometheus exporter for processes started on Linux. One may wonder what processes are started on Linux machines and if things are expected. Generally it's difficult to see if process is intended to be run or not. This utility aims at making low-overhead monitoring of every process launch with intention to remove noisy parts of process trees. Events are provided through Linux kernel [Process Events Connector](https://lwn.net/Articles/157150/).

Let's take a typical SystemD process tree and try to find `prom-cnproc` in it:

```bash
$ pstree
serge@satyricon:~/prom-cnproc$ pstree
systemd─┬─accounts-daemon───2*[{accounts-daemon}]
        │ .. omitted for brevity
        └─sh───node─┬─node─┬─bash
                    │      ├─bash───sudo───bash───prom-cnproc-x86-linux───2*[{prom-cnproc}]
                    │      └─12*[{node}]
                    └─node─┬─node───6*[{node}]
```

... and Prometheus exporter will present it as `/sh/node/bash/prom-cnproc`. Double-nesting of `node` processes is rolled up. `systemd` is omitted, because it is the mother of all dragons. Architecture and OS are stripped out from the binary name.

```bash
curl http://localhost:9898/
processes{state="RUNNING",tree="/sh/node/bash/prom-cnproc"} 1
```

More additions to come in the future, like presenting specific python modules instead of just `python3` binary, flagging processes based on high-entropy binary paths, and probably more.

Main logic depends on [cnproc](https://crates.io/crates/cnproc) Rust crate. All the work is only the initial prototype and you should use it at your own risk.

Building - `cargo build --release`

