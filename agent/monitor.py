"""
Guardian — Lightweight free EDR agent.
Monitors processes, file changes, and network connections.
"""
import json
import os
import time
import logging
from datetime import datetime

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("guardian")

try:
    import psutil
except ImportError:
    log.error("psutil required: pip install psutil")
    raise

SNAPSHOT_DIR = "/tmp/guardian"
os.makedirs(SNAPSHOT_DIR, exist_ok=True)


class ProcessMonitor:
    def __init__(self):
        self._baseline = {}

    def snapshot(self):
        procs = {}
        for p in psutil.process_iter(["pid", "name", "exe", "cmdline", "create_time", "username"]):
            try:
                pinfo = p.info
                procs[pinfo["pid"]] = {
                    "name": pinfo["name"],
                    "exe": pinfo["exe"],
                    "cmdline": " ".join(pinfo["cmdline"] or []),
                    "created": pinfo["create_time"],
                    "user": pinfo["username"],
                }
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        return procs

    def diff(self, current):
        events = []
        current_ids = set(current.keys())
        baseline_ids = set(self._baseline.keys())

        for pid in current_ids - baseline_ids:
            p = current[pid]
            events.append({
                "type": "process_new",
                "pid": pid,
                "name": p["name"],
                "exe": p["exe"],
                "cmdline": p["cmdline"][:200],
                "user": p["user"],
                "time": datetime.now().isoformat(),
                "severity": self._rate_process(p),
            })

        for pid in baseline_ids - current_ids:
            if pid in self._baseline:
                events.append({
                    "type": "process_ended",
                    "pid": pid,
                    "name": self._baseline[pid]["name"],
                    "time": datetime.now().isoformat(),
                    "severity": "info",
                })

        self._baseline = current
        return events

    def _rate_process(self, p):
        name = (p.get("name") or "").lower()
        cmdline = (p.get("cmdline") or "").lower()
        exe = (p.get("exe") or "").lower()

        suspicious_keywords = ["mimikatz", "laZagne", "bloodhound", "psexec", "wmiexec",
                              "crackmapexec", "evil-winrm", "chisel", "ligolo", "ngrok"]
        for kw in suspicious_keywords:
            if kw in name or kw in cmdline or kw in exe:
                return "high"

        if any(s in name for s in ["powershell", "cmd.exe", "wscript", "cscript"]):
            suspicious_flags = ["-enc", "-e ", "bypass", "hidden", "downloadstring",
                               "invoke-expression", "iex", "frombase64"]
            for flag in suspicious_flags:
                if flag in cmdline:
                    return "high"

        download_tools = ["curl", "wget", "certutil", "bitsadmin", "powershell"]
        if name in download_tools:
            return "medium"

        return "low"


class ConnectionMonitor:
    def snapshot(self):
        conns = []
        try:
            for c in psutil.net_connections(kind="inet"):
                if c.status == "ESTABLISHED" and c.raddr:
                    conns.append({
                        "pid": c.pid,
                        "local": f"{c.laddr.ip}:{c.laddr.port}",
                        "remote": f"{c.raddr.ip}:{c.raddr.port}",
                        "status": c.status,
                    })
        except psutil.AccessDenied:
            pass
        return conns


class FileMonitor:
    def __init__(self, watch_dirs=None):
        self.watch_dirs = watch_dirs or ["/tmp", "/var/tmp", os.path.expanduser("~/Downloads")]
        self._files = {}
        self._init_files()

    def _init_files(self):
        for d in self.watch_dirs:
            if os.path.isdir(d):
                self._scan_dir(d)

    def _scan_dir(self, path, depth=0):
        if depth > 3:
            return
        try:
            for entry in os.scandir(path):
                try:
                    stat = entry.stat()
                    self._files[entry.path] = {
                        "size": stat.st_size,
                        "mtime": stat.st_mtime,
                        "ctime": stat.st_ctime,
                    }
                    if entry.is_dir() and not entry.name.startswith("."):
                        self._scan_dir(entry.path, depth + 1)
                except OSError:
                    pass
        except PermissionError:
            pass

    def scan(self):
        events = []
        current = {}
        for d in self.watch_dirs:
            if os.path.isdir(d):
                self._scan_dir(d)
        for path, info in self._files.items():
            current[path] = info
            if path not in self._files:
                events.append({
                    "type": "file_new",
                    "path": path,
                    "size": info["size"],
                    "time": datetime.now().isoformat(),
                    "severity": "medium",
                })
        self._files = current
        return events


class Guardian:
    def __init__(self):
        self.proc_mon = ProcessMonitor()
        self.conn_mon = ConnectionMonitor()
        self.file_mon = FileMonitor()
        self.running = True
        self.alerts = []

    def tick(self):
        events = []

        procs = self.proc_mon.snapshot()
        events.extend(self.proc_mon.diff(procs))

        if len(self.alerts) % 5 == 0:
            events.extend(self.file_mon.scan())

        high = [e for e in events if e["severity"] == "high"]
        medium = [e for e in events if e["severity"] == "medium"]
        self.alerts.extend(high + medium)

        if high:
            log.warning(f"Found {len(high)} high-severity events")
            for e in high[:3]:
                log.warning(f"  [{e['type']}] {e.get('name','') or e.get('path','')}")
        if medium:
            for e in medium[:2]:
                log.info(f"  [{e['type']}] {e.get('name','') or e.get('path','')}")

        return {"high": len(high), "medium": len(medium), "events": events}

    def get_alerts(self, limit=50):
        return self.alerts[-limit:]

    def get_stats(self):
        procs = len(psutil.pids())
        conns = len(self.conn_mon.snapshot())
        high = len([a for a in self.alerts if a["severity"] == "high"])
        return {"processes": procs, "connections": conns, "total_alerts": len(self.alerts), "high_alerts": high}


def run_agent(duration=None):
    g = Guardian()

    log.info("Guardian agent started")
    log.info(f"Monitoring {len(psutil.pids())} processes")

    if duration:
        end = time.time() + duration
        while time.time() < end:
            g.tick()
            time.sleep(5)
    else:
        while g.running:
            try:
                g.tick()
                time.sleep(5)
            except KeyboardInterrupt:
                log.info("Shutting down")
                break

    return g


if __name__ == "__main__":
    g = run_agent()
    print(f"\nAlerts collected: {len(g.alerts)}")
    for a in g.alerts[-10:]:
        print(f"  [{a['severity']}] {a['type']}: {a.get('name','') or a.get('path','')}")
