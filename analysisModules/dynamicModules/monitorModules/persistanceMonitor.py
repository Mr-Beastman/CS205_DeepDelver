import time
import threading
import subprocess
import winreg
import os
from typing import Dict, List, Any

class PersistenceMonitor:
    """
    Persistence monitor that:
      captures a basline
      records events
    """

    def __init__(self, checkInterval: float = 2.0):
        self.checkInterval = checkInterval

        # common persistence locations
        self.startupFolders = [
            os.path.expandvars(r"%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup"),
            os.path.expandvars(r"%ProgramData%\Microsoft\Windows\Start Menu\Programs\Startup")
        ]

        self.runKeys = [
            (winreg.HKEY_CURRENT_USER,  r"Software\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_CURRENT_USER,  r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
            (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
        ]

        self.results: Dict[str, List[Dict[str, Any]]] = {"baseline": [], "events": []}

    def snapshotStartupFolders(self) -> Dict[str, set]:
        snapshot = {}
        for folder in self.startupFolders:
            try:
                items = os.listdir(folder) if os.path.isdir(folder) else []
            except PermissionError:
                items = []
            snapshot[folder] = set(items)
        return snapshot

    def snapshotRunKeys(self) -> Dict[str, Dict[str, str]]:
        snapshot = {}
        for hive, path in self.runKeys:
            keyId = f"{hive}\\{path}"
            values = {}
            try:
                with winreg.OpenKey(hive, path, 0, winreg.KEY_READ) as key:
                    for i in range(winreg.QueryInfoKey(key)[1]):
                        try:
                            name, val, _ = winreg.EnumValue(key, i)
                            values[name] = val
                        except OSError:
                            continue
            except FileNotFoundError:

                values = {}
            except PermissionError:
                values["__error__"] = "ACCESS_DENIED"
            snapshot[keyId] = values
        return snapshot

    def snapshotServices(self) -> set:
        try:
            raw = subprocess.check_output(["sc", "query", "type=", "service", "state=", "all"], shell=False, text=True)

            serviceName = set()
            for line in raw.splitlines():
                if "SERVICE_NAME:" in line:
                    serviceName.add(line.split(":", 1)[1].strip())
            return serviceName
        except Exception:
            return set()

    def getServiceBinaryPath(self, svc_name: str) -> str:
        """Try to get service binary path via `sc qc` parsing. Return empty string on failure."""
        try:
            raw = subprocess.check_output(["sc", "qc", svc_name], shell=False, text=True, stderr=subprocess.DEVNULL)
            for line in raw.splitlines():
                if "BINARY_PATH_NAME" in line:
                    parts = line.split(":", 1)
                    if len(parts) > 1:
                        return parts[1].strip()
            return ""
        except Exception:
            return ""

    def snapshotTasks(self) -> set:
        try:
            raw = subprocess.check_output(["schtasks", "/query"], shell=False, text=True, stderr=subprocess.DEVNULL)
            lines = raw.splitlines()
            tasks = set()

            for line in lines[2:]:
                if not line.strip():
                    continue
                cols = line.split()
                task = cols[0]
                tasks.add(task)
            return tasks
        except Exception:
            return set()

    def createBaseline(self):
        baseline = []

        # startup folders
        startup_snap = self.snapshotStartupFolders()
        for folder, items in startup_snap.items():
            for item in items:
                try:
                    full_path = os.path.join(folder, item)
                except Exception:
                    full_path = item
                baseline.append({
                    "type": "startupFolder",
                    "location": folder,
                    "name": item,
                    "path": full_path,
                    "timestamp": time.time()
                })

        # run keys
        run_snap = self.snapshotRunKeys()
        for keyId, values in run_snap.items():

            if "__error__" in values:
                baseline.append({
                    "type": "runKey",
                    "location": keyId,
                    "name": None,
                    "value": None,
                    "note": "ACCESS_DENIED",
                    "timestamp": time.time()
                })
                continue

            for name, val in values.items():
                baseline.append({
                    "type": "runKey",
                    "location": keyId,
                    "name": name,
                    "value": val,
                    "timestamp": time.time()
                })

        services = self.snapshotServices()
        for svc in services:
            binpath = self.getServiceBinaryPath(svc)
            baseline.append({
                "type": "service",
                "location": "services",
                "name": svc,
                "binaryPath": binpath,
                "timestamp": time.time()
            })

        # scheduled tasks
        tasks = self.snapshotTasks()
        for t in tasks:
            baseline.append({
                "type": "scheduledTask",
                "location": "scheduledTasks",
                "name": t,
                "timestamp": time.time()
            })

        return baseline

    def runMonitor(self, stopEvent: threading.Event):
        """
        Capture baseline then monitor for changes. Returns dict:
          {"baseline": [...], "events": [...]}
        """
        print("PersistenceMonitor started")

        # create baseline
        baseline = self.createBaseline()
        self.results["baseline"] = baseline

        #snapshots for change detection
        prevSnapshot = {
            "startupFolders": self.snapshotStartupFolders(),
            "runKeys": self.snapshotRunKeys(),
            "services": self.snapshotServices(),
            "tasks": self.snapshotTasks()
        }

        try:
            while not stopEvent.is_set():
                current = {
                    "startupFolders": self.snapshotStartupFolders(),
                    "runKeys": self.snapshotRunKeys(),
                    "services": self.snapshotServices(),
                    "tasks": self.snapshotTasks()
                }

                # startup folder
                for folder, prevItems in prevSnapshot["startupFolders"].items():
                    newItems = current["startupFolders"].get(folder, set())
                    added = newItems - prevItems
                    removed = prevItems - newItems

                    for item in added:
                        try:
                            full_path = os.path.join(folder, item)
                        except Exception:
                            full_path = item
                        self.results["events"].append({
                            "event": "added",
                            "type": "startupFolder",
                            "location": folder,
                            "name": item,
                            "path": full_path,
                            "timestamp": time.time()
                        })
                    for item in removed:
                        try:
                            full_path = os.path.join(folder, item)
                        except Exception:
                            full_path = item
                        self.results["events"].append({
                            "event": "removed",
                            "type": "startupFolder",
                            "location": folder,
                            "name": item,
                            "path": full_path,
                            "timestamp": time.time()
                        })

                # runKey changes
                for keyId, newValues in current["runKeys"].items():
                    oldValues = prevSnapshot["runKeys"].get(keyId, {})

                    # additions/modifications
                    for name, val in newValues.items():
                        if name not in oldValues:
                            self.results["events"].append({
                                "event": "added",
                                "type": "runKey",
                                "location": keyId,
                                "name": name,
                                "value": val,
                                "timestamp": time.time()
                            })
                        elif oldValues.get(name) != val:
                            self.results["events"].append({
                                "event": "modified",
                                "type": "runKey",
                                "location": keyId,
                                "name": name,
                                "old": oldValues.get(name),
                                "new": val,
                                "timestamp": time.time()
                            })

                    # deletions
                    for name in oldValues:
                        if name not in newValues:
                            self.results["events"].append({
                                "event": "removed",
                                "type": "runKey",
                                "location": keyId,
                                "name": name,
                                "timestamp": time.time()
                            })

                # services changes
                added_svcs = current["services"] - prevSnapshot["services"]
                removed_svcs = prevSnapshot["services"] - current["services"]
                for svc in added_svcs:
                    binpath = self.getServiceBinaryPath(svc)
                    self.results["events"].append({
                        "event": "added",
                        "type": "service",
                        "location": "services",
                        "name": svc,
                        "binaryPath": binpath,
                        "timestamp": time.time()
                    })
                for svc in removed_svcs:
                    self.results["events"].append({
                        "event": "removed",
                        "type": "service",
                        "location": "services",
                        "name": svc,
                        "timestamp": time.time()
                    })

                # scheduled tasks
                added_tasks = current["tasks"] - prevSnapshot["tasks"]
                removed_tasks = prevSnapshot["tasks"] - current["tasks"]
                for t in added_tasks:
                    self.results["events"].append({
                        "event": "added",
                        "type": "scheduledTask",
                        "location": "scheduledTasks",
                        "name": t,
                        "timestamp": time.time()
                    })
                for t in removed_tasks:
                    self.results["events"].append({
                        "event": "removed",
                        "type": "scheduledTask",
                        "location": "scheduledTasks",
                        "name": t,
                        "timestamp": time.time()
                    })

                # rotate snapshots
                prevSnapshot = current
                time.sleep(self.checkInterval)

        except KeyboardInterrupt:
            print("PersistenceMonitor stopped manually")
        except Exception as e:
            print(f"PersistenceMonitor error: {e}")

        print(f"PersistenceMonitor stopped : {len(self.results['events'])} events recorded (baseline items: {len(self.results['baseline'])}).")
        return self.results
