import time
import winreg
import threading
from analysisModules.dynamicModules.config.registryKeys import defaultKeys


class RegistryMonitor:

    def __init__(self, checkInterval: float = 0.5):
        self.checkInterval = checkInterval
        self.monitoringKeys = defaultKeys

        self.results = {
            "baseline": [],
            "events": []
        }

        self._prevSnapshot = None

    def createRegistrySnapshot(self) -> dict:
        """
        Create a snapshot of monitored registry keys.
        Returns raw dict for change detection + stores baseline entry list.
        """
        snapshot = {}

        for hive, path in self.monitoringKeys:
            keyId = f"{hive}\\{path}"

            try:
                with winreg.OpenKey(hive, path, 0, winreg.KEY_READ) as key:
                    values = {}
                    for i in range(winreg.QueryInfoKey(key)[1]):
                        try:
                            name, val, _ = winreg.EnumValue(key, i)
                            values[name] = val
                        except OSError:
                            continue

                    snapshot[keyId] = values

                    #baseline items
                    for name, val in values.items():
                        self.results["baseline"].append({
                            "type": "registryValue",
                            "key": keyId,
                            "name": name,
                            "value": val,
                            "timestamp": time.time()
                        })

            except FileNotFoundError:
                snapshot[keyId] = {}

            except PermissionError:
                snapshot[keyId] = {"__error__": "ACCESS_DENIED"}
                self.results["baseline"].append({
                    "type": "registryKey",
                    "key": keyId,
                    "note": "ACCESS_DENIED",
                    "timestamp": time.time()
                })

        return snapshot

    def runMonitor(self, stopEvent: threading.Event) -> dict:
        """
        Starts detection of registry value changes
        Returns:
            {
                "baseline": [...],
                "events": [...]
            }
        """
        print("RegistryMonitor Started")

        self._prevSnapshot = self.createRegistrySnapshot()

        try:
            while not stopEvent.is_set():
                currentSnapshot = self.createRegistrySnapshot()

                for keyPath, newValues in currentSnapshot.items():
                    oldValues = self._prevSnapshot.get(keyPath, {})

                    # skip access denied
                    if "__error__" in newValues:
                        continue

                    # added/modified
                    for name, val in newValues.items():
                        if name not in oldValues:
                            self.results["events"].append({
                                "event": "added",
                                "type": "registryValue",
                                "key": keyPath,
                                "name": name,
                                "value": val,
                                "timestamp": time.time()
                            })
                        elif oldValues[name] != val:
                            self.results["events"].append({
                                "event": "modified",
                                "type": "registryValue",
                                "key": keyPath,
                                "name": name,
                                "old": oldValues[name],
                                "new": val,
                                "timestamp": time.time()
                            })

                    # deleted
                    for name in oldValues:
                        if name not in newValues:
                            self.results["events"].append({
                                "event": "removed",
                                "type": "registryValue",
                                "key": keyPath,
                                "name": name,
                                "timestamp": time.time()
                            })

                self._prevSnapshot = currentSnapshot
                time.sleep(self.checkInterval)

        except KeyboardInterrupt:
            print("RegistryMonitor stopped manually")

        print(f"RegistryMonitor Stopped — {len(self.results['events'])} events detected")
        return self.results
