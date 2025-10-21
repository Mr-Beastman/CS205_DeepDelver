import time
import json
import winreg
import threading
from pathlib import Path
from analysisModules.dynamicModules.config.registryKeys import defaultKeys

class RegistryMonitor:

    def __init__(self, checkInterval: float = 0.5):
        self.checkInterval = checkInterval
        self.monitoringKeys = defaultKeys

    def createRegistrySnapshot(self) -> dict:
        #docString
        """
        create an intial snapshot before running the exe file for comparison
        """
        registrySnapshot = {}

        for hive, path in self.monitoringKeys:
            keyid = f"{hive}\\{path}"
            try:
                with winreg.OpenKey(hive, path, 0, winreg.KEY_READ) as key:
                    values = {}
                    for i in range(winreg.QueryInfoKey(key)[1]):
                        try:
                            name, val, _ = winreg.EnumValue(key, i)
                            values[name] = val
                        except OSError:
                            continue
                    registrySnapshot[keyid] = values
            except FileNotFoundError:
                registrySnapshot[keyid] = {}
            except PermissionError:
                registrySnapshot[keyid] = {"__error__": "ACCESS_DENIED"}
        
        return registrySnapshot  



    def runMonitor(self, stopEvent, outputPath: Path):
        #docString
        """
        Monitors selected registry keys for changes.
        """

        print("Registry Monitor Started")
        prevSnapshot = self.createRegistrySnapshot()


        results = {"changes": []}

        try:
            while not stopEvent.is_set():
                currentSnapshot = self.createRegistrySnapshot()

                # checking snapshots for changes
                for k, v in currentSnapshot.items():
                    prevVersion = prevSnapshot.get(k, {})
                    for name, val in v.items():
                        if name not in prevVersion:
                            results["changes"].append({"action": "added", "key": k, "name": name, "value": val})
                        elif prevVersion[name] != val:
                            results["changes"].append({"action": "modified", "key": k, "name": name, "old": prevVersion[name], "new": val})
                    for name in prevVersion:
                        if name not in v:
                            results["changes"].append({"action": "deleted", "key": k, "name": name})

                prevSnapshot = currentSnapshot
                time.sleep(self.checkInterval)

        except KeyboardInterrupt:
            print("Registry Monitor Closed by user")

        outFile = outputPath/"RegistryReport.json"
        outFile.write_text(json.dumps(results, indent=2))


###  Test Function ###
def testRun(outPath: str) -> None:
    #docString
    """
    Used to test monitor during development.
    
    Parameters:
        str : location for output file to be saved.
    """

    path = Path(outPath)
    rm = RegistryMonitor()
    stopEvent = threading.Event()
    rm.runRegistryMonitor(stopEvent, path)