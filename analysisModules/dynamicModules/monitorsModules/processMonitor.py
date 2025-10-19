import time
import json
import logging
from pathlib import Path
import threading
import psutil

class ProcessMonitor:
    def __init__(self, checkInterval: float = 0.2):
        self.checkInterval = checkInterval

    def runProcessMonitor(self, stopEvent: threading.Event, outputPath: Path) -> None:
        #docString
        """
        Real time process monitoring using psutil.
        """

        #start logging notifiactions
        logging.info("ProcessMonitor Started")

        results = {"processes":[]}
        observedPids = set()

        try:
            while not stopEvent.is_set():
                for proc in psutil.process_iter(attrs=["pid", "name"]):
                    pId = proc.info["pid"]
                    name = proc.info["name"]
                    if pId not in observedPids:
                        results["processes"].append({"pid": pId, "name": name})
                        observedPids.add(pId)
                        logging.debug(f"New process detected: {name} (PID {pId})")
                time.sleep(self.checkInterval)
        except KeyboardInterrupt:
            print("Monitor ended by user via KeyBoardInterrupt")

        outFile = outputPath/"report.json"
        outFile.write_text(json.dumps(results, indent=2))

        logging.info(f"ProcessMonitor logs saved to {outFile}")


###  Test Function ###
def testRun(outPath: str) -> None:
    #docString
    """
    Used to test monitor during development.
    
    Parameters:
        str : location for output file to be saved.
    """

    path = Path(outPath)
    pm = ProcessMonitor()
    stopEvent = threading.Event()
    pm.runProcessMonitor(stopEvent, path)
