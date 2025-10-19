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
        logging.info(f"{self.name} Started")

        results = {"processes":[]}
        counter = 0

        while not stopEvent.is_set() and i < 50:
            results["processes"].append(f"simproc_{counter}.exe")
            i += 1
            time.sleep(self.checkInterval)

        outFile = outputPath/f"{self.name}.json"
        outFile.write_text(json.dumps(results))

        logging.info(f"{self.name} logs saved to {outFile}")