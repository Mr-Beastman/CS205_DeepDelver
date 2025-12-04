import time
import threading
import psutil

class ProcessMonitor:

    def __init__(self, checkInterval: float = 0.2):
        self.checkInterval = checkInterval
        self._observedPids = set()  

    def runMonitor(self, stopEvent: threading.Event) -> list:
        """
        Real-time process monitoring.
        Returns:
            result (list) : list of observed processes.
        """

        print("ProcessMonitor Started")
        results = []

        try:
            while not stopEvent.is_set():
                for proc in psutil.process_iter(attrs=["pid", "name"]):
                    pId = proc.info.get("pid")
                    name = proc.info.get("name", "unknown")

                    if pId not in self._observedPids:
                        results.append({
                            "pid": pId,
                            "name": name
                        })
                        self._observedPids.add(pId)

                time.sleep(self.checkInterval)  # avoid CPU spinning

        except KeyboardInterrupt:
            print("ProcessMonitor stopped manually")

        print(f"ProcessMonitor collected {len(results)} processes")
        return results
