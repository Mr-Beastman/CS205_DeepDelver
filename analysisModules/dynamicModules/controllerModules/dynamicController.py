import threading
from pathlib import Path

from analysisModules.dynamicModules.monitorModules.processMonitor import ProcessMonitor
from analysisModules.dynamicModules.monitorModules.registryMonitior import RegistryMonitor

class DynamicController:

    def __init__(
        self,
        monitors: list,           
        filePath: str,    
        outputPath: str,           
    ):
        self.monitors = monitors
        self.filePath = str(filePath)
        self.outputPath = Path(outputPath)
        self.stopEvent = threading.Event()
        self.threads =  []      

    def startMonitors(self):

        print("\n === Starting Monitors === \n")

        for monitor in self.monitors:
            thread = threading.Thread(
                target = monitor.runMonitor,
                args = (self.stopEvent, self.outputPath),
                name=f"monitor-{getattr(monitor, 'name', monitor.__class__)}",
                daemon=True,
            )

            thread.start()

            self.threads.append(thread)
            print(f"{thread.name} has been started")

    def stopMonitors(self):
        print("\n === Ending Monitors === \n")

        self.stopEvent.set()

        for thread in self.threads:
            thread.join(timeout=5)
            print(f"{thread.name} has been stopped")

        print("\n === All Montiors have been stopped === ")

            
## test function for dev

def testController(filePath:str, outputPath:str) -> None:

    monitors = []

    pm = ProcessMonitor()
    rm = RegistryMonitor()

    if pm:
        monitors.append(pm)
    if rm:
        monitors.append(rm)

    controller = DynamicController(monitors, filePath, outputPath)

    try:
        controller.startMonitors()
        while True:
            pass
    except KeyboardInterrupt:
        controller.stopMonitors()