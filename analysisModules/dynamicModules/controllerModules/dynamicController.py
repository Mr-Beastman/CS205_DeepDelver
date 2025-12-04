import threading

from analysisModules.dynamicModules.monitorModules.processMonitor import ProcessMonitor
from analysisModules.dynamicModules.monitorModules.registryMonitor import RegistryMonitor
from analysisModules.dynamicModules.monitorModules.persistanceMonitor import PersistenceMonitor
from analysisModules.dynamicModules.monitorModules.networkMonitor import NetworkMonitor
from analysisModules.dynamicModules.monitorModules.fileSystemMonitor import FileSystemMonitor

from analysisModules.dynamicModules.analyserModules.processAnalyser import ProcessAnalyser
from analysisModules.dynamicModules.analyserModules.registryAnalyser import RegistryAnalyser
from analysisModules.dynamicModules.analyserModules.persistanceAnalyser import PersistenceAnalyser
from analysisModules.dynamicModules.analyserModules.networkAnalyser import NetworkAnalyser
from analysisModules.dynamicModules.analyserModules.fileSystemAnalyser import FileSystemAnalyser


class DynamicController:

    def __init__(self, filePath: str):
        self.filePath = filePath
        self.stopEvent = threading.Event()
        self.monitorObjects = []
        self.monitorThreads = []

        #  onitor data
        self.processRaw = {}
        self.registryRaw = {}
        self.networkRaw = {}
        self.persistenceRaw = {}
        self.filesystemRaw = {}

        # results
        self.processResults = {}
        self.registryResults = {}
        self.networkResults = {}
        self.persistenceResults = {}
        self.filesystemResults = {}

    def loadMonitors(self) -> None:
        print("\n=== Loading Dynamic Monitors ===")

        self.monitorObjects = [
            ProcessMonitor(),
            RegistryMonitor(),
            NetworkMonitor(),
            PersistenceMonitor(),
            FileSystemMonitor(),
        ]

        for m in self.monitorObjects:
            print(f"Loaded: {m.__class__.__name__}")

    def threadWrapper(self, monitor):
        """Store RAW results (analysis happens later)"""
        try:
            result = monitor.runMonitor(self.stopEvent)

            if not isinstance(result, (dict, list)):
                result = {"error": "unexpected result format"}

            name = monitor.__class__.__name__
            if name == "ProcessMonitor":
                self.processRaw = result
            elif name == "RegistryMonitor":
                self.registryRaw = result
            elif name == "NetworkMonitor":
                self.networkRaw = result
            elif name == "PersistenceMonitor":
                self.persistenceRaw = result
            elif name == "FileSystemMonitor":
                self.filesystemRaw = result

        except Exception as e:
            print(f"Error in {monitor.__class__.__name__}: {e}")

    def startDynamicAnalysis(self) -> None:
        print("\n=== Starting Dynamic Analysis ===")
        self.loadMonitors()

        for monitor in self.monitorObjects:
            t = threading.Thread(
                target=self.threadWrapper,
                args=(monitor,),
                daemon=True,
                name=monitor.__class__.__name__
            )
            self.monitorThreads.append(t)
            t.start()

        print("=== Dynamic Monitoring Active ===")

    def stopDynamicAnalysis(self) -> None:
        print("\n=== Stopping Dynamic Analysis ===")
        self.stopEvent.set()

        for t in self.monitorThreads:
            t.join(timeout=5)
            print(f"{t.name} stopped")

        print("\n=== Running Dynamic Analysers ===")
        self.runDynamicAnalyers()

        print("=== Dynamic Analysis Complete ===")

    def runDynamicAnalyers(self):

        print("> Analysing Processes")
        self.processResults = ProcessAnalyser().analyse(self.processRaw)

        print("> Analysing Registry")
        self.registryResults = RegistryAnalyser().analyse(self.registryRaw.get("events", []))

        print("> Analysing Network")
        self.networkResults = NetworkAnalyser().analyse(self.networkRaw)

        print("> Analysing Persistance")   
        self.persistenceResults = PersistenceAnalyser().analyse(self.persistenceRaw.get("events", []))

        print("> Analysing File System")
        self.filesystemResults = FileSystemAnalyser().analyse(self.filesystemRaw)

    def combineResults(self) -> dict:

        return {
            "process": self.processResults,
            "registry": self.registryResults,
            "network": self.networkResults,
            "persistence": self.persistenceResults,
            "filesystem": self.filesystemResults,
        }
