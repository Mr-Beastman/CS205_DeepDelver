import time
import threading
from pathlib import Path
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import os

class FileSystemMonitor(FileSystemEventHandler):
    """
    Focused malware-relevant file system monitoring.
    Only tracks suspicious directories and notable file types.
    Stores events as a list compatible with DynamicController.
    """

    # abused directories
    suspiciousDirs = [
        Path(os.getenv("APPDATA", "")),          
        Path(os.getenv("LOCALAPPDATA", "")),  
        Path(os.path.join(os.getenv("USERPROFILE", ""), "Downloads")),
        Path(os.path.join(os.getenv("USERPROFILE", ""), "Start Menu", "Programs", "Startup"))
    ]

    # abused file types
    notableExtensions = [".exe", ".dll", ".vbs", ".ps1", ".bat", ".cmd", ".scr"]

    def __init__(self, checkInterval: float = 0.5):
        super().__init__()
        self.checkInterval = checkInterval
        self.results = []
        self.name = "FileSystemMonitor"
        self.observer = None

    def recordEvent(self, eventType, path, destPath=None, isDir=False):
        ext = Path(path).suffix.lower()
        self.results.append({
            "eventType": eventType,
            "path": path,
            "destPath": destPath or "",
            "extension": ext,
            "isDirectory": isDir,
            "timestamp": time.time()
        })

    def onCreated(self, event):
        self.recordEvent("created", event.src_path, isDir=event.is_directory)

    def onDeleted(self, event):
        self.recordEvent("deleted", event.src_path, isDir=event.is_directory)

    def onModified(self, event):
        self.recordEvent("modified", event.src_path, isDir=event.is_directory)

    def onMoved(self, event):
        self.recordEvent("moved", event.src_path, destPath=event.dest_path, isDir=event.is_directory)

    def runMonitor(self, stopEvent: threading.Event):

        self.observer = Observer()

        for path in self.suspiciousDirs:
            if path.exists():
                self.observer.schedule(self, str(path), recursive=True)
                print(f"{self.name} watching: {path}")

        self.observer.start()

        try:
            while not stopEvent.is_set():
                time.sleep(self.checkInterval)
        except KeyboardInterrupt:
            print(f"{self.name} stopped by KeyboardInterrupt")

        self.observer.stop()
        self.observer.join()

        print(f"{self.name} stopped — {len(self.results)} events recorded.")
        return self.results
