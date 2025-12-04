import os
import re
from pathlib import Path

class FileSystemAnalyser:
    sensitivePaths = [
        r"\\AppData\\Roaming",
        r"\\AppData\\Local\\Temp",
        r"\\ProgramData",
        r"\\Windows\\System32",
        r"\\Windows\\Temp",
        r"\\Users\\.*\\AppData\\LocalLow",
        r"\\Startup",
    ]
    randomNameRegex = re.compile(r"^[A-Za-z0-9]{8,15}\.(exe|dll|dat|tmp)$")
    suspiciousExtensions = {".exe", ".dll", ".sys", ".bat", ".cmd", ".ps1"}

    def analyse(self, fileData: list) -> list:
        results = []

        for event in fileData:
            path = event.get("path") or event.get("srcPath")
            eventType = event.get("eventType", "")
            if not path:
                continue

            flagged = False

            # paths
            if any(re.search(p, path, flags=re.IGNORECASE) for p in self.sensitivePaths):
                results.append({
                    "eventType": "SensitivePath",
                    "description": f"{eventType.upper()} in sensitive path: {path}",
                    "details": {"path": path, "eventType": eventType},
                    "riskLevel": "medium"
                })
                flagged = True

            # sus exten
            ext = Path(path).suffix.lower()
            if eventType == "created" and ext in self.suspiciousExtensions:
                results.append({
                    "eventType": "ExecutableCreated",
                    "description": f"Created executable file: {path}",
                    "details": {"path": path, "eventType": eventType, "extension": ext},
                    "riskLevel": "high"
                })
                flagged = True

            # random name
            if eventType == "created" and self.randomNameRegex.match(os.path.basename(path)):
                results.append({
                    "eventType": "RandomFilename",
                    "description": f"Randomized filename created: {path}",
                    "details": {"path": path, "eventType": eventType},
                    "riskLevel": "medium"
                })
                flagged = True

            # moved
            if eventType == "moved":
                dest = event.get("destPath")
                oldExt = Path(path).suffix.lower()
                newExt = Path(dest).suffix.lower() if dest else ""
                if oldExt != newExt and newExt in self.suspiciousExtensions:
                    results.append({
                        "eventType": "RenameToExecutable",
                        "description": f"File renamed to executable: {path} → {dest}",
                        "details": {"srcPath": path, "destPath": dest, "oldExt": oldExt, "newExt": newExt},
                        "riskLevel": "high"
                    })
                    flagged = True


            # safe/not flagged
            if not flagged:
                results.append({
                    "eventType": eventType or "normal",
                    "description": "No suspicious activity detected",
                    "details": {"path": path, "eventType": eventType},
                    "riskLevel": "safe"
                })

        return results
