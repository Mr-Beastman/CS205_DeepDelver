class PersistenceAnalyser:
    badExtensions = {".exe", ".dll", ".vbs", ".ps1", ".bat", ".cmd", ".scr"}
    safeDirs = ["\\windows\\system32", "\\windows\\syswow64", "\\program files", "\\program files (x86)"]
    suspiciousTaskKeywords = {"update", "service", "system", "agent", "google", "windowsupdate"}

    def _assessRisk(self, path: str, eventType: str, name: str = "") -> str:
        if not path:
            return "medium"
        p = path.lower().replace("/", "\\")

        if any(p.endswith(ext) for ext in self.badExtensions) and not any(sd in p for sd in self.safeDirs):
            return "high"

        if eventType == "scheduledTask" and any(kw in name.lower() for kw in self.suspiciousTaskKeywords):
            return "high"
        return "medium"

    def analyse(self, persistenceEvents: list) -> list:
        results = []

        for event in persistenceEvents:
            eventType = event.get("type")
            action = event.get("event")
            name = event.get("name", "")
            location = event.get("location", "")
            timestamp = event.get("timestamp")
            filePath = event.get("path") or event.get("binaryPath") or event.get("value", "")

            risk = self._assessRisk(filePath, eventType, name)

            if eventType == "startupFolder":
                results.append({
                    "category": "Persistence: Startup Folder",
                    "action": action,
                    "name": name,
                    "location": location,
                    "filePath": filePath,
                    "timestamp": timestamp,
                    "riskLevel": risk
                })

            elif eventType == "runKey":
                results.append({
                    "category": "Persistence: Run Registry Key",
                    "action": action,
                    "name": name,
                    "location": location,
                    "value": filePath,
                    "timestamp": timestamp,
                    "riskLevel": risk
                })

            elif eventType == "service":
                results.append({
                    "category": "Persistence: Installed Service",
                    "action": action,
                    "serviceName": name,
                    "binaryPath": filePath,
                    "location": location,
                    "timestamp": timestamp,
                    "riskLevel": risk
                })

            elif eventType == "scheduledTask":
                results.append({
                    "category": "Persistence: Scheduled Task",
                    "action": action,
                    "taskName": name,
                    "location": location,
                    "timestamp": timestamp,
                    "riskLevel": risk
                })

            else:
                results.append({
                    "category": f"Unknown Persistence Type ({eventType})",
                    "event": event,
                    "riskLevel": "medium"
                })

        return results
