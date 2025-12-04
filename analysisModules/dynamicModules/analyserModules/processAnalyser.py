class ProcessAnalyser:
    """Analyse process events and assign risk levels, deduplicating multiple snapshots."""
    
    highRisk = ["\\temp\\", "\\appdata\\", "\\users\\"]
    systemPaths = ["\\windows\\system32", "\\windows\\syswow64"]

    riskPriority = {"high": 3, "medium": 2, "safe": 1}

    def _assessRisk(self, path: str, procType: str) -> str:
        """Return risk based on path or type"""
        if not path:
            return "medium"
        p = path.lower().replace("/", "\\")

        if any(sysdir in p for sysdir in self.systemPaths):
            return "medium" if procType != "system" else "safe"

        if any(risk in p for risk in self.highRisk):
            return "high"

        return "medium"

    def analyse(self, processEvents: list) -> list:
        """
        Deduplicate processes by PID + path.
        For duplicates, keep the highest risk level.
        """
        deduped = {}

        for event in processEvents:
            pid = event.get("pid")
            path = (event.get("path") or "").lower()
            name = event.get("name", "")
            procType = event.get("type", "unknown")

            if not pid or not path:
                continue

            risk = self._assessRisk(path, procType)

            key = (pid, path)

            if key in deduped:
                existing_risk = deduped[key]["riskLevel"]
                if self.riskPriority[risk] > self.riskPriority[existing_risk]:
                    deduped[key]["riskLevel"] = risk
            else:
                deduped[key] = {
                    "pid": pid,
                    "name": name,
                    "path": path,
                    "type": procType,
                    "riskLevel": risk
                }

        return list(deduped.values())
