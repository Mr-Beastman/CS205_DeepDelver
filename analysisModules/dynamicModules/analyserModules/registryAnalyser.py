class RegistryAnalyser:

    def analyse(self, registryEvents: list) -> list:
        results = []

        for event in registryEvents:
            category = "Registry Value Change"
            risk = "info"
            eventAction = event.get("event")

            if eventAction == "added":
                category = "Registry Value Added"

                val = event.get("value")
                if val and val.lower().endswith((".exe", ".dll", ".vbs", ".ps1", ".bat", ".cmd", ".scr")):
                    risk = "high"
            elif eventAction == "modified":
                category = "Registry Value Modified"

                newVal = event.get("new")
                if newVal and newVal.lower().endswith((".exe", ".dll", ".vbs", ".ps1", ".bat", ".cmd", ".scr")):
                    risk = "high"
            elif eventAction == "removed":
                category = "Registry Value Removed"
                risk = "low"

            results.append({
                "category": category,
                "key": event.get("key"),
                "name": event.get("name"),
                "oldValue": event.get("old"),
                "newValue": event.get("new"),
                "value": event.get("value"),
                "timestamp": event.get("timestamp"),
                "riskLevel": risk
            })

        return results
