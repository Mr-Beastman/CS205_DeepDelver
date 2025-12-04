class RiskAnalyser:
    """
    Aggregates results from all static and dynamic analysers
    to calculate a unified risk score and rating.
    """

    def __init__(self, combinedResults: dict):
        self.staticResults = combinedResults.get("StaticAnalysis", {})
        self.dynamicResults = combinedResults.get("DynamicAnalysis", {})
        self.totalScore = 0
        self.rating = ""
        self.breakdown = {}

    #scoring static results

    def scoreMetadata(self):

        print("> Scoring Metadata")
        meta = self.staticResults.get("metadata", {})
        score = 0

        # section names flagged by MetadataAnalyser
        score += len(meta.get("fileSectionsNames", {})) * 5

        # file size
        fileSizeInfo = meta.get("fileSize", {}).get("fileSize", {}).get("result", "")
        if "Very large" in fileSizeInfo:
            score += 2

        # timestamps flagged
        timestamps = meta.get("fileTimeStamps", {})
        for entry in timestamps.values():
            if isinstance(entry, dict) and entry.get("result") == "Timestamp in the future":
                score += 3

        return "metadata", score

    def scoreSections(self):
        print("> Scoring Sections")
        sections = self.staticResults.get("sections", {})

        anomalies = sections.get("anomalies", [])
        suspiciousSections = sections.get("suspiciousSections", [])
        score = len(anomalies) * 5 + len(suspiciousSections) * 10
        return "sections", score

    def scoreHashes(self):
        print("> Scoring Hashes")
        hashes = self.staticResults.get("hashes", {}).get("hashes", [])

        score = sum(50 for h in hashes if h.get("result") == "Malicious")
        return "hashes", score

    def scoreImports(self):
        print("> Scoring Imports")
        imports = self.staticResults.get("imports", {})

        score = 0
        for dll, funcs in imports.items():
            for func, funcData in funcs.items():
                if isinstance(funcData, dict) and funcData.get("severity") == "high":
                    score += 5
        return "imports", score

    def scoreEntropy(self):
        print("> Scoring Entopy")
        entropy = self.staticResults.get("entropy", {})
        score = 0

        sev = entropy.get("shannon", {}).get("severity")
        score += {"high": 10, "medium": 5, "low": 1}.get(sev, 0)

        spikes = entropy.get("spikes", {}).get("value", 0)
        if spikes > 20:
            score += 5
        elif spikes > 5:
            score += 1

        return "entropy", score

    def scoreStrings(self):
        print("> Scoring Strings")
        strings = self.staticResults.get("strings", {})

        categoryWeights = {
            "urls": {"Malicious": 20, "Suspicious": 5, "Not Flagged": 0},
            "commands": {"Suspicious": 5, "Not Flagged": 0},
            "registryKeys": {"Suspicious": 5, "Not Flagged": 0},
            "filePaths": {"Suspicious": 5, "Not Flagged": 0},
            "emails": {"Suspicious": 3, "Not Flagged": 0},
            "ips": {"Malicious": 20, "Not Flagged": 0},
            "base64": {"Not Flagged": 0},
        }

        score = 0
        for category, entries in strings.items():
            if isinstance(entries, list):
                for entry in entries:
                    classification = entry.get("classification", "Not Flagged")
                    score += categoryWeights.get(category, {}).get(classification, 0)

        return "strings", score
    
    def scoreStatic(self):
            """
            Modular scoring for static analysis categories.
            Each scoring function returns: (categoryName, score)
            """
            total = 0
            breakdown = {}
            
            print("\n=== Scoring Static Results===")

            scorers = [
                self.scoreMetadata,
                self.scoreSections,
                self.scoreHashes,
                self.scoreImports,
                self.scoreEntropy,
                self.scoreStrings,
            ]

            for scorer in scorers:
                category, value = scorer()
                breakdown[category] = value
                total += value

            self.breakdown["static"] = breakdown
            return total

    # dynamic scoring
    def _scoreDynamicModule(self, moduleName: str, weightHigh: int, weightMedium: int) -> int:
            """
            Generic scoring function for dynamic monitors.
            """
            entries = self.dynamicResults.get(moduleName, [])
            score = 0
            for e in entries:
                risk = e.get("riskLevel", "medium").lower()
                if risk == "high":
                    score += weightHigh
                elif risk == "medium":
                    score += weightMedium
            return score

    def scoreProcessMonitor(self):
        print("> Scoring ProcessMonitor")
        score = self._scoreDynamicModule("process", weightHigh=10, weightMedium=5)
        return "ProcessMonitor", score

    def scoreRegistryMonitor(self):
        print("> Scoring RegistryMonitor")
        score = self._scoreDynamicModule("registry", weightHigh=8, weightMedium=4)
        return "RegistryMonitor", score

    def scoreFileSystemMonitor(self):
        print("> Scoring FileSystemMonitor")
        score = self._scoreDynamicModule("filesystem", weightHigh=6, weightMedium=3)
        return "FileSystemMonitor", score

    def scoreNetworkMonitor(self):
        print("> Scoring NetworkMonitor")
        score = self._scoreDynamicModule("network", weightHigh=10, weightMedium=5)
        return "NetworkMonitor", score

    def scorePersistenceMonitor(self):
        print("> Scoring PersistenceMonitor")
        score = self._scoreDynamicModule("persistence", weightHigh=12, weightMedium=6)
        return "PersistenceMonitor", score

    def scoreDynamic(self):
        total = 0
        breakdown = {}
        print("\n=== Scoring Dynamic Results===")
        scorers = [
            self.scoreProcessMonitor,
            self.scoreRegistryMonitor,
            self.scoreNetworkMonitor,
            self.scorePersistenceMonitor,
            self.scoreFileSystemMonitor,
        ]
        for scorer in scorers:
            category, value = scorer()
            breakdown[category] = value
            total += value
        self.breakdown["dynamic"] = breakdown
        return total

    #calculate the total risk from resulsts
    def calculateRisk(self):
        staticScore = self.scoreStatic()
        dynamicScore = self.scoreDynamic()

        # score weight sum
        self.totalScore = (staticScore + dynamicScore)

        # thresholds
        if self.totalScore >= 200:
            self.rating = "Critical / Highly Suspicious"
        elif self.totalScore >= 120:
            self.rating = "High"
        elif self.totalScore >= 60:
            self.rating = "Medium"
        else:
            self.rating = "Low – No immediate flags"

        return {
            "totalScore": self.totalScore,
            "rating": self.rating,
            "breakdown": self.breakdown
        }