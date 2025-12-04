import os, re


class StringAnalyser:
    """Analyses strings extracted from a binary (URLs, IPs, paths, registry keys, commands, emails, base64)."""

    def __init__(self, stringData: dict):
        self.data = stringData or {}
        self.configFiles = {
            "urls": "analysisModules/staticModules/config/urlConfig/unarmedUrls.csv",
            "commands": "analysisModules/staticModules/config/stringConfig/commands.txt",
            "registryKeys": "analysisModules/staticModules/config/stringConfig/registry.txt",
            "ips": "analysisModules/staticModules/config/stringConfig/flaggedIP.csv"
        }

        self.knownUrls = []
        self.knownCommands = []
        self.knownRegistry = []
        self.knownPath = []
        self.knownEmails = []
        self.knownIps = []

        self.loadConfigs()

    def armUrl(self, url: str) -> str:
        """Convert unarmed URLs (hxxp/hxxps) to normal http/https format."""
        return (url.replace("hxxps://", "https://")
                   .replace("hxxp://", "http://"))

    def loadFileList(self, path: str) -> list:
        """Load a list of strings from a config file."""
        if not os.path.exists(path):
            return []
        with open(path, "r", encoding="utf-8") as f:
            return [line.strip().lower() for line in f if line.strip() and not line.startswith("#")]

    def loadConfigs(self):
        """Load known suspicious or malicious records from config files"""
        self.knownUrls = set(self.loadFileList(self.configFiles.get("urls", "")))
        self.knownCommands = set(self.loadFileList(self.configFiles.get("commands", "")))
        self.knownRegistry = set(self.loadFileList(self.configFiles.get("registryKeys", "")))
        self.knownIps = set(self.loadFileList(self.configFiles.get("ips", "")))


    def isValidUrl(self, url: str) -> bool:
        """Check if a URL is minimally valid, without IP parsing."""
        url = self.armUrl(url).strip()
        if not (url.startswith("http://") or url.startswith("https://")):
            return False

        # Remove scheme
        host = url.split("://", 1)[1].split("/", 1)[0]  # get netloc part
        if not host or host.endswith(".") or "." not in host:
            return False

        # Only allow letters, numbers, hyphens, dots
        if not re.fullmatch(r"[a-zA-Z0-9.-]+", host):
            return False

        return True



    # --- Classification methods ---
    def classifyUrl(self, item: str) -> str:
        """Compare URL against flagged list, only if valid."""
        if not self.isValidUrl(item):
            return "InvalidUrl"
        armedItem = self.armUrl(item).lower()
        if any(armedItem in self.armUrl(k) for k in self.knownUrls):
            return "Malicious"
        return "Not Flagged"

    def classifyCommand(self, item: str) -> str:
        return "Suspicious" if item.lower() in self.knownCommands else "Not Flagged"

    def classifyRegistry(self, item: str) -> str:
        lower = item.lower()
        if any(k in lower for k in self.knownRegistry):
            return "Suspicious"
        return "Not Flagged"

    def classifyPath(self, item: str) -> str:
        lower = item.lower()
        if any(lower.endswith(ext) for ext in (".exe", ".dll", ".bat", ".vbs", ".ps1")):
            if any(folder in lower for folder in ("\\appdata", "\\temp", "\\programdata")):
                return "Suspicious"
        return "Not Flagged"

    def classifyEmail(self, item: str) -> str:
        lower = item.lower()
        badTlds = (".ru", ".cn", ".tk", ".xyz", ".top", ".info")
        disposableHosts = ("mail.ru", "outlook.cn", "proton.me")
        if any(lower.endswith(t) for t in badTlds) or any(h in lower for h in disposableHosts):
            return "Suspicious"
        return "Not Flagged"

    def classifyIP(self, item: str) -> str:
        return "Malicious" if item.lower() in self.knownIps else "Not Flagged"

    # --- Dispatcher ---
    def classifyItem(self, category: str, item: str) -> str:
        item = item.strip()
        match category:
            case "urls": return self.classifyUrl(item)
            case "commands": return self.classifyCommand(item)
            case "registryKeys": return self.classifyRegistry(item)
            case "filePaths": return self.classifyPath(item)
            case "emails": return self.classifyEmail(item)
            case "ips": return self.classifyIP(item)
        return "Not Flagged"

    # --- Main analysis ---
    def analyseStrings(self) -> dict:
        """Analyse all strings using rule-based classification, filtering invalid URLs."""
        analysed = {}
        for category, items in self.data.items():
            analysed[category] = []
            for item in items:
                # Skip invalid URLs early
                if category == "urls" and not self.isValidUrl(item):
                    continue
                analysed[category].append({
                    "value": item,
                    "classification": self.classifyItem(category, item)
                })
        return analysed
