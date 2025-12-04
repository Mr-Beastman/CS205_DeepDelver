import re

class StringExtractor:
    """
    Extracts ASCII and UTF-16 strings from a Windows binary file and attempts to find URLs, IPs, file paths, registry keys, commands, emails and Base64 elements
    """

    def __init__(self, filePath: str):
        self.filePath = filePath
        self.binaryData = None
        self.asciiStrings = []
        self.utf16Strings = []
        self.allStrings = []

    # ---- Load File ----
    def loadFile(self):
        """
        Load the binary file into memory
        """
        if self.binaryData is None:
            with open(self.filePath, "rb") as file:
                self.binaryData = file.read()  

    # ---- String Extraction ----
    def extractAscii(self, minLength: int = 4):
        """
        Extract ASCII strings from the binary

        Parameter: 
            int : min length of strings to extract
        """
        asciiPattern = re.compile(rb"[ -~]{%d,}" % minLength)
        self.asciiStrings = [match.decode(errors="ignore") for match in asciiPattern.findall(self.binaryData)]

    def extractUtf16(self, minLength: int = 4):
        """
        Extract UTF-16 encoded strings from the binary

        Parameter: 
            int : min length of strings to extract
        """
        utf16Pattern = re.compile(rb"(?:[ -~]\x00){" + str(minLength).encode() + rb",}")
        matches = utf16Pattern.findall(self.binaryData)
        self.utf16Strings = [m.decode("utf-16le", errors="ignore") for m in matches]


    def extractUrls(self) -> list:
        """
        Extract URLs from all strings.

        Return: 
            list: unique URLs
        """
        urls = []
        urlPattern = re.compile(r"https?://[^\s\"'<>]+")
        for string in self.allStrings:
            for u in urlPattern.findall(string):
                if len(u) > 8 and not any(c in u for c in ' {}|^`\\'):
                    urls.append(u)
        return list(dict.fromkeys(urls))

    def extractIPs(self) -> list:
        """
        Extract IPv4 addresses from strings

        Return: 
            list :  unique IPs
        """
        ips = []
        ipPattern = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
        for string in self.allStrings:
            for ip in ipPattern.findall(string):
                if ip not in ["0.0.0.0", "127.0.0.1"]:
                    ips.append(ip)
        return list(dict.fromkeys(ips))

    def extractFilePaths(self) -> list:
        """
        Extract Windows file paths, focusing on executables, DLLs, scripts, and temp files.

        Return: 
            list : unique file paths
        """
        paths = []
        pathPattern = re.compile(
            r"[A-Za-z]:\\(?:[^\x00-\x1f\\:*?\"<>|]+\\)+(?:\w+\.(?:exe|dll|tmp|bat|vbs))?"
        )
        for string in self.allStrings:
            match = pathPattern.search(string)
            if match:
                candidate = match.group()
                if len(candidate) > 3 and not re.search(r"[:$<>\|]{2,}", candidate):
                    paths.append(candidate)
        return list(dict.fromkeys(paths))

    def extractRegistryKeys(self) -> list:
        """
        Extract Windows registry keys from strings

        Return: 
            list : unique registry keys
        """
        keys = []
        keyPattern = re.compile(r"H[KL]CU\\(?:Software\\|System\\|Wow6432Node\\)[A-Za-z0-9\\]+")
        for string in self.allStrings:
            match = keyPattern.search(string)
            if match:
                keys.append(match.group())
        return list(dict.fromkeys(keys))

    def extractCommands(self) -> list:
        """
        Extract execution commands such as cmd.exe, powershell, wscript, rundll32

        Return:
            lsit : unique commands
        """
        commands = []
        commandPattern = re.compile(r"(cmd\.exe|powershell|wscript|rundll32)\b", re.IGNORECASE)
        for string in self.allStrings:
            commands.extend(commandPattern.findall(string))
        return list(dict.fromkeys(commands))

    def extractEmails(self) -> list:
        """
        Extract email addresses from all strings.

        Return: 
            list : unique emails
        """
        emails = []
        emailPattern = re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+")
        for string in self.allStrings:
            emails.extend(emailPattern.findall(string))
        return list(dict.fromkeys(emails))

    def extractBase64(self) -> list:
        """
        Extract Base64 encoded strings

        REturn: 
            list : unique Base64
        """
        b64strings = []
        b64Pattern = re.compile(r"[A-Za-z0-9+/]{20,}={0,2}")
        for string in self.allStrings:
            b64strings.extend(b64Pattern.findall(string))
        return list(dict.fromkeys(b64strings))

    # ---- Full Extraction ----
    def extractAll(self, minAscii: int = 4, minUtf16: int = 4) -> dict:
        """
        Extract all string types and patterns from the binary.

        Parameter: 
            int : min length for ASCII strings.
            int : min length for UTF-16 strings.
        Return: 
            dict: urls, ips, filePaths, registryKeys, commands, emails, base64.
        """
        self.loadFile()
        self.extractAscii(minAscii)
        self.extractUtf16(minUtf16)
        self.allStrings = self.asciiStrings + self.utf16Strings

        return {
            "urls": self.extractUrls(),
            "ips": self.extractIPs(),
            "filePaths": self.extractFilePaths(),
            "registryKeys": self.extractRegistryKeys(),
            "commands": self.extractCommands(),
            "emails": self.extractEmails(),
            "base64": self.extractBase64()
        }
