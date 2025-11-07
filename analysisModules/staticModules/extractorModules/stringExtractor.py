import re
import os

class StringExtractor:

    def __init__(self, filePath:str):
        self.filePath = filePath
        self.binaryData = None
        self.asciiStrings = []
        self.utf16Strings = []
        self.allStrings = []

# ---- Loading File ----

    def loadFile(self):
        #docString
        """
        Ensure file is loaded in binary mode
        """

        if self.binaryData is None:
            with open(self.filePath, "rb") as file:
                self.binaryData = file.read()  

# ---- String Extraction ----

    def extractAscii(self, minLength: int = 4):


        print("> Extracting ASCII strings")
    
        asciiPattern = re.compile(rb"[ -~]{%d,}" % minLength)

        patternMatches = asciiPattern.findall(self.binaryData)

        for match in patternMatches:
            decodedString = match.decode(errors="ignore")
            self.asciiStrings.append(decodedString)

    def extractUtf16(self, minLength: int = 4):

        print("> Extracting utf16 strings")
        
        utf16Pattern = re.compile((rb"(?:[ -~]\x00){" + str(minLength).encode() + rb",}"))
        patternMatches = utf16Pattern.findall(self.binaryData)
        
        for mactch in patternMatches:
            try:
                decodedString = mactch.decode("utf-16le", errors="ignore")
                self.utf16Strings.append(decodedString)
            except Exception:
                continue


    def extractStrings(self):
        #docString
        """
        extract ASCII and Utf16 strings from the binary file and store in single list

        Parameters/Returns :
            None
        """
        self.extractAscii()
        self.extractAscii()

        self.allStrings = self.asciiStrings + self.utf16Strings



            
# ---- Pattern extactors ----

    def extractUrls(self) -> list:
        #docString
        """
        extract urls from the files ASCII strings

        Returns:
            list: of strings that match url patterns
        """

        urls = []
        urlPattern = re.compile(r"https?://[^\s\"'<>]+")

        print("> Checking Strings for Urls")

        for string in self.allStrings:
            found = urlPattern.findall(string)
            urls.extend(found)
        
        return urls
    
    def extractIPs(self) -> list:
        """
        extract ips from the files ASCII strings

        Returns:
            list: of strings that match ip patterns
        """

        ips = []
        ipPattern = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

        print("> Checking Strings for IPs")

        for string in self.allStrings:
            found = ipPattern.findall(string)
            for ip in found:
                ips.append(ip)

        return ips

    def extractFilePaths(self) -> list:
        """
        extract file paths from the files ASCII strings

        Returns:
            list: of strings that match file path patterns
        """

        paths = []
        pathPattern = re.compile(r"[A-Za-z]:\\(?:[^\x00-\x1f\\:*?\"<>|]+\\)*[^\x00-\x1f\\:*?\"<>|]*")

        print("> Checking Strings for File Paths")

        for string in self.allStrings:
            if pathPattern.search(string):
                paths.append(string)

        
        return paths
    
    def extractRegistryKeys(self) -> list:
        #docString
        """
        """

        keys = []
        keyPattern = re.compile(r"H[KL]CU\\[A-Za-z0-9\\]+")

        print("> Checking Strings for Registry Keys")
        
        for string in self.allStrings:
            if keyPattern.search(string):
                keys.append(string)

        return keys
    

    def extractCommands(self) -> list:
        #docString
        """
        """

        commands = []
        commandPattern = re.compile(r"(cmd\.exe|powershell|wscript|rundll32)\b", re.IGNORECASE)

        print("> Checking Strings for Commands")
        
        for string in self.allStrings:
            found = commandPattern.findall(string)
            for command in found:
                commands.append(command)

        return commands

    def extractEmails(self) -> list:
        #docString
        """
        Extract email addresses
        """
        
        emails = []
        emailPattern = re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+")

        print("> Checking Strings for Email Addresses")
        
        for string in self.allStrings:
            found = emailPattern.findall(string)
            for email in found:
                emails.append(email)

        return emails
    
    def extractBase64(self) -> list:
        #docString
        """
        Extract long base64-like strings
        """
        b64strings = []
        b64Pattern = re.compile(r"[A-Za-z0-9+/]{20,}={0,2}")

        print("> Checking Strings for Base64")

        for string in self.allStrings:
            found = b64Pattern.findall(string)
            for b64 in found:
                b64strings.append(b64)

        return b64strings

# ---- controller ----

    def extractAll(self) -> dict:
        #docString
        """
        Run all string based extractions and return via disctionary

        Parameters: 
            None
        Returns:
            dict : containing type and results.
        """

        self.loadFile()

        self.extractStrings()


        return {
            "urls": self.extractUrls(),
            "ips": self.extractIPs(),
            "file_paths": self.extractFilePaths(),
            "registry_keys": self.extractRegistryKeys(),
            "commands": self.extractCommands(),
            "emails": self.extractEmails(),
            "base64": self.extractBase64()
        }