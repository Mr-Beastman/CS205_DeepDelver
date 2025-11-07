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
        extract ASCII and Utf16 strings from the binary file and store in class

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

        print("> Checking Strings for Urls")

        urlPattern = re.compile(r"https?://[^\s\"'<>]+")

        for string in self.asciiStrings:
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

        for string in self.asciiStrings:
            if ipPattern.search(string):
                ips.append(string)

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

        for string in self.asciiStrings:
            if pathPattern.search(string):
                paths.append(string)

        
        return paths