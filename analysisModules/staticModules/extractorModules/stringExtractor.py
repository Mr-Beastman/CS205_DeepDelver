import re

from utilities.utilities import functionTimer

class StringExtractor:

    def __init__(self, filePath:str):
        self.filePath = filePath
        self.binaryData = None

    def loadFile(self):
        #docString
        """
        Ensure file is loaded in binary mode
        """

        if self.binaryData is None:
            with open(self.filePath, "rb") as file:
                self.binaryData = file.read()
        return self.binaryData    
    
    def extractStrings(self, minLength: int = 4) -> list:
        #docString
        """
        extract printable ASCII strings from the binary file

        Parameters:
            minLength (int): minimum length of strings to extract

        Returns:
            list: list of ASCII strings found in the file
        """
        data = self.loadFile()

        matches = re.findall(rb"[ -~]{%d,}" % minLength, data)

        asciiStrings = []

        for match in matches:
            decodedString = match.decode(errors="ignore")
            asciiStrings.append(decodedString)

        return asciiStrings

    @functionTimer
    def extractUrls(self) -> list:
        #docString
        """
        extract urls from the files ASCII strings

        Returns:
            list: of strings that match url patterns
        """
        urls = []

        asciiStrings = self.extractStrings()

        for string in asciiStrings:
            if re.match(r"https?://", string):
                urls.append(string)

        
        return urls