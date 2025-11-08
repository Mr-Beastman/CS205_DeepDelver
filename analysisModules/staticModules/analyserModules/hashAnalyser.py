from utilitieModules.utilities import loadCsv

class HashAnalyser():

    def __init__(self, hash:dict):
        self.hash = hash
        self.flaggedHash = []
        self.analysisResults = {}
        self.hashCSV = "analysisModules/staticModules/config/flaggedHashList.csv"

    def loadHashCsv(self):
        #docString
        """
        Loads csv containing malcious hashIds for comparsion

        Parameters/Returns:
            None
        """
        self.flaggedHash = loadCsv(self.hashCSV)

    def isMalicious(self, hash) -> bool:
        #docString
        """
        Checks if provided hash str is in the flagged hash csv

        Parameters:
            str: hash Id to check
        Returns:
            bool : True in list, False not in list
        """
        for malwareHash in self.flaggedHash:
            if malwareHash == hash:
                return True
        
        return False
    
    def analyseHash(self) -> dict:
        #docString
        """
        logic used to drive hash analyser

        Parameters:
            dict: containing extracted hash ids
        Returns:
            dict : originall dict updated with updated flags (Malicious/Not Flagged)
        """
        for _, value in self.hash.items():
            if self.isMalicious(value['code']):
                value['flag'] = "Malicious"
            else:
                value['flag'] = "Not Flagged"

        return self.hash