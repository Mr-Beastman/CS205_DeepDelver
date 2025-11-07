import math
from collections import Counter

class EntropyExtractor:

    def __init__(self, filePath:str):
        self.filePath = filePath

        with open(self.filePath, 'rb') as file:
            self.data = file.read()

        self.counts = Counter(self.data)

    def getShannonEntrophy(self) -> float:
        #docString
        """
        ph
        """
        print("> Getting Shannon Entrophy")

        shannonEntropy = 0.0

        for count in self.counts.values():
            x = count / len(self.data)
            shannonEntropy -= x * math.log(x,2)

        return shannonEntropy
    
    def getPartEntrophy(self) -> dict:
        #docString
        """
        ph
        """
        
        print("> Getting Part Entrophy")

        partEntropy = {}
        dataLength = len(self.data)

        for byte, count in self.counts.items():
            part = count / dataLength
            partEntropy[byte] = -part *math.log(part, 2)

        return partEntropy
    
    def getEntropy(self) -> dict:

        return {
            'shannon':self.getShannonEntrophy(),
            'part':self.getPartEntrophy()
        }
