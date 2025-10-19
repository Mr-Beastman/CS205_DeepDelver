import math
from collections import Counter

class Entropy:

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

        shannomEntropy = 0.0

        for count in self.counts.values():
            x = count / len(self.data)
            shannomEntropy -= x * math.log(x,2)

        return shannomEntropy
    
    def getPartEntrophy(self) -> dict:
        #docString
        """
        ph
        """

        partEntropy = {}
        dataLength = len(self.data)

        for byte, count in self.counts.items():
            part = count / dataLength
            partEntropy[byte] = -part *math.log(part, 2)

        return partEntropy
