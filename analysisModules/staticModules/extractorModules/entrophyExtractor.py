import math
from collections import Counter

class EntropyExtractor:
    """
    Extracts entropy information from a binary file for static malware analysis.
    """

    def __init__(self, filePath: str):
        self.filePath = filePath
        with open(self.filePath, 'rb') as file:
            self.data = file.read()
        self.counts = Counter(self.data)

    def getShannonEntropy(self) -> float:
        """
        Calculate the Shannon entropy

        Returns:
            float: Shannon entropy value
        """
        print("> Getting Shannon Entropy")
        shannon_entropy = 0.0
        dataLength = len(self.data)

        for count in self.counts.values():
            probability = count / dataLength
            shannon_entropy -= probability * math.log(probability, 2)

        return shannon_entropy

    def getpartEntropy(self) -> dict:
        """
        Calculate the entropy contribution of each byte.

        Returns:
            dict : byte to its entropy contribution.
        """
        print("> Getting part Entropy")
        partEntropy = {}
        dataLength = len(self.data)

        for byte, count in self.counts.items():
            probability = count / dataLength
            partEntropy[byte] = -probability * math.log(probability, 2)

        return partEntropy

    def getEntropy(self) -> dict:
        """
        Return both Shannon entropy and part entropy.

        Returns:
            dict: type and results.
        """
        return {
            'shannon': self.getShannonEntropy(),
            'part': self.getpartEntropy()
        }
