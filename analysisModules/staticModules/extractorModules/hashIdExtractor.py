import hashlib

class HashIdExtractor:

    def __init__(self, filePath:str):
        self.filePath = filePath
        self.hashType = ["Md5","Sha1","sha256"]
        
    def getHashId(self, hashType:list = None) -> dict:
        """
        Calculate the hash of a file using the specified types.

        Parameters:
            type (list): Hash type 'md5', 'sha1', 'sha256', etc. Will use predefined list if none supplied.
        Returns:
            dict: The hexadecimal digest of the file hash.
        """
        
        hashId = {}

        print("> Checking Hash Overrides")
        if hashType is None:
            hashType = self.hashType


        print("> Attempting to Extract Hash Ids")
        for hash in hashType:
            try:
                hasher = hashlib.new(hash)
                with open(self.filePath, "rb") as file:
                    while chunk := file.read(8192):
                        hasher.update(chunk)
                hashId[hash] = {
                    "code":hasher.hexdigest()
                }
            except ValueError:
                hashId[hash] = "Unsupported hash type"

        print("> Hash Ids Extracted")

        return hashId
