import hashlib
import requests

# --------- Get file hash data -------------- #

class HashId:

    def __init__(self, filePath:str):
        self.filePath = filePath
        self.hashType = ["Md5","Sha1","sha256"]
        
    def getHashId(self, hashType:list = None) -> dict:
        # docString
        """
        Calculate the hash of a file using the specified types.

        Parameters:
            type (list): Hash type 'md5', 'sha1', 'sha256', etc. Will use predefined list if none supplied.
        Returns:
            dict: The hexadecimal digest of the file hash.
        """
        hashId = {}

        if hashType is None:
            hashType = self.hashType

        for hash in hashType:
            try:
                hasher = hashlib.new(hash)
                with open(self.filePath, "rb") as file:
                    while chunk := file.read(8192):
                        hasher.update(chunk)
                hashId[hash] = hasher.hexdigest()
            except ValueError:
                hashId[hash] = "Unsupported hash type"

        return hashId
