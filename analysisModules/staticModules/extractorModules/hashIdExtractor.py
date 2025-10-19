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


# --------- rabit hole -------------- #

# features that are not fully implemented #

# testing hash checking via virustotal database - hardcoded api for dev.
    def queryHashDatabase(fileHash):
        #docString
        """
        Check supplied hash against virus total API
        Parameters: 
            fileHash (str) : The hash to be checked
        Returns:
            result of check
        """
        url = f"https://www.virustotal.com/api/v3/files/{fileHash}"
        headers = {
            "x-apikey": "baa45a1163c1f5ae437788e0a5d6716ef6791d07228a2ef24ffd34bef4999c14"
        }

        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            print(data)
        else:
            print({"error": "Failed to retrieve data", "status_code": response.status_code})
