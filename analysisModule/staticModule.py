import hashlib
import requests


def getHash(filePath, type):
    # docString
    """
    Calculate the hash of a file using the specified type.
    Parameters:
        filePath (str): Path to the file
        type (str): Hash type 'md5', 'sha1', 'sha256', etc
    Returns:
        str: The hexadecimal digest of the file hash.
    """

    #fucntion
    hashFunction = hashlib.new(type)

    with open(filePath, 'rb') as file:
        while chunk := file.read(8192):
            hashFunction.update(chunk)
    
    print 
    return hashFunction.hexdigest()

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
