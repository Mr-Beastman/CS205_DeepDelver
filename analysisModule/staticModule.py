import hashlib


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

    hashFunction = hashlib.new(type)

    with open(filePath, 'rb') as file:
        while chunk := file.read(8192):
            hashFunction.update(chunk)
    
    return hashFunction.hexdigest()