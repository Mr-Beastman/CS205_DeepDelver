import os
import magic
from datetime import datetime

# --------- Get standard File data --------------

def getFileName(filePath: str) -> str:
    #docString
    """
    Return the files name and extention
    Parameters:
        filePath (str): path to the file
    Returns:
        str: file size with MB or GB suffixhelo
    """
    return os.path.basename(filePath)

def getFileExtention(filePath: str) -> str:
    #docString
    """
    Return actual file extention
    Parameters:
        filePath (str): path to the file
    Returns:
        str: files extention type
    """

    return magic.from_file(filePath, mime=True)

def getFileSize(filePath: str) -> str:
    #docString
    """
    Return the size of a file in MB if under 1 GB, else in GB.
    Parameters:
        filePath (str): path to the file
    Returns:
        str: file size with MB or GB suffixhelo
    """
    sizeBytes = os.path.getsize(filePath)
    sizeGB = sizeBytes / 1_000_000_000
    
    if sizeGB >= 1:
        return f"{round(sizeGB, 2)} GB"
    else:
        size_mb = sizeBytes / 1_000_000
        return f"{round(size_mb, 2)} MB"

def getFileTimestamps(filePath: str) -> list:
    #docString
    """
    Return file timestamps from executable header

    Parameters:
        filePath (str): Path to the file.

    Returns:
        list: list with "Created", "Modified" and "Accesssed"
    """
    st = os.stat(filePath)

    ctime = datetime.fromtimestamp(st.st_ctime)
    mtime = datetime.fromtimestamp(st.st_mtime)
    atime = datetime.fromtimestamp(st.st_atime)

    return [
        "Created: " + ctime.strftime("%d-%m-%Y %H:%M:%S"),
        "Modified: " + mtime.strftime("%d-%m-%Y %H:%M:%S"),
        "Accessed: " + atime.strftime("%d-%m-%Y %H:%M:%S")
    ]