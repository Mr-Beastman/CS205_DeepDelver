import time
from pathlib import Path
from functools import wraps

def functionTimer(function):
    """
    record the time a process takes, helps monitor preformance
    """
    @wraps(function)
    def wrapper(*args, **kwargs):
        start = time.perf_counter()
        result = function(*args, **kwargs)
        end = time.perf_counter()
        print(f"{function.__name__} took: {end - start:.2f} seconds")
        return result
    return wrapper


def isExe(filepath: str) -> bool:
    """
    Return True only if the file is a real .exe (PE file).
    """
    if not filepath.lower().endswith(".exe"):
        return False

    try:
        with open(filepath, "rb") as f:
            header = f.read(2)
            return header == b"MZ"
    except Exception:
        return False

def loadCsv(filePath: str) -> list:
    """
    Load a csv or plain text file and ignore # comments

    Parameters:
        filePath (str): file path to known urls
    
    Returns:
        urls in list form
    """
    
    fileContents = []

    path = Path(filePath)

    with path.open("r", encoding="utf-8") as f:
        for line in f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    fileContents.append(line)

    return fileContents