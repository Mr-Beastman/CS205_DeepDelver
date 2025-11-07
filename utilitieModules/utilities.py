import time
from pathlib import Path
from functools import wraps

def functionTimer(function):
    """
    record the time a process takes, help monitor preformance
    
    """
    @wraps(function)
    def wrapper(*args, **kwargs):
        start = time.perf_counter()
        result = function(*args, **kwargs)
        end = time.perf_counter()
        print(f"{function.__name__} took: {end - start:.2f} seconds")
        return result
    return wrapper




def loadCsv(filePath: str) -> list:
    """
    Load a csv or plain text file.

    Parameters:
        filePath (str): file path to known urls
    
    Returns:
        urls in list form
    """
    
    urls = []

    path = Path(filePath)
    if not path.exists():
        print(f"[!] File not found: {filePath}")
        return urls

    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                urls.append(line)

    return urls