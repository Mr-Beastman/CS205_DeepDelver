import time
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