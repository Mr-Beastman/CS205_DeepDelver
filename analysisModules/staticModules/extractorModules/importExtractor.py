import pefile


def ImportExtractor(filePath:str) -> dict:
    #docString
    """
    Extracts imported DLLs and their functions from pe file

    Paramaters:
        filePath (str): Path to the exe file

    Returns:
        dict: DLL and list of its imported functions, or error.   
    """
    print("> Extracting APIs")
    
    imports = {}

    try:
        pe = pefile.PE(filePath)

        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dllName = entry.dll.decode(errors="ignore")
                funcNames = []
                for imp in entry.imports:
                    if imp.name:
                        funcNames.append(imp.name.decode(errors="ignore"))
                    else:
                        funcNames.append(f"Ordinal_{imp.ordinal}")
                imports[dllName] = funcNames
        else:
            imports["None"] = ["No imports found"]

    except Exception as error:
        imports["Error"] = [str(error)]

    return imports