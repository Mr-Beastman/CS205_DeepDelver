import os
import magic
import pefile
from datetime import datetime

# --------- Get standard File data -------------- #

class FileMetadata:

    def __init__(self, filePath:str):
        self.filePath = filePath

    def getFileName(self) -> str:
        #docString
        """
        Return the files name and extention

        Returns:
            str: file size with MB or GB suffixhelo
        """
        return os.path.basename(self.filePath)

    def getFileExtention(self) -> str:
        #docString
        """
        Return actual file extention
        Parameters:
            filePath (str): path to the file
        Returns:
            str: files extention type
        """

        return magic.from_file(self.filePath, mime=True)

    def getFileSize(self) -> str:
        #docString
        """
        Return the size of a file in MB if under 1 GB, else in GB.
        Parameters:
            filePath (str): path to the file
        Returns:
            str: file size with MB or GB suffixhelo
        """
        sizeBytes = os.path.getsize(self.filePath)
        sizeGB = sizeBytes / 1_000_000_000
        
        if sizeGB >= 1:
            return f"{round(sizeGB, 2)} GB"
        else:
            size_mb = sizeBytes / 1_000_000
            return f"{round(size_mb, 2)} MB"

    def getFileTimestamps(self) -> list:
        #docString
        """
        Return file timestamps from executable header

        Returns:
            list: list with "Created", "Modified" and "Accesssed"
        """
        pe = pefile.PE(self.filePath)
        stats = os.stat(self.filePath)

        compileTime = datetime.fromtimestamp(pe.FILE_HEADER.TimeDateStamp)
        createdTime = datetime.fromtimestamp(stats.st_birthtime)
        modifiedTime = datetime.fromtimestamp(stats.st_mtime)
        accessedTime = datetime.fromtimestamp(stats.st_atime)

        return [
            "Compiled:" + compileTime.strftime("%d-%m-%Y %H:%M:%S"),
            "Created: " + createdTime.strftime("%d-%m-%Y %H:%M:%S"),
            "Modified: " + modifiedTime.strftime("%d-%m-%Y %H:%M:%S"),
            "Accessed: " + accessedTime.strftime("%d-%m-%Y %H:%M:%S")
        ]

    def getFileArchitecture(self) -> str:
        #docString
        """
        Return CPU architecture the file was compiled for

        Returns:
            str: hexadecimal representing the machine type 
        """
        
        try:
            file = pefile.PE(self.filePath)

            return hex(file.FILE_HEADER.Machine)
        
        except Exception as error:
            return None, str(error)
        
    def getFileSections(self) -> dict:
        #docString
        """
        Extract file sections with metadata

        Returns:
            dict: file sections with related information
        """
        fileSections = {}

        try:
            file = pefile.PE(self.filePath)

            for section in file.sections:
                        name = section.Name.decode(errors='ignore').rstrip('\x00')

                        fileSections[name] = {
                            "VirtualAddress": section.VirtualAddress,
                            "VirtualSize": section.Misc_VirtualSize,
                            "SizeOfRawData": section.SizeOfRawData,
                            "PointerToRawData": section.PointerToRawData,
                            "Characteristics": section.Characteristics
                        }

            return fileSections

        except Exception as error:
            return None, str(error) 

    def getFileSectionsCount(self) -> int:
        #docString
        """
        Return the number of sections in the PE file

        Returns:
            int: Number of sections in the file.
        """

        try:
            file = pefile.PE(self.filePath)

            return file.FILE_HEADER.NumberOfSections
        
        except Exception as error:
            return None, str(error)   

    def getFileEntryPoint(self) -> str:
        #docString
        """
        Return the entry point address of the PE file

        Returns:
            str: hexadecimal string of the file's entry point address.      
        """
        
        try:
            file = pefile.PE(self.filePath)

            return hex(file.OPTIONAL_HEADER.AddressOfEntryPoint)
        
        except Exception as error:
            return None, str(error)

    def getAllMetaData(self) -> dict:
        #docString
        """
        Runs all current checks and return the basic metadata of the PE file.

        Returns:
            dict: dictionary containing file metadata
        """

        return {
            "fileName": self.getFileName(),
            "fileType": self.getFileExtention(),
            "fileSize": self.getFileSize(),
            "fileTimeStamps": self.getFileTimestamps(),
            "fileSectionCount": self.getFileSectionsCount(),
            "fileEntryPoint": self.getFileEntryPoint()
        }