import os
import magic
import pefile
from datetime import datetime

class MetadataExtractor:

    architectureMap = {
        0x014c: "x86",
        0x8664: "x64",
        0x01c0: "ARM",
        0x01c4: "ARMv7",
        0xaa64: "ARM64",
    }

    def __init__(self, filePath: str):
        self.filePath = filePath
        self.pe = None 

    def getPE(self):
        if self.pe is None:
            try:
                self.pe = pefile.PE(self.filePath)
            except Exception as e:
                self.pe = None
        return self.pe

    def getFileName(self) -> str:
        """
        Return the file's name with extension.

        Returns:
            str: file name
        """
        print("> Getting File Name")
        return os.path.basename(self.filePath)

    def getFileExtension(self) -> str:
        """
        Return the MIME type

        Returns:
            str: MIME type
        """
        print("> Getting File Extension")
        try:
            return magic.from_file(self.filePath, mime=True)
        except Exception:
            return None

    def getFileSize(self) -> str:
        """
        Return the size of the file in MB if under 1 GB, else in GB.]

        Returns:
            str: file size with suffix
        """
        print("> Getting File Size")
        try:
            sizeBytes = os.path.getsize(self.filePath)
            sizeGB = sizeBytes / 1000000000
            if sizeGB >= 1:
                return f"{round(sizeGB, 2)} GB"
            else:
                sizeMB = sizeBytes / 1000000
                return f"{round(sizeMB, 2)} MB"
        except Exception:
            return None

    def getFileTimestamps(self) -> list[str]:
        """
        Return file timestamps from PE header and filesystem.

        Returns:
            list[str]: ["compiled:...", "created:...", "modified:...", "accessed:..."]
        """
        print("> Getting File Time Stamps")
        
        try:
            stats = os.stat(self.filePath)

            compileTime = datetime.fromtimestamp(self.pe.FILE_HEADER.TimeDateStamp) if self.pe else None
            createdTime = datetime.fromtimestamp(getattr(stats, 'st_birthtime', stats.st_ctime))
            modifiedTime = datetime.fromtimestamp(stats.st_mtime)
            accessedTime = datetime.fromtimestamp(stats.st_atime)

            return [
                f"compiled: {compileTime.strftime('%d-%m-%Y %H:%M:%S')}" if compileTime else "Compiled: N/A",
                f"created: {createdTime.strftime('%d-%m-%Y %H:%M:%S')}",
                f"modified: {modifiedTime.strftime('%d-%m-%Y %H:%M:%S')}",
                f"accessed: {accessedTime.strftime('%d-%m-%Y %H:%M:%S')}"
            ]
        except Exception:
            return []

    def getFileArchitecture(self) -> str:
        """
        Return CPU architecture the file was compiled for.

        Returns:
            str:  architecture for example "x86", "x64"
        """
        print("> Getting File Architecture")
        try:
            if self.pe:
                machine = self.pe.FILE_HEADER.Machine
                return self.architectureMap.get(machine, f"Unknown ({hex(machine)})")
            return None
        except Exception:
            return None

    def getFileSections(self) -> dict:
        """
        Extract file sections with metadata.

        Returns:
            dict: section names
        """
        print("> Getting File Sections")
        sections = {}
        try:
            if not self.pe:
                return sections

            for section in self.pe.sections:
                name = section.Name.decode(errors='ignore').rstrip('\x00')
                sections[name] = {
                    "virtualAddress": section.VirtualAddress,
                    "virtualSize": section.Misc_VirtualSize,
                    "sizeOfRawData": section.SizeOfRawData,
                    "pointerToRawData": section.PointerToRawData,
                    "characteristics": section.Characteristics
                }
            return sections
        except Exception:
            return {}

    def getFileSectionsCount(self) -> int:
        """
        Cont the number of sections in the file.

        Returns:
            int: number of sections
        """
        print("> Getting File Section Count")
        try:
            if self.pe:
                return self.pe.FILE_HEADER.NumberOfSections
            return 0
        except Exception:
            return 0

    def getFileEntryPoint(self) -> str:
        """
        Return the entry point of the files

        Returns:
            str: entry point address
        """
        print("> Getting File Entry Point")
        try:
            if self.pe:
                return hex(self.pe.OPTIONAL_HEADER.AddressOfEntryPoint)
            return None
        except Exception:
            return None

    def getAllMetaData(self) -> dict:
        """
        Extract all metadata from the file.

        Returns:
            dict: metadata including name, type, size, architecture, timestamps, sections, entry point
        """
        print("> Extracting all Metadata")

        self.pe = self.getPE() 

        return {
            "fileName": self.getFileName(),
            "fileType": self.getFileExtension(),
            "fileSize": self.getFileSize(),
            "fileArchitecture": self.getFileArchitecture(),
            "fileTimeStamps": self.getFileTimestamps(),
            "fileSections": self.getFileSections(),
            "fileSectionCount": self.getFileSectionsCount(),
            "fileEntryPoint": self.getFileEntryPoint()
        }