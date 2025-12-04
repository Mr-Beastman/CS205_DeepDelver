# Importing extractor modules
from analysisModules.staticModules.extractorModules.metadataExtractor import MetadataExtractor
from analysisModules.staticModules.extractorModules.hashIdExtractor import HashIdExtractor
from analysisModules.staticModules.extractorModules.stringExtractor import StringExtractor
from analysisModules.staticModules.extractorModules.importExtractor import ImportExtractor
from analysisModules.staticModules.extractorModules.entrophyExtractor import EntropyExtractor

# Importing analyser modules
from analysisModules.staticModules.analyserModules.metadataAnalyser import MetadataAnalyser
from analysisModules.staticModules.analyserModules.stringAnalyser import StringAnalyser
from analysisModules.staticModules.analyserModules.hashAnalyser import HashAnalyser
from analysisModules.staticModules.analyserModules.entropyAnalyser import EntropyAnalyser
from analysisModules.staticModules.analyserModules.importAnalyser import ImportAnalyser
from analysisModules.staticModules.analyserModules.sectionAnalyser import SectionAnalyser


class StaticController:

    def __init__(self, filePath: str):
        self.filePath = filePath
        self.rawMetadata = {}
        self.metadataResults = {}
        self.hashResults = {}
        self.stringResults = {}
        self.importResults = {}
        self.entropyResults = {}
        self.sectionResults = {}

    def runStaticAnalysis(self) -> None:

        print("\n=== Performing Full Static Analysis ===")

        # -------------------- Metadata --------------------
        print("\n= Extracting Metadata =")
        metadataObj = MetadataExtractor(self.filePath)
        self.rawMetadata = metadataObj.getAllMetaData()

        print("\n= Analysing Metadata =")
        metadataAnalyser = MetadataAnalyser(self.rawMetadata)
        self.metadataResults = metadataAnalyser.analyseMetadata()

        # -------------------- Section Analysis --------------------
        print("\n= Analysing Sections =")
        sectionAna = SectionAnalyser(self.rawMetadata.get("fileSections", {}))
        self.sectionResults = sectionAna.analyseSections()

        # -------------------- Hashes --------------------
        print("\n= Extracting Hash IDs =")
        hashObj = HashIdExtractor(self.filePath)
        hashExtractions = hashObj.getHashId()

        print("\n= Analysing Hash Ids =")
        hashAnalyser = HashAnalyser(hashExtractions)
        self.hashResults = hashAnalyser.analyseHash()

        # -------------------- Strings --------------------
        print("\n= Extracting Strings =")
        stringExt = StringExtractor(self.filePath)
        stringExtractions = stringExt.extractAll()

        print("\n= Analysing Strings =")
        stringAna = StringAnalyser(stringExtractions)
        self.stringResults = stringAna.analyseStrings()

        # -------------------- Imports --------------------
        print("\n= Extracting Imports =")
        importExtract = ImportExtractor(self.filePath)

        print("\n= Analysing Imports =")
        importAnalyser = ImportAnalyser(importExtract)
        self.importResults = importAnalyser.analyseImports()

        # -------------------- Entropy --------------------
        print("\n= Extracting Entropy =")
        entropyObj = EntropyExtractor(self.filePath)
        entropyExtractions = entropyObj.getEntropy()

        print("\n= Analysing Entropy =")
        entropyAnalyser = EntropyAnalyser(entropyExtractions)
        self.entropyResults = entropyAnalyser.analyseEntropy()

        print("\n=== Static Analysis Complete ===")


    def extractFileInfo(self) -> dict:
        """
            extract simple file infor for use in report generation summary
        """
        if not self.rawMetadata:
            return {}
        return {
            "fileName": self.rawMetadata.get("fileName", "Unknown"),
            "fileType": self.rawMetadata.get("fileType", "Unknown"),
            "fileSize": self.rawMetadata.get("fileSize", "Unknown"),
            "fileArchitecture": self.rawMetadata.get("fileArchitecture", "Unknown"),
            "fileTimeStamps": self.rawMetadata.get("fileTimeStamps", []),
            "fileSectionCount": self.rawMetadata.get("fileSectionCount", 0),
            "fileEntryPoint": self.rawMetadata.get("fileEntryPoint", "Unknown")
        }

    def combineResults(self) -> dict:
        """Combine all static analysis results into a single dict."""
        return {
            "fileInfo": self.extractFileInfo(),
            "metadata": self.metadataResults,
            "sections": self.sectionResults,
            "hashes": self.hashResults,
            "strings": self.stringResults,
            "imports": self.importResults,
            "entropy": self.entropyResults,
        }
