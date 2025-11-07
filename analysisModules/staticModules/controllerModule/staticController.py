
#importing extractor modules
from analysisModules.staticModules.extractorModules.metadataExtractor import MetadataExtractor
from analysisModules.staticModules.extractorModules.hashIdExtractor import HashIdExtractor
from analysisModules.staticModules.extractorModules.stringExtractor import StringExtractor
from analysisModules.staticModules.extractorModules.importExtractor import ImportExtractor
from analysisModules.staticModules.extractorModules.entrophyExtractor import EntropyExtractor

#importing analyser modules
from analysisModules.staticModules.analyserModules.stringAnalyser import StringAnalyser

class StaticController:

    def __init__(self, filePath:str):
        self.filePath = filePath
        self.metadataResults = {}
        self.hashResults = {}
        self.stringUrlResults = []
        self.stringIPResults = []
        self.stringFilePaths = []
        self.importResults = []
        self.shannonEntropyResults = float()
        self.partEntropyResults = []
        

    def runStaticAnalysis(self)->None:

        print("\n=== Preforming Full Static Anslysis ===")

        print("\n= Starting Metadata Extraction =")
        metadataObj = MetadataExtractor(self.filePath)
        self.metadataResults = metadataObj.getAllMetaData()

        print("\n= Starting Hash Extraction =")
        hashObj = HashIdExtractor(self.filePath)
        self.hashResults = hashObj.getHashId()

        print("\n= Starting String Extraction =")
        stringExt = StringExtractor(self.filePath)
        stringExt.loadFile()
        stringExt.extractStrings()
        stringUrls = stringExt.extractUrls()
        self.stringIPResults = stringExt.extractIPs()
        self.stringFilePaths = stringExt.extractFilePaths()

        print("\n= Starting String Analyser =")
        stringAna = StringAnalyser(stringUrls)
        stringAna.loadUrlsCsv()
        self.stringUrlResults = stringAna.analyseUrls()

        print("\n= Starting Import Extraction =")
        importObj = ImportExtractor(self.filePath)
        self.importResults = importObj.getImports()

        print("\n= Starting Entophy Extraction =")
        entropyObj = EntropyExtractor(self.filePath)
        self.shannonEntropyResults = entropyObj.getShannonEntrophy()
        self.partEntropyResults = entropyObj.getPartEntrophy()

        print("\n=== Static Analysis Complete ===")

