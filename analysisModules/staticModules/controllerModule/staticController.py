
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
        self.stringExtractions = {}
        self.stringResults = {}
        self.entropyExtractions = {}
        

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

        self.stringExtractions = stringExt.extractAll()

        print("\n= Starting String Analyser =")
        stringAna = StringAnalyser(self.stringExtractions["urls"])
        stringAna.loadUrlsCsv()
        self.stringResults['urls'] = stringAna.analyseUrls()

        print("\n= Starting Import Extraction =")
        importObj = ImportExtractor(self.filePath)
        self.importResults = importObj.getImports()

        print("\n= Starting Entophy Extraction =")
        entropyObj = EntropyExtractor(self.filePath)
        self.entropyExtractions = entropyObj.getEntropy()

        print("\n=== Static Analysis Complete ===")

