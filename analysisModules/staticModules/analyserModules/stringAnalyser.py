class StringAnalyser():

    def __init__(self, urls:list):
        self.urls = urls
        self.knownMalware = []
        self.analysisResults = {}
        self.malwareCSV = "analysisModules/staticModules/config/urlConfig/unarmedUrls.csv"

# ---- Url related ----

    def armUrl(self,unarmed: str) -> str:
        #docString
        """
        Convers an unarmed url hxxp://example.com to an armed one http://example.com

        Parameters:
            str: unarmed url with prefix hxxp or hxxps

        Returns:
            str : armed url with prefix http or https

        WARNING : Do not store or click armed links
        """
        
        return unarmed.strip().replace("hxxps://", "https://").replace("hxxp://", "http://")

    def loadUrlsCsv(self) -> None:
        #docString
        """
        load know malware related URLS from specified file to class obj.

        Parameters/Returns : None 
        """
        with open(self.malwareCSV, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    self.knownMalware.append(self.armUrl(line))

    def isMalicious(self, url) -> bool:
        #docString
        """
        brute force check if url submited exists within known malware list

        Parameter: 
            str: Url to be compared
        Return:
            Bool: True url is on comparison list, False it is not
        """
        
        for malware in self.knownMalware:
            if malware in url:
                return True
        
        return False


    def analyseUrls(self) -> dict:
        """
        Comapre a list of urls to classify them as 'safe', 'unknown', or 'malicious'.

        Parameters:
            urls (list): list of URLs to analyse

        Returns:
            dict {url: classification}: classification being 'safe', 'unknown', or 'malicious'
        """

        for url in self.urls:
            
            if self.isMalicious(url):
                classification = "Malicious"
            else:
                classification = "unknown"

            self.analysisResults[url] = classification

        return self.analysisResults