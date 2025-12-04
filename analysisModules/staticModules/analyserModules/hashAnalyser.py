from utilitieModules.utilities import loadCsv

class HashAnalyser:
    """
    Analyse extracted file hashes against a known flagged hash list.
    Returns results fully in memory.
    """

    def __init__(self, hashResults: dict):
        """
        :param hashResults: Dict of extracted hashes, e.g.
            {
                'Md5': {'code': '...'},
                'Sha1': {'code': '...'},
                'sha256': {'code': '...'}
            }
        """
        self.hashResults = hashResults
        self.flaggedHashes = []
        self.hashCSV = "analysisModules/staticModules/config/flaggedHashList.csv"

    def loadFlaggedHashes(self):
        """Loads CSV containing known malicious hashes into memory."""
        self.flaggedHashes = loadCsv(self.hashCSV)

    def analyseHash(self) -> dict:
        """
        Analyse hashes and return a structured dict suitable for reports.
        :return: {
            "summary": {"total": int, "malicious": int, "clean": int},
            "hashes": [list of dicts per hash]
        }
        """
        if not self.flaggedHashes:
            self.loadFlaggedHashes()

        output = []
        summary = {
            "total": 0,
            "malicious": 0,
            "clean": 0
        }

        for hashType, hashData in self.hashResults.items():
            code = hashData.get("code")
            if not code:
                continue

            summary["total"] += 1
            isMalicious = code in self.flaggedHashes

            entry = {
                "hashType": hashType,
                "hashValue": code,
                "flagged": isMalicious,
            }

            if isMalicious:
                entry["severity"] = "high"
                entry["result"] = "Malicious"
                entry["indicator"] = "Hash matches known malicious entry."
                summary["malicious"] += 1
            else:
                entry["severity"] = "info"
                entry["result"] = "Not Flagged"
                entry["indicator"] = "Hash not present in blacklist."
                summary["clean"] += 1

            output.append(entry)

        return {
            "summary": summary,
            "hashes": output
        }
