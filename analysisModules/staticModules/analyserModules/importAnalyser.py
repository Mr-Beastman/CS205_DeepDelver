import re
from analysisModules.staticModules.config.importConfig.importApis import apiCategories, notableApis

class ImportAnalyser:
    """Analyse PE imports for notable/suspicious APIs and categorize them."""

    def __init__(self, imports: dict):
        self.imports = imports or {}
        self.categorized = {}
        self.suspicious = {}
        self.apiCategories = apiCategories
        self.notableApis = notableApis

    def normalize(self, name: str) -> str:
        if not name:
            return ""
        name = re.sub(r"@[\d]+$", "", name.strip())
        if len(name) > 1 and name[-1] in ("A", "W") and name[-2].isalpha():
            name = name[:-1]
        return re.sub(r"[^A-Za-z0-9_]", "", name).upper()

    def categorizeImports(self) -> dict:
        self.categorized = {cat: [] for cat in self.apiCategories.keys()}
        self.categorized["uncategorized"] = []

        for dll, funcs in self.imports.items():
            for func in funcs:
                norm = self.normalize(func)
                matched = False

                for cat, apiSet in {k: {self.normalize(a) for a in v} for k, v in self.apiCategories.items()}.items():
                    if norm in apiSet:
                        self.categorized[cat].append((dll, func))
                        matched = True
                        break
                if not matched:
                    self.categorized["uncategorized"].append((dll, func))

        return self.categorized

    def getNotableApis(self) -> dict:
        self.suspicious = {}
        normalizedNotables = {self.normalize(n) for n in self.notableApis}
        for dll, funcs in self.imports.items():
            flagged = []
            for func in funcs:
                if self.normalize(func) in normalizedNotables:
                    flagged.append(func)
            if flagged:
                self.suspicious[dll] = flagged
        return self.suspicious

    def analyseImports(self) -> dict[str, dict[str, dict[str, str]]]:
        """
        Run analyses and return results
        
        Returns:
            results (dict): set up by DLL and function:
        """
        self.categorizeImports()
        self.getNotableApis()

        results: dict[str, dict[str, dict[str, str]]] = {}

        for cat, funcs in self.categorized.items():
            for dll, func in funcs:
                severity = "high" if dll in self.suspicious and func in self.suspicious[dll] else "info"
                resultDesc = "Notable API" if severity == "high" else "Normal API"

                if dll not in results:
                    results[dll] = {}

                results[dll][func] = {
                    "category": cat,
                    "dll": dll,
                    "function": func,
                    "severity": severity,
                    "result": resultDesc
                }

        return results
