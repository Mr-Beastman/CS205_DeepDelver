import os
import magic
import pefile

class StringExtractor:

    def __init__(self, filePath:str):
        self.filePath = filePath