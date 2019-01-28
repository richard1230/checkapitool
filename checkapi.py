#!/usr/bin/python
# -*- coding: utf-8 -*-
import os, string, shutil, re,sys
import pefile  

# PEfile_Path = r"/tmp/python-3.exe"
PEfile_Path = sys.argv[1]
checkresult =sys.argv[2]
pe = pefile.PE(PEfile_Path)
print PEfile_Path

for importeddll in pe.DIRECTORY_ENTRY_IMPORT:
    def _read(_file):
         with open(_file, 'r') as f:
            txt = f.read().strip()
            strings = txt.split(',')
            strings = [s.strip().strip('"').strip() for s in strings]

         return strings


    origins = _read('./api.txt')

    for importedapi in importeddll.imports:	
        with open(checkresult, 'a') as f:
      
            if importedapi.name in origins:
                i=i+1
                print importedapi.name
                f.write((importedapi.name) + '   ')
	print "\n"
                






