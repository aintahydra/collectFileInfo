#!/bin/python3

import sys
import os
import argparse
import threading
import magic #requires 'pip install python-magic', REF.(for different OSes): https://pypi.org/project/python-magic 
import hashlib
import requests
import json
import re
import configparser
import whois #requires 'pip install python-whois' # do not 'pip install whois'
from censys.search import CensysHosts #requires 'pip install censys; censys config', REF.: https://support.censys.io/hc/en-us/articles/360056141971-Search-2-0-Python-Library and https://censys-python.readthedocs.io/en/stable/index.html

class CollectFileInfo(threading.Thread):

    _ip_pattern = re.compile(r"[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}")

    _vt_api_key = ""
    _print_w_color = 0
    _print_whois_report = 0
    _print_censys_report = 0
    _print_vt_report = 0
    _print_file_contents = 0

    _ANSI_C_FY = '' # set to print foreground yellow
    _ANSI_C_FR = '' # set to print foreground red
    _ANSI_C_FK_BY = '' # set to print background yellow
    _ANSI_C_X = ''  # unset ANSI codes
    _ANSI_C_B = ''  # set to print bold
    _ANSI_C_U = ''  # set to print the underline
        
    # VT v3 API, Get a file report
    #   - format: https://www.virustotal.com/api/v3/files/{id}
    def VT_API_freport(self, file_path, file_hash):
        with open(file_path, "rb") as file:
            url = "https://www.virustotal.com/api/v3/files/" + file_hash #"https://www.virustotal.com/api/v3/files/id
            headers = {"accept": "application/json", "x-apikey": self._vt_api_key}
            resp = requests.get(url, headers=headers) 
            resp_json = resp.json()
            
            print("\t[VT report]")

            try:
                malicious_cnt = int(resp_json['data']['attributes']['last_analysis_stats']['malicious'])
                suspicious_cnt = int(resp_json['data']['attributes']['last_analysis_stats']['suspicious'])
                undetected_cnt = int(resp_json['data']['attributes']['last_analysis_stats']['undetected'])
                harmless_cnt = int(resp_json['data']['attributes']['last_analysis_stats']['harmless'])
                print("\t-LAST_ANALYSIS_STATS(malicious+suspicious / undetected+harmless): ", self._ANSI_C_FY, "(", (malicious_cnt + suspicious_cnt), "/", \
                    (malicious_cnt + suspicious_cnt + undetected_cnt + harmless_cnt), ")", self._ANSI_C_X)
            except KeyError as kerr:
                pass
            except ValueError as verr:
                pass

            try:
                print(self._ANSI_C_B, f"\t-Trusted Verdict: this file, named \"{resp_json['data']['attributes']['trusted_verdict']['filename']}\", has been verdicted as \"{resp_json['data']['attributes']['trusted_verdict']['verdict']}\" by {resp_json['data']['attributes']['trusted_verdict']['organization']}", self._ANSI_C_X)
            except KeyError as kerr:
                pass
            except ValueError as verr:
                pass

            try:
                print("\t-Exiftool", \
                    "\n\t  InternalName: ", resp_json['data']['attributes']['exiftool']['InternalName'], \
                    "\n\t  FileDescription: ", resp_json['data']['attributes']['exiftool']['FileDescription'], \
                    "\n\t  Characterset: ", resp_json['data']['attributes']['exiftool']['CharacterSet'], \
                    "\n\t  OriginalFileName: ", resp_json['data']['attributes']['exiftool']['OriginalFileName'], \
                    )
            except KeyError as kerr:
                pass
            except ValueError as verr:
                pass

    def init(self):
        config = configparser.ConfigParser()
        try:
            config.read('config.ini', encoding='utf-8')
            config.sections()
            self._vt_api_key = config['API_KEYS']['VIRUS_TOTAL']
                       
            self._print_w_color = int(config['OPTIONS']['PRINT_W_COLOR'])
            self._print_whois_report = int(config['OPTIONS']['WHOIS_REPORT'])
            self._print_censys_report = int(config['OPTIONS']['CENSYS_REPORT'])
            self._print_vt_report = int(config['OPTIONS']['VT_LOOKUP'])
            self._print_file_contents = int(config['OPTIONS']['PRINT_FILE_CONTENTS'])

            # ANSI Escape Codes: https://en.wikipedia.org/wiki/ANSI_escape_code
            # FG: Black(30), White(97), Red(31), Green(32), Yellow(33), ...
            # BG: Yellow(103), White(47)
            self._ANSI_C_FY = '\033[33m' if self._print_w_color == 1 else '' # foreground yellow
            self._ANSI_C_FR = '\033[31m' if self._print_w_color == 1 else '' # fg red
            self._ANSI_C_FK_BY = '\033[30m \033[103m' if self._print_w_color == 1 else '' # fg black, bg yellow
            self._ANSI_C_X = '\033[0m' if self._print_w_color == 1 else '' # exit ANSI codes
            self._ANSI_C_B = '\033[1m' if self._print_w_color == 1 else '' # bold
            self._ANSI_C_U = '\033[4m' if self._print_w_color == 1 else '' # underline
        except Error as err:
            print("Error: ", err)


    def start(self, dir_root):

        for root, dirs, files, in os.walk(dir_root):
            for file in files: 
                fpath = os.path.join(root, file)

                # print the file name 
                print("\nFile:", self._ANSI_C_B, self._ANSI_C_U, fpath, self._ANSI_C_X, self._ANSI_C_X)

                # print the magic
                mstr = magic.from_file(fpath)
                print("\t", mstr)

                # filter: PE32, PE32+, ELF and also shell scripts 
                if ("executable" in mstr):

                    # print MD5 hash 
                    with open(fpath, 'rb') as f:
                        file_md5 = hashlib.md5(f.read()).hexdigest()
                        print(self._ANSI_C_FY, "\t[AN EXECUTABLE]", self._ANSI_C_X, f"MD5: {file_md5}")

                        # query to virustotal.com
                        if self._print_vt_report == 1: 
                            self.VT_API_freport(fpath, file_md5)

                elif ("certificate" in mstr):
                    print(self._ANSI_C_FY, "\t[A Certificate]", self._ANSI_C_X)

                elif ("ASCII" in mstr):
                    #print("\t[An ASCII Text]")

                    if (self._print_file_contents > 0):
                        with open(fpath, 'rt') as f:
                            try: 
                                # print some bytes of the text
                                print(self._ANSI_C_FY, f"\t(Printing first {self._print_file_contents} bytes) >> \n\t", self._ANSI_C_X, f.read(self._print_file_contents)) 

                            except UnicodeDecodeError as uderr:
                                pass
                else:
                    pass

######################################################
# main
######################################################

if __name__ == "__main__":
    #Start
    parser = argparse.ArgumentParser()
    parser.add_argument('--directory', '-d', type=str, help="specify directory to scan")
    args = parser.parse_args()

    if len(sys.argv) == 1:
        parser.print_help()
    else:
        cfi = CollectFileInfo()
        if os.path.isdir(args.directory):
            cfi.init()
            cfi.start(args.directory)
        else:
            print(f"{args.directory} is not a directory")