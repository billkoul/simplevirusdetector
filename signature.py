import os
import urllib2
import cPickle as Pickle
from subprocess import Popen, PIPE
from argparse import ArgumentParser
from bs4 import BeautifulSoup
import codecs

signatures = []

def compile_sigs():
    with open('virussignatures') as fp:
    	for line in fp:
		signatures.append(line.split("=",1)[1])

def check_sig(fn):
    dump = " "
    with open(fn, 'rb') as f:
    	for chunk in iter(lambda: f.read(32), b''):
        	dump = codecs.encode(chunk, 'hex')

    res = ""


    for sig in signatures:
	if dump in sig:
		res = sig
    return res


if __name__ == "__main__":
    parser = ArgumentParser()
    parser.add_argument("file_path", help="Detect signatures in file")

    args = parser.parse_args()

    print("[*] Checking File for Known Signatures")
    print("[*] This may take a moment...")

    compile_sigs()
    results = check_sig(args.file_path)

    if(results):
    	print("\n[*] File Signature(s) detected:\n")
	print(results)
    else:
        print("\n[!] No File Signature Detected.\n")
