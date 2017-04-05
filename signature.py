import os
import urllib2
from argparse import ArgumentParser

signatures = []

def add_sigs():
    with open('virussignatures') as fp:
    	for line in fp:
		signatures.append(line.split("=",1)[1])

def check_sig(file):
    dump = " "
    with open(file, 'rb') as f:
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

    print("Checking File for Known Signatures")
    print("This may take a moment...")

    add_sigs()
    results = check_sig(args.file_path)

    if(results):
    	print("\nSignature detected:\n")
	print(results)
    else:
        print("\nNo Signature Detected.\n")
