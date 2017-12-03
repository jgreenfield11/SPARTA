#!/usr/bin/python

import sys
import io
import time
import hashlib

#checking input parameters
if len(sys.argv) < 2:
    print ("Sparta <source> <destination>")
else:
    print ("Sparta {} {}".format(sys.argv[1],sys.argv[2]))

with open(sys.argv[2], "wb") as dest:
    #attempting to open the source disk for stream reading
    print ("Destination file {} open for writing".format(sys.argv[2]))
    md5hash = hashlib.md5()
    #starting timer
    start = time.time()
    with open(sys.argv[1], "rb") as source:
        #trying to read 512 byte blocks
        print ("Source file {} open for reading".format(sys.argv[1]))
        block = source.read(512)
        md5hash.update(block)
        while block:
            dest.write(block)
            block = source.read(512)
            md5hash.update(block)
    end = time.time()
    dest.close()
    source.close()
    print ("Imaging complete. Time taken: {} seconds".format(end - start))
    print ("Source hash: {}".format(md5hash.hexdigest()))
    print ("Computing Destination Hash")

    destmd5hash = hashlib.md5()
    with open(sys.argv[2], "rb") as dest:
        print ("Dest file {} open for computing hash".format(sys.argv[2]))
        block = dest.read(512)
        destmd5hash.update(block)
        while block:
            block = dest.read(512)
            destmd5hash.update(block)
    print ("Verification complete. Destination hash: {}".format(destmd5hash.hexdigest()))
    if md5hash.hexdigest() == destmd5hash.hexdigest():
        print("Verification successful, hashes match")
    else:
        print ("Verification unsuccessful.")
