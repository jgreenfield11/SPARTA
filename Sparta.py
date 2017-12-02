#!/usr/bin/python

import sys
import io

#checking input parameters
if len(sys.argv) < 2:
    print ("Sparta <source> <destination>")
else:
    print ("Sparta {} {}".format(sys.argv[1],sys.argv[2]))

with open(sys.argv[2], "wb") as dest:
    #attempting to open the source disk for stream reading
    with open(sys.argv[1], "rb") as source:
        #trying to read 512 byte blocks
        block = source.read(512)
        while block:
            dest.write(block)
            block = source.read(512)
