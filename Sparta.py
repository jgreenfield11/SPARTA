#!/usr/bin/python

import sys
import time
import hashlib
import argparse
import struct

from MFT import MFTEnumerator
from MFT import InvalidRecordException

from BinaryParser import Mmap
from BinaryParser import OverrunBufferException

def parseMFTForFiles(mftpath):
    file_records = []
    with Mmap(mftpath) as mftbuffer:
        enum = MFTEnumerator(mftbuffer)
        num_records = enum.len()

        for mft_id in range(0, num_records):
            try:
                mft_record = enum.get_record(mft_id)
                if not mft_record.is_directory():
                #the record is a file
                    file_records.append(mft_record)
            except OverrunBufferException:
                return
            except InvalidRecordException:
                mft_id += 1
                continue

    return file_records

def parseMBRforVBRLocation(mbr):
    #grab the first partition entry, and return the starting sector
    return struct.unpack("<I", mbr[454:458])[0]

def parseVBRforSectorsPerCluster(vbr):
    return struct.unpack("B", vbr[13:14])[0]

def main():
    #checking input parameters
    if len(sys.argv) < 3:
        print ("Sparta <source> <destination> <MFT>")
    else:
        print ("Sparta {} {} {}".format(sys.argv[1],sys.argv[2], sys.argv[3]))

    sourcepath = sys.argv[1]
    destpath = sys.argv[2]
    mftpath = sys.argv[3]

    parser = argparse.ArgumentParser(description='SPARTA: System for '
                                                 'Parallel Acquisitions with '
                                                 'Real-Time Analysis')
    parser.add_argument('source', action="store", help="Source Path (Device or DD Image")
    parser.add_argument('destination', action="store", help="Destination File Path")
    parser.add_argument('mft_path', action="store", help="Source MFT path")
    arg_results = parser.parse_args()


    #reading MFT for processing
    fileMFTRecords = parseMFTForFiles(arg_results.mft_path)

    #Disk imaging functionality
    with open(arg_results.destination, "wb") as dest:
        #attempting to open the source disk for stream reading
        print ("Destination file {} open for writing".format(destpath))
        md5hash = hashlib.md5()
        #starting timer
        start = time.time()

        blocknum = 0
        with open(arg_results.source, "rb") as source:
            #trying to read 512 byte blocks
            print ("Source file {} open for reading".format(sourcepath))
            #first block is MBR. Parse it.
            block = source.read(512)
            blocknum += 1
            vbr_sector = parseMBRforVBRLocation(block)
            md5hash.update(block)
            dest.write(block)

            #Now reading/writing padding sectors until VBR
            block = source.read(vbr_sector * 512 - 512)
            md5hash.update(block)
            dest.write(block)

            #We should now be at the VBR. We should now be reading the VBR ($Boot)
            block = source.read(512)
            sectors_per_cluster = parseVBRforSectorsPerCluster(block)
            bytes_per_cluster = sectors_per_cluster * 512
            md5hash.update (block)
            dest.write(block)

            #we now have to read the rest of the $boot file
            block = source.read(bytes_per_cluster - 512)
            md5hash.update(block)
            dest.write(block)

            #we read the rest of the drive by cluster sizes
            while block:
                block = source.read(bytes_per_cluster)
                md5hash.update(block)
                dest.write(block)

        end = time.time()
        dest.close()
        source.close()
        print ("Imaging complete. Time taken: {} seconds".format(end - start))
        print ("Source hash: {}".format(md5hash.hexdigest()))
        print ("Computing Destination Hash")

        destmd5hash = hashlib.md5()
        with open(sys.argv[2], "rb") as dest:
            print ("Dest file {} open for computing hash".format(destpath))
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

if __name__ == "__main__":
    main()