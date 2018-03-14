#!/usr/bin/python

import time
import hashlib
import argparse

from MFT import *

from BinaryParser import Mmap
from BinaryParser import OverrunBufferException

def parseMFTForFiles(mftpath):

    #initializing the physical cluster map
    #the key for the cluster map will be the physical cluster
    #the value will be a tuple [length of run, mft_record for run, and a boolean as to whether it is the last
    #run in the runlist
    cluster_map = {}
    with Mmap(mftpath) as mftbuffer:
        enum = MFTEnumerator(mftbuffer)
        num_records = enum.len()

        for mft_id in range(0, num_records):
            try:
                mft_record = enum.get_record(mft_id)
                if not mft_record.is_directory() and mft_record.is_active():
                #the record is a file and allocated
                #building the clustermap
                    data_attrib = mft_record.data_attribute()
                    #if the data is non-resident, then we care. Otherwise, the data is in the attribute
                    if data_attrib and data_attrib.non_resident() > 0:
                        filename_attrib = mft_record.filename_information()
                        filename = filename_attrib.filename()
                        runlist = mft_record.data_attribute().runlist()
                        dataruns = runlist.runs()

                        #print("Filename: {}".format(filename))

                        #The code in MFT.py actually gives the runlist as volume offsets
                        count = 1
                        for (offset, length) in dataruns:
                            #print("Runlist offset: {} Runlist length: {}".format(offset, length))
                            if count != runlist._entries().__len__():
                                cluster_map[offset] = [length, mft_record, False]
                            else:
                                cluster_map[offset] = [length, mft_record, True]

            except OverrunBufferException:
                return
            except InvalidRecordException:
                mft_id += 1
                continue

    #now to see the contents of the cluster map

    return cluster_map

def printClusterMap(cluster_map):
    for cluster in cluster_map:
        cm_entry = cluster_map[cluster]
        length = cm_entry[0]
        mft_record = cm_entry[1]
        last_cluster = cm_entry[2]
        filename = mft_record.filename_information().filename()

        print("Cluster: {}\tLength: {}\tFile: {}\tLast Cluster: {}".format(cluster, length, filename, last_cluster))



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
    cluster_map = parseMFTForFiles(arg_results.mft_path)

    #printClusterMap(cluster_map)

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