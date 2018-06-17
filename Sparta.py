#!/usr/bin/python

##Joseph Greenfield
##jsgreenfield@my.uri.edu
##

import argparse
import hashlib
import time
import datetime
# for multi-threaded
from Queue import Queue
from threading import Thread

import case

from BinaryParser import Mmap
from BinaryParser import OverrunBufferException
from MFT import *

# setting up a global Queues for file processing
num_processing_threads = 2
unprocessedFileQueue = Queue()
processedFileQueue = Queue()

# instantiating the output document
case_output = case.Document()

# instantiating the file signatures list
file_signatures = []


# This will replace the tuples stuff that I wrote below
class FileData(object):

    def __init__(self, mft_record):
        self.mft_record = mft_record

    def mft_record(self):
        return self.mft_record


class UnprocessedFileData(FileData):

    def __init__(self, mft_record, file_data):
        super(UnprocessedFileData, self).__init__(mft_record)
        self.file_data = file_data


class ProcessedFileData(FileData):

    def __init__(self, mft_record, file_hash, file_signature):
        super(ProcessedFileData, self).__init__(mft_record)
        self.file_hash = file_hash
        self.file_signature = file_signature

class ClusterMapEntry(object):

    def __init__(self, run_length, mft_record, file_offset, last_run):
        self.run_length = run_length
        self.mft_record = mft_record
        self.file_offset = file_offset
        self.last_run = last_run

class FileSignatureEntry(object):

    def __init__(self, fileDescription, fileSig, fileExt, fileCategory):
        self.fileDescription = fileDescription
        self.fileSig = fileSig
        self.fileExt = fileExt
        self.fileCategory = fileCategory

def processFileFromQueue():
    while True:
        unprocessedFile = unprocessedFileQueue.get()

        filename = unprocessedFile.mft_record.filename_information().filename()
        print("Processing File: {}".format(filename))

        # hash only the logical file size
        filesize = unprocessedFile.mft_record.data_attribute().data_size()
        md5hash = hashlib.md5(unprocessedFile.file_data[0:filesize])

        fileSiganture = ""
        # checking signatures
        for signature in file_signatures:
            signature_length = len(signature[1])
            file_bytes_to_check = unprocessedFile.file_data[0:signature_length]

            # signature_as_string = base64.encode(signature[1])

            if (file_bytes_to_check == signature[1]):
                # we have a signature match
                fileSiganture = signature[0]
                break

        processedFileQueue.put(ProcessedFileData(unprocessedFile.mft_record, md5hash, fileSiganture))

        unprocessedFileQueue.task_done()


def writeCaseOutput():
    while True:
        processedFile = processedFileQueue.get()
        case_file = case_output.create_uco_object('Trace')
        case_file_property = case_file.create_property_bundle(
            'File',
            fileName=processedFile.mft_record.filename_information().filename()
        )
        processedFileQueue.task_done()


def parseMFTForFiles(mftpath):
    # initializing the physical cluster map
    # the key for the cluster map will be the physical cluster
    # the value will be a tuple [length of run, mft_record for run, logical offset within the file,
    # and a boolean as to whether it is the last run in the runlist

    cluster_map = {}
    with Mmap(mftpath) as mftbuffer:
        enum = MFTEnumerator(mftbuffer)
        num_records = enum.len()

        for mft_id in range(0, num_records):
            try:
                mft_record = enum.get_record(mft_id)
                if not mft_record.is_directory() and mft_record.is_active():
                    # the record is a file and allocated
                    # building the clustermap
                    data_attrib = mft_record.data_attribute()
                    # if the data is non-resident, then we care. Otherwise, the data is in the attribute
                    if data_attrib and data_attrib.non_resident() > 0:
                        filename_attrib = mft_record.filename_information()
                        filename = filename_attrib.filename()
                        runlist = mft_record.data_attribute().runlist()
                        dataruns = runlist.runs()

                        # print("Filename: {}".format(filename))

                        # The code in MFT.py actually gives the runlist as volume offsets
                        # This will keep track of where in the logical file the cluster run should be
                        file_offset = 0
                        last_offset = 0

                        for (offset, length) in dataruns:
                            cluster_map[offset] = ClusterMapEntry(length, mft_record,file_offset, False)
                            file_offset += length
                            if offset > last_offset:
                                last_offset = offset
                        cluster_map[last_offset].last_run = True

                    #elif data_attrib and data_attrib.resident() > 0:
                        #the data is resident to the MFT. Parse it


            except OverrunBufferException:
                return
            except InvalidRecordException:
                mft_id += 1
                continue

    return cluster_map


def printClusterMap(cluster_map):
    for cluster in cluster_map:
        cm_entry = cluster_map[cluster]
        print(
            "Cluster: {}\tLength: {}\tOffset: {}\tFile: {}\tLast Cluster: {}".format(cluster, cm_entry.run_length,
                                                                                     cm_entry.file_offset,
                                                                                     cm_entry.mft_record.filename_information().filename(),
                                                                                     cm_entry.last_run))

def parseMBRforVBRLocation(mbr):
    # grab the first partition entry, and return the starting sector
    return struct.unpack("<I", mbr[454:458])[0]


def parseVBRforSectorsPerCluster(vbr):
    return struct.unpack("B", vbr[13:14])[0]


##This is the code for the non-threaded version
# def processFile(mft_record, file_data, file_signatures, case_output):
#     filename = mft_record.filename_information().filename()
#     #hash only the logical file size
#     filesize = mft_record.data_attribute().data_size()
#     md5hash = hashlib.md5(file_data[0:filesize])
#     fileSiganture = ""
#
#     #checking signatures
#     for signature in file_signatures:
#         signature_length = len(signature[1])
#         file_bytes_to_check = file_data[0:signature_length]
#
#         #signature_as_string = base64.encode(signature[1])
#
#         if (file_bytes_to_check == signature[1]):
#             #we have a signature match
#             fileSiganture = signature[0]
#             break
#
#
#     print("File: {}\tMD5 Hash: {}\tSignature: {}".format(filename, md5hash.hexdigest(),fileSiganture))
#
#     #adding the file to the output
#     case_file = case_output.create_uco_object('Trace')
#     case_file_property = case_file.create_property_bundle(
#         'File',
#         fileName=filename
#     )

def main():
    # checking input parameters
    if len(sys.argv) < 3:
        print ("Sparta <source> <destination> <MFT>")
    else:
        print ("Sparta {} {} {}".format(sys.argv[1], sys.argv[2], sys.argv[3]))

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

    # writing preliminary information for Case output
    instrument = case_output.create_uco_object(
        'Tool',
        name='SPARTA',
        version='0.1',
        creator='Joseph Greenfield')

    performer = case_output.create_uco_object('Identity')
    performer.create_property_bundle(
        'SimpleName',
        givenName='John',
        familyName='Doe')

    action = case_output.create_uco_object(
        'ForensicAction',
        startTime=datetime.now()
    )

    # instantiating our file processing threads
    for i in range(num_processing_threads):
        t = Thread(target=processFileFromQueue)
        t.daemon = True
        t.start()

    # instantiating our Case output builder thread
    t = Thread(target=writeCaseOutput)
    t.daemon = True
    t.start()

    # building datastructure for file signatures
    # right now, it will iterate through each signature and see if there is a match
    # this is a very inefficient way to do it, but we'll see if there is a significant impact on performance
    with open("signatures_GCK.txt", "r") as signatures:
        for line in signatures:
            currline = line.split(",")
            fileDescription = currline[0]
            fileSig = currline[1].replace(" ", "")
            fileExt = currline[4]
            fileCategory = currline[5].strip('\n')

            # fileSigBytes = fileSig.split(" ")
            # trying to convert the string to a byte array
            fileSigBytes = bytearray.fromhex(fileSig)

            file_signatures.append((fileDescription, fileSigBytes, fileExt, fileCategory))

    # reading MFT for processing
    cluster_map = parseMFTForFiles(arg_results.mft_path)

    printClusterMap(cluster_map)

    # we are building a dictionary of files that actually contain the binary data for each file
    # the key will be the MFT record number, the value will be the binary data
    files = {}

    # Disk imaging functionality
    with open(arg_results.destination, "wb") as dest:
        # attempting to open the source disk for stream reading
        print ("Destination file {} open for writing".format(destpath))
        md5hash = hashlib.md5()
        # starting timer
        start = time.time()

        with open(arg_results.source, "rb") as source:
            # trying to read 512 byte blocks
            print ("Source file {} open for reading".format(sourcepath))
            # first block is MBR. Parse it.
            block = source.read(512)
            vbr_sector = parseMBRforVBRLocation(block)
            md5hash.update(block)
            dest.write(block)

            # Now reading/writing padding sectors until VBR
            block = source.read(vbr_sector * 512 - 512)
            md5hash.update(block)
            dest.write(block)

            # We should now be at the VBR. We should now be reading the VBR ($Boot)
            block = source.read(512)
            # $Boot is cluster number 0
            clusterNum = 0
            # lookup the entry in the cluster map
            map_entry = cluster_map[clusterNum]
            # update our cluster numbering to the next cluster after the full run
            clusterNum += map_entry.run_length
            sectors_per_cluster = parseVBRforSectorsPerCluster(block)
            bytes_per_cluster = sectors_per_cluster * 512
            md5hash.update(block)
            dest.write(block)

            # we now have to read the rest of the $boot file
            block += source.read(bytes_per_cluster * map_entry.run_length - 512)
            md5hash.update(block)
            dest.write(block)

            # if the $boot is done (unfragmented), then process it, otherwise, we'll move on to the main processing code
            if map_entry.last_run:
                # (mft_record,block, file_signatures, case_output)
                unprocessedFileQueue.put(UnprocessedFileData(map_entry.mft_record, block))
            else:
                # we add the $boot to the file map
                files[map_entry.mft_record.mft_record_number] = block

            # we read the rest of the drive by cluster runs
            while block:
                # if this cluster is assigned to a valid file
                if clusterNum in cluster_map:
                    #[cluster_run_length, mft_record, offset, last_run] = cluster_map[clusterNum]
                    map_entry = cluster_map[clusterNum]

                    mft_record_num = map_entry.mft_record.mft_record_number()
                    # read in the entire cluster run
                    block = source.read(bytes_per_cluster * map_entry.run_length)
                    clusterNum += map_entry.run_length

                    # check to see if the file has any data already read
                    if mft_record_num not in files and map_entry.last_run:
                        # processFile(mft_record,block, file_signatures, case_output)
                        unprocessedFileQueue.put(UnprocessedFileData(map_entry.mft_record, block))
                    elif mft_record_num in files and not map_entry.last_run:
                        files[mft_record_num][map_entry.file_offset:map_entry.file_offset + map_entry.run_length * bytes_per_cluster - 1] = block
                    elif mft_record_num in files and map_entry.last_run:
                        files[mft_record_num] = bytearray(map_entry.mft_record.filename_information().logical_size())
                        # processFile(mft_record, files[mft_record_num], file_signatures, case_output)
                        unprocessedFileQueue.put(UnprocessedFileData(map_entry.mft_record, files[mft_record_num]))


                # otherwise, read the cluster and move on
                else:
                    block = source.read(bytes_per_cluster)
                    clusterNum += 1

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

        unprocessedFileQueue.join()
        processedFileQueue.join()
        print ("All file processing complete")

        # writing the Case document output
        case_output.serialize(format='json-ld', destination='output.json')


if __name__ == "__main__":
    main()
