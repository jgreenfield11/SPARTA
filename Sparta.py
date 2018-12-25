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

#for CASE/UCO Output
import case

#To add the INDXParse library
import sys
sys.path.insert(0, "/home/joe/INDXParse")

#INDXParse stuff
from BinaryParser import Mmap
from BinaryParser import OverrunBufferException
from MFT import *

#Progress Bar
from progressbar import ProgressBar, Percentage, Bar, ETA, AdaptiveETA

# setting up a global Queues for file processing
num_processing_threads = 10
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
        #print("Processing File: {}".format(filename))

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
        fn = processedFile.mft_record.filename_information()
        si = processedFile.mft_record.standard_information()
        data = processedFile.mft_record.data_attribute()

        case_file = case_output.create_uco_object('Trace')
        case_file_property = case_file.create_property_bundle(
            'File',
            fileName=fn.filename(),
            extension=os.path.splitext(fn.filename()),
            isDirectory=False,
            createdTime=si.created_time(),
            accessedTime=si.accessed_time(),
            modifiedTime=si.modified_time(),
            metadataChangeTime=si.changed_time(),
            sizeInBytes=data.data_size()
        )

        #print ("Processed Filename: {}\tHash: {}\tSignature: {}".format(
        #     processedFile.mft_record.filename_information().filename(),
        #     processedFile.file_hash.hexdigest(),
        #     processedFile.file_signature))
        processedFileQueue.task_done()

        #Temporary Debugging


def parseMFTForFiles(mftpath):
    # initializing the physical cluster map
    # the key for the cluster map will be the physical cluster
    # the value will be a tuple [length of run, mft_record for run, logical offset within the file,
    # and a boolean as to whether it is the last run in the runlist

    MFTProcessStart = datetime.now()
    print ("Beginning processing MFT at {}".format(MFTProcessStart))
    sys.stdout.flush()

    cluster_map = {}
    with Mmap(mftpath) as mftbuffer:
        enum = MFTEnumerator(mftbuffer)
        num_records = enum.len()

        pbar = ProgressBar(widgets=[
            "MFT Records Processed: ", Percentage(),
            ' ', Bar(),
            ' ', AdaptiveETA(),
        ], maxval=num_records).start()
        for mft_id in range(0, num_records):
            try:
                mft_record = enum.get_record(mft_id)
                if not mft_record.is_directory() and mft_record.is_active():
                    # the record is a file and allocated
                    # building the clustermap

                    data_attrib = mft_record.data_attribute()
                    filename_attrib = mft_record.filename_information()
                    # if the data is non-resident, then we care. Otherwise, the data is in the attribute
                    if data_attrib and filename_attrib and data_attrib.non_resident() > 0:

                        runlist = mft_record.data_attribute().runlist()
                        dataruns = runlist.runs()

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
                pbar.update(mft_id + 1)


            except OverrunBufferException:
                return
            except InvalidRecordException:
                mft_id += 1
                continue
        pbar.finish()

    MFTProcessEnd = datetime.now()
    print ("Complete Processing MFT. Time Taken: {}".format(MFTProcessEnd - MFTProcessStart))
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

def parseVBRforTotalSectors(vbr):
    return struct.unpack("<Q", vbr[40:48])[0]


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
    #checking input parameters
    # if len(sys.argv) < 3:
    #     print ("Sparta <source> <destination> <MFT>")
    # else:
    #     print ("Sparta {} {} {}".format(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]))
    #
    # # sourcepath = sys.argv[1]
    # # destpath = sys.argv[2]
    # # mftpath = sys.argv[3]
    # # fileProcessing = sys.argv[4]

    parser = argparse.ArgumentParser(description='SPARTA: System for '
                                                 'Parallel Acquisitions with '
                                                 'Real-Time Analysis')
    parser.add_argument('source', action="store", help="Source Path (Device or DD Image")
    parser.add_argument('destination', action="store", help="Destination File Path")
    parser.add_argument('metadata', action="store", help="Path for file metadata")
    parser.add_argument('mft_path', action="store", help="Source MFT path")
    parser.add_argument('--file_processing', action='store_true', default=False, dest='file_processing')
    arg_results = parser.parse_args()

    sourcepath = arg_results.source
    destpath = arg_results.destination
    mftpath = arg_results.mft_path
    mpath = arg_results.metadata
    file_processing = arg_results.file_processing

    # writing preliminary information for Case output
    instrument = case_output.create_uco_object(
        'Tool',
        name='SPARTA',
        version='0.1',
        creator='Joseph Greenfield')

    performer = case_output.create_uco_object('Identity')
    performer.create_property_bundle(
        'SimpleName',
        givenName='Joe',
        familyName='Greenfield'
    )

    action = case_output.create_uco_object(
        'ForensicAction',
        startTime=datetime.now()
    )
    action.create_property_bundle(
        'ActionReferences',
        performer = performer,
        instrument=instrument,
        object=None,
        result=[]
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
    if file_processing == True:
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

    #printClusterMap(cluster_map)

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

        source_numbytes = 0
        #determining number of bytes in the input drive
        fd = os.open(arg_results.source, os.O_RDONLY)
        try:
            source_numbytes = os.lseek(fd, 0, os.SEEK_END)
        finally:
            os.close(fd)

        curr_sector = 0

        with open(arg_results.source, "rb") as source:
            # trying to read 512 byte blocks
            print ("Source file {} open for reading".format(sourcepath))
            # first block is MBR. Parse it.

            if file_processing == False:
                source_numsectors = source_numbytes / 512 + 1
                pbar = ProgressBar(widgets=[
                    "Sectors Read: ", Percentage(),
                    ' ', Bar(),
                    ' ', AdaptiveETA(),
                ], maxval=source_numsectors).start()

                curr_sector = 0
                block = source.read(512)

                while block:
                    curr_sector += 1
                    pbar.update(curr_sector)
                    md5hash.update(block)
                    dest.write(block)
                    block = source.read(512)

            else:
                source_numsectors = source_numbytes / 512 + 1
                pbar = ProgressBar(widgets=[
                    "Clusters Read: ", Percentage(),
                    ' ', Bar(),
                    ' ', AdaptiveETA(),
                ], maxval=source_numsectors).start()

                block = source.read(512)
                curr_sector += 1
                pbar.update(curr_sector)
                vbr_sector = parseMBRforVBRLocation(block)
                md5hash.update(block)
                dest.write(block)

                # Now reading/writing padding sectors until VBR
                block = source.read(vbr_sector * 512 - 512)
                curr_sector = vbr_sector - 1
                pbar.update(curr_sector)
                md5hash.update(block)
                dest.write(block)

                # We should now be at the VBR. We should now be reading the VBR ($Boot)
                block = source.read(512)
                # $Boot is cluster number 0
                clusterNum = 0
                curr_sector += 1
                # lookup the entry in the cluster map
                map_entry = cluster_map[clusterNum]
                # update our cluster numbering to the next cluster after the full run
                clusterNum += map_entry.run_length
                sectors_per_cluster = parseVBRforSectorsPerCluster(block)
                bytes_per_cluster = sectors_per_cluster * 512
                #total_clusters = parseVBRforTotalSectors(block)/sectors_per_cluster
                #md5hash.update(block)
                #dest.write(block)

                # we now have to read the rest of the $boot file
                block += source.read(bytes_per_cluster * map_entry.run_length - 512)
                curr_sector += (map_entry.run_length - 1) * sectors_per_cluster
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

                        # check to see if the file has any data already read
                        # non-fragmented files fall under this category
                        if mft_record_num not in files and map_entry.last_run:
                            unprocessedFileQueue.put(UnprocessedFileData(map_entry.mft_record, block))
                        else:
                            if mft_record_num not in files:
                                files[mft_record_num] = bytearray(map_entry.mft_record.data_attribute().allocated_size())
                            block_offset_start = map_entry.file_offset * bytes_per_cluster
                            block_offset_end = map_entry.file_offset * bytes_per_cluster + map_entry.run_length * bytes_per_cluster
                            files[mft_record_num][block_offset_start:block_offset_end] = block

                            if map_entry.last_run:
                                unprocessedFileQueue.put(UnprocessedFileData(map_entry.mft_record, files[mft_record_num]))

                        curr_sector += (map_entry.run_length - 1) * sectors_per_cluster
                        clusterNum += map_entry.run_length
                        pbar.update(curr_sector)

                    # otherwise, read the cluster and move on
                    else:
                        block = source.read(bytes_per_cluster)
                        curr_sector += sectors_per_cluster
                        clusterNum += 1
                        pbar.update(curr_sector)

                    md5hash.update(block)
                    dest.write(block)
        imaging_end = time.time()
        pbar.finish()
        dest.close()
        source.close()
        print ("Imaging complete. Time taken: {} seconds".format(imaging_end - start))
        print ("Items remaining in unprocessed queue: {}".format(unprocessedFileQueue.qsize()))
        print ("Items remaining in processed queue for CASE output: {}".format(processedFileQueue.qsize()))
        print ("Source hash: {}".format(md5hash.hexdigest()))
        print ("Computing Destination Hash")


        destmd5hash = hashlib.md5()

        dest_numbytes = 0

        with open(sys.argv[2], "rb") as dest:
            print ("Dest file {} open for computing hash".format(destpath))
            dest_numsectors = os.path.getsize(sys.argv[2])/512 + 1
            curr_sector = 0
            pbar = ProgressBar(widgets=[
                "Sectors Read: ", Percentage(),
                ' ', Bar(),
                ' ', AdaptiveETA(),
            ], maxval=dest_numsectors).start()
            block = dest.read(4096)
            curr_sector += 1
            pbar.update(curr_sector)
            destmd5hash.update(block)
            while block:
                block = dest.read(4096)
                curr_sector += 1
                destmd5hash.update(block)
                pbar.update(curr_sector)
            pbar.finish()
        dest.close()

        print ("Verification complete. Destination hash: {}".format(destmd5hash.hexdigest()))
        if md5hash.hexdigest() == destmd5hash.hexdigest():
            print("Verification successful, hashes match")
        else:
            print ("Verification unsuccessful.")

        print ("Items remaining in unprocessed queue: {}".format(unprocessedFileQueue.qsize()))
        print ("Items remaining in processed queue for CASE output: {}".format(processedFileQueue.qsize()))
        unprocessedFileQueue.join()
        processedFileQueue.join()
        print ("All file processing complete")

        # writing the Case document output

        case_output.serialize(format='json-ld', destination=mpath)

        print ("SPARTA complete. Total time taken: {} seconds".format(time.time() - start))


if __name__ == "__main__":
    main()
