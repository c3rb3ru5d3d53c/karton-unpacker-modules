#!/usr/bin/env python3

import logging
import argparse
import json
from karton.core import Task, Resource
from qiling import *
import yara
import pefile
import hexdump

__author__  = '4rchib4ld'
__version__ = '1.0.0'

yara_rule_iceloader = """
rule iceloaderpacker {
    strings:
        $obfuscationCode = {89 DA [0-7] B? FF 44 30 [0-17] C2 44 30 [0-8] 20 ?? 08 D0 [0-8] 88 84}
    condition:
        uint16(0) == 0x5a4d and filesize < 800KB and
        all of them
    }
"""

log = logging.getLogger(__name__) # Setup Logging

class KartonUnpackerModule():

    """
    Unpacks IceLoader executables using the Qiling Framework
    """

    def __init__(self, sample, config):
        self.enabled = self.yara_check(sample)
        self.config = config       
        self.data = sample.content
        if self.config['rootfs'] is None:
            log.warn("rootfs is disabled, iceloader unpacker disabled")
            self.enabled = False
        if self.config['debug'] is True:
            logging.basicConfig(level=logging.DEBUG)
            self.verbose = 4
        else:
            logging.basicConfig(level=logging.INFO)
            self.verbose = 0

    def yara_check(self, sample) -> bool:
        """
        Checking if the sample matches the yara rule. If it does, get the code used for encryption
        """
        self.data = sample.content
        self.name = sample.name
        yarac = yara.compile(source=yara_rule_iceloader)
        matches = yarac.match(data=self.data)
        if matches:
            start = int(matches[0].strings[0][0])
            end = start + len(matches[0].strings[0][2])
            self.obfuscationCode = sample.content[start:end-2] # Removing the last two bytes because I use them as markor for the end of the code
            return True
        return False

    def extractRdataSect(self, pe):
        """ 
        Extracting the payload from the .rdata section
        """
        startOfDebugDirectory = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_DEBUG"]].VirtualAddress
        for section in pe.sections:
            if ".rdata" in str(section.Name):
                rdata = section.get_data()
                rdata = rdata[0x80:]
                RdataVirtualAddress = section.VirtualAddress
                endOfPayload = startOfDebugDirectory - RdataVirtualAddress - 0x80
                if self.config['debug'] is True:
                    log.debug('EXTRACTED RDATA section:')
                    hexdump.hexdump(rdata[:endOfPayload])
                return rdata[:endOfPayload]
    
    def extractDataSect(self, pe):
        """
        Extracting the payload from the .data section
        """
        for section in pe.sections:
            if ".data" in str(section.Name):
                data = section.get_data()
                # OK this one is hardcoded, maybe I can do something about it
                if self.config['debug'] is True:
                    log.debug('EXTRACTED DATA section:')
                    hexdump.hexdump(data[16:16400])
                return data[16:16400]

    def rdataDecode(self, rdata):
        """
        Decoding .rdata. Making it ready for the next stage
        """
        decodedRdata = bytearray()
        for i in range(0, len(rdata), 2):
            decodedRdata.append(rdata[i])
        if self.config['debug'] is True:
            log.debug('Decoded RDATA section:')
            hexdump.hexdump(decodedRdata)
        return decodedRdata

    def rdataDecrypt(self, decodedRdata):
        """
        Starting from the end for the data, and a byte every 20 bytes. Then it loops again, but from len(data)-1 and so on
        """
        payload = bytearray()
        decrem = decodedRdata[-1] # That's where the value is located
        count = 0
        scount = 0
        lenRdata = len(decodedRdata) - 1
        i = lenRdata
        while scount != decrem:
            payload.append(decodedRdata[i])
            i -= decrem
            count = count + 1
            if count == 512:
                i = len(decodedRdata) - 1
                count = 0
                scount += 1
                i = lenRdata - scount
        if self.config['debug'] is True:
            log.debug('Decrypted RDATA section:')
            hexdump.hexdump(payload[::-1])
        return payload[::-1]


    def runObfuscationCode(self, decodedRdata):
        """
        Treat the obfuscation code as a shellcode (could have used the code offset instead) and run it in a loop
        """
        ql = Qiling(code=self.obfuscationCode, 
            rootfs=self.config['rootfs'] + '/x8664_windows',
            ostype="windows",
            archtype="x8664",
            multithread=False,
            console=False,
            verbose=self.verbose
        )
        try:
            deobfuscatedPayload = bytearray()
            count = 0
            key = 1 # Maybe this will change ?
            for byte in decodedRdata:
                if count == 512:
                    key += 1
                    count = 0
                # initialize machine registers
                ql.reg.al = byte
                ql.reg.bl = key
                # Running the code
                ql.run()
                # Extracting the value
                result = ql.reg.al
                count += 1
                deobfuscatedPayload.append(result)
            
        except Exception as error:
            log.error(error)

        if self.config['debug'] is True:
            log.debug('Deobfuscated Payload :')
            hexdump.hexdump(deobfuscatedPayload[::1])
        return deobfuscatedPayload[::1]

    def decryptSecondStage(self, encryptedPayload, dataSect):
        """
        The final decryption. Loop throught the data section and take two bytes at a time, adding them and getting the corresponding char in the decrypted payload from .rdata
        """
        secondStage = bytearray()
        count = 0
        step = 512
        padding = 0
        for i in range(0, len(encryptedPayload) * 2, 2):
            try:
                currentChar = encryptedPayload[int.from_bytes(bytes([dataSect[i % len(dataSect)]]) + bytes([dataSect[(i+1) % len(dataSect)]]), "little") + padding]
                secondStage.append(currentChar)
            except IndexError:
                pass   
            count += 1
            if count == step:
                padding += step
                count = 0
        secondStage = bytes(secondStage) # Bytearray -> bytes, needed by Karton
        if self.config['debug'] is True:
            log.debug('Second Stage :')
            hexdump.hexdump(secondStage)
        return secondStage

    def main(self) -> list:
        # Perform Operations on self.data to unpack the sample
        pe = pefile.PE(data = self.data)
        #Extracting data from data and rdata
        rdata = self.extractRdataSect(pe)
        data = self.extractDataSect(pe)
        decryptedRdata = self.rdataDecrypt(self.rdataDecode(rdata))
        encryptedPayload = self.runObfuscationCode(decryptedRdata)
        unpacked_data = self.decryptSecondStage(encryptedPayload, data)
        task = Task(
            headers={
                'type': 'sample',
                'kind': 'runnable',
                'stage': 'recognized'
            },
            payload={
                'parent': Resource(name='sample', content=self.data),      # Set Parent Data (Packed Sample)
                'sample': Resource(name='unpacked', content=unpacked_data) # Set Child Data (Unpacked Sample)
            }
        )
        # A list of tasks must be returned, as there can be more than one unpacked child
        return [task]

if __name__ in '__main__':
    parser = argparse.ArgumentParser(
        prog='example.py',
        description=f'Karton Unpacker Service Example Module v{__version__} (CLI Test Utility)',
        epilog=f'Author: {__author__}'
    )
    parser.add_argument('-i','--input', help='Input File', type=str, required=True)
    parser.add_argument('--rootfs', help='RootFS', type=str, default=None, required=True)
    parser.add_argument('--debug', help='Debug', action="store_true", default=False, required=False)
    args = parser.parse_args()
    f = open(args.input, 'rb')
    sample = Resource(name=args.input, content=f.read())
    f.close()
    config = {
        'rootfs': args.rootfs,
        'debug': args.debug
    }

    module = KartonUnpackerModule(sample, config)
    if module.enabled is True:
        task = module.main()
        data = json.loads(str(task))
        print(json.dumps(data, indent=4))
