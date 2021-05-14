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
    meta:
        author      = "4rchib4ld"
        description = "Iceloader"
        reference   = "https://4rchib4ld.github.io/blog/HoneymoonOnIceloader/"
        type        = "malware.loader"
        created     = "2021-05-14"
        os          = "windows"
        tlp         = "white"
        rev         = 1
    strings:
        $obfuscationCode = {89 DA [0-7] B? FF 44 30 [0-17] C2 44 30 [0-8] 20 ?? 08 D0 [0-8] 88 84} // This code is used for deobfuscation
    condition:
        uint16(0) == 0x5a4d and filesize < 800KB and // We only want PE files
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

    def extractPayloadFromSect(self, pe, sectionName):
        """ 
        Extracting the payload from the pe section. Different routines because of the different section that can be used
        """
        for section in pe.sections:
            if sectionName == section.Name:
                if ".rdata" in str(sectionName):
                    startOfDebugDirectory = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_DEBUG"]].VirtualAddress
                    rdata = section.get_data()
                    RdataVirtualAddress = section.VirtualAddress
                    endOfPayload = startOfDebugDirectory - RdataVirtualAddress
                    return rdata[:endOfPayload]
                data = section.get_data()
                log.debug(f"Size of extracted payload section : {len(data)}")
                return data
    
    def extractDecryptionSect(self, pe, sectionName):
        """
        Extracting the payload from the pe section

        """
        for section in pe.sections:
            if sectionName == section.Name:
                data = section.get_data()
                endoffset = 16400 # hardcoded value, but it's always the same
                extractedValue = int.from_bytes(data[:4], 'little')
                data =  data[16:endoffset]
                log.debug(f"Size of the extracted decryption section : {len(data)}\nExtracted value : {extractedValue}")
                return data, extractedValue

    def payloadDecode(self, data):
        """
        Decoding the payload. Making it ready for the next stage
        """
        decodedData = bytearray()
        for i in range(0, len(data), 2):
            decodedData.append(data[i])
        log.debug(f"Size decoded payload section: {len(decodedData)}")
        return decodedData

    def payloadDecrypt(self, decodedPayload, decrementationCounter):
        """
        Starting from the end for the decodedPayload, and a byte every n bytes. Then it loops again, but from len(data)-1 and so on
        """
        payload = bytearray()
        count = 0
        scount = 0
        payloadSize = len(decodedPayload) - 1
        i = payloadSize
        while scount != decrementationCounter:
            try:
                payload.append(decodedPayload[i])
            except:
                pass
            i -= decrementationCounter
            count = count + 1
            if count == 512:
                count = 0
                scount += 1
                i = payloadSize - scount

        log.debug(f"Size of the decrypted payload section : {len(payload)}")
        return payload[::-1]

    def gettingObfuscationCode(file, yaraRule):
        """
        Retrieving the code used for obfuscation using a Yara rule
        """
        rules = yara.compile(filepath=yaraRule)
        f = open(file, "rb")
        matches = rules.match(data=f.read())
        f.close()
        if matches:
            obfuscationCode = matches[0].strings[0][2]
        else:
            obfuscationCode = 0
        log.debug(f"Obfuscation code : {obfuscationCode}")
        return obfuscationCode

    def runObfuscationCode(self, obfuscatedPayload):
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
            for byte in obfuscatedPayload:
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

        log.debug(f"Size of deobfuscated payload : {len(deobfuscatedPayload)}")
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
        log.debug(f"Size of the decrypted second stage : {len(secondStage)}")
        return secondStage

    def selectingSections(self, pe):
        """
        Sorting the biggest region of the file. The biggest is the packed executable, the second one the data used for decryption
        """
        sort = {}
        for section in pe.sections:
            if not ".text" in str(section.Name) and not ".data" in str(section.Name): # we don't care about .text
                sort[section.Name] = section.Misc_VirtualSize
            if ".data" in str(section.Name):
                dataSectionSize = section.Misc_VirtualSize
                dataSectionName = section.Name
        sortedSection = sorted(sort.items(), key=lambda x: x[1], reverse=True)
        payloadSection = sortedSection[0][0]
        payloadSectionSize = sortedSection[0][1]
        log.debug(f"Biggest section is : {payloadSection} with size {payloadSectionSize}")
        if dataSectionSize > (payloadSectionSize * 5): #means that everything is in .data
            log.debug("Everything is in .data")
            dataSect = self.extractPayloadFromSect(pe, dataSectionName)
            extractedPayload, extractedDecryptionSection, extractedValue = self.scanningData(dataSect)
        else:
            extractedPayload = self.extractPayloadFromSect(pe, payloadSection)
            extractedDecryptionSection, extractedValue  = self.extractDecryptionSect(pe, dataSectionName)
        
        return extractedPayload, extractedDecryptionSection, extractedValue


    def scanningData(self, data):
        """
        Sometimes everything is in the .data section, so we need to parse it in order to get the data we want. I use a Yara rule in order to find the markor
        """
        markorYara = """
        rule  findMarkor
        {
        strings:
            $markor = { 00 ?? ?? 00 ?? ?? 00 00 00 00 00 00 00 00 00 }
        condition:
            all of them
        }
        """
        yarac = yara.compile(source=markorYara)
        matches = yarac.match(data=data)
        extractedValue = int.from_bytes(matches[0].strings[0][2][:4], 'little')
        offset = matches[0].strings[0][0]
        payload = data[:offset]
        dataSect = data[offset+16:offset+16400] #skipping the 16bytes that are used as a delimeter
        log.debug(f"extracted payload size : {payload}\n extracted data section size : {dataSect} \n extracted value : {extractedValue}")
        return payload, dataSect, extractedValue

    def main(self) -> list:
        # Perform Operations on self.data to unpack the sample
        pe = pefile.PE(data = self.data)

        extractedPayload, extractedDecryptionSection, extractedValue = self.selectingSections(pe)
        decrementationCounter = extractedValue // 512 # that's how it is calculated
        obfuscatedPayload   = self.payloadDecrypt(self.payloadDecode(extractedPayload), decrementationCounter)
        deobfuscatedPayload = self.runObfuscationCode(obfuscatedPayload)
        unpackedExecutable  = self.decryptSecondStage(deobfuscatedPayload, extractedDecryptionSection)
        with open("test.bin", "wb") as f:
            f.write(unpackedExecutable)
        task = Task(
            headers={
                'type': 'sample',
                'kind': 'runnable',
                'stage': 'recognized'
            },
            payload={
                'parent': Resource(name='sample', content=self.data),      # Set Parent Data (Packed Sample)
                'sample': Resource(name='unpacked', content=unpackedExecutable) # Set Child Data (Unpacked Sample)
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
