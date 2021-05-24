#!/usr/bin/env python

import re
import io
import os
import sys
import json
import yara
import pefile
import struct
import zipfile
import argparse
import logging
from unicorn import *
from unicorn.x86_const import *
from capstone import *
from capstone.x86 import *
from karton.core import Karton, Task, Resource

log = logging.getLogger(__name__)

__author__ = 'c3rb3ru5'
__version__ = '1.0.0'

yara_rule_0 = """
rule fatalrat_loader_0 {
    meta:
        author      = "c3rb3ru5d3d53c"
        description = "FatalRAT Loader"
        hash        = "bb56f20a2a0dec07dcde2cd7abf75eaf"
        reference   = "https://twitter.com/LittleRedBean2/status/1391012054228742148"
        type        = "malware.rat"
        created     = "2021-05-13"
        os          = "windows"
        tlp         = "white"
        rev         = 1
    strings:
        $decrypt_routine_0 = {55 8b ec 83 ec ?? 0f b6 4? ?? 99 b9 ?? ?? ?? ??
                              f7 f9 83 c2 ?? 88 5? ?? c7 4? ?? ?? ?? ?? ?? eb
                              ?? 8b 5? ?? 83 c2 01 89 5? ?? 8b 4? ?? 3b 4? ??
                              73 ?? 0f b6 4? ?? 8b 5? ?? 0f be 02 33 c1 8b 4?
                              ?? 88 01 0f b6 5? ?? 8b 4? ?? 0f be 08 03 ca 8b
                              5? ?? 88 0a 8b 4? ?? 83 c0 ?? 89 4? ?? eb ?? 8b
                              e5 5d c3}
        $get_password_0    = {83 c4 04 89 4? ?? 68 00 80 00 00 6a 00 8b 5? ?? 52 ff 15 ?? ?? ?? ?? 83 7? ?? 00 74}
        $zip_magic_0       = {50 4b 03 04}
        $config_0          = {74 ?? 81 ec ?? ?? ?? ?? b9 ?? ?? ?? ?? be ?? ??
                              ?? ?? 8b fc f3 a5 ff 5?}
    condition:
        uint16(0) == 0x5a4d and
        uint32(uint32(0x3c)) == 0x00004550 and
        $decrypt_routine_0 and
        $zip_magic_0 and
        $get_password_0 and
        $config_0
}
"""

class KartonUnpackerModule():

    def __init__(self, sample, config):
        self.data    = sample.content
        self.config  = config
        self.enabled = self.yara_check(sample, yara_rule_0)
        self.regSS   = re.compile(br'\xc6\x45.*')
        if self.config['debug'] is True:
            logging.basicConfig(level=logging.DEBUG)
        else:
            logging.basicConfig(level=logging.INFO)

    def yara_check(self, data, yara_rule):
        self.yarac = yara.compile(source=yara_rule)
        self.matches = self.yarac.match(data=self.data)
        if len(self.matches) > 0:
            return True
        return False

    def get_matches(self, matches, string):
        if len(matches) > 0:
            results = []
            for match in matches[0].strings:
                if match[1] == '$' + string:
                    results.append(match)
            return results
        return None

    def extract_password(self, matches, data, buffer_size):
        log.debug('extracting zip encryption password')
        zip_pass_matches = self.get_matches(matches, 'get_password_0')
        zip_pass_offset = zip_pass_matches[0][0] + len(zip_pass_matches[0][2])
        zip_pass_data = data[zip_pass_offset:zip_pass_offset + buffer_size]
        password = []
        for i in self.md.disasm(zip_pass_data, 0x400000):
            match = re.findall(self.regSS, i.bytes)
            if len(match) > 0:
                password.append(match[0][3])
        password = bytes(password).decode('ascii')
        password = password.strip('\x00')
        log.debug(f'extracted packed binary password {password}')
        return password

    def extract_packed_code(self, data, matches):
        log.debug('extracting packed code')
        zip_matches = self.get_matches(matches, 'zip_magic_0')
        zip_match = zip_matches[len(zip_matches)-1]
        zip_data = data[zip_match[0]:]
        password = self.extract_password(matches, data, 64)
        packed_data = None
        z = zipfile.ZipFile(io.BytesIO(zip_data))
        z.setpassword(password.encode())
        for zf in z.namelist():
            if not zf.endswith('/'):
                packed_data = z.read(zf)
                break
        z.close()
        return packed_data

    def setup_memory(self):
        log.debug('emulating memory')
        self.BASE_ADDRESS  = 0x400000
        self.STACK_ADDRESS = 0x410000
        self.DATA_ADDRESS  = 0x420000
        self.mu.mem_map(self.BASE_ADDRESS, 32 * 1024 * 1024)   # Map 32MB of Memory
        self.mu.mem_write(self.BASE_ADDRESS, self.CODE)        # Write Decryption Routine Code
        self.mu.mem_write(self.DATA_ADDRESS, self.PACKED_CODE) # Write Encrypted Data
        self.mu.reg_write(UC_X86_REG_ESP, self.STACK_ADDRESS)  # Write Stack Address

    def setup_stack(self):
        log.debug('emulating stack')
        self.mu.mem_write(self.STACK_ADDRESS + 4, struct.pack('<I', self.DATA_ADDRESS))     # Set Address of Packed Code
        self.mu.mem_write(self.STACK_ADDRESS + 8, struct.pack('<I', len(self.PACKED_CODE))) # Set Size of Packed Code
        self.mu.mem_write(self.STACK_ADDRESS + 0xc, struct.pack('<I', 0x400))               # Set the Key

    def hook_code(self, uc, address, size, user_data):
        for i in self.md.disasm(uc.mem_read(address, size), address):
            if i.mnemonic == 'ret':
                uc.emu_stop()

    def setup_hooks(self):
        log.debug('setting up emulator hooks')
        self.mu.hook_add(UC_HOOK_CODE, self.hook_code)

    def setup_emulator(self):
        log.debug('setting up emulator')
        self.mu          = Uc(UC_ARCH_X86, UC_MODE_32)
        self.md          = Cs(CS_ARCH_X86, CS_MODE_32)
        self.CODE        = self.get_matches(self.matches, 'decrypt_routine_0')[0][2]
        self.PACKED_CODE = self.extract_packed_code(self.data, self.matches)
        self.setup_memory()
        self.setup_stack()
        self.setup_hooks()

    def extract_encrypted_config(self):
        log.debug('extracting encrytped config')
        config_addr_data = self.get_matches(self.matches, 'config_0')[0][2]
        config_va = struct.unpack('<I', config_addr_data[14:18])[0]
        pe = pefile.PE(data=self.data)
        config_rva = config_va - pe.OPTIONAL_HEADER.ImageBase
        config_data = self.data[config_rva:config_rva+681]
        log.debug('extracted encrypted config')
        return config_data

    def setup_config_decryptor(self, config_data, code, key):
        log.debug('emulating memory')
        self.BASE_ADDRESS  = 0x400000
        self.STACK_ADDRESS = 0x410000
        self.DATA_ADDRESS  = 0x420000
        self.mu.mem_write(self.BASE_ADDRESS, code)             # Write Decryption Routine Code
        self.mu.mem_write(self.DATA_ADDRESS, config_data)      # Write Encrypted Data
        self.mu.reg_write(UC_X86_REG_ESP, self.STACK_ADDRESS)  # Write Stack Address
        log.debug('emulating stack')
        self.mu.mem_write(self.STACK_ADDRESS + 4, struct.pack('<I', self.DATA_ADDRESS)) # Set Address of Packed Code
        self.mu.mem_write(self.STACK_ADDRESS + 8, struct.pack('<I', len(config_data)))  # Set Size of Packed Code
        self.mu.mem_write(self.STACK_ADDRESS + 0xc, struct.pack('<I', key))             # Set the Key
        log.debug('emulating hooks')
        self.mu.hook_add(UC_HOOK_CODE, self.hook_code)

    def main(self):
        config_encrypted = self.extract_encrypted_config()
        config_encrypted = re.sub(br'\x00+', b'\x00', config_encrypted)
        config_encrypted = config_encrypted.split(b'\x00')
        self.setup_emulator()
        log.debug('emulation started')
        self.mu.emu_start(self.BASE_ADDRESS, self.BASE_ADDRESS + len(self.CODE))
        log.debug('emulation completed')
        unpacked = self.mu.mem_read(self.DATA_ADDRESS, len(self.PACKED_CODE))
        if unpacked is not None:
            log.debug('succesfully unpacked binary')
            task = Task(
                headers={
                    "type": "sample",
                    "kind": "raw"
                },
                payload={
                    "parent": Resource(name='sample', content=self.data),
                    "sample": Resource(name='unpacked', content=bytes(unpacked))
                }
            )
            return [task]
        return []

if __name__ in '__main__':
    parser = argparse.ArgumentParser(
        prog='fatalrat.py',
        description=f'Karton Unpacker Service Example Module v{__version__} (CLI Test Utility)',
        epilog=f'Author: {__author__}'
    )
    parser.add_argument('-i','--input', help='Input File', type=str, required=True)
    parser.add_argument('--debug', help='Debug', action="store_true", default=False, required=False)
    args = parser.parse_args()
    f = open(args.input, 'rb')
    sample = Resource(name=args.input, content=f.read())
    f.close()
    module = KartonUnpackerModule(
        sample,
        {
            'debug': args.debug
        }
    )
    if module.enabled is True:
        log.debug('unpacking started')
        task = module.main()
        data = json.loads(str(task))
        print(json.dumps(data, indent=4))
