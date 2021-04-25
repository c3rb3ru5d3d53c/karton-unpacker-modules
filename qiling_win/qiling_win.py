#!/usr/bin/env python

import os
import sys
import yara
import json
import pefile
import logging
import tempfile
import argparse
from qiling import *
from qiling.const import *
from qiling.exception import *
from qiling.os.const import *
from qiling.os.windows.const import *
from qiling.os.windows.fncc import *
from qiling.os.windows.handle import *
from qiling.os.windows.thread import *
from qiling.os.windows.utils import *
from karton.core import Karton, Task, Resource

log = logging.getLogger(__name__)

__author__  = "c3rb3ru5"
__version__ = "1.0.0"

syscalls = []
memory   = []
kernel32 = 'kernel32_dll'
ntdll    = "ntdll_dll"

def create_hooks(ql):
    # Create Windows API Hooks
    ql.set_api("VirtualAlloc", hook_VirtualAlloc)
    ql.set_api("VirtualProtect", hook_VirtualProtect)
    ql.set_api("VirtualFree", hook_VirtualFree)
    ql.set_api("memcpy", hook_memcpy)
    ql.set_api("WriteProcessMemory", hook_WriteProcessMemory)
    ql.set_api("Sleep", hook_Sleep)

@winsdkapi(cc=STDCALL, dllname=kernel32)
def hook_Sleep(ql, address, params):
    # Anti-Anti-Debug 
    return 0

@winsdkapi(cc=STDCALL, dllname=kernel32)
def hook_VirtualAlloc(ql, address, params):
    addr = ql.os.heap.alloc(params["dwSize"])
    data =  {
        'library': 'kernel32',
        'function': 'VirtualAlloc',
        'params': params
    }
    print(json.dumps(data, indent=4))
    return addr

@winsdkapi(cc=STDCALL, dllname=kernel32, replace_params_type={'SIZE_T': 'UINT', 'DWORD': 'UINT'})
def hook_VirtualProtect(ql, address, params):
    data = {
        'library': 'kernel32',
        'function': 'VirtualProtect',
        'params': params
    }
    print(json.dumps(data, indent=4))
    return 1

@winsdkapi(cc=STDCALL, dllname=kernel32)
def hook_VirtualFree(ql, address, params):
    lpAddress = params["lpAddress"]
    ql.os.heap.free(lpAddress)
    data = {
        'library': 'kernel32',
        'function': 'VirtualFree',
        'params': params
    }
    print(json.dumps(data, indent=4))
    return 1

@winsdkapi(cc=STDCALL, dllname=kernel32)
def hook_WriteProcessMemory(ql, address, params):
    try:
        data = {
            'library': 'kernel32',
            'function': 'WriteProcessMemory',
            'params': params
        }
        print(json.dumps(data, indent=4))
        data = bytes(ql.mem.read(params['lpBuffer'], params['nSize']))
        ql.mem.write(params['lpBaseAddress'], data)
        param['lpNumberOfBytesWritten'] = params['nSize']
        return 1
    except Exception as error:
        ql.log.exception(error)
        return 0

@winsdkapi(cc=CDECL, dllname=ntdll, replace_params={"dest": POINTER, "src": POINTER, "count": UINT})
def hook_memcpy(ql, address, params):
    syscalls.append(
        {
            'library': 'ntdll',
            'function': 'memcpy',
            'params': params
        }
    )
    try:
        data = bytes(ql.mem.read(params['src'], params['count']))
        ql.mem.write(params['dest'], data)
    except Exception as e:
        ql.log.exception("")
    return params['dest']

logging.basicConfig(level=logging.DEBUG)

yara_rule_upx = """
rule upx{
    strings:
        $mz      = "MZ"
        $upx1    = {55505830000000}
        $upx2    = {55505831000000}
        $upx_sig = "UPX!"
    condition:
        $mz at 0 and
        $upx1 in (0..1024) and
        $upx2 in (0..1024) and
        $upx_sig in (0..1024)
}
"""

yara_rule_is_pe = """
rule pe{
    condition:
    uint16(0) == 0x5a4d and
    uint32(uint32(0x3c)) == 0x00004550
}
"""

class KartonUnpackerModule():

    """
    Unpacks Executables that Create Executable Memory using the Qiling Framework
    """

    def __init__(self, sample) -> None:
        self.enabled = self.yara_check(sample)

    def yara_check(self, sample) -> bool:
        self.data = sample.content
        self.name = sample.name
        yarac = yara.compile(source=yara_rule_upx)
        matches = yarac.match(data=self.data)
        if matches:
            return False
        yarac = yara.compile(source=yara_rule_is_pe)
        matches = yarac.match(data=self.data)
        if matches:
            return True
        return False

    def write_sample_tempfile(self):
        sample_packed = tempfile.mktemp()
        f = open(sample_packed, 'wb')
        f.write(self.data)
        f.close()
        return sample_packed

    def main(self) -> Task:
        sample_packed = self.write_sample_tempfile()
        pe = pefile.PE(sample_packed)
        if hex(pe.FILE_HEADER.Machine) == '0x14c':
            # 32-bit Binary
            try:
                log.info(f"starting analysis of win32 executable {self.name}")
                ql = Qiling(
                    argv=[sample_packed],
                    rootfs='/home/c3rb3ru5/Tools/titan-temufs' + '/x86_windows',
                    multithread=False,
                    console=False,
                    log_override=log,
                    verbose=4
                )
                create_hooks(ql)
                ql.run(timeout=1000)
            except Exception as error:
                log.error(error)
        if hex(pe.FILE_HEADER.Machine) == '0x8664':
            # 64-bit Binary
            try:
                log.info(f"starting analysis of win64 executable {self.name}")
                ql = Qiling(
                    argv=[sample_packed],
                    rootfs='/home/c3rb3ru5/Tools/titan-temufs' + '/x86_windows',
                    multithread=False,
                    console=False,
                    log_override=log,
                    verbose=0
                )
                create_hooks(ql)
                ql.run(timeout=1000)
            except Exception as error:
                log.error(error)
        return None

# return Task(
#     headers={
#         "type": "sample",
#         "kind": "raw"
#     },
#     payload={
#         "parent": Resource(name='sample', content=self.data),
#         "sample": child_resource
#     }
# )
        
if __name__ in '__main__':
    logging.basicConfig(level=logging.DEBUG)
    parser = argparse.ArgumentParser(
        prog='qiling_win.py',
        description=f'Karton Windows Unpacker Service module v{__version__} powered by Qiling Framework (CLI Test Utility)',
        epilog=f'Author: {__author__}'
    )
    parser.add_argument('-i','--input', help='Input File', type=str, required=True)
    parser.add_argument('-t', '--timeout', help="Timeout", type=int, default=2000, required=False)
    parser.add_argument('-d', '--debug', help='Debug', action='store_true', default=False, required=False)
    parser.add_argument('-r', '--rootfs', help='RootFS', type=str, default=None, required=False)
    args = parser.parse_args()
    f = open(args.input, 'rb')
    sample = Resource(name=args.input, content=f.read())
    f.close()
    module = KartonUnpackerModule(sample)
    if module.enabled is True:
        task = module.main()
        # data = json.loads(str(task))
        # print(json.dumps(data, indent=4))
