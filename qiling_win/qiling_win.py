#!/usr/bin/env python

import os
import sys
import yara
import json
import pefile
import logging
import tempfile
import argparse
import ctypes
import struct
from qiling import *
from qiling.const import *
from qiling.exception import *
from qiling.os.const import *
from qiling.os.windows.const import *
from qiling.os.windows.fncc import *
from qiling.os.windows.handle import *
from qiling.os.windows.thread import *
from qiling.os.windows.utils import *
from qiling.os.windows.structs import *
from karton.core import Karton, Task, Resource

log = logging.getLogger(__name__)

logging.basicConfig(level=logging.DEBUG)

__author__  = "c3rb3ru5"
__version__ = "1.0.0"

memory      = []
dumps       = []
kernel32    = 'kernel32_dll'
ntdll       = 'ntdll_dll'
user32      = 'user32_dll'

def dump_executable_memory(self, ql, memory) -> bool:
    """
    Dumps Executable Memory
    """
    if len(memory) > 0:
        for block in memory:
            if block['flProtect'] in [PAGE_EXECUTE, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY]:
                try:
                    dumps.append(ql.mem.read(block['address'], block['size']))
                    dumps = list(set(dumps))
                except Exception as error:
                    log.error(f'unable to read address {address} with size {size}')
                    False
    return True

# Preprocessor Definitions

PAGE_EXECUTE           = 0x10
PAGE_EXECUTE_READ      = 0x20
PAGE_EXECUTE_READWRITE = 0x40
PAGE_EXECUTE_WRITECOPY = 0x80
PAGE_NOACCESS          = 0x01
PAGE_READONLY          = 0x02
PAGE_READWRITE         = 0x04
PAGE_WRITECOPY         = 0x08
PAGE_TARGETS_INVALID   = 0x40000000
PAGE_TARGETS_NO_UPDATE = 0x40000000

# Data Structures

class ProcessInformation(WindowsStruct):
    """
    typedef struct _PROCESS_INFORMATION {
    HANDLE hProcess;
    HANDLE hThread;
    DWORD  dwProcessId;
    DWORD  dwThreadId;
    } PROCESS_INFORMATION, *PPROCESS_INFORMATION, *LPPROCESS_INFORMATION;
    """
    def __init__(self, ql, hProcess=None, hThread=None, dwProcessId=None, dwThreadId=None):
        super().__init__(ql)
        self.hProcess    = [hProcess, self.POINTER_SIZE, 'little', int],
        self.hThread     = [hThread, self.POINTER_SIZE, 'little', int]
        self.dwProcessId = [dwProcessId, self.DWORD_SIZE, 'little', int]
        self.dwThreadId  = [dwThreadId, self.DWORD_SIZE, 'little', int]

def create_hooks(ql):
    # Create Windows API Hooks
    ql.set_api("VirtualAlloc", hook_VirtualAlloc)
    ql.set_api("VirtualAllocEx", hook_VirtualAllocEx)
    ql.set_api("VirtualProtect", hook_VirtualProtect)
    ql.set_api("VirtualFree", hook_VirtualFree)
    ql.set_api("memcpy", hook_memcpy)
    ql.set_api("WriteProcessMemory", hook_WriteProcessMemory)
    ql.set_api("Sleep", hook_Sleep)
    ql.set_api("CreateProcessA", hook_CreateProcessA)
    ql.set_api("IsDebuggerPresent", hook_IsDebuggerPresent)

# Anti-Anti Debug
@winsdkapi(cc=STDCALL, dllname=kernel32)
def hook_Sleep(ql, address, params):
    if params['dwMilliseconds'] > 30000:
        ql.log.info('long kernel32.Sleep detected, continuing...')
    return 0

@winsdkapi(cc=STDCALL, dllname=kernel32)
def hook_IsDebuggerPresent(ql, address, params):
    ql.log.info('process called kernel32.IsDebuggerPresent, returning 0')
    return 0

# @winsdkapi(cc=STDCALL, dllname=kernel32)
# def hook_CreateProcessA(ql, address, params):
#     CREATE_SUSPENDED = 0x00000004
#     if params['dwCreationFlags'] & CREATE_SUSPENDED == CREATE_SUSPENDED:
#         thread_status = QlWindowsThread.READY
#     else:
#         thread_status = QlWindowsThread.RUNNING
#     new_thread = QlWindowsThread(ql)
#     ql.os.thread_manager.append(thread)
#     thread_id = new_thread.create(
#         lpStartAddress,
#         0x0,
#         thread_status
#     )
#     params['lpProcessInformation'] = ProcessInformation(hProcess=hProcess, hThread=hThread, dwProcessId=CreateProcessId(), dwThreadId=CreateThreadId())
#     data = {
#         'library': 'kernel32',
#         'function': 'CreateProcessA',
#         'params': params
#     }
#     print(json.dumps(data, indent=4))

# Memory Operations

@winsdkapi(cc=STDCALL, dllname=kernel32)
def hook_VirtualAlloc(ql, address, params):
    addr = ql.os.heap.alloc(params["dwSize"])
    memory.append({'address': addr, 'size': params['dwSize'], 'flProtect': params['flProtect']})
    ql.log.debug(json.dumps({'library': 'kernel32','function': 'VirtualAlloc','params': params}))
    return addr

@winsdkapi(cc=STDCALL, dllname="kernel32_dll")
def hook_VirtualAllocEx(ql, address, params):
    addr = ql.os.heap.alloc(params['dwSize'])
    memory.append({'address': addr, 'size': params['dwSize'], 'flProtect': params['flProtect']})
    ql.log.debug(json.dumps({'library': 'kernel32','function': 'VirtualAllocEx','params': params}))
    return addr

@winsdkapi(cc=STDCALL, dllname=kernel32)
def hook_WriteProcessMemory(ql, address, params):
    try:
        ql.log.debug(json.dumps({'library': 'kernel32','function': 'WriteProcessMemory','params': params}))
        data = bytes(ql.mem.read(params['lpBuffer'], params['nSize']))
        ql.mem.write(params['lpBaseAddress'], data)
        param['lpNumberOfBytesWritten'] = params['nSize']
        return 1
    except Exception as error:
        ql.log.exception(error)
        return 0

@winsdkapi(cc=CDECL, dllname=ntdll, replace_params={"dest": POINTER, "src": POINTER, "count": UINT})
def hook_memcpy(ql, address, params):
    ql.log.debug(json.dumps({'library': 'ntdll','function': 'memcpy','params': params}))
    try:
        data = bytes(ql.mem.read(params['src'], params['count']))
        ql.mem.write(params['dest'], data)
    except Exception as e:
        ql.log.exception("")
    return params['dest']

@winsdkapi(cc=STDCALL, dllname=kernel32, replace_params_type={'SIZE_T': 'UINT', 'DWORD': 'UINT'})
def hook_VirtualProtect(ql, address, params):
    memory.append({'address': params['lpAddress'], 'size': params['dwSize'], 'flNewProtect': params['flNewProtect']})
    ql.log.debug(json.dumps({'library': 'kernel32','function': 'VirtualProtect','params': params}))
    return 1

# Memory Extraction Trigger Functions

@winsdkapi(cc=STDCALL, dllname=kernel32)
def hook_VirtualFree(ql, address, params):
    ql.log.debug(json.dumps({'library': 'kernel32','function': 'VirtualFree','params': params}))
    dumps.append()
    dump_executable_memory(ql, memory)
    ql.log.debug('---MEMORY-DUMPS---')
    ql.log.debug(dumps)
    ql.log.debug('---MEMORY-DUMPS---')
    ql.os.heap.free(params['lpAddress'])
    return 1

@winsdkapi(cc=STDCALL, dllname=kernel32)
def hook_CreateRemoteThread(ql, address, params):
    ql.log.debug(json.dumps({'library': 'kernel32','function': 'CreateRemoteThread','params': params}))
    dump_executable_memory(ql, memory)
    ql.log.debug('---MEMORY-DUMPS---')
    ql.log.debug(dumps)
    ql.log.debug('---MEMORY-DUMPS---')
    return 1

@winsdkapi(cc=STDCALL, dllname=user32)
def hook_EnumWindows(ql, address, params):
    ql.log.debug(json.dumps({'library', 'user32', 'function': 'EnumWindows', 'params': params}))
    dump_executable_memory(ql, memory)
    ql.log.debug('---MEMORY-DUMPS---')
    ql.log.debug(dumps)
    ql.log.debug('---MEMORY-DUMPS---')
    return 1

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
                ql.run(timeout=50000)
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
                ql.run(timeout=5000)
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
