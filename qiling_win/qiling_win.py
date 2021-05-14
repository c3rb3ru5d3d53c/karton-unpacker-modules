#!/usr/bin/env python

import os
import sys
import yara
import json
import time
import signal
import ctypes
import struct
import pefile
import hexdump
import logging
import tempfile
import argparse
import capstone
import hashlib
from qiling import *
from io import BytesIO
from qiling.const import *
from qiling.exception import *
from qiling.os.const import *
from qiling.os.windows.const import *
from qiling.os.windows.fncc import *
from qiling.os.windows.handle import *
from qiling.os.windows.thread import *
from qiling.os.windows.utils import *
from qiling.os.windows.structs import *
from contextlib import contextmanager

from karton.core import Karton, Task, Resource

log = logging.getLogger(__name__)

__author__  = "c3rb3ru5"
__version__ = "1.0.0"

memory       = []
memory_dumps = []
kernel32     = 'kernel32_dll'
ntdll        = 'ntdll_dll'
user32       = 'user32_dll'
md32         = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
md64         = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)

def raise_timeout(signum, frame):
    raise TimeoutError

@contextmanager
def timeout(time):
    signal.signal(signal.SIGALRM, raise_timeout)
    signal.alarm(time)
    try:
        yield
    except TimeoutError:
        pass
    finally:
        signal.signal(signal.SIGALRM, signal.SIG_IGN)

def dump_executable_memory(ql) -> bool:
    """
    Dumps Executable Memory
    """
    for block in memory:
        if block['flProtect'] in [PAGE_EXECUTE, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY]:
            memory_dumps.append(ql.mem.read(block['address'], block['size']))
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

class ExceptionRecord(WindowsStruct):
    """
    typedef struct _EXCEPTION_RECORD {
    DWORD                    ExceptionCode;
    DWORD                    ExceptionFlags;
    struct _EXCEPTION_RECORD *ExceptionRecord;
    PVOID                    ExceptionAddress;
    DWORD                    NumberParameters;
    ULONG_PTR                ExceptionInformation[EXCEPTION_MAXIMUM_PARAMETERS];
    } EXCEPTION_RECORD;
    """
    def __init__(self, ql, ExceptionCode=None,
        ExceptionFlags=None, ExceptionRecord=None,
        ExceptionAddress=None, NumberParameters=None,
        ExceptionInformation=None):
        super().__init__(ql)
        self.ExceptionCode = [ExceptionCode, self.DWORD_SIZE, 'little', int]
        self.ExceptionFlags = [ExceptionFlags, self.DWORD_SIZE, 'little', int]
        self.ExceptionRecord = [ExceptionRecord, self.POINTER_SIZE, 'little', int]
        self.ExceptionAddress = [ExceptionAddress, self.POINTER_SIZE, 'little', int]
        self.NumberParameters = [NumberParameters, self.DWORD_SIZE, 'little', int]
        self.ExceptionInformation = [ExceptionInformation, self.POINTER_SIZE, 'little', int]

def hook_apis(ql):
    """
    Create Windows API Hooks
    """
    ql.set_api("VirtualAlloc", hook_VirtualAlloc)
    ql.set_api("VirtualAllocEx", hook_VirtualAllocEx)
    ql.set_api("VirtualProtect", hook_VirtualProtect)
    ql.set_api("VirtualFree", hook_VirtualFree)
    ql.set_api("memcpy", hook_memcpy)
    ql.set_api("WriteProcessMemory", hook_WriteProcessMemory)
    ql.set_api("EnumWindows", hook_EnumWindows)
    ql.set_api("CopyMemory", hook_CopyMemory)
    # Anti-Anti Debug
    ql.set_api("Sleep", hook_Sleep)
    ql.set_api("IsDebuggerPresent", hook_IsDebuggerPresent)
    # Supporting Functions
    ql.set_api("RtlUnwindEx", hook_RtlUnwindEx)
    ql.set_api("RtlVirtualUnwind", hook_RtlVirtualUnwind)
    ql.set_api("RtlLookupFunctionEntry", hook_RtlLookupFunctionEntry)

# Anti-Anti Debug Function Hooks
@winsdkapi(cc=STDCALL, dllname=kernel32)
def hook_Sleep(ql, address, params):
    if params['dwMilliseconds'] > 30000:
        ql.log.info('long kernel32.Sleep detected, continuing...')
    return 0

@winsdkapi(cc=STDCALL, dllname=kernel32)
def hook_IsDebuggerPresent(ql, address, params):
    ql.log.info('process called kernel32.IsDebuggerPresent, returning 0')
    return 0

# Supporting Functions

@winsdkapi(cc=STDCALL, dllname=kernel32)
def hook_RtlUnwindEx(ql, address, params):
    return 0

@winsdkapi(cc=STDCALL, dllname=kernel32)
def hook_RtlVirtualUnwind(ql, address, params):
    return 0

@winsdkapi(cc=STDCALL, dllname=kernel32)
def hook_RtlLookupFunctionEntry(ql, address, params):
    return 0

# Suspicious Memory Functions

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

@winsdkapi(cc=STDCALL, dllname=kernel32, replace_params_type={'SIZE_T': 'UINT', 'DWORD': 'UINT'})
def hook_VirtualProtect(ql, address, params):
    memory.append({'address': params['lpAddress'], 'size': params['dwSize'], 'flNewProtect': params['flNewProtect']})
    ql.log.debug(json.dumps({'library': 'kernel32','function': 'VirtualProtect','params': params}))
    return 1

# Memory Extraction Trigger Functions

def hook_asm_x86(ql, address, size):
    """
    Hooks Suspicious x86 Assembly Instructions to Trigger Memory Extraction
    """
    buf = ql.mem.read(address, size)
    for i in md32.disasm(buf, address):
        # Dump Memory on Suspicious Direct Call to EAX
        if (i.mnemonic == 'call' and i.op_str == 'eax'):
            dump_executable_memory(ql)
            ql.log.debug('MEMORY_DUMP_COUNT: {memory_dump_count}'.format(memory_dump_count=len(memory_dumps)))

def hook_asm_x64(ql, address, size):
    """
    Hooks Suspicious x64 Assembly Instructions to Trigger Memory Extraction
    """
    buf = ql.mem.read(address, size)
    for i in md64.disasm(buf, address):
        # Dump Memory on Suspicious Direct Call to RAX
        if (i.mnemonic == 'call' and i.op_str == 'rax'):
            dump_executable_memory(ql)
            ql.log.debug('MEMORY_DUMP_COUNT: {memory_dump_count}'.format(memory_dump_count=len(memory_dumps)))

@winsdkapi(cc=CDECL, dllname=ntdll, replace_params={"dest": POINTER, "src": POINTER, "count": UINT})
def hook_memcpy(ql, address, params):
    ql.log.debug(json.dumps({'library': 'ntdll','function': 'memcpy','params': params}))
    try:
        data = bytes(ql.mem.read(params['src'], params['count']))
        ql.mem.write(params['dest'], data)
    except Exception as e:
        ql.log.exception("")
    dump_executable_memory(ql)
    ql.log.debug('MEMORY_DUMP_COUNT: {memory_dump_count}'.format(memory_dump_count=len(memory_dumps)))
    return params['dest']

@winsdkapi(cc=STDCALL, dllname=kernel32)
def hook_CopyMemory(ql, address, params):
    ql.log.debug(json.dumps({'library': 'kernel32','function': 'CopyMemory','params': params}))
    try:
        data = bytes(ql.mem.read(params['Source'], params['Length']))
        ql.mem.write(params['Destination'], data)
    except Exception as error:
        ql.log.error(error)
    dump_executable_memory(ql)
    ql.log.debug('MEMORY_DUMP_COUNT: {memory_dump_count}'.format(memory_dump_count=len(memory_dumps)))
    return params['Destination']

@winsdkapi(cc=STDCALL, dllname=kernel32)
def hook_VirtualFree(ql, address, params):
    ql.log.debug(json.dumps({'library': 'kernel32','function': 'VirtualFree','params': params}))
    dumps.append()
    dump_executable_memory(ql)
    ql.log.debug('MEMORY_DUMP_COUNT: {memory_dump_count}'.format(memory_dump_count=len(memory_dumps)))
    ql.os.heap.free(params['lpAddress'])
    return 1

@winsdkapi(cc=STDCALL, dllname=kernel32)
def hook_CreateRemoteThread(ql, address, params):
    ql.log.debug(json.dumps({'library': 'kernel32','function': 'CreateRemoteThread','params': params}))
    dump_executable_memory(ql)
    ql.log.debug('MEMORY_DUMP_COUNT: {memory_dump_count}'.format(memory_dump_count=len(memory_dumps)))
    return 1

@winsdkapi(cc=STDCALL, dllname=user32)
def hook_EnumWindows(ql, address, params):
    ql.log.debug(json.dumps({'library': 'user32', 'function': 'EnumWindows', 'params': params}))
    dump_executable_memory(ql)
    ql.log.debug('MEMORY_DUMP_COUNT: {memory_dump_count}'.format(memory_dump_count=len(memory_dumps)))
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

    def __init__(self, sample, config) -> None:
        self.enabled = self.yara_check(sample)
        self.config = config
        if self.config['rootfs'] is None:
            log.warn("rootfs is disabled, qiling_win unpacker disabled")
            self.enabled = False
        if self.config['debug'] is True:
            logging.basicConfig(level=logging.DEBUG)
            self.verbose = 4
        else:
            logging.basicConfig(level=logging.INFO)
            self.verbose = 0

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
        sample_packed = tempfile.NamedTemporaryFile(delete=False)
        f = open(sample_packed.name, 'wb')
        f.write(self.data)
        f.close()
        return sample_packed.name

    def delete_sample_tempfile(self, file_path):
        if os.path.isfile(file_path):
            os.remove(file_path)

    def get_tasks(self):
        global memory_dumps
        self.memory_dump_cleanup()
        tasks = []
        if len(memory_dumps) <= 0:
            return tasks
        log.info("Successfully Extracted {memory_dumps_count} Suspicious Memory Dump(s)".format(memory_dumps_count=len(memory_dumps)))
        for memory_dump in memory_dumps:
            if self.config['debug'] is True:
                log.debug('EXTRACTED_PAYLOAD:')
                hexdump.hexdump(memory_dump)
            tasks.append(Task(
                headers=self.get_headers(memory_dump),
                payload={
                    'parent': Resource(name='sample', content=self.data),
                    'sample': Resource(name='unpacked', content=memory_dump)
                }
            ))
        return tasks

    def get_headers(self, memory_dump):
        headers = {
            'type': 'sample',
            'kind': 'runnable',
            'stage': 'recognized'
        }
        yarac = yara.compile(source=yara_rule_is_pe)
        matches = yarac.match(data=memory_dump)
        if matches:
            pe = pefile.PE(BytesIO(memory_dump))
            if hex(pe.FILE_HEADER.Machine) == '0x14c':
                headers['platform'] = 'win32'
            if hex(pe.FILE_HEADER.Machine) == '0x8664':
                headers['platform'] = 'win64'
        return headers

    def memory_dump_cleanup(self):
        """
        Converts Bytearrays to Bytes and Dedups Array
        """
        global memory_dumps
        for i in range(0, len(memory_dumps)):
            memory_dumps[i] = bytes(memory_dumps[i])
        memory_dumps = list(set(memory_dumps))

    def main(self) -> list:
        sample_packed = self.write_sample_tempfile()
        pe = pefile.PE(sample_packed)
        if hex(pe.FILE_HEADER.Machine) == '0x14c':
            # 32-bit Binay
            with timeout(self.config['timeout']):
                try:
                    log.info(f"starting analysis of win32 executable {self.name}")
                    ql = Qiling(
                        argv=[sample_packed],
                        rootfs=self.config['rootfs'] + '/x86_windows',
                        multithread=False,
                        console=False,
                        log_override=log,
                        verbose=self.verbose
                    )
                    hook_apis(ql)
                    ql.hook_code(hook_asm_x86)
                    ql.run(timeout=self.config['emulator_timeout'])
                except Exception as error:
                    log.error(error)
        if hex(pe.FILE_HEADER.Machine) == '0x8664':
            # 64-bit Binary
            with timeout(self.config['timeout']):
                try:
                    log.info(f"starting analysis of win64 executable {self.name}")
                    ql = Qiling(
                        argv=[sample_packed],
                        rootfs=self.config['rootfs'] + '/x86_windows',
                        multithread=False,
                        console=False,
                        log_override=log,
                        verbose=self.verbose
                    )
                    hook_apis(ql)
                    ql.hook_code(hook_asm_x64)
                    ql.run(timeout=self.config['emulator_timeout'])
                except Exception as error:
                    log.error(error)
        self.delete_sample_tempfile(sample_packed)
        return self.get_tasks()

if __name__ in '__main__':
    parser = argparse.ArgumentParser(
        prog='qiling_win.py',
        description=f'Karton Windows Unpacker Service module v{__version__} powered by Qiling Framework (CLI Test Utility)',
        epilog=f'Author: {__author__}'
    )
    parser.add_argument('--input', help='Input File', type=str, required=True)
    parser.add_argument('--emulator-timeout', help="Emulator Timeout", type=int, default=5000, required=False)
    parser.add_argument('--timeout', help='Task Timeout', type=int, default=30, required=False)
    parser.add_argument('--debug', help='Debug', action='store_true', default=True, required=False)
    parser.add_argument('--rootfs', help='RootFS', type=str, default=None, required=True)
    args = parser.parse_args()
    config = {
            'rootfs': args.rootfs,
            'emulator_timeout': args.emulator_timeout,
            'timeout': args.timeout,
            'debug': args.debug
    }
    f = open(args.input, 'rb')
    sample = Resource(name=args.input, content=f.read())
    f.close()
    module = KartonUnpackerModule(sample=sample, config=config)
    if module.enabled is True:
        tasks = module.main()
        for task in tasks:
            data = json.loads(str(task))
            print(json.dumps(data, indent=4))

# Works in Progress
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
