#!/usr/bin/env python

import os
import sys
import yara
import json
import logging
import tempfile
import argparse
from karton.core import Karton, Task, Resource
import subprocess

log = logging.getLogger(__name__)

__author__  = "c3rb3ru5"
__version__ = "3.96"

# YARA Signature to Detect UPX Packed Executables
yara_rule = """
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

class KartonUnpackerModule():

    """
    Unpacks UPX Executables for the Karton Unpacker Service
    """

    def __init__(self, sample, config) -> None:
        self.enabled = self.yara_check(sample)
        if self.config['debug'] is True:
            logging.basicConfig(level=logging.DEBUG)
        else:
            logging.basicConfig(level=logging.INFO)

    def yara_check(self, sample) -> bool:
        self.yara = yara.compile(source=yara_rule)
        self.data = sample.content
        self.name = sample.name
        matches = self.yara.match(data=self.data)
        if matches:
            log.info(f"{self.name} is a upx executable")
            return True
        return False

    def main(self) -> Task:
        log.info(f"upx unpacking {self.name}")
        upx = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'upx')
        sample_unpacked = tempfile.mktemp()
        sample_packed = tempfile.mktemp()
        f = open(sample_packed, 'wb')
        f.write(self.data)
        f.close()
        command = [upx, '-d', sample_packed, '-o', sample_unpacked]
        command = subprocess.list2cmdline(command)
        out = subprocess.getoutput(command)
        if os.path.exists(sample_packed):
                os.remove(sample_packed)
        if "Unpacked 1 file".lower() in out.lower():
            log.info(f"saved unpacked upx executable to {sample_unpacked}")
            f = open(sample_unpacked, 'rb')
            child_resource = Resource(name='unpacked', content=f.read())
            f.close()
            if os.path.exists(sample_unpacked):
                os.remove(sample_unpacked)
            return Task(
                headers={
                    "type": "sample",
                    "kind": "raw"
                },
                payload={
                    "parent": Resource(name='sample', content=self.data),
                    "sample": child_resource
                }
            )
            return [task]
        log.error(f"failed to unpack: {self.sample_packed.name}")
        return None
        
if __name__ in '__main__':
    logging.basicConfig(level=logging.DEBUG)
    parser = argparse.ArgumentParser(
        prog='upx.py',
        description=f'Karton Unpacker Service module for UPX v{__version__} (CLI Test Utility)',
        epilog=f'Author: {__author__}'
    )
    parser.add_argument('-i','--input', help='Input File', type=str, required=True)
    args = parser.parse_args()
    f = open(args.input, 'rb')
    sample = Resource(name=args.input, content=f.read())
    f.close()
    module = KartonUnpackerModule(sample)
    if module.enabled is True:
        task = module.main()
        data = json.loads(str(task))
        print(json.dumps(data, indent=4))
