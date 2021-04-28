#!/usr/bin/env python

import yara
import signal
import logging
import argparse
from contextlib import contextmanager
from karton.core import Karton, Task, Resource

log = logging.getLogger(__name__)

__author__  = "c3rb3ru5"
__version__ = "1.0.0"

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

yara_rule_is_pe = """
rule pe{
    $mz = {5a 4d}
    $pe = {00 00 45 50}
    condition:
        uint16(0) == 0x5a4d and
        uint32(uint32(0x3c)) == 0x00004550 and
        @mz[1] @
        
}
"""

class KartonUnpackerModule():

    """
    A Karton Unpacker Module that Extracts Embedded Executables
    """

    def __init__(self, sample, config):
        self.enabled = self.yara_check(sample)
        self.config = config
        if self.config['debug'] is True:
            logging.basicConfig(level=logging.DEBUG)
        else:
            logging.basicConfig(level=logging.INFO)

    def yara_check(self, sample) -> bool:
        yarac = yara.compile(source=yara_rule_is_pe)
        self.data = sample.content
        self.name = sample.name
        self.matches = yarac.match(data=self.data)
        print(self.matches)
        if len(self.matches) > 1:
            log.info(f"{self.name} contains an embedded executable")
            return True
        return False

    def main(self) -> list:
        log.info()
        print("Hello World!")

if __name__ in '__main__':
    logging.basicConfig(level=logging.DEBUG)
    parser = argparse.ArgumentParser(
        prog='embedded.py',
        description=f'Karton Unpacker Service module for Embedded Executables v{__version__} (CLI Test Utility)',
        epilog=f'Author: {__author__}'
    )
    parser.add_argument('-i','--input', help='Input File', type=str, required=True)
    parser.add_argument('--timeout', help='Task Timeout', type=int, default=30, required=False)
    parser.add_argument('--debug', help='Debug', action='store_true', default=False, required=False)
    args = parser.parse_args()
    config = {
        'timeout': args.timeout,
        'debug': args.debug
    }
    f = open(args.input, 'rb')
    sample = Resource(name=args.input, content=f.read())
    f.close()
    module = KartonUnpackerModule(sample=sample, config=config)
    if module.enabled is True:
        task = module.main()
        data = json.loads(str(task))
        print(json.dumps(data, indent=4))
