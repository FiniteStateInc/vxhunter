# coding=utf-8
import logging

from vxhunter_core import VxTarget
from vxhunter_utility.common import *
from vxhunter_utility.symbol import add_symbol, fix_symbol_table_structs

from ghidra.util.task import TaskMonitor

# Logger setup
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
consolehandler = logging.StreamHandler()
console_format = logging.Formatter('[%(levelname)-8s][%(module)s] %(message)s')
consolehandler.setFormatter(console_format)
logger.addHandler(consolehandler)

# For https://github.com/VDOO-Connected-Trust/ghidra-pyi-generator
try:
    from ghidra_builtins import *

except Exception as err:
    pass

try:
    vx_version = askChoice("Choice", "Please choose VxWorks main Version ", ["5.x", "6.x"], "5.x")
    if vx_version == u"5.x":
        vx_version = 5

    elif vx_version == u"6.x":
        vx_version = 6

    if vx_version:
        firmware_path = currentProgram.domainFile.getMetadata()['Executable Location']
        firmware = open(firmware_path, 'rb').read()

        word_size = currentProgram.getDefaultPointerSize()
        big_endian = currentProgram.getLanguage().isBigEndian()

        # VxTarget's init will exit if a valid base address isn't found, therefore we don't have to check after here
        target = VxTarget(firmware_path=firmware_path, 
                          firmware=firmware, 
                          vx_version=vx_version, 
                          big_endian=big_endian, 
                          word_size=word_size)

        load_address = target.load_address

        # Rebase_image
        target_block = currentProgram.memory.blocks[0]
        address = toAddr(load_address)
        logger.debug("Rebasing. target_block: {}; load_address: {}".format(target_block, address))
        currentProgram.memory.moveBlock(target_block, address, TaskMonitor.DUMMY)

        # Create symbol table structs
        logger.debug("Creating symbol table.")
        symbol_table_start = target.symbol_table_start + target.load_address
        symbol_table_end = target.symbol_table_end + target.load_address
        fix_symbol_table_structs(symbol_table_start, symbol_table_end, vx_version)

        # Load symbols
        symbols = target.get_symbols()
        for symbol in symbols:
            try:
                symbol_name = symbol["name"]
                symbol_name_addr = symbol["name_addr"]
                symbol_dest_addr = symbol["dest_addr"]
                symbol_flag = symbol["flag"]
                add_symbol(symbol_name, symbol_name_addr, symbol_dest_addr, symbol_flag)

            except Exception as err:
                logger.error("add_symbol failed: {}".format(err))
                continue

except Exception as err:
    print(err)
