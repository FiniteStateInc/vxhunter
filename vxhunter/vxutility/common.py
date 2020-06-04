import math
import re
import time
import string
import struct as st
import sys

from ghidra.program.model.mem import Memory
from ghidra.program.model.address import GenericAddress
from ghidra.util.task import TaskMonitor
from ghidra.program.flatapi import FlatProgramAPI
from ghidra.program.model.util import CodeUnitInsertionException

from __main__ import currentProgram, isRunningHeadless, askChoice, getScriptArgs

# Init Ghidra vars
cp = currentProgram
fp = FlatProgramAPI(cp)
mem = cp.memory

SUPPORTED_VX_VERSIONS = [5, 6]

# Init program metadata
word_size = cp.getDefaultPointerSize()
is_big_endian = cp.getLanguage().isBigEndian()

# Init struct formatting vars
endy_str = ['<', '>'][is_big_endian]
word_str = ['B', 'H', 'I', 'Q'][int(math.log(word_size, 2))]


def get_args():
    script_name = None
    vx_ver = None

    if isRunningHeadless():
        # Start by making sure we were passed a script name and a VxWorks version
        args = getScriptArgs()

        if len(args) < 2:
            print_err('Must pass a script name and a VxWorks version')
        else:
            # Make sure our VxWorks version is valid
            script_name = args[0]
            vx_ver = int(args[1])
    else:
        script_name = sys.argv[0]
        vx_ver = int(askChoice('Pick a VxWorks Version', '...if you dare!', SUPPORTED_VX_VERSIONS, SUPPORTED_VX_VERSIONS[0]))

    # Make sure our VxWorks version is 5 or 6
    if vx_ver not in SUPPORTED_VX_VERSIONS:
        print_err('VxWorks version must be in %s' % ', '.join([int(v) for v in SUPPORTED_VX_VERSIONS]), script_name)
        vx_ver = None

    return script_name, vx_ver


def print_out(msg, script_name=None):
    if script_name is not None:
        msg = '%s: %s' % (script_name, msg)

    msg += '\n'

    sys.stdout.write(msg)
    sys.stdout.flush()


def print_err(msg, script_name=None):
    if script_name is not None:
        msg = '%s: %s' % (script_name, msg)

    msg += '\n'

    sys.stderr.write(msg)
    sys.stderr.flush()


def is_offset_in_current_program(off):
    '''
    Return whether or not `off` is in a defined memory region.
    '''
    for block in cp.memory.blocks:
        if block.start.offset <= off <= block.end.offset:
            return True

    return False


def is_address_in_current_program(addr):
    '''
    Return whether or not `addr` is in a defined memory region.
    '''
    return is_offset_in_current_program(addr.offset)


def pack(val, signed=False, size=None):
    if size is None:
        size = word_size

    fmt = endy_str + ['B', 'H', 'I', 'Q'][int(math.log(size, 2))]

    if signed:
        fmt = fmt.lower()

    return st.pack(fmt, val)


def get_value(data, signed=False):
    '''
    Wrapper around `struck.unpack` with different options on size and whether
    to interpret at signed.
    '''

    # Get the struct format based on size and signed
    fmt = endy_str + ['B', 'H', 'I', 'Q'][int(math.log(len(data), 2))]

    if signed:
        fmt = fmt.lower()

    # Finally, interpret the data
    data = st.unpack(fmt, data)[0]

    return data


def get_value_from_addr(addr, size):
    '''
    Dereference an address in the current program.
    '''
    if not isinstance(addr, GenericAddress): addr = fp.toAddr(addr)
    return get_value(fp.getBytes(addr, size))


def read_data_at(addr, size):
    '''
    Read `size` bytes at address `addr`.
    '''
    if not isinstance(addr, GenericAddress): addr = fp.toAddr(addr)
    return fp.getBytes(addr, size)


def get_ascii_at(addr, maxlen=1000):
    s = ''
    ptr = fp.toAddr(addr.offset)

    while len(s) < maxlen:
        try:
            char = chr(fp.getBytes(ptr, 1)[0]) # read one byte at a time
        except:
            return None

        if char == '\x00':                 # break if it's a null terminator
            break
        
        if not char in string.printable:   # fail if the character isn't printable
            return None

        s += char
        ptr = ptr.add(1)

    return s


def maybe_define_string(addr):
    '''
    Try to define a string at `addr`.
    '''
    s = get_ascii_at(addr)
    
    if s is None or len(s) == 0: # don't define an empty string
        return None

    try:
        if fp.createAsciiString(addr, len(s)) is None: # try to create the string
            return None
    except CodeUnitInsertionException:
        return None

    return s


def maybe_get_string_at(addr):
    '''
    Get the string at `addr` or define one.
    '''
    if not isinstance(addr, GenericAddress): addr = fp.toAddr(addr)
    data = fp.getDataAt(addr)

    if data is None:
        return maybe_define_string(addr) # if no data is defined, try to define a string
    elif data.hasStringValue():
        return str(data.getValue())      # if a string is defined, return it
    else:
        return None                      # if other data is defined, return None


def get_string_from_addr(addr):
    '''
    Get the string defined at `addr` or the address if no string is defined.
    '''
    if not isinstance(addr, GenericAddress): addr = fp.toAddr(addr)
    s = maybe_get_string_at(addr)

    if s is None:
        s = '0x%08x' % addr.offset

    return s


def auto_analyze():
    '''
    Perform Ghidra auto-analysis.
    '''
    analyze(cp)


'''
Wrappers for manipulating memory regions through the Ghidra API.
'''

def do_memory_op(op, *args):
    try:
        res = op(*args)
        if res is None: 
            return True

        return res
    except:
        return False

def create_uninitialized_block(name, start, length, overlay=False):
    return do_memory_op(mem.createUninitializedBlock, name, start, length, overlay)

def create_initialized_block(name, start, length, fill=0, monitor=TaskMonitor.DUMMY, overlay=False):
    return do_memory_op(mem.createInitializedBlock, name, start, length, fill, monitor, overlay)

def move_block(block, addr, monitor=TaskMonitor.DUMMY):
    return do_memory_op(mem.moveBlock, block, addr, monitor)

def split_block(block, addr):
    return do_memory_op(mem.split, block, addr)

def split_main_memory(addr):
    return split_block(mem.blocks[0], addr)

def join_blocks(b1, b2):
    return do_memory_op(mem.join, b1, b2)

def remove_block(b):
    do_memory_op(mem.removeBlock, b, TaskMonitor.DUMMY)

def get_memory_blocks():
    return mem.blocks

def get_main_memory():
    if len(mem.blocks) == 0: return None
    return mem.blocks[0]

