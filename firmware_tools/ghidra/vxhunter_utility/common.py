# coding=utf-8
from ghidra.app.util.demangler import DemangledException
from ghidra.app.util.demangler.gnu import GnuDemangler
from ghidra.program.model.mem import Memory
from ghidra.util.task import TaskMonitor
from ghidra.program.flatapi import FlatProgramAPI
import struct as st
import logging
import time
import math
import re
import string

# The Python module that Ghidra directly launches is always called __main__.  If we import
# everything from that module, this module will behave as if Ghidra directly launched it.
from __main__ import *

debug = False

# Init Default Logger
def init_logger(logger):
    console_handler = logging.StreamHandler()
    console_format = logging.Formatter('[%(levelname)-8s][%(module)s.%(funcName)s] %(message)s')
    console_handler.setFormatter(console_format)

    logger.addHandler(console_handler)
    logger.setLevel(logging.INFO)

    if debug:
        logger.setLevel(logging.DEBUG)


logger = logging.getLogger('Default Logger')
init_logger(logger)

# Init Ghidra vars
cp = currentProgram
fp = FlatProgramAPI(cp)
mem = cp.memory

SPACE_RAM = 417

# Init program metadata
word_size = cp.getDefaultPointerSize()
is_big_endian = cp.getLanguage().isBigEndian()

# Init struct formatting vars
endy_str = ['<', '>'][is_big_endian]
word_str = ['B', 'H', 'I', 'Q'][int(math.log(word_size, 2))]

# Init bookmark vars
fs_bookmark_type = "fs-bookmark"
fs_bookmark_category = "fs-metadata"

# Demangler vars
demangler = GnuDemangler()
listing = cp.getListing()
can_demangle = demangler.canDemangle(cp)


def get_vxworks_version_from_user():
    '''
    Helper function to get the VxWorks version from the user.
    If the choice is valid, we mark the version in a comment at the base address
    so we don't have to ask again.
    '''
    version_choice = askChoice("Choice", 
                           "Please choose VxWorks main version ", 
                           ["5.x", "6.x"], 
                           "5.x")

    vx_version = None

    if version_choice == u"5.x":   vx_version = 5
    elif version_choice  == u"6.x": vx_version = 6
    else:
        logging.error('Unsupported VxWorks version: %s' % vx_version)

    if vx_version is not None:
        base = cp.getImageBase()
        bookmark_man = cp.getBookmarkManager()
        bookmark_man.setBookmark(base,
                                 fs_bookmark_type,
                                 fs_bookmark_category,
                                 'VxWorks version %d' % vx_version)

    return vx_version


def get_vxworks_version():
    '''
    Helper function to get the VxWorks version, either from an EOL comment
    at the first address or by asking the user.
    '''
    base = cp.getImageBase()
    bookmark_man = cp.getBookmarkManager()
    fs_bookmarks = bookmark_man.getBookmarks(base, fs_bookmark_type)

    if len(fs_bookmarks) == 0:
        return get_vxworks_version_from_user()

    # Make sure the comment matches the format we expect.
    version_re = re.compile('VxWorks version \d{1}')

    for bookmark in fs_bookmarks:
        if bookmark.getCategory() != fs_bookmark_category:
            continue

        comment = bookmark.getComment()
   
        if not version_re.match(comment):
            continue

        return int(comment.split(' ')[-1])
    
    # If we didn't find a matching comment, ask the user.
    return get_vxworks_version_from_user()


def is_address_in_current_program(addr):
    '''
    Return whether or not `addr` is in a defined memory region.
    '''
    for block in cp.memory.blocks:
        if block.start.offset <= addr.offset <= block.end.offset:
            return True

    return False


def get_value(data, signed=False, size=None):
    '''
    Wrapper around `struck.unpack` with different options on size and whether
    to interpret at signed.
    '''

    # Use `word_size` as a default size.
    if size is None:
        size = word_size 

    # Get the struct format based on size and signed
    fmt = endy_str + ['B', 'H', 'I', 'Q'][int(math.log(size, 2))]

    if signed:
        fmt = fmt.lower()

    # Finally, interpret the data
    data = st.unpack(fmt, data)[0]

    return data


def get_value_from_addr(addr, size):
    '''
    Dereference an address in the current program.
    '''
    return get_value(fp.getBytes(addr, size))


def maybe_define_string(addr):
    '''
    Try to define a string at `addr`.
    '''
    s = ''
    strlen = 0
    ptr = toAddr(addr.offset)

    while getDataAt(ptr) is None:
        char = chr(fp.getBytes(ptr, 1)[0]) # read one byte at a time

        if char == '\x00':                 # break if it's a null terminator
            break
        
        if not char in string.printable:   # fail if the character isn't printable
            return None

        s += char
        strlen += 1
        ptr = ptr.add(1)

    if createAsciiString(addr, strlen) is None: # try to create the string
        return None

    return s


def maybe_get_string_at(addr):
    '''
    Get the string at `addr` or define one.
    '''
    data = getDataAt(addr)

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
    s = maybe_get_string_at(addr)

    if s is None:
        s = '0x%08x' % addr.offset

    return s



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
    return split_block(cp.memory.blocks[0], addr)


def join_blocks(b1, b2):
    return do_memory_op(mem.join, b1, b2)

