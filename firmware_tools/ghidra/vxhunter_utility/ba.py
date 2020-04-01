import os
import struct as st
import subprocess
import math
import sys
from difflib import SequenceMatcher

# VxWorks versions supported
SUPPORTED_VX_VERSIONS = [5, 6]

# Symbol types for VxWorks 5.5
VX5_SYM_TYPES = [
    0x03,  # Global Absolute
    0x04,  # Local .text
    0x05,  # Global .text
    0x06,  # Local Data
    0x07,  # Global Data
    0x08,  # Local BSS
    0x09,  # Global BSS
    0x12,  # Local Common symbol
    0x13,  # Global Common symbol
    0x40,  # Local Symbols related to a PowerPC SDA section
    0x41,  # Global Symbols related to a PowerPC SDA section
    0x80,  # Local symbols related to a PowerPC SDA2 section
    0x81,  # Local symbols related to a PowerPC SDA2 section
]

# Symbol types for VxWorks 6.8
VX6_SYM_TYPES = [
    0x03,  # Global Absolute
    0x04,  # Local .text
    0x05,  # Global .text
    0x08,  # Local Data
    0x09,  # Global Data
    0x10,  # Local BSS
    0x11,  # Global BSS
    0x20,  # Local Common symbol
    0x21,  # Global Common symbol
    0x40,  # Local Symbols
    0x41,  # Global Symbols
]

# Some known VxWorks base addresses to check before perform base-address finding algorithm
KNOWN_BASE_ADDRS = [
    0x80002000, 
    0x10000, 
    0x1000, 
    0xf2003fe4, 
    0x100000, 
    0x107fe0
]

# The amount of entries in a candidate symbol table needed for it to be chosen as the actual symbol table
SYMTAB_MIN_COUNT = 100


def log(s, logger, verbose):
    if not verbose:
        return

    # TODO: Figure out how to make this formatting not look weird
    if logger is None: print(s)
    else:              logger.info(s)



def get_symbol_fmt(endy_str, word_size_str, vx_ver):
    '''
    Return the `struct` format for the symbol struct depending on the VxWorks version and the size of said struct.
    Note: This function assumes that `vx_ver` has already been validated.
    '''
    if vx_ver == 5: fmt = endy_str + (word_size_str * 3) + 'H' + 'BB'
    else:           fmt = endy_str + (word_size_str * 4) + 'H' + 'BB'

    return fmt, st.calcsize(fmt)



def get_ptr_fmt(endy_str, word_size_str, vx_ver):
    '''
    Return the `struct` format for the possible pointers depending on the VxWorks version and the size of said struct.
    Note: This function assumes that `vx_ver` has already been validated.
    '''
    if vx_ver == 5: fmt = endy_str + (word_size_str * 3)
    else:           fmt = endy_str + (word_size_str * 4)

    return fmt, st.calcsize(fmt)



def sym_dict(offset, name_ptr, val_ptr, grp, sym_type, null):
    return { 
        'name_addr': name_ptr, 
        'dest_addr': val_ptr, 
        'flag': sym_type, 
        'offset': offset 
    }



def is_sym_valid(sym_types, name_ptr, val_ptr, grp, sym_type, null):
    is_sym = True
    is_sym &= sym_type in sym_types # expect that the symbol type is in the list of symbol types for the vx version
    is_sym &= null == 0             # expect that the null struct-terminator is indeed null
    is_sym &= grp == 0              # expect that the symbol group is null
    is_sym &= name_ptr != 0         # expect that the symbol name is not null
    return is_sym



def parse_sym(data, offset, sym_st_fmt, sym_size, sym_types):
    '''
    Return a symbol dictionary and whether or not said symbol is valid for the current VxWorks version.
    '''
    fields = list(st.unpack(sym_st_fmt, data[offset : offset+sym_size]))

    # if the symbol is a VxWorks 6 symbol, delete the fourth field since it's not checked anyways
    if len(fields) == 7:
        del fields[3]

    # the first field doesn't matter either, trim it
    del fields[0]

    # return the symbol and whether or not it is valid
    return sym_dict(offset, *fields), is_sym_valid(sym_types, *fields)
    


def get_pointers(data, endy_str, word_size, vx_ver, verbose=False, logger=None):
    '''
    TODO: Find a better name for this function

    Return the candidate pointers and symbol table (if one is found). Works by scanning the file for valid
    symbols until 100 consecutive valid symbols are found. Then the rest of the symbol table is parsed.
    '''
    if vx_ver not in SUPPORTED_VX_VERSIONS:
        log('VxWorks version ', vx_ver, ' is currently not supported', logger, True)
        return {}, []

    word_size_str = ['B', 'H', 'I', 'Q'][int(math.log(word_size, 2))]

    sym_st_fmt, sym_st_size = get_symbol_fmt(endy_str, word_size_str, vx_ver)
    ptr_st_fmt, ptr_st_size = get_ptr_fmt(endy_str, word_size_str, vx_ver)

    if vx_ver == 5: sym_types = VX5_SYM_TYPES
    else:           sym_types = VX6_SYM_TYPES

    symtab_low = None # the lowest name_ptr address in the current candidate symbol table
    symtab_hi = None  # the highest name_ptr address in the current candidate symbol table

    ptrtab = set()
    symtab = []

    i = 0

    while i < len(data) - sym_st_size:
        ptrs = st.unpack(ptr_st_fmt, data[i : i+ptr_st_size])
        ptrtab.update(set(ptrs))

        sym, sym_valid = parse_sym(data, i, sym_st_fmt, sym_st_size, sym_types)

        # if the current symbol struct is not a valid symbol, only increment the cursor by `word_size` bytes
        # in case we are unaligned with the symbol table (this assumes the symbol table is word-aligned)
        if not sym_valid:
            symtab_low, symtab_hi = None, None
            symtab = []
            i += word_size
            continue

        # the name pointer must be within the bounds of the current symbol table
        sym_in_bounds = True
        name_addr = sym['name_addr']

        if symtab_low is not None and symtab_hi is not None:
            sym_in_bounds &= symtab_hi <= min(symtab_low, name_addr) + len(data)
            sym_in_bounds &= max(symtab_hi, name_addr) <= symtab_low + len(data)

        if not sym_in_bounds:
            symtab_low, symtab_hi = name_addr, name_addr
            symtab = [sym]

        # here, we have a valid symbol that is within the bounds of the current symbol table
        if symtab_low is not None and symtab_hi is not None:
            symtab_low = min(symtab_low, name_addr)
            symtab_hi = max(symtab_hi, name_addr)
        else:
            symtab_low, symtab_hi = name_addr, name_addr

        symtab.append(sym)

        # increase the cursor by the symbol size since we have a valid symbol
        i += sym_st_size

        # if we have 100 consecutive symbols, assume that this is indeed the symbol table
        if len(symtab) >= SYMTAB_MIN_COUNT:
            log('Symbol table found at 0x%08x' % symtab[0]['offset'], logger, verbose)
            break

    
    # throw out the candidate symbol table and return if it's below the threshold count
    if len(symtab) < SYMTAB_MIN_COUNT:
        return ptrtab, []
    
    # if we have a valid symbol table (at least 100 symbols), get the rest of the symbol table
    for i in range(i, len(data) - sym_st_size, sym_st_size):
        ptrs = st.unpack(ptr_st_fmt, data[i : i+ptr_st_size])
        ptrtab.update(set(ptrs))

        sym, sym_valid = parse_sym(data, i, sym_st_fmt, sym_st_size, sym_types)

        # once we have seen an invalid symbol, break out of the loop
        if not sym_valid:
            break

        symtab.append(sym)

    log('Symbol table ends at 0x%08x' % (i - sym_st_size), logger, verbose)

    return ptrtab, symtab



def get_strings(fname, n=8):
    '''
    Use the `strings` utility to return a mapping of string offset -> string for all strings of length >= n
    '''
    out = subprocess.check_output(['strings', '-n', str(n), '-o', fname])

    # python2/3 compat fix - python2 `check_output` returns a string while python3 returns bytes
    # Note: The process of splitting on newlines fails for things like embedded HTML so we'll lose some strings but it'll be good enough
    if sys.version_info[0] < 3: out = out.split('\n')[:-1]
    else:                       out = str(out)[2:-1].split('\\n')[:-1]

    out = [o.strip().split(' ') for o in out]

    return { int(o[0]): ' '.join(o[1:]) for o in out if len(o) >= 2 and o[0].isdigit() } 



class BAFinder(object):
    def __init__(self, fname, data, endy_str='<', word_size=4, vx_ver=6, verbose=False, logger=None, strlen=8, test_addr=None):
        '''
        Initialize the base finder object, find the strings, symbol table, and base address.

        fname:      The file name of the firmware on disk.
        data:       The contents of the firmware binary file.
        endy_str:   '<' or '>' depending on the endianness of the target arch.
        word_size:  The word size of the target arch (1, 2, 4, or 8).
        vx_ver:     5 or 6 depending on the target VxWorks version.
        verbose:    Whether or not to print logging/debugging info.
        logger:     Optional logger object.
        strlen:     Minimum length of strings to use in base-finding algorithm.
        test_addr:  A candidate base address to test. If this is not None,
                        the base-find algorithm is not performed.
        '''
        self.fname = fname
        self.data = data
        self.base_addr = 0
        self.symtab = []

        # Get a mapping of offset -> string for all strings of at least length 4
        self.all_strings = get_strings(self.fname, n=4)

        # Get the offsets of every string with at least length 8 (less false positives)
        self.strtab = { s[0] for s in self.all_strings.items() if len(s[1]) >= strlen }
        self.ptrtab, self.symtab = get_pointers(self.data, endy_str, word_size, vx_ver, verbose=verbose, logger=logger)

        # Don't go any farther if we're just testing a base address
        if test_addr is not None:
            self.base_addr = test_addr
            ref_ratio = self.get_ref_ratio()
            log('Base address of 0x%08x has a ref ratio of %.4f' % (test_addr, ref_ratio), logger, True)
            exit()

        # Check if any of the known base addresses are good matches before doing the base address finding algo
        for ba_cand in KNOWN_BASE_ADDRS:
            log('Trying base address of 0x%08x' % ba_cand, logger, verbose) 

            if self.is_base_addr_good(ba=ba_cand):
                log('Base address is 0x%08x' % ba_cand, logger, verbose)

                self.base_addr = ba_cand
                return

        # reset the reference ratio - this is a little ugly, will want to change later
        if hasattr(self, 'ref_ratio'):
            delattr(self, 'ref_ratio')

        # If we reached here, none of the known base addresses were a good match so we do the base finding algo

        # 1. Sort the pointers and string offsets
        self.strtab = sorted(self.strtab)
        self.ptrtab = sorted(self.ptrtab)

        # 2. Get the differences between consecutive elements
        strdiffs = [self.strtab[i] - self.strtab[i-1] for i in range(1, len(self.strtab))]
        ptrdiffs = [self.ptrtab[i] - self.ptrtab[i-1] for i in range(1, len(self.ptrtab))]

        # 3. Find the longest common substring between the diffs
        sm = SequenceMatcher(None, strdiffs, ptrdiffs)
        aidx, bidx, size = sm.find_longest_match(0, len(strdiffs), 0, len(ptrdiffs))

        # 4. Get the base address from the longest common substring
        self.base_addr = abs(self.ptrtab[bidx + 1] - self.strtab[aidx + 1])
        self.matching_substr_size = size

        log('Base address is 0x%08x' % ba_cand, logger, verbose)


    def is_base_addr_good(self, T=0.5, ba=None):
        '''
        Check to see if the base address is good. The criteria for good is that
        at least `T` percent of the strings at least `self.strlen` characters long
        are referenced.

        If `ba` is not None, we are testing an explicit base address, otherwise, we are
        testing `self.base_addr`.
        '''
        if ba is not None and hasattr(self, 'ref_ratio'):
            delattr(self, 'ref_ratio')
        else:
            ba = self.base_addr

        if hasattr(self, 'ref_ratio'):
            return self.ref_ratio

        strtab_reloc = { o + ba for o in self.strtab }
        self.ref_ratio = len(strtab_reloc.intersection(self.ptrtab)) / float(len(strtab_reloc))

        return self.ref_ratio > T


    def get_ref_ratio(self):
        '''
        Calculate, store, and return the ratio of strings in `self.strab` that are referenced
        with a base address of `self.base_addr`.
        '''
        if hasattr(self, 'ref_ratio'):
            return self.ref_ratio

        strtab_reloc = { o + self.base_addr for o in self.strtab }
        self.ref_ratio = len(strtab_reloc.intersection(self.ptrtab)) / float(len(strtab_reloc))

        return self.ref_ratio


    def get_symbol_table(self):
        '''
        Get the name for each symbol and return the VxWorks symbol table.
        '''
        # python2/3 things for getting strings
        if type(self.data) == str: 
            convert_fn = str
            null_terminator = '\x00'
        else:                      
            convert_fn = chr
            null_terminator = 0

        for i, sym in enumerate(self.symtab):
            # Check if "strings" already returned the name.
            try:
                self.symtab[i]['name'] = self.all_strings[sym['name_addr'] - self.base_addr]

            # Otherwise, get the ascii string at the name address.
            except KeyError:
                off = self.symtab[i]['name_addr'] - self.base_addr
                sym_name = ''

                while self.data[off] != null_terminator:
                    sym_name += convert_fn(self.data[off])
                    off += 1

                self.symtab[i]['name'] = sym_name

        return self.symtab


    def get_symbol_addr_clusters(self):
        '''
        Experimental function to create a memory map based on clusters of symbol addresses.
        Doesn't really work right now.
        '''
        # Sort the symbol table by destination address.
        self.symtab = sorted(self.symtab, key=lambda x: x['dest_addr'])

        regions = []

        for sym in self.symtab:
            a = sym['dest_addr']
            reg_idx = None

            for i, (lo, hi) in enumerate(regions):
                if a >= lo - 0x1000 and a <= hi + 0x1000:
                    reg_idx = i
                    break
            
            if reg_idx is None:
                print('Creating a new region for %s at 0x%08x' % (sym['name'], a))
                regions.append((a, a))

                # Keep the regions sorted by the lower bound.
                regions = sorted(regions, key=lambda r: r[0])
            else:
                lo, hi = regions[reg_idx]
                lo, hi = min(lo, a), max(lo, a)
                regions[reg_idx] = (lo, hi)

            # Coalesce the regions.
            reg_idx = 0
    
            while reg_idx < len(regions)-1:
                lo1, hi1 = regions[reg_idx]
                lo2, hi2 = regions[reg_idx+1]

                # If the consecutive regions are overlapping, create a unified region,
                # deleting the second region.
                if hi1 >= lo2:
                    regions[reg_idx] = (lo1, hi2)
                    del regions[reg_idx+1]
                    continue

                reg_idx += 1

        for lo, hi in regions:
            print('0x%08x - 0x%08x' % (lo, hi))


if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument('-e', dest='endy', type=str, default='little', help='Endianness of the binary (big or little)')
    parser.add_argument('-w', dest='word_size', type=int, default=4, help='Word size of the binary (1, 2, 4, or 8)')
    parser.add_argument('-t', dest='test_addr', type=lambda x: int(x, 16), default=None, help='A base address to test')
    parser.add_argument('-x', dest='vx_ver', type=int, default=6, help='VxWorks version (%s)' % ', '.join(map(str, SUPPORTED_VX_VERSIONS)))
    parser.add_argument('-n', dest='strlen', type=int, default=8, help='The min length for strings to reference')
    parser.add_argument('-v', dest='verbose', action='store_true', help='Whether or not to print out debugging info')
    parser.add_argument('fname', type=str, help='filename of the binary')
    args = parser.parse_args()

    if args.endy not in ['little', 'big']:
        print('Endianness must be "big" or "little"')
        exit()

    if args.word_size not in [1, 2, 4, 8]:
        print('Word size must be 1, 2, 4, or 8')
        exit()

    if args.vx_ver not in SUPPORTED_VX_VERSIONS:
        print('VxWorks version must be in ', SUPPORTED_VX_VERSIONS)
        exit()

    endy_str = ['<', '>'][['little', 'big'].index(args.endy)]

    with open(args.fname, 'rb') as f:
        data = f.read()

    baf = BAFinder(args.fname, 
                   data, 
                   endy_str=endy_str, 
                   word_size=args.word_size, 
                   vx_ver=args.vx_ver, 
                   verbose=args.verbose,
                   strlen=args.strlen,
                   test_addr=args.test_addr)

    symtab = baf.get_symbol_table()

    #baf.get_symbol_addr_clusters()

    print('Base Address: 0x%08x' % baf.base_addr)

    if hasattr(baf, 'matching_substr_size'):
        print('\tLongest common substring is %d diffs long' % baf.matching_substr_size)

    print('\tRatio of strings referenced: %.4f' % baf.get_ref_ratio())
    print('\t%d symbols found' % len(symtab))
