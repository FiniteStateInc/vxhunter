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

# Symbol struct size for VxWorks 5/6
VX5_SYM_SIZE = 16
VX6_SYM_SIZE = 20


def sym_dict(name_ptr, val_ptr, sym_type, offset):
	return { 
		'symbol_name_addr': name_ptr, 
		'symbol_dest_addr': val_ptr, 
		'symbol_flag': sym_type, 
		'offset': offset 
	}


def is_sym(name_ptr, grp, null, sym_types):
	is_sym = True
	is_sym &= sym_type in sym_types
	is_sym &= null == 0
	is_sym &= grp == 0
	is_sym &= name_ptr != 0
	return is_sym
	

def get_pointers(data, endstr, sz, vx_ver, verbose=False):
	if vx_ver not in SUPPORTED_VX_VERSIONS:
		print('VxWorks version ', vx_ver, ' is currently not supported')
		return {}, []

    ptrtab = set()

    symtab_low = None # the lowest name_ptr address in the current candidate symbol table
    symtab_hi = None  # the highest name_ptr address in the current candidate symbol table

    symtab = []

    szstr = ['B', 'H', 'I', 'Q'][int(math.log(sz, 2))]
    sym_st_fmt = endstr + (szstr * 4) + 'H' + 'BB'
    sym_sz = sz * 4 + 4

    i = 0

    while i < len(data) - sym_sz:
        unk1, name_ptr, val_ptr, unk2, grp, sym_type, null = st.unpack(sym_st_fmt, data[i:i+sym_sz])

		ptrtab.update({unk1, name_ptr, val_ptr, unk2})

        if not is_sym(name_ptr, grp, null, sym_types):
            symtab_low, symtab_hi = None, None
            symtab = []
            i += 4
            continue

        # the name pointer must be within the bounds of the current symbol table
        sym_in_bounds = True

        if symtab_low is not None and symtab_hi is not None:
            sym_in_bounds &= symtab_hi <= min(symtab_low, name_ptr) + len(data)
            sym_in_bounds &= max(symtab_hi, name_ptr) <= symtab_low + len(data)

        if not sym_in_bounds:
            symtab_low, symtab_hi = name_ptr, name_ptr
			symtab = [sym_dict(name_ptr, val_ptr, sym_type, i)]

        # here, we have a valid symbol that is within the bounds of the current symbol table
        if symtab_low is not None and symtab_hi is not None:
            symtab_low = min(symtab_low, name_ptr)
            symtab_hi = max(symtab_hi, name_ptr)
        else:
            symtab_low, symtab_hi = name_ptr, name_ptr

		symtab.append(sym_dict(name_ptr, val_ptr, sym_type, i))

        # increase the cursor by the symbol size since we have a valid symbol
        i += sym_sz

        # if we have 100 consecutive symbols, assume that this is indeed the symbol table
        if len(symtab) >= SYMTAB_MIN_COUNT:
            print('Symbol table found at 0x%08x' % symtab[0]['offset'])
            break

	
	# throw out the candidate symbol table and return if it's below the threshold count
	if len(symtab) < SYMTAB_MIN_COUNT:
		return ptrtab, []
    
    # if we have a valid symbol table (at least 100 symbols), get the rest of the symbol table
	for i in range(i, len(data), sym_sz):
        unk1, name_ptr, val_ptr, unk2, grp, sym_type, null = st.unpack(sym_st_fmt, data[i:i+sym_sz])

		ptrtab.update({unk1, name_ptr, val_ptr, unk2})

        # once we have seen an invalid symbol, break out of the loop
        if not is_sym(name_ptr, grp, null, sym_types):
            break

		symtab.append(sym_dict(name_ptr, val_ptr, sym_type, i))

	if verbose:
        print('Symbol table ends at 0x%08x' % (i - sym_sz))

    return ptrtab, symtab


def get_strings(fname, n=8):
	'''
	Use the `strings` utility to return a mapping of string offset -> string for all strings of length >= n
	'''
    out = subprocess.check_output(['strings', '-n', str(n), '-o', fname])

    # python2/3 compat fix - python2 `check_output` returns a string while python3 returns bytes
    if sys.version_info[0] < 3: out = out.split('\n')[:-1]
    else:                       out = str(out)[2:-1].split('\\n')[:-1]

    out = [o.strip().split(' ') for o in out]

    return { int(o[0]): o[1] for o in out if len(o) == 2 }


class BAFinder(object):
    def __init__(self, fname, data, endy_str='<', wordsize=4, verbose=False):
        self.fname = fname
        self.data = data

		# Get a mapping of offset -> string for all strings of at least length 4
		self.all_strings = get_strings(self.fname, n=4)

		# Get the offsets of every string with at least length 8 (less false positives)
		self.strtab = { s[0] for s in self.all_strings.items() if len(s[1]) >= 8 }
        self.ptrtab, self.symtab = get_pointers(self.data, endy_str, wordsize, verbose=verbose)

        # 1. Sort the pointers and string offsets
        self.strtab = sorted(self.strtab)
        self.ptrtab = sorted(self.ptrtab)

        # 2. Get the differences between consecutive elements
        strdiffs = [self.strtab[i] - self.strtab[i-1] for i in range(1, len(self.strtab))]
        ptrdiffs = [self.ptrtab[i] - self.ptrtab[i-1] for i in range(1, len(self.ptrtab))]

        # 3. Find the longest common substring between the diffs
        sm = SequenceMatcher(None, strdiffs, ptrdiffs)
        aidx, bidx, sz = sm.find_longest_match(0, len(strdiffs), 0, len(ptrdiffs))

        # 4. Get the base address from the longest common substring
        base_addr = abs(self.ptrtab[bidx + 1] - self.strtab[aidx + 1])

        self.base_addr = base_addr
        self.matching_substr_sz = sz

    def is_base_addr_good(self, T=0.5):
        if hasattr(self, 'ref_ratio'):
            return self.ref_ratio

        strtab_reloc = { o + self.base_addr for o in self.strtab }
        self.ref_ratio = len(strtab_reloc.intersection(self.ptrtab)) / float(len(strtab_reloc))
        return self.ref_ratio

    def get_ref_ratio(self):
        if hasattr(self, 'ref_ratio'):
            return self.ref_ratio

        strtab_reloc = { o + self.base_addr for o in self.strtab }
        self.ref_ratio = len(strtab_reloc.intersection(self.ptrtab)) / float(len(strtab_reloc))
        return self.ref_ratio

    def get_symbol_table(self):
        # not needed, just to so that output matches vxhunter exactly
        self.symtab = sorted(self.symtab, key=lambda x: x['symbol_name_addr'])

        # python2/3 things for getting strings
        if type(self.data) == str: 
            convert_fn = str
            null_terminator = '\x00'
        else:                      
            convert_fn = chr
            null_terminator = 0

        for i, sym in enumerate(self.symtab):
            try:
                self.symtab[i]['symbol_name'] = all_strings[sym['symbol_name_addr'] - self.base_addr]
            except KeyError:
                off = self.symtab[i]['symbol_name_addr'] - self.base_addr
                sym_name = ''

                while self.data[off] != null_terminator:
                    sym_name += convert_fn(self.data[off])
                    off += 1

                self.symtab[i]['symbol_name'] = sym_name

        return self.symtab


if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument('-e', dest='endy', type=str, default='little', help='endianness of the binary (big or little)')
    parser.add_argument('-w', dest='wordsize', type=int, default=4, help='word size of the binary (1, 2, 4, or 8)')
    parser.add_argument('fname', type=str, help='filename of the binary')
    args = parser.parse_args()

    if args.endy not in ['little', 'big']:
        print('Endianness must be "big" or "little"')

    if args.wordsize not in [1, 2, 4, 8]:
        print('Wordsize must be 1, 2, 4, or 8')

    endy_str = ['<', '>'][['little', 'big'].index(args.endy)]

    with open(args.fname, 'rb') as f:
        data = f.read()

    baf = BAFinder(args.fname, data, endy_str=endy_str, wordsize=args.wordsize)
    symtab = baf.get_symbol_table()

    print('Base Address: 0x%08x' % baf.base_addr)
    print('\tLongest common substring is %d diffs long' % baf.matching_substr_sz)
    print('\tRatio of strings referenced: %.4f' % baf.get_ref_ratio())
    print('\t%d symbols found' % len(symtab))
