import os
import struct as st
import subprocess
import math
import sys
from difflib import SequenceMatcher

# VxWorks 6.8
vx_6_sym_types = [
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

sym_types = vx_6_sym_types

def get_pointers(data, endstr, sz):
    ptrtab = set()

    symtab_low = None
    symtab_hi = None
    symtab_count = 0
    symtab = []

    szstr = ['B', 'H', 'I', 'Q'][int(math.log(sz, 2))]
    sym_st_fmt = endstr + (szstr * 4) + 'H' + 'BB'
    sym_sz = sz * 4 + 4

    i = 0

    while i < len(data) - sym_sz:
        unk1, name_ptr, val_ptr, unk2, grp, sym_type, null = st.unpack(sym_st_fmt, data[i:i+sym_sz])

        ptrtab.add(unk1)
        ptrtab.add(name_ptr)
        ptrtab.add(val_ptr)
        ptrtab.add(unk2)

        is_sym = True
        is_sym &= sym_type in sym_types
        is_sym &= null == 0
        is_sym &= grp == 0
        is_sym &= name_ptr != 0

        if not is_sym:
            symtab_low, symtab_hi = None, None
            symtab_count = 0
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
            symtab_count = 1
            symtab = [{ 
                'symbol_name_addr': name_ptr, 
                'symbol_dest_addr': val_ptr, 
                'symbol_flag': sym_type, 
                'offset': i 
            }]

        # here, we have a valid symbol that is within the bounds of the current symbol table
        if symtab_low is not None and symtab_hi is not None:
            symtab_low = min(symtab_low, name_ptr)
            symtab_hi = max(symtab_hi, name_ptr)
        else:
            symtab_low, symtab_hi = name_ptr, name_ptr

        symtab_count += 1

        symtab.append({ 
            'symbol_name_addr': name_ptr, 
            'symbol_dest_addr': val_ptr, 
            'symbol_flag': sym_type, 
            'offset': i 
        })

        # increase the cursor by the symbol size since we have a valid symbol
        i += sym_sz

        # if we have 100 consecutive symbols, assume that this is indeed the symbol table
        if symtab_count >= 100:
            print('Symbol table found at 0x%08x' % symtab[0]['offset'])
            break

    
    # if we have a valid symbol table (at least 100 symbols), get the rest of the symbol table
    while symtab_count >= 100 and i < len(data):
        unk1, name_ptr, val_ptr, unk2, grp, sym_type, null = st.unpack(sym_st_fmt, data[i:i+sym_sz])

        ptrtab.add(unk1)
        ptrtab.add(name_ptr)
        ptrtab.add(val_ptr)
        ptrtab.add(unk2)

        is_sym = True
        is_sym &= sym_type in sym_types
        is_sym &= null == 0
        is_sym &= grp == 0
        is_sym &= name_ptr != 0

        i += sym_sz

        # once we have seen an invalid symbol, break out of the loop
        if not is_sym:
            break

        symtab.append({ 
            'symbol_name_addr': name_ptr, 
            'symbol_dest_addr': val_ptr, 
            'symbol_flag': sym_type, 
            'offset': i 
        })

    if symtab_count >= 100:
        print('Symbol table ends at 0x%08x' % (i - sym_sz))

    return ptrtab, symtab

def get_strings(fname, n=8):
    out = subprocess.check_output(['strings', '-n', str(n), '-o', fname])

    # python2/3 compat fix
    if sys.version_info[0] < 3: out = out.split('\n')[:-1]
    else:                       out = str(out)[2:-1].split('\\n')[:-1]

    out = [o.strip().split(' ') for o in out]
    return { int(o[0]): o[1] for o in out if len(o) == 2 }


class BAFinder(object):
    def __init__(self, fname, data):
        self.fname = fname
        self.data = data

        self.strtab = set(get_strings(self.fname).keys())
        self.ptrtab, self.symtab = get_pointers(self.data, '<', 4)
        #self.ptrtab, self.symtab = get_pointers(self.data, '>', 4)

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
        self.matching_seq_sz = sz

    def is_base_addr_good(self, T=0.5):
        strtab_reloc = { o + self.base_addr for o in self.strtab }
        return (len(strtab_reloc.intersection(self.ptrtab)) / float(len(strtab_reloc))) > T

    def get_ref_ratio(self):
        strtab_reloc = { o + self.base_addr for o in self.strtab }
        return len(strtab_reloc.intersection(self.ptrtab)) / float(len(strtab_reloc))

    def get_symbol_table(self):
        all_strings = get_strings(self.fname, n=3)

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
    fname = sys.argv[1]
    with open(fname, 'rb') as f:
        data = f.read()
    baf = BAFinder(fname, data)
    print(baf.base_addr)
    print(baf.is_base_addr_good())

    if not baf.is_base_addr_good():
        print(baf.get_ref_ratio())

    symtab = baf.get_symbol_table()
    for sym in symtab:
        print(sym['symbol_name'])
