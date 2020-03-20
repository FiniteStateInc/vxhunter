def print_symtab(symtab):
	for sym in symtab:
		print(hex(sym['offset']), sym['sym_name'], 

if __name__ == '__main__':
	import sys

	fname = sys.argv[1]
	ba = int(sys.argv[2], 16)

	with open(fname, 'rb') as f:
		data = f.read()

	endstr = '<'
	sz = 4


    szstr = ['B', 'H', 'I', 'Q'][int(math.log(sz, 2))]
    sym_st_fmt = endstr + (szstr * 4) + 'H' + 'BB'
    sym_sz = sz * 4 + 4

    symtab = []
    i = 0

    while i < len(data) - sym_sz:
        unk1, name_ptr, val_ptr, unk2, grp, sym_type, null = st.unpack(sym_st_fmt, data[i:i+sym_sz])

        is_sym = True
        is_sym &= sym_type in sym_types
        is_sym &= null == 0
        is_sym &= grp == 0
        is_sym &= name_ptr != 0

        if not is_sym:
			if len(symtab) > 5:
				

            i += 4
            continue

        # the name pointer must be within the bounds of the current symbol table
        sym_in_bounds = name_ptr < len(data)

        if not sym_in_bounds:
			i += 4
			continue

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

