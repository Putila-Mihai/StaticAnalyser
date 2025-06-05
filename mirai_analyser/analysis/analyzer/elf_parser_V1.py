# analysis/elf_parser.py

from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection
import os
import re

def is_elf(file_path):
    with open(file_path, 'rb') as f:
        magic = f.read(4)
    return magic == b'\x7fELF'

def extract_ascii_strings(data, min_length=4):
    pattern = rb'[\x20-\x7e]{%d,}' % min_length
    return [s.decode('utf-8', errors='ignore') for s in re.findall(pattern, data)]

def parse_elf(file_path):
    if not os.path.exists(file_path):
        print(f"[!] File not found: {file_path}")
        return

    if not is_elf(file_path):
        print(f"[!] Not a valid ELF file: {file_path}")
        return

    with open(file_path, 'rb') as f:
        elf = ELFFile(f)

        print(f"[+] Parsing ELF file: {file_path}")
        # ELF class (32 sau 64 bit)
        elf_class = elf.elfclass  # int: 32 or 64
        print(f"    - ELF Class: {elf_class}-bit")

        # Data encoding (endianness)
        data_encoding = elf.little_endian
        print(f"    - Data encoding: {'Little endian' if data_encoding else 'Big endian'}")

        # Machine architecture (ex: x86-64, ARM)
        machine = elf.get_machine_arch()
        print(f"    - Machine: {machine}")

        # Entry point
        print(f"    - Entry point: 0x{elf.header['e_entry']:x}")

        print(f"[+] Sections:")
        for section in elf.iter_sections():
            print(f"    - {section.name} (Addr: {hex(section['sh_addr'])}, Size: {section['sh_size']})")

        # Segmente
        print(f"[+] Program Headers:")
        for seg in elf.iter_segments():
            print(f"    - Type: {seg['p_type']}, Vaddr: {hex(seg['p_vaddr'])}, Filesz: {seg['p_filesz']}")
 
        print("[+] Symbol Table:")
        #Symbol table
        found = False
        for section in elf.iter_sections():
            if isinstance(section, SymbolTableSection):
                for symbol in section.iter_symbols():
                    name = symbol.name
                    addr = symbol['st_value']
                    sym_type = symbol['st_info']['type']
                    if name and sym_type == 'STT_FUNC':  # doar funcții, sau scoți filtrul
                        print(f"    - {name} at 0x{addr:x}")
                        found = True
        if not found:
            print("    - No function symbols found.")

        print("[+] Extracted Strings:")
        for section_name in ['.rodata', '.data']:
            section = elf.get_section_by_name(section_name)
            if section:
                data = section.data()
                strings = extract_ascii_strings(data)
                if strings:
                    print(f"    - From {section_name}:")
                    for s in strings[:10]:  # primele 10 stringuri per secțiune
                        print(f"        • {s}")

        stripped = elf.get_section_by_name('.symtab') is None
        print(f"[+] Is binary stripped? {'Yes' if stripped else 'No'}")


# Pentru testare
if __name__ == "__main__":
    test_path = "../samples/c.elf"
    parse_elf(test_path)
