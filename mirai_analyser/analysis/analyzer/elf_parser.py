# elf_parser.py
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection
import re
from typing import List, Dict, Any, Optional

class ELFInfo:
    """A data class to hold parsed ELF information."""
    def __init__(self):
        self.elf_class = None               # 32 or 64 bit
        self.data_encoding = None           # Little/big endian
        self.machine_arch = None            # Architecture (e.g., ARM, x86)
        self.entry_point = None             # Entry point address
        self.sections = []                  # List of sections: {name, addr, size, data}
        self.segments = []                  # List of segments: {type, vaddr, filesz}
        self.symbol_tables = []             # All symbol tables (.symtab, .dynsym)
        self.dynamic_symbols = []           # Symbols from .dynsym
        self.is_stripped = True             # True if no .symtab
        self.strings = {}                   # ASCII strings per section: {section_name: [strings]}

class ELFParser:
    def __init__(self, file_path):
        self.file_path = file_path
        self.elffile = None
        self.elf_info = ELFInfo()
        self._file_handle = None

    def parse(self) -> Optional[ELFInfo]:
        """parse the ELF file and populate ELFInfo."""
        try:
            # Open the file and store the handle. DO NOT use 'with' here.
            self._file_handle = open(self.file_path, 'rb')
            self.elffile = ELFFile(self._file_handle)

            # Header Info
            self.elf_info.elf_class = self.elffile.elfclass
            self.elf_info.data_encoding = self.elffile.little_endian
            self.elf_info.machine_arch = self.elffile.get_machine_arch()
            self.elf_info.entry_point = self.elffile.header['e_entry']

            # Sections
            for section in self.elffile.iter_sections():
                section_info = {
                    'name': section.name,
                    'addr': section['sh_addr'],
                    'size': section['sh_size'],
                    'data': section.data() if section.name in ['.text', '.data', '.rodata'] else None
                }
                self.elf_info.sections.append(section_info)

                # Symbol tables
                if isinstance(section, SymbolTableSection):
                    self.elf_info.symbol_tables.append(section)
                    if section.name == '.dynsym':
                        for symbol in section.iter_symbols():
                            self.elf_info.dynamic_symbols.append(symbol)

            # Segments
            for segment in self.elffile.iter_segments():
                segment_info = {
                    'type': segment['p_type'],
                    'vaddr': segment['p_vaddr'],
                    'filesz': segment['p_filesz']
                }
                self.elf_info.segments.append(segment_info)

            # Is stripped?
            self.elf_info.is_stripped = self.elffile.get_section_by_name('.symtab') is None

            # Extract ASCII strings from selected sections
            self.elf_info.strings = extract_strings_from_sections(self.elf_info.sections)

            return self.elf_info

        except FileNotFoundError:
            raise FileNotFoundError(f"[ELFParser] File not found: '{self.file_path}'")
        except Exception as e:
            # If an error occurs during parsing, attempt to close the file
            if self._file_handle:
                self._file_handle.close()
                self._file_handle = None
            raise IOError(f"[ELFParser] Failed to parse ELF file '{self.file_path}': {e}")

    # Add a method to explicitly close the file handle
    def close(self):
        if self._file_handle:
            self._file_handle.close()
            self._file_handle = None
        self.elffile = None # Also clear the elftools object reference


# --- Helper Functions ---

def extract_ascii_strings(data, min_length=4):
    """Extract readable ASCII strings from binary data."""
    pattern = rb'[\x20-\x7e]{%d,}' % min_length
    return [s.decode('utf-8', errors='ignore') for s in re.findall(pattern, data)]

def extract_strings_from_sections(sections):
    """Go through ELF sections and extract ASCII strings from .rodata, .data, .text."""
    strings = {}
    for section in sections:
        # Check if 'data' key exists and is not None
        if 'data' in section and section['data']:
            found = extract_ascii_strings(section['data'])
            if found:
                strings[section['name']] = found
    return strings