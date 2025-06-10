# elf_parser.py
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection
import re
from typing import List, Dict, Any, Optional
import os

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
        
    def get_report(self) -> str:
        """
        Generates a formatted string report of the parsed ELF information.
        This method assumes parse() has already been called successfully.
        """
        report_lines = []
        report_lines.append("="*80)
        report_lines.append(f"ELF ANALYSIS REPORT: {os.path.basename(self.file_path)}")
        report_lines.append("="*80)

        report_lines.append("\n--- ELF Header Information ---")
        report_lines.append(f"  ELF Class:           {self.elf_info.elf_class}-bit")
        report_lines.append(f"  Data Encoding:       {'Little-Endian' if self.elf_info.data_encoding else 'Big-Endian'}")
        report_lines.append(f"  Machine Architecture: {self.elf_info.machine_arch}")
        report_lines.append(f"  Entry Point Address: 0x{self.elf_info.entry_point:x}")
        report_lines.append(f"  Stripped:            {'Yes' if self.elf_info.is_stripped else 'No'}")

        report_lines.append("\n--- Sections ---")
        if self.elf_info.sections:
            report_lines.append(f"{'Name':<20} {'Address':<10} {'Size':<10} {'Data Loaded?':<12}")
            report_lines.append(f"{'-'*20} {'-'*10} {'-'*10} {'-'*12}")
            for section in self.elf_info.sections:
                data_loaded = 'Yes' if section['data'] is not None else 'No'
                report_lines.append(f"{section['name']:<20} 0x{section['addr']:<8x} 0x{section['size']:<8x} {data_loaded:<12}")
        else:
            report_lines.append("  No sections found.")

        report_lines.append("\n--- Segments (Headers) ---")
        if self.elf_info.segments:
            report_lines.append(f"{'Type':<15} {'Virtual Address':<17} {'File Size':<12}")
            report_lines.append(f"{'-'*15} {'-'*17} {'-'*12}")
            for segment in self.elf_info.segments:
                report_lines.append(f"{segment['type']:<15} 0x{segment['vaddr']:<15x} 0x{segment['filesz']:<10x}")
        else:
            report_lines.append("  No segments found.")

        report_lines.append("\n--- Dynamic Symbols (.dynsym) ---")
        if self.elf_info.dynamic_symbols:
            report_lines.append(f"  Total Dynamic Symbols: {len(self.elf_info.dynamic_symbols)}")
            report_lines.append("  First 10 Dynamic Symbols (Name, Value, Size, Type):")
            for i, symbol in enumerate(self.elf_info.dynamic_symbols):
                if i >= 10: break
                report_lines.append(f"    - {symbol.name:<25} Value:0x{symbol['st_value']:<10x} Size:{symbol['st_size']:<5} Type:{symbol['st_info']['type']}")
        else:
            report_lines.append("  No dynamic symbols found.")

        report_lines.append("\n--- Extracted Strings (Summary) ---")
        total_strings = sum(len(s) for s in self.elf_info.strings.values())
        if total_strings > 0:
            report_lines.append(f"  Total Extracted Strings: {total_strings}")
            report_lines.append("  Strings per Section:")
            for section_name, strings_list in self.elf_info.strings.items():
                report_lines.append(f"    - {section_name}: {len(strings_list)} strings")
        else:
            report_lines.append("  No ASCII strings found in selected sections.")
        
        report_lines.append("\n" + "="*80)

        return "\n".join(report_lines)

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