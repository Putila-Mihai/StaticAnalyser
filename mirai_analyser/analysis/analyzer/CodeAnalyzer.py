from capstone import Cs, CS_ARCH_ARM, CS_ARCH_MIPS, CS_ARCH_X86, \
                     CS_MODE_ARM, CS_MODE_THUMB, CS_MODE_MIPS32, CS_MODE_LITTLE_ENDIAN, CS_MODE_BIG_ENDIAN, \
                     CS_MODE_32, CS_MODE_64, CsInsn,  CS_GRP_CALL, CS_GRP_JUMP, CS_OP_IMM

from typing import List, Dict, Any, Optional
from elf_parser import ELFInfo
from config import *

class Function:
    def __init__(self, start_address: int, name: Optional[str] = None, func_type: str = 'unknown'):
        self.start_address = start_address
        self.name = name if name else f"sub_{hex(start_address)}"
        self.func_type = func_type # e.g., 'local', 'imported', 'discovered_call', 'discovered_prologue'
        self.end_address: Optional[int] = None # Will be determined later, or conservatively estimated
        self.instructions: List[CsInsn] = [] # Instructions belonging to this function
        self.called_functions: set[int] = set() # Addresses of functions called by this one
        self.xrefs_from: set[int] = set() # Addresses that reference (call/jump to) this function
        self.basic_blocks: List[Any] = [] # (To be populated when building CFG)
        self.score: float = 0.0 # For heuristics later
        self.tags: List[str] = [] # Tags from SymbolAnalyzer or other heuristics

class CodeAnalyzer:
    def __init__(self, elf_info: ELFInfo):
        self.elf_info = elf_info
        self.md = None  # Capstone disassembler engine
        self.instructions: List[CsInsn] = [] # List to store disassembled instructions
        self.functions: Dict[int, Function] = {} # Initialize the function map
        self.text_section_data_info = None

    def _init_capstone(self) -> bool:

        arch = self.elf_info.machine_arch
        endianness = CS_MODE_LITTLE_ENDIAN if self.elf_info.data_encoding else CS_MODE_BIG_ENDIAN
        
        cs_arch = None
        cs_mode = endianness

        if arch == 'ARM':
            cs_arch = CS_ARCH_ARM
            # Determine ARM mode (ARM or Thumb).
            # If entry_point is odd, it suggests Thumb mode.
            if self.elf_info.entry_point is not None and self.elf_info.entry_point % 2 != 0:
                 cs_mode |= CS_MODE_THUMB # Set Thumb mode
                 print("Info: Entry point is odd, setting Capstone to Thumb mode for ARM.")
            else:
                 cs_mode |= CS_MODE_ARM # Set ARM mode (default for even entry points)
                 print("Info: Entry point is even, setting Capstone to ARM mode (not Thumb).")

        elif arch == 'MIPS':
            cs_arch = CS_ARCH_MIPS
            cs_mode |= CS_MODE_MIPS32 # Mirai typically uses MIPS32

        else:
            # For any other architecture, we explicitly do not support it.
            print(f"Error: Unsupported architecture '{arch}'. This analyzer only supports ARM and MIPS for Mirai.")
            return False

        try:
            self.md = Cs(cs_arch, cs_mode)
            self.md.detail = True
            return True
        except Exception as e:
            print(f"Error initializing Capstone for {arch}: {e}")
            return False

    def disassemble_code(self) -> bool:
        """
        Disassembles the raw bytes of the .text section.
        """
        
        for section in self.elf_info.sections:
            if section['name'] == '.text':
                self.text_section_data_info = section
                break

        if not self.text_section_data_info or not self.text_section_data_info['data']:
            print("Error: '.text' section not found or contains no data in ELFInfo.")
            return False

        if not self._init_capstone():
            return False

        text_data = self.text_section_data_info['data']
        text_vaddr = self.text_section_data_info['addr']

        if not text_data:
            print("Warning: .text section data is empty.")
            return False

        print(f"Disassembling {len(text_data)} bytes from {self.elf_info.machine_arch} at VAddr {hex(text_vaddr)}...")
        try:
            # `disasm` yields instructions.
            for insn in self.md.disasm(text_data, text_vaddr):
                self.instructions.append(insn)
                print(f'\n {insn}')
            print(f"Successfully disassembled {len(self.instructions)} instructions.")
            return True
        except Exception as e:
            print(f"Error during disassembly: {e}")
            return False

    def find_functions(self, symbol_analyzer_result: Dict[str, Any]) -> None:
        if not self.instructions:
            print("Warning: No disassembled instructions. Cannot find functions.")
            return

        # 1. Always add the ELF entry point
        if self.elf_info.entry_point is not None:
            entry_point_addr = self.elf_info.entry_point
            # Adjust entry point for Thumb mode if applicable
            if self.elf_info.machine_arch == 'ARM' and (entry_point_addr % 2 != 0):
                entry_point_addr -= 1 # Capstone expects even addresses for ARM modes
            
            # Check if it's already tagged by symbol analysis (e.g., '_start' or 'main')
            entry_name = 'ELF_Entry'
            entry_type = 'local' # Default to local, could be refined by symbols
            entry_tags = []

            # Populate from symbol_analyzer_result if available
            symbol_function_map = symbol_analyzer_result.get('function_map', {})
            if entry_point_addr in symbol_function_map:
                sym_info = symbol_function_map[entry_point_addr]
                entry_name = sym_info.get('name', entry_name)
                entry_type = sym_info.get('type', entry_type)
                entry_tags = sym_info.get('tags', [])

            func = Function(entry_point_addr, name=entry_name, func_type=entry_type)
            func.tags.extend(entry_tags) # Add tags from symbol analyzer
            self.functions[entry_point_addr] = func
            print(f"Added ELF Entry Point: {func.name} (0x{func.start_address:x})")


        # 2. Case: Binary has symbol information (not stripped, or partial symbols)
        if not symbol_analyzer_result.get('is_stripped', True) or symbol_analyzer_result.get('function_map'):
            print("Using symbol table information to find functions...")
            self._find_functions_from_symbols(symbol_analyzer_result['function_map'])
        else:
            print("Binary is stripped/no symbols. Relying on code heuristics...")

        # 3. Find functions from call targets (applicable to both stripped and unstripped)
        self._find_functions_from_call_targets()

        # 4. Find functions from common prologues (primarily for stripped binaries)
        # This is more robustly applied AFTER processing calls, as calls are a stronger indicator.
        if symbol_analyzer_result.get('is_stripped', True): # Only focus on prologues if stripped
             self._find_functions_from_prologues()

        print(f"Finished function identification. Found {len(self.functions)} functions.")

    def _find_functions_from_symbols(self, symbol_function_map: Dict[int, Dict[str, Any]]) -> None:
        """Helper to add functions identified by SymbolAnalyzer."""
        for addr, sym_details in symbol_function_map.items():
            if addr not in self.functions: # Only add if not already added (e.g., by entry point)
                func = Function(
                    start_address=addr,
                    name=sym_details.get('name'),
                    func_type=sym_details.get('type', 'symbol')
                )
                func.tags.extend(sym_details.get('tags', []))
                self.functions[addr] = func
                # print(f"  Added symbol-based function: {func.name} (0x{func.start_address:x})")
            else: # If already added (e.g., entry point is also a symbol)
                # Refine info if the new symbol info is better (e.g., provides a name)
                existing_func = self.functions[addr]
                if not existing_func.name.startswith("sub_") and sym_details.get('name'):
                    existing_func.name = sym_details['name']
                if existing_func.func_type == 'unknown' or (existing_func.func_type == 'imported' and sym_details.get('type') == 'local'):
                    existing_func.func_type = sym_details['type']
                existing_func.tags.extend(sym_details.get('tags', []))
                existing_func.tags = list(set(existing_func.tags)) # Remove duplicates


    def _find_functions_from_call_targets(self) -> None:
        """Helper to find function entry points from direct call targets."""
        for insn in self.instructions:
            # Check if instruction is a call instruction
            # Capstone puts call/jump instructions in specific groups (CS_GRP_CALL, CS_GRP_JUMP)
            if (insn.group(CS_GRP_CALL) and not insn.group(CS_GRP_JUMP)) or \
               (self.elf_info.machine_arch == 'ARM' and insn.mnemonic.startswith('bl')) or \
               (self.elf_info.machine_arch == 'MIPS' and insn.mnemonic.startswith('jal')):
                
                # Try to extract the target address from operands
                # This often involves checking immediate operands
                target_addr = None
                for op in insn.operands:
                    if op.type == 2: # CS_OP_IMM for immediate operand
                        target_addr = op.value.imm
                        break
                
                if target_addr is not None:
                    # Adjust target address for ARM Thumb if it's an odd address
                    if self.elf_info.machine_arch == 'ARM' and (target_addr % 2 != 0):
                        target_addr -= 1 # Strip Thumb bit for function start

                    # Ensure the target address falls within the .text section (or an executable segment)
                    # This prevents adding random data as functions
                    is_in_text_section = False
                    if self.text_section_data_info:
                        text_start = self.text_section_data_info['addr']
                        text_end = text_start + self.text_section_data_info['size']
                        if text_start <= target_addr < text_end:
                            is_in_text_section = True
                    
                    if is_in_text_section and target_addr not in self.functions:
                        func = Function(target_addr, func_type='discovered_call')
                        self.functions[target_addr] = func
                        # print(f"  Added call target function: 0x{target_addr:x}")
                        # Also add a cross-reference to the called function
                        self.functions[target_addr].xrefs_from.add(insn.address)
                        # And track that this instruction's function calls the target
                        # (Requires determining which function 'insn' belongs to, will do later during basic block parsing)

    def _find_functions_from_prologues(self) -> None:

        current_arch_prologues = []

        if self.elf_info.machine_arch in PROLOGUE_PATTERNS:
            current_arch_prologues = PROLOGUE_PATTERNS[self.elf_info.machine_arch]
        else:
            print(f"Info: No specific prologue patterns defined for {self.elf_info.machine_arch}.")
            return

        for i, insn in enumerate(self.instructions):
            
            if insn.address in self.functions:
                continue
            if i + 1 >= len(self.instructions):
                continue

            next_insn = self.instructions[i+1]

            for pattern_mnemonics, pattern_op_contains in current_arch_prologues:

                if len(pattern_mnemonics) > len(self.instructions) - i:
                    continue 

                # Check the first instruction in the pattern
                mnemonic_match_0 = False
                if pattern_mnemonics[0] == 'push' and insn.mnemonic == 'push':
                    mnemonic_match_0 = True
                elif pattern_mnemonics[0] == 'stm' and insn.mnemonic.startswith('stm'):
                    mnemonic_match_0 = True

                if not mnemonic_match_0:
                    continue

                mnemonic_match_1 = (next_insn.mnemonic == pattern_mnemonics[1])

                # Check operand string containment (this is the heuristic part)
                op_str_match_0 = pattern_op_contains[0].lower() in insn.op_str.lower()
                op_str_match_1 = pattern_op_contains[1].lower() in next_insn.op_str.lower()

                # Special check for ARM 'push'/'stm' to ensure 'lr' is saved
                if self.elf_info.machine_arch == 'ARM':
                    if (pattern_mnemonics[0] == 'push' or pattern_mnemonics[0] == 'stm') and 'lr' not in insn.op_str.lower():
                        continue # Must save LR for a typical function prologue

                if mnemonic_match_0 and mnemonic_match_1 and op_str_match_0 and op_str_match_1:

                    func = Function(insn.address, func_type='discovered_prologue')
                    self.functions[insn.address] = func
                    print(f"  Added prologue-based function: 0x{insn.address:x} ({self.elf_info.machine_arch})")
                    break # Break from pattern loop, found a function, move to next instruction


    # def build_cfg(self):
    #     """Builds control flow graphs for functions."""
    #     pass

    # def apply_heuristics(self):
    #     """Applies behavioral heuristics to functions and code."""
    #     pass