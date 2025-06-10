import os # Added for path handling
import graphviz
from capstone import Cs, CS_ARCH_ARM, CS_ARCH_MIPS, \
                     CS_MODE_ARM, CS_MODE_THUMB, CS_MODE_MIPS32, CS_MODE_LITTLE_ENDIAN, CS_MODE_BIG_ENDIAN, \
                     CsInsn, CS_GRP_CALL, CS_GRP_JUMP, CS_GRP_RET, CS_GRP_BRANCH_RELATIVE, CS_OP_IMM

from typing import List, Dict, Any, Optional, Set

# Assuming ELFInfo is imported from your elf_parser.py
from elf_parser import ELFInfo
from config import PROLOGUE_PATTERNS # Only import what's used, not *

# --- New BasicBlock Class ---
class BasicBlock:
    def __init__(self, start_address: int):
        self.start_address: int = start_address
        self.end_address: Optional[int] = None # Address of the last instruction in the block
        self.instructions: List[CsInsn] = []
        self.successors: Set[int] = set() # Set of successor basic block start addresses
        self.predecessors: Set[int] = set() # Set of predecessor basic block start addresses
        self.is_entry_block: bool = False # True if this is the first block of a function
        self.is_exit_block: bool = False # True if this block ends with a return or unconditional jump out of function
        self.terminator_type: str = 'fall_through' # 'call', 'jump_unconditional', 'jump_conditional', 'ret', 'indirect_jump'
        self.function_address: Optional[int] = None # The start address of the function this block belongs to

    def add_instruction(self, insn: CsInsn):
        self.instructions.append(insn)
        self.end_address = insn.address # Update end_address with each added instruction's address

    def __repr__(self):
        start = hex(self.start_address)
        end = hex(self.end_address) if self.end_address is not None else 'N/A'
        num_insns = len(self.instructions)
        return f"BB(0x{start[2:]}-0x{end[2:]}, {num_insns} insns, succ={len(self.successors)})"

# --- Updated Function Class ---
class Function:
    def __init__(self, start_address: int, name: Optional[str] = None, func_type: str = 'unknown'):
        self.start_address = start_address
        self.name = name if name else f"sub_{hex(start_address)}"
        self.func_type = func_type # e.g., 'local', 'imported', 'discovered_call', 'discovered_prologue'
        self.end_address: Optional[int] = None # Will be determined later, or conservatively estimated (last instruction in function)
        self.instructions: List[CsInsn] = [] # All instructions strictly belonging to this function
        self.called_functions: Set[int] = set() # Addresses of functions called by this one (used for call graph)
        self.xrefs_from: Set[int] = set() # Addresses that reference (call/jump to) this function. Contains calling function addresses.
        self.basic_blocks: Dict[int, BasicBlock] = {} # Map BB start_addr to BasicBlock object
        self.entry_block_address: Optional[int] = None # The start_address of the function's entry block
        self.score: float = 0.0 # For heuristics later
        self.tags: List[str] = [] # Tags from SymbolAnalyzer or other heuristics

    def __repr__(self):
        return f"Function(0x{self.start_address:x}, {self.name}, {self.func_type}, {len(self.basic_blocks)} BBs)"


class CodeAnalyzer:
    def __init__(self, elf_info: ELFInfo):
        self.elf_info = elf_info
        self.md = None  # Capstone disassembler engine
        self.instructions: List[CsInsn] = [] # List to store ALL disassembled instructions linearly
        self.addr_to_idx: Dict[int, int] = {} # Map instruction address to its index in self.instructions
        self.functions: Dict[int, Function] = {} # Map function start_addr to Function object
        self.text_section_data_info = None

    def _init_capstone(self) -> bool:
        arch = self.elf_info.machine_arch
        endianness = CS_MODE_LITTLE_ENDIAN if self.elf_info.data_encoding else CS_MODE_BIG_ENDIAN
        
        cs_arch = None
        cs_mode = endianness

        if arch == 'ARM':
            cs_arch = CS_ARCH_ARM
            if self.elf_info.entry_point is not None and self.elf_info.entry_point % 2 != 0:
                 cs_mode |= CS_MODE_THUMB # Set Thumb mode
                 # print("Info: Entry point is odd, setting Capstone to Thumb mode for ARM.")
            else:
                 cs_mode |= CS_MODE_ARM # Set ARM mode (default for even entry points)
                 # print("Info: Entry point is even, setting Capstone to ARM mode (not Thumb).")

        elif arch == 'MIPS':
            cs_arch = CS_ARCH_MIPS
            cs_mode |= CS_MODE_MIPS32 # Mirai typically uses MIPS32

        else:
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
        Disassembles the raw bytes of the .text section and populates self.instructions.
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

        # print(f"Disassembling {len(text_data)} bytes from {self.elf_info.machine_arch} at VAddr {hex(text_vaddr)}...")
        try:
            for i, insn in enumerate(self.md.disasm(text_data, text_vaddr)):
                self.instructions.append(insn)
                self.addr_to_idx[insn.address] = i # Populate address-to-index map
            # print(f"Successfully disassembled {len(self.instructions)} instructions.")
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
            
            entry_name = 'ELF_Entry'
            entry_type = 'local' 
            entry_tags = []

            symbol_function_map = symbol_analyzer_result.get('function_map', {})
            if entry_point_addr in symbol_function_map:
                sym_info = symbol_function_map[entry_point_addr]
                entry_name = sym_info.get('name', entry_name)
                entry_type = sym_info.get('type', entry_type)
                entry_tags = sym_info.get('tags', [])

            func = Function(entry_point_addr, name=entry_name, func_type=entry_type)
            func.tags.extend(entry_tags)
            self.functions[entry_point_addr] = func
            # print(f"Added ELF Entry Point: {func.name} (0x{func.start_address:x})")


        # 2. Case: Binary has symbol information (not stripped, or partial symbols)
        if not symbol_analyzer_result.get('is_stripped', True) or symbol_analyzer_result.get('function_map'):
            # print("Using symbol table information to find functions...")
            self._find_functions_from_symbols(symbol_analyzer_result['function_map'])
        # else:
            # print("Binary is stripped/no symbols. Relying on code heuristics...")

        # 3. Find functions from call targets (applicable to both stripped and unstripped)
        self._find_functions_from_call_targets()

        # 4. Find functions from common prologues (primarily for stripped binaries)
        if symbol_analyzer_result.get('is_stripped', True):
             self._find_functions_from_prologues()

        # print(f"Finished function identification. Found {len(self.functions)} functions.")

    def _find_functions_from_symbols(self, symbol_function_map: Dict[int, Dict[str, Any]]) -> None:
        """Helper to add functions identified by SymbolAnalyzer."""
        for addr, sym_details in symbol_function_map.items():
            if addr not in self.functions:
                func = Function(
                    start_address=addr,
                    name=sym_details.get('name'),
                    func_type=sym_details.get('type', 'symbol')
                )
                func.tags.extend(sym_details.get('tags', []))
                self.functions[addr] = func
            else:
                existing_func = self.functions[addr]
                if not existing_func.name.startswith("sub_") and sym_details.get('name'):
                    existing_func.name = sym_details['name']
                if existing_func.func_type == 'unknown' or (existing_func.func_type == 'imported' and sym_details.get('type') == 'local'):
                    existing_func.func_type = sym_details['type']
                existing_func.tags.extend(sym_details.get('tags', []))
                existing_func.tags = list(set(existing_func.tags))


    def _find_functions_from_call_targets(self) -> None:
        """Helper to find function entry points from direct call targets."""
        for insn in self.instructions:
            if (insn.group(CS_GRP_CALL) and not insn.group(CS_GRP_JUMP)) or \
               (self.elf_info.machine_arch == 'ARM' and insn.mnemonic.startswith('bl')) or \
               (self.elf_info.machine_arch == 'MIPS' and insn.mnemonic.startswith('jal')):
                
                target_addr = None
                for op in insn.operands:
                    if op.type == CS_OP_IMM: # Using CS_OP_IMM constant
                        target_addr = op.value.imm
                        break
                
                if target_addr is not None:
                    if self.elf_info.machine_arch == 'ARM' and (target_addr % 2 != 0):
                        target_addr -= 1 # Strip Thumb bit for function start

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
                        # self.functions[target_addr].xrefs_from.add(insn.address) # This will be handled in CFG build
                        # (Requires determining which function 'insn' belongs to, will do later during basic block parsing)

    def _find_functions_from_prologues(self) -> None:

        current_arch_prologues = []

        if self.elf_info.machine_arch in PROLOGUE_PATTERNS:
            current_arch_prologues = PROLOGUE_PATTERNS[self.elf_info.machine_arch]
        else:
            # print(f"Info: No specific prologue patterns defined for {self.elf_info.machine_arch}.")
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

                mnemonic_match_0 = False
                if pattern_mnemonics[0] == 'push' and insn.mnemonic == 'push':
                    mnemonic_match_0 = True
                elif pattern_mnemonics[0] == 'stm' and insn.mnemonic.startswith('stm'):
                    mnemonic_match_0 = True
                elif insn.mnemonic == pattern_mnemonics[0]: # For generic mnemonic matches (added this)
                    mnemonic_match_0 = True

                if not mnemonic_match_0:
                    continue

                mnemonic_match_1 = (next_insn.mnemonic == pattern_mnemonics[1])

                op_str_match_0 = pattern_op_contains[0].lower() in insn.op_str.lower()
                op_str_match_1 = pattern_op_contains[1].lower() in next_insn.op_str.lower()

                if self.elf_info.machine_arch == 'ARM':
                    if (pattern_mnemonics[0] == 'push' or pattern_mnemonics[0] == 'stm') and 'lr' not in insn.op_str.lower():
                        continue 

                if mnemonic_match_0 and mnemonic_match_1 and op_str_match_0 and op_str_match_1:

                    func = Function(insn.address, func_type='discovered_prologue')
                    self.functions[insn.address] = func
                    # print(f"  Added prologue-based function: 0x{insn.address:x} ({self.elf_info.machine_arch})")
                    break # Break from pattern loop, found a function, move to next instruction

    def build_control_flow_graphs(self) -> None:
    
        if not self.functions:
            print("Warning: No functions identified. Cannot build CFGs.")
            return

        # print("\n--- Building Control Flow Graphs ---")
        sorted_function_addrs = sorted(self.functions.keys())
        
        # Calculate approximate function end addresses (for instruction assignment)
        # This is a heuristic: function ends when next function starts, or end of .text section.
        function_boundaries = {}
        for i, addr in enumerate(sorted_function_addrs):
            start_addr = addr
            next_func_start = None
            if i + 1 < len(sorted_function_addrs):
                next_func_start = sorted_function_addrs[i+1]
            
            # Default end is end of .text section
            end_addr_inclusive = self.text_section_data_info['addr'] + self.text_section_data_info['size'] - 1

            if next_func_start is not None:
                # The function ends at the instruction *before* the next function starts
                # This ensures functions don't overlap in assigned instructions
                if next_func_start in self.addr_to_idx and self.addr_to_idx[next_func_start] > 0:
                     prev_insn_idx = self.addr_to_idx[next_func_start] - 1
                     if prev_insn_idx < len(self.instructions):
                        end_addr_inclusive = self.instructions[prev_insn_idx].address + self.instructions[prev_insn_idx].size -1
            
            function_boundaries[addr] = end_addr_inclusive # Inclusive end address

        # Assign instructions to functions and build basic blocks
        for func_addr in sorted_function_addrs:
            func = self.functions[func_addr]
            func_end_addr_limit = function_boundaries[func_addr] # The highest address an instruction for this function can have

            # If function start address is not found in instructions, skip
            if func.start_address not in self.addr_to_idx:
                # print(f"Warning: Function 0x{func.start_address:x} not found in disassembled instructions map. Skipping CFG for this function.")
                continue

            bb_leaders = set()
            bb_leaders.add(func.start_address) # Function start is always a BB leader

            start_idx_global = self.addr_to_idx[func.start_address]
            func.instructions = [] # Clear previous instructions to repopulate accurately

            # Iterate through instructions starting from the function's start address
            # and within its estimated bounds
            for i in range(start_idx_global, len(self.instructions)):
                insn = self.instructions[i]

                # Stop if we've gone past the function's estimated end address
                # or if we hit the start of another identified function
                if insn.address > func_end_addr_limit or \
                   (insn.address != func.start_address and insn.address in self.functions):
                    break 

                func.instructions.append(insn) # Add instruction to function's instruction list

                # Identify potential basic block boundaries
                # A basic block ends if the current instruction is a control flow instruction
                # and the instruction *after* it starts a new block.
                # The target of a jump/call is also a new block.
                
                is_terminator = False
                
                if insn.group(CS_GRP_CALL):
                    is_terminator = True
                    # Fall-through address (instruction immediately after call) is a new BB leader
                    fall_through_addr = insn.address + insn.size
                    if fall_through_addr <= func_end_addr_limit: # Ensure fall-through is within function bounds
                        bb_leaders.add(fall_through_addr)
                    
                    # Extract call target and add to called_functions set for call graph
                    for op in insn.operands:
                        if op.type == CS_OP_IMM:
                            call_target = op.value.imm
                            if self.elf_info.machine_arch == 'ARM' and (call_target % 2 != 0):
                                call_target -= 1 # Strip Thumb bit if necessary
                            func.called_functions.add(call_target)
                            
                            # Populate xrefs_from for the CALLED function (inter-procedural link)
                            if call_target in self.functions:
                                self.functions[call_target].xrefs_from.add(func.start_address) # ADDED THIS LINE
                            break

                elif insn.group(CS_GRP_JUMP):
                    is_terminator = True
                    
                    # Extract jump target(s)
                    jump_targets = set()
                    for op in insn.operands:
                        if op.type == CS_OP_IMM:
                            target = op.value.imm
                            if self.elf_info.machine_arch == 'ARM' and (target % 2 != 0):
                                target -= 1 # Strip Thumb bit if necessary
                            jump_targets.add(target)
                            break # Assume one immediate target for direct jumps
                    
                    # Add all direct jump targets as leaders if they are within function bounds
                    for target_addr in jump_targets:
                        if func.start_address <= target_addr <= func_end_addr_limit:
                            bb_leaders.add(target_addr)
                            # Consider jump targets also as potential xrefs_from if they land in another function
                            # However, for CFG, we track within-function jumps. Cross-function jumps are effectively calls/returns.
                            # For pure XREFS, we track calls and explicit jumps to function entries.
                            if target_addr in self.functions and target_addr != func.start_address:
                                self.functions[target_addr].xrefs_from.add(func.start_address)


                    # For conditional jumps, the fall-through is also a leader
                    # Capstone's CS_GRP_BRANCH_RELATIVE group often indicates conditional branches
                    # We also check for non-call jumps, as calls can also be in CS_GRP_JUMP
                    if insn.group(CS_GRP_BRANCH_RELATIVE) and not insn.group(CS_GRP_CALL):
                        fall_through_addr = insn.address + insn.size
                        if fall_through_addr <= func_end_addr_limit:
                            bb_leaders.add(fall_through_addr)
                    # If it's an indirect jump (no immediate operand), its fall-through is still a new block
                    elif not jump_targets and not insn.group(CS_GRP_RET): # Not a direct jump and not a return
                        fall_through_addr = insn.address + insn.size
                        if fall_through_addr <= func_end_addr_limit:
                            bb_leaders.add(fall_through_addr)


                elif insn.group(CS_GRP_RET):
                    is_terminator = True
                    # No fall-through, this block is an exit block.
            
                # If current instruction is a terminator, the *next* instruction (if any) is a leader
                if is_terminator:
                    next_insn_linear_addr = insn.address + insn.size
                    if next_insn_linear_addr <= func_end_addr_limit and \
                       next_insn_linear_addr not in self.functions: # Don't start BB in the middle of another function
                        bb_leaders.add(next_insn_linear_addr)

            # Update the function's actual end address based on the last instruction assigned to it
            if func.instructions:
                last_insn = func.instructions[-1]
                func.end_address = last_insn.address + last_insn.size - 1
            else:
                func.end_address = func.start_address # No instructions found for function

            # 2. Create BasicBlock objects and assign instructions
            sorted_bb_leaders = sorted(list(bb_leaders))
            
            # Filter leaders to only those truly within the determined function bounds
            valid_bb_leaders = [
                addr for addr in sorted_bb_leaders
                if func.start_address <= addr <= func.end_address
            ]
            
            if not valid_bb_leaders:
                # This could happen for very small functions or if range calculation was off
                # print(f"Warning: No valid basic block leaders found for function 0x{func.start_address:x} within its bounds.")
                continue

            # Iterate through leaders to define basic blocks
            for k, leader_addr in enumerate(valid_bb_leaders):
                if leader_addr not in self.addr_to_idx:
                    # print(f"Error: Leader address 0x{leader_addr:x} not in global instructions map. Skipping BB creation.")
                    continue

                bb = BasicBlock(leader_addr)
                bb.function_address = func.start_address

                current_insn_idx = self.addr_to_idx[leader_addr]
                
                # Determine where this basic block ends
                # It ends either at the instruction before the next leader, or the end of the function's instructions.
                bb_end_idx_global = len(self.instructions) - 1 # Default to end of all instructions

                if k + 1 < len(valid_bb_leaders):
                    next_leader_addr = valid_bb_leaders[k+1]
                    if next_leader_addr in self.addr_to_idx:
                        bb_end_idx_global = self.addr_to_idx[next_leader_addr] - 1
                
                # Ensure we don't go past the function's actual end instruction
                func_last_insn_idx_global = self.addr_to_idx[func.instructions[-1].address] if func.instructions else -1
                bb_end_idx_global = min(bb_end_idx_global, func_last_insn_idx_global)
                
                # Add instructions to the basic block
                for insn_idx in range(current_insn_idx, bb_end_idx_global + 1):
                    if insn_idx >= len(self.instructions): break # Bounds check
                    insn_to_add = self.instructions[insn_idx]
                    
                    # Double check if this instruction is part of a *new* function or outside current function's bound
                    # This check is crucial to prevent blocks from spilling into other functions
                    if insn_to_add.address > func.end_address:
                        break
                    if insn_to_add.address != leader_addr and insn_to_add.address in self.functions:
                        break # If it's a new function's start, this block ends here

                    bb.add_instruction(insn_to_add)

                if not bb.instructions:
                    # print(f"Warning: Basic Block at 0x{bb.start_address:x} in function 0x{func.start_address:x} has no instructions after assignment. Skipping.")
                    continue

                # Determine terminator type for the block
                terminator_insn = bb.instructions[-1]
                if terminator_insn.group(CS_GRP_RET):
                    bb.terminator_type = 'ret'
                    bb.is_exit_block = True
                elif terminator_insn.group(CS_GRP_CALL):
                    bb.terminator_type = 'call'
                elif terminator_insn.group(CS_GRP_JUMP):
                    if terminator_insn.group(CS_GRP_BRANCH_RELATIVE) and not terminator_insn.group(CS_GRP_CALL):
                        bb.terminator_type = 'jump_conditional'
                    else:
                        bb.terminator_type = 'jump_unconditional'
                
                # If the block is the last instruction in the function and didn't terminate explicitly
                if bb.end_address == func.end_address and bb.terminator_type == 'fall_through':
                    bb.is_exit_block = True # Implicit exit block


                func.basic_blocks[bb.start_address] = bb

                if k == 0: # First basic block of the function
                    bb.is_entry_block = True
                    func.entry_block_address = bb.start_address
                
            # 3. Determine Control Flow Edges (Successors and Predecessors)
            for bb_addr, bb in func.basic_blocks.items():
                if not bb.instructions: continue # Skip if no instructions for some reason

                terminator_insn = bb.instructions[-1]
                
                # If it's a return instruction, it's an exit block with no intra-procedural successors
                if bb.terminator_type == 'ret':
                    bb.is_exit_block = True
                    continue # No successors for a return

                # Calculate fall-through address
                fall_through_addr = terminator_insn.address + terminator_insn.size
                
                # Get direct jump/call targets (if any)
                jump_targets = set()
                if terminator_insn.group(CS_GRP_JUMP) or terminator_insn.group(CS_GRP_CALL):
                    for op in terminator_insn.operands:
                        if op.type == CS_OP_IMM:
                            target = op.value.imm
                            if self.elf_info.machine_arch == 'ARM' and (target % 2 != 0):
                                target -= 1 # Strip Thumb bit
                            jump_targets.add(target)
                            break

                # Handle different terminator types to set successors
                if bb.terminator_type == 'jump_unconditional':
                    if jump_targets:
                        target_addr = list(jump_targets)[0]
                        if target_addr in func.basic_blocks: # Check if target is within current function's basic blocks
                            bb.successors.add(target_addr)
                            func.basic_blocks[target_addr].predecessors.add(bb_addr)
                        # else: jump is outside this function or to an unknown address (treat as exit)
                    if not bb.successors: # If no valid internal successor, it's an exit
                        bb.is_exit_block = True

                elif bb.terminator_type == 'jump_conditional':
                    # Path 1: Jump target
                    if jump_targets:
                        target_addr = list(jump_targets)[0]
                        if target_addr in func.basic_blocks:
                            bb.successors.add(target_addr)
                            func.basic_blocks[target_addr].predecessors.add(bb_addr)
                    
                    # Path 2: Fall-through
                    if fall_through_addr in func.basic_blocks:
                        bb.successors.add(fall_through_addr)
                        func.basic_blocks[fall_through_addr].predecessors.add(bb_addr)
                    elif not bb.successors: # If both paths lead outside or are unrecognized
                         bb.is_exit_block = True

                elif bb.terminator_type == 'call':
                    # For intra-procedural CFG, the primary successor is the fall-through return point
                    if fall_through_addr in func.basic_blocks:
                        bb.successors.add(fall_through_addr)
                        func.basic_blocks[fall_through_addr].predecessors.add(bb_addr)
                    # If call is the last instruction of the function (tail call or exit)
                    elif bb.end_address == func.end_address:
                         bb.is_exit_block = True # Consider it an exit if no fall-through within func

                elif bb.terminator_type == 'fall_through':
                    # Successor is simply the next basic block in linear memory order
                    if fall_through_addr in func.basic_blocks:
                        bb.successors.add(fall_through_addr)
                        func.basic_blocks[fall_through_addr].predecessors.add(bb_addr)
                    else: # If falls off the end of the current function's defined instructions
                        bb.is_exit_block = True # Implicit exit block

            # print(f"  CFG built for function {func.name} (0x{func.start_address:x}): {len(func.basic_blocks)} basic blocks.")

    def print_analysis_summary(self):
        """
        Prints a comprehensive summary of the analysis, including
        disassembly info, identified functions, intra-procedural CFGs,
        and an inter-procedural call graph.
        """
        print("\n" + "="*80)
        print(f"      ANALYSIS REPORT")
        print("="*80)

        # --- Section 1: Disassembly Summary ---
        print("\n" + "-"*30 + " Disassembly Summary " + "-"*29)
        print(f"Architecture: {self.elf_info.machine_arch} ({'Little-Endian' if self.elf_info.data_encoding else 'Big-Endian'})")
        print(f"Entry Point: {hex(self.elf_info.entry_point) if self.elf_info.entry_point else 'N/A'}")
        print(f"Total Disassembled Instructions: {len(self.instructions)}")
        print("-" * 80)

        # --- Section 2: Identified Functions ---
        print("\n" + "-"*30 + " Identified Functions " + "-"*29)
        if self.functions:
            sorted_functions = sorted(self.functions.values(), key=lambda f: f.start_address)
            for func in sorted_functions:
                num_bbs = len(func.basic_blocks) if func.basic_blocks else 0
                tags_str = f" (Tags: {', '.join(func.tags)})" if func.tags else ""
                print(f"  0x{func.start_address:x}: {func.name} (Type: {func.func_type}, BBs: {num_bbs}){tags_str}")
        else:
            print("  No functions were identified.")
        print("-" * 80)

        # --- Section 3: Intra-Procedural CFG Details (per Function) ---
        print("\n" + "-"*20 + " Intra-Procedural CFG Details (per Function) " + "-"*20)
        if self.functions:
            sorted_functions_with_cfg = sorted(self.functions.values(), key=lambda f: f.start_address)
            for func in sorted_functions_with_cfg:
                if not func.basic_blocks:
                    print(f"\nFunction: {func.name} (0x{func.start_address:x}) - No basic blocks found.")
                    continue

                print(f"\nFunction: {func.name} (0x{func.start_address:x})")
                print(f"  Entry Block: {hex(func.entry_block_address) if func.entry_block_address else 'N/A'}")
                print(f"  End Address: {hex(func.end_address) if func.end_address else 'N/A'}")
                print(f"  Total Basic Blocks: {len(func.basic_blocks)}")

                sorted_bbs = sorted(func.basic_blocks.values(), key=lambda bb: bb.start_address)
                for bb in sorted_bbs:
                    entry_exit_flags = []
                    if bb.is_entry_block: entry_exit_flags.append("ENTRY")
                    if bb.is_exit_block: entry_exit_flags.append("EXIT")
                    flags_str = f" ({', '.join(entry_exit_flags)})" if entry_exit_flags else ""

                    succ_addrs = [hex(s) for s in sorted(list(bb.successors))]
                    pred_addrs = [hex(p) for p in sorted(list(bb.predecessors))]
                    
                    bb_end_display = hex(bb.end_address) if bb.end_address is not None else 'N/A'

                    print(f"    BB 0x{bb.start_address:x}-0x{bb_end_display} ({len(bb.instructions)} insns){flags_str}")
                    print(f"      Terminator Type: {bb.terminator_type}")
                    print(f"      Successors: [{', '.join(succ_addrs) if succ_addrs else 'None'}]")
                    print(f"      Predecessors: [{', '.join(pred_addrs) if pred_addrs else 'None'}]")
                    
                    # Optional: Print instructions within each basic block
                    # for insn in bb.instructions:
                    #     print(f"        0x{insn.address:x}:\t{insn.mnemonic}\t{insn.op_str}")
        else:
            print("  No functions found to display CFG for.")
        print("-" * 80)

        # --- Section 4: Inter-Procedural Call Graph ---
        print("\n" + "-"*29 + " Inter-Procedural Call Graph " + "-"*28)
        call_graph_summary = {} # caller_name -> [callee_name]
        
        # Populate call_graph_summary for functions that call others
        if self.functions:
            for func_addr, func in self.functions.items():
                if func.called_functions:
                    caller_name = func.name
                    call_graph_summary[caller_name] = []
                    for target_addr in sorted(list(func.called_functions)): # Sort for consistent output
                        target_func = self.functions.get(target_addr)
                        target_name = target_func.name if target_func else f"unresolved_0x{target_addr:x}"
                        call_graph_summary[caller_name].append(target_name)

            if call_graph_summary:
                print("\nFunctions Calling Others:")
                for caller_name in sorted(call_graph_summary.keys()): # Sort callers
                    callees = sorted(call_graph_summary[caller_name]) # Sort callees
                    print(f"  {caller_name} -> {', '.join(callees)}")
            else:
                print("  No function calls identified (Call Graph is empty).")
            
            print("\nFunctions Called By Others (Xrefs-To):")
            # Create a map for quick lookup of function names by address
            addr_to_name = {addr: func.name for addr, func in self.functions.items()}

            xrefs_to_summary = {} # callee_name -> [caller_name]
            for func_addr, func in self.functions.items():
                if func.xrefs_from:
                    callee_name = func.name
                    xrefs_to_summary[callee_name] = []
                    for caller_addr in sorted(list(func.xrefs_from)): # Sort for consistent output
                        caller_name = addr_to_name.get(caller_addr, f"unresolved_0x{caller_addr:x}")
                        xrefs_to_summary[callee_name].append(caller_name)
            
            if xrefs_to_summary:
                for callee_name in sorted(xrefs_to_summary.keys()): # Sort callees
                    callers = sorted(xrefs_to_summary[callee_name]) # Sort callers
                    print(f"  {callee_name} <- {', '.join(callers)}")
            else:
                print("  No explicit cross-references (xrefs-from) to functions found.")
        else:
            print("  No functions to build call graph from.")
        print("-" * 80)

        print("\n" + "="*80)
        print("                  ANALYSIS END")
        print("="*80 + "\n")
    
    def visualize_cfg(self, func_address: int, output_filename: str = "cfg_graph.gv") -> Optional[str]:
        """
        Generates a Graphviz DOT representation and renders an image for a single function's CFG.
        Args:
            func_address: The start address of the function to visualize.
            output_filename: The base name for the DOT file and the rendered image (e.g., 'my_func_cfg').
        Returns:
            The path to the rendered image file, or None if the function is not found.
        """
        func = self.functions.get(func_address)
        if not func:
            print(f"Error: Function 0x{func_address:x} not found for CFG visualization.")
            return None
        if not func.basic_blocks:
            print(f"Warning: Function 0x{func_address:x} ({func.name}) has no basic blocks to visualize.")
            return None

        dot = graphviz.Digraph(comment=f'CFG of {func.name}', format='png', graph_attr={'rankdir': 'TB'}) # TB = Top to Bottom

        # Add nodes (Basic Blocks)
        for bb_addr, bb in func.basic_blocks.items():
            label = f"BB_0x{bb.start_address:x}"
            if bb.end_address:
                label += f"-0x{bb.end_address:x}"
            label += f" ({len(bb.instructions)} insns)\n"
            
            # Add first few instructions to the label for context
            for i, insn in enumerate(bb.instructions):
                if i >= 5: # Limit to first 5 instructions
                    label += "...\n"
                    break
                label += f"0x{insn.address:x}: {insn.mnemonic} {insn.op_str}\n"

            shape = 'box'
            style = ''
            fillcolor = 'lightblue'
            if bb.is_entry_block:
                fillcolor = 'lightgreen'
            if bb.is_exit_block:
                fillcolor = 'lightcoral'
            
            dot.node(f'0x{bb.start_address:x}', label=label, shape=shape, style='filled', fillcolor=fillcolor, fontname='monospace')

        # Add edges (Control Flow)
        for bb_addr, bb in func.basic_blocks.items():
            for succ_addr in bb.successors:
                if succ_addr in func.basic_blocks: # Ensure successor is a valid BB within this function
                    # Determine edge color/style (e.g., red for conditional false, blue for true, black for unconditional)
                    edge_color = 'black'
                    if bb.terminator_type == 'jump_conditional':
                        # This logic is simplistic, true/false branches need more analysis
                        # For now, just mark all conditional branches a different color
                        if succ_addr == (bb.instructions[-1].address + bb.instructions[-1].size): # Fall-through
                            edge_color = 'blue'
                        else: # Jump target
                            edge_color = 'red'

                    dot.edge(f'0x{bb.start_address:x}', f'0x{succ_addr:x}', color=edge_color)
                else:
                    # Handle cases where a successor is outside the analyzed function boundary but within text section.
                    # This might indicate an indirect jump to another function, or end of function with fall-through
                    pass # Not drawing external edges in intra-CFG

        try:
            # Render the graph
            output_path = dot.render(output_filename, view=False, cleanup=True)
            print(f"CFG for {func.name} saved to: {output_path}")
            return output_path
        except Exception as e:
            print(f"Error rendering CFG for {func.name}: {e}")
            print("Please ensure Graphviz system executable is installed and in your PATH.")
            return None

    def visualize_call_graph(self, output_filename: str = "call_graph.gv") -> Optional[str]:
        """
        Generates a Graphviz DOT representation and renders an image for the inter-procedural call graph.
        Args:
            output_filename: The base name for the DOT file and the rendered image (e.g., 'program_call_graph').
        Returns:
            The path to the rendered image file, or None if an error occurs.
        """
        dot = graphviz.Digraph(comment='Program Call Graph', format='png', graph_attr={'rankdir': 'LR'}) # LR = Left to Right

        # Create nodes for all identified functions
        for func_addr, func in self.functions.items():
            shape = 'box'
            style = 'filled'
            fillcolor = 'white'
            
            if func.func_type == 'ELF_Entry':
                fillcolor = 'lightgreen'
            elif func.func_type == 'imported':
                fillcolor = 'lightblue'
            elif func.func_type == 'discovered_prologue':
                fillcolor = 'lightgray'
            
            label = f"{func.name}\n0x{func.start_address:x}"
            dot.node(f'0x{func.start_address:x}', label=label, shape=shape, style=style, fillcolor=fillcolor)

        # Add edges based on called_functions
        for func_addr, func in self.functions.items():
            for called_addr in func.called_functions:
                # Only draw edges to functions we know about (i.e., within self.functions)
                # Unresolved external calls might be represented differently if needed
                if called_addr in self.functions:
                    dot.edge(f'0x{func.start_address:x}', f'0x{called_addr:x}')
                else:
                    # Optionally, add external nodes for unresolved calls
                    unresolved_name = f"external_0x{called_addr:x}"
                    if unresolved_name not in dot.source: # Avoid duplicate node definitions
                        dot.node(unresolved_name, label=f"External: {hex(called_addr)}", shape='note', color='red', fontcolor='red')
                    dot.edge(f'0x{func.start_address:x}', unresolved_name, color='red', style='dashed')


        try:
            output_path = dot.render(output_filename, view=False, cleanup=True)
            print(f"Call Graph saved to: {output_path}")
            return output_path
        except Exception as e:
            print(f"Error rendering Call Graph: {e}")
            print("Please ensure Graphviz system executable is installed and in your PATH.")
            return None