import os
import graphviz
from capstone import Cs, CS_ARCH_ARM, CS_ARCH_MIPS, \
                     CS_MODE_ARM, CS_MODE_THUMB, CS_MODE_MIPS32, CS_MODE_LITTLE_ENDIAN, CS_MODE_BIG_ENDIAN, \
                     CsInsn, CS_GRP_CALL, CS_GRP_JUMP, CS_GRP_RET, CS_GRP_BRANCH_RELATIVE, CS_OP_IMM

from typing import List, Dict, Any, Optional, Set

from elf_parser import ELFInfo
from config import PROLOGUE_PATTERNS 

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
        self.end_address = insn.address

    def __repr__(self):
        start = hex(self.start_address)
        end = hex(self.end_address) if self.end_address is not None else 'N/A'
        num_insns = len(self.instructions)
        return f"BB(0x{start[2:]}-0x{end[2:]}, {num_insns} insns, succ={len(self.successors)})"

class Function:
    def __init__(self, start_address: int, name: Optional[str] = None, func_type: str = 'unknown'):
        self.start_address = start_address
        self.name = name if name else f"sub_{hex(start_address)}"
        self.func_type = func_type # e.g., 'local', 'imported', 'discovered_call', 'discovered_prologue'
        self.end_address: Optional[int] = None
        self.instructions: List[CsInsn] = [] # All instructions strictly belonging to this function
        self.called_functions: Set[int] = set() # Addresses of functions called by this one (call graph)
        self.xrefs_from: Set[int] = set() # Addresses that reference (call/jump to) this function.
        self.basic_blocks: Dict[int, BasicBlock] = {} # Map of BBs (start_addr as key)
        self.entry_block_address: Optional[int] = None # The start_address of the function's entry block
        self.tags: List[str] = []

    def __repr__(self):
        return f"Function(0x{self.start_address:x}, {self.name}, {self.func_type}, {len(self.basic_blocks)} BBs)"


class CodeAnalyzer:
    def __init__(self, elf_info: ELFInfo):
        self.elf_info = elf_info
        self.md = None  # Capstone engine
        self.instructions: List[CsInsn] = [] # List to store all disassembled instructions linearly
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
                 cs_mode |= CS_MODE_THUMB
            else:
                 cs_mode |= CS_MODE_ARM

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
        
        if self.elf_info.entry_point is not None:
            entry_point_addr = self.elf_info.entry_point
            
            if self.elf_info.machine_arch == 'ARM' and (entry_point_addr % 2 != 0):
                entry_point_addr -= 1 
            
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
           


        
        if not symbol_analyzer_result.get('is_stripped', True) or symbol_analyzer_result.get('function_map'):
            
            self._find_functions_from_symbols(symbol_analyzer_result['function_map'])
        else:
            print("Binary is stripped/no symbols. Relying on code heuristics...")

       
        self._find_functions_from_call_targets()

        
        if symbol_analyzer_result.get('is_stripped', True):
             self._find_functions_from_prologues()

    def _find_functions_from_symbols(self, symbol_function_map: Dict[int, Dict[str, Any]]) -> None:
        """Helper to add functions identified by SymbolAnalyzer or update existing ones with symbol info."""
        for addr, sym_details in symbol_function_map.items():
            if addr not in self.functions:
               
                func = Function(
                    start_address=addr,
                    name=sym_details.get('name'),
                    func_type=sym_details.get('type', 'symbol') # Default to 'symbol' type
                )
                func.tags.extend(sym_details.get('tags', []))
                self.functions[addr] = func
            else:
               
                existing_func = self.functions[addr]
                
                sym_name = sym_details.get('name')
                if sym_name:
                   
                    if existing_func.name.startswith("sub_") or existing_func.name == "ELF_Entry":
                        existing_func.name = sym_name
                    if existing_func.func_type in ['unknown', 'discovered_call', 'discovered_prologue']:
                        existing_func.func_type = sym_details.get('type', 'symbol')
                    elif existing_func.func_type == 'imported' and sym_details.get('type') == 'local':
                        existing_func.func_type = sym_details['type']

                existing_func.tags.extend(sym_details.get('tags', []))
                existing_func.tags = list(set(existing_func.tags)) # Deduplicate tags


    def _find_functions_from_call_targets(self) -> None:
        for insn in self.instructions:
            if (insn.group(CS_GRP_CALL) and not insn.group(CS_GRP_JUMP)) or \
               (self.elf_info.machine_arch == 'ARM' and insn.mnemonic.startswith('bl')) or \
               (self.elf_info.machine_arch == 'MIPS' and insn.mnemonic.startswith('jal')):
                
                target_addr = None
                for op in insn.operands:
                    if op.type == CS_OP_IMM: 
                        target_addr = op.value.imm
                        break
                
                if target_addr is not None:
                    if self.elf_info.machine_arch == 'ARM' and (target_addr % 2 != 0):
                        target_addr -= 1 

                    is_in_text_section = False
                    if self.text_section_data_info:
                        text_start = self.text_section_data_info['addr']
                        text_end = text_start + self.text_section_data_info['size']
                        if text_start <= target_addr < text_end:
                            is_in_text_section = True
                    
                    if is_in_text_section and target_addr not in self.functions:
                        func = Function(target_addr, func_type='discovered_call')
                        self.functions[target_addr] = func
                
    def _find_functions_from_prologues(self) -> None:

        current_arch_prologues = []

        if self.elf_info.machine_arch in PROLOGUE_PATTERNS:
            current_arch_prologues = PROLOGUE_PATTERNS[self.elf_info.machine_arch]
        else:
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
                    break # Break from pattern loop, found a function, move to next instruction

    def build_control_flow_graphs(self) -> None:
    
        if not self.functions:
            print("Warning: No functions identified. Cannot build CFGs.")
            return

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
            func_end_addr_limit = function_boundaries[func_addr]

            if func.start_address not in self.addr_to_idx:
                continue

            bb_leaders = set()
            bb_leaders.add(func.start_address) # Function start is always a BB leader

            start_idx_global = self.addr_to_idx[func.start_address]
            func.instructions = [] 

            for i in range(start_idx_global, len(self.instructions)):
                insn = self.instructions[i]

               
                if insn.address > func_end_addr_limit or \
                   (insn.address != func.start_address and insn.address in self.functions):
                    break 

                func.instructions.append(insn) 
               
                is_terminator = False
                
                if insn.group(CS_GRP_CALL):
                    is_terminator = True
                    fall_through_addr = insn.address + insn.size
                    if fall_through_addr <= func_end_addr_limit: # Ensure fall-through is within function bounds
                        bb_leaders.add(fall_through_addr)
                    
                    for op in insn.operands:
                        if op.type == CS_OP_IMM:
                            call_target = op.value.imm
                            if self.elf_info.machine_arch == 'ARM' and (call_target % 2 != 0):
                                call_target -= 1 # Strip Thumb bit if necessary
                            func.called_functions.add(call_target)
                            
                            if call_target in self.functions:
                                self.functions[call_target].xrefs_from.add(func.start_address) # ADDED THIS LINE
                            break

                elif insn.group(CS_GRP_JUMP):
                    is_terminator = True
                    
                    jump_targets = set()
                    for op in insn.operands:
                        if op.type == CS_OP_IMM:
                            target = op.value.imm
                            if self.elf_info.machine_arch == 'ARM' and (target % 2 != 0):
                                target -= 1 
                            jump_targets.add(target)
                            break
                    
                    for target_addr in jump_targets:
                        if func.start_address <= target_addr <= func_end_addr_limit:
                            bb_leaders.add(target_addr)
                            # Consider jump targets also as potential xrefs_from if they land in another function
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
                    elif not jump_targets and not insn.group(CS_GRP_RET): 
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

            sorted_bb_leaders = sorted(list(bb_leaders))
            
            valid_bb_leaders = [
                addr for addr in sorted_bb_leaders
                if func.start_address <= addr <= func.end_address
            ]
            
            if not valid_bb_leaders:
                continue

            for k, leader_addr in enumerate(valid_bb_leaders):
                if leader_addr not in self.addr_to_idx:
                    continue

                bb = BasicBlock(leader_addr)
                bb.function_address = func.start_address

                current_insn_idx = self.addr_to_idx[leader_addr]
                
                # Determine where this basic block ends
                # It ends either at the instruction before the next leader, or the end of the function's instructions.
                bb_end_idx_global = len(self.instructions) - 1 

                if k + 1 < len(valid_bb_leaders):
                    next_leader_addr = valid_bb_leaders[k+1]
                    if next_leader_addr in self.addr_to_idx:
                        bb_end_idx_global = self.addr_to_idx[next_leader_addr] - 1
                
                # Ensure we don't go past the function's actual end instruction
                func_last_insn_idx_global = self.addr_to_idx[func.instructions[-1].address] if func.instructions else -1
                bb_end_idx_global = min(bb_end_idx_global, func_last_insn_idx_global)
                
                for insn_idx in range(current_insn_idx, bb_end_idx_global + 1):
                    if insn_idx >= len(self.instructions): break # Bounds check
                    insn_to_add = self.instructions[insn_idx]
                    
                    # Double check if this instruction is part of a *new* function or outside current function's bound
                    # This check is crucial to prevent blocks from spilling into other functions
                    if insn_to_add.address > func.end_address:
                        break
                    if insn_to_add.address != leader_addr and insn_to_add.address in self.functions:
                        break

                    bb.add_instruction(insn_to_add)

                if not bb.instructions:
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
                    bb.is_exit_block = True 


                func.basic_blocks[bb.start_address] = bb

                if k == 0: # First basic block of the function
                    bb.is_entry_block = True
                    func.entry_block_address = bb.start_address
                
            #Determine Control Flow Edges (Successors and Predecessors)
            for bb_addr, bb in func.basic_blocks.items():
                if not bb.instructions: continue 

                terminator_insn = bb.instructions[-1]
                
                if bb.terminator_type == 'ret':
                    bb.is_exit_block = True
                    continue 

                # Calculate fall-through address
                fall_through_addr = terminator_insn.address + terminator_insn.size
                
                # Get direct jump/call targets
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
                    if not bb.successors:
                        bb.is_exit_block = True

                elif bb.terminator_type == 'jump_conditional':
                    # Jump target
                    if jump_targets:
                        target_addr = list(jump_targets)[0]
                        if target_addr in func.basic_blocks:
                            bb.successors.add(target_addr)
                            func.basic_blocks[target_addr].predecessors.add(bb_addr)
                    
                    # Fall-through
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
                         bb.is_exit_block = True

                elif bb.terminator_type == 'fall_through':
                    # Successor is simply the next basic block in linear memory order
                    if fall_through_addr in func.basic_blocks:
                        bb.successors.add(fall_through_addr)
                        func.basic_blocks[fall_through_addr].predecessors.add(bb_addr)
                    else: # If falls off the end of the current function's defined instructions
                        bb.is_exit_block = True # Implicit exit block

    def get_report(self) -> str:
    
        report_lines = []
        report_lines.append("="*80)
        report_lines.append("CODE ANALYSIS REPORT")
        report_lines.append("="*80)

        report_lines.append("\n--- Disassembly Summary ---")
        if self.text_section_data_info:
            report_lines.append(f"  .text Section VAddr: 0x{self.text_section_data_info['addr']:x}")
            report_lines.append(f"  .text Section Size:  0x{self.text_section_data_info['size']:x} bytes")
        report_lines.append(f"  Total Disassembled Instructions: {len(self.instructions)}")

        report_lines.append("\n--- Function Summary ---")
        report_lines.append(f"  Total Functions Identified: {len(self.functions)}")
        
        func_types_count = {}
        for func in self.functions.values():
            func_types_count[func.func_type] = func_types_count.get(func.func_type, 0) + 1
        
        report_lines.append("  Functions by Type:")
        for func_type, count in sorted(func_types_count.items()):
            report_lines.append(f"    - {func_type.replace('_', ' ').title()}: {count}")

        report_lines.append("\n--- Detailed Function List ---")
        if not self.functions:
            report_lines.append("  No functions to display.")
        else:
            report_lines.append(f"{'Address':<10} {'Name':<35} {'Type':<15} {'Tags':<20} {'BBs':<5} {'Calls':<6} {'XRefs':<6}")
            report_lines.append(f"{'-'*10} {'-'*35} {'-'*15} {'-'*20} {'-'*5} {'-'*6} {'-'*6}")
            
            sorted_functions = sorted(self.functions.values(), key=lambda f: f.start_address)
            for func in sorted_functions:
                tags_str = ', '.join(func.tags) if func.tags else 'None'
                report_lines.append(
                    f"0x{func.start_address:08x} {func.name:<35} {func.func_type:<15} {tags_str:<20} "
                    f"{len(func.basic_blocks):<5} {len(func.called_functions):<6} {len(func.xrefs_from):<6}"
                )

        report_lines.append("\n--- Call Graph Summary ---")
        functions_with_calls = sorted([f for f in self.functions.values() if f.called_functions], key=lambda f: len(f.called_functions), reverse=True)
        functions_with_xrefs = sorted([f for f in self.functions.values() if f.xrefs_from], key=lambda f: len(f.xrefs_from), reverse=True)

        if functions_with_calls:
            report_lines.append(" Top 5 Functions Making Calls:")
            for i, func in enumerate(functions_with_calls[:5]):
                report_lines.append(f"    {i+1}. {func.name} (0x{func.start_address:x}) calls {len(func.called_functions)} others.")
        else:
            report_lines.append(" No functions observed making calls.")

        if functions_with_xrefs:
            report_lines.append(" Top 5 Functions Being Called/Referenced:")
            for i, func in enumerate(functions_with_xrefs[:5]):
                report_lines.append(f"    {i+1}. {func.name} (0x{func.start_address:x}) has {len(func.xrefs_from)} cross-references.")
        else:
            report_lines.append(" No functions observed being called/referenced.")

        report_lines.append("\n" + "="*80)
        return "\n".join(report_lines)

    def get_visualization(self, output_dir: str = "visualizations", 
                            base_name: Optional[str] = None,
                            generate_cfgs: bool = True,
                            cfg_filter_mirai_tags: bool = True,
                            cfg_filter_entry_point: bool = True,
                            cfg_filter_min_xrefs: int = 5, # Generate CFG for functions with >= 5 xrefs
                            cfg_filter_min_calls_made: int = 5, # Generate CFG for functions calling >= 5 others
                            cfg_max_count: int = 15 # Max number of CFGs to generate if there are to many results
                            ) -> List[str]:
        if not self.functions:
            print("Warning: No functions identified. Skipping visualization generation.")
            return []
        os.makedirs(output_dir, exist_ok=True)
        generated_files = []
        
        if base_name is None:
            base_name = os.path.basename(self.elf_info.file_path).replace('.', '_') + "_analysis"
        
        print(f"[*] Generating visualizations to '{output_dir}'...")

        print("  - Generating Global Call Graph...")
        call_graph = graphviz.Digraph(comment='Global Call Graph', format='png')
        call_graph.attr(rankdir='LR', size='15,15')

        for func_addr, func in self.functions.items():
            label = f"{func.name}\n(0x{func.start_address:x})"
            color = 'lightgray'
            if func.func_type == 'imported':
                color = 'lightgoldenrod'
            elif func.func_type == 'local':
                color = 'lightblue'
            elif func.func_type == 'ELF_Entry':
                color = 'greenyellow'

            if func.tags:
                label += f"\nTags: {', '.join(func.tags)}"

            call_graph.node(f'Func_{func_addr:x}', label=label, shape='box', style='filled', fillcolor=color)

        for func_addr, func in self.functions.items():
            for called_func_addr in func.called_functions:
                if called_func_addr in self.functions: 
                    call_graph.edge(f'Func_{func_addr:x}', f'Func_{called_func_addr:x}')
                pass 

        try:
            output_path_base = os.path.join(output_dir, f"{base_name}_call_graph")
            dot_file = call_graph.render(output_path_base, view=False, cleanup=True)
            generated_files.append(dot_file)
            print(f"  Generated Call Graph: {dot_file}")
        except Exception as e:
            print(f"  Error generating Call Graph: {e}")

        if generate_cfgs:
            print("  - Generating Control Flow Graphs for selected functions...")
            
            cfgs_to_generate = set()

            # Mirai-tagged functions
            if cfg_filter_mirai_tags:
                for func_addr, func in self.functions.items():
                    if any('mirai' in tag.lower() for tag in func.tags): # Check if any tag contains 'mirai'
                        cfgs_to_generate.add(func_addr)
            
            # ELF Entry Point
            if cfg_filter_entry_point and self.elf_info.entry_point in self.functions:
                cfgs_to_generate.add(self.elf_info.entry_point)

            # Functions with many xrefs or calls (prioritize more relevant ones first)
            # We'll build a sorted list and add them until max_count is reached
            candidate_funcs = sorted(self.functions.values(), key=lambda f: (len(f.xrefs_from) + len(f.called_functions)), reverse=True)
            
            for func in candidate_funcs:
                if func.start_address in cfgs_to_generate: # Already added
                    continue
                if len(func.xrefs_from) >= cfg_filter_min_xrefs or \
                   len(func.called_functions) >= cfg_filter_min_calls_made:
                    cfgs_to_generate.add(func.start_address)
                
                if len(cfgs_to_generate) >= cfg_max_count:
                    break

            generated_cfg_count = 0
            for func_addr in cfgs_to_generate:
                if generated_cfg_count >= cfg_max_count:
                    print(f"    Max CFG count ({cfg_max_count}) reached. Skipping remaining.")
                    break

                func = self.functions[func_addr]
                if not func.basic_blocks:
                    continue

                dot = graphviz.Digraph(comment=f'CFG for {func.name}', format='png')
                dot.attr(rankdir='TB', size='15,10') 
                
                for bb_addr, bb in func.basic_blocks.items():
                    label_lines = []
                    label_lines.append(f"BB: 0x{bb.start_address:x}")
                    
                    for i, insn in enumerate(bb.instructions):
                        if i >= 5 and len(bb.instructions) > 5: 
                            label_lines.append("...")
                            break
                        label_lines.append(f"  0x{insn.address:x}: {insn.mnemonic} {insn.op_str}")

                    color = 'lightblue'
                    if bb.is_entry_block:
                        color = 'greenyellow'
                    elif bb.is_exit_block:
                        color = 'salmon'
                    
                    dot.node(f'BB_{bb_addr:x}', label='\n'.join(label_lines), shape='box', style='filled', fillcolor=color)

                for bb_addr, bb in func.basic_blocks.items():
                    for succ_addr in bb.successors:
                        if succ_addr in func.basic_blocks: 
                            dot.edge(f'BB_{bb_addr:x}', f'BB_{succ_addr:x}')
                
                try:
                    output_path_base = os.path.join(output_dir, f"{base_name}_cfg_0x{func_addr:x}_{func.name.replace(':', '_')}")
                    dot_file = dot.render(output_path_base, view=False, cleanup=True)
                    generated_files.append(dot_file)
                    generated_cfg_count += 1
                except Exception as e:
                    print(f"    Error generating CFG for {func.name} (0x{func_addr:x}): {e}")
            
            if generated_cfg_count > 0:
                print(f"  Generated {generated_cfg_count} selected CFG(s).")
            else:
                print("  No CFGs generated based on the current filters.")


        print(f"[*] Visualization generation complete. Total files: {len(generated_files)}")
        return generated_files