from elftools.elf.sections import SymbolTableSection
from typing import List, Dict, Any, Optional
from config import SYMBOL_MIRAI_KEYWORDS
FunctionEntry = Dict[str, Any] # {'name': str, 'address': int, 'type': str, 'tags': List[str]}

class SymbolAnalyzer:
    def __init__(self, elf_info: Any):
        self.elf_info = elf_info
        self.function_map: Dict[int, FunctionEntry] = {} 

    def _tag_function(self, func_name: str, address: int, func_type: str):
        if address not in self.function_map:
            self.function_map[address] = {
                'name': func_name,
                'type': func_type,
                'tags': []
            }
        else:

            if self.function_map[address]['name'] != func_name:
                 pass
            
            # Refine function type: if the current type is 'unknown' or less specific, update it
            # This logic can be adjusted based on desired type precedence
            current_type = self.function_map[address]['type']
            if func_type != 'unknown' and (current_type == 'unknown' or (current_type == 'imported' and func_type == 'local')):
                # Prioritize local over imported if both are found for the same address
                self.function_map[address]['type'] = func_type
            elif func_type != 'unknown' and func_type != current_type and current_type != 'local':
                 # Allow updates if new type is different and not 'unknown', and current isn't 'local'
                 self.function_map[address]['type'] = func_type

        current_tags = self.function_map[address]['tags']

        for category_name, keywords_list in SYMBOL_MIRAI_KEYWORDS.items():
        
            if category_name in current_tags:
                continue

            for keyword in keywords_list:
                if keyword in func_name:
                    current_tags.append(category_name)
                    break 
        
    def analyze_symbols(self):
        imported_func_names = set()

        # Dynamic Symbols (.dynsym)
        for symtab_section in self.elf_info.symbol_tables:
            if symtab_section.name == '.dynsym':
                for symbol in symtab_section.iter_symbols():
                    if symbol.entry.st_info['type'] == 'STT_FUNC':
                        name = symbol.name
                        if not name: 
                            continue

                        address = symbol.entry.st_value 
                        # For imports, st_value is often 0, meaning it's an unresolved import
                        # We still want to track its name
                        if address == 0:
                            imported_func_names.add(name)
                        else:
                            # If it has an address, it's a defined symbol, potentially an imported
                            # function whose address is known (e.g., from PLT/GOT resolution in a loaded library)
                            self._tag_function(name, address, 'imported')
                            imported_func_names.add(name)

        # Symbol Tables 
        for symtab_section in self.elf_info.symbol_tables:
            if symtab_section.name == '.dynsym':
                continue

            for symbol in symtab_section.iter_symbols():
                name = symbol.name
                if not name:
                    continue

                address = symbol.entry.st_value
                sym_type = symbol.entry.st_info['type']

                if sym_type == 'STT_FUNC':
                    # If this function's name was found in .dynsym (i.e., it's an import) AND has an address,
                    # or if it's a local function with an address
                    if address != 0:
                        if name in imported_func_names:
                            self._tag_function(name, address, 'imported')
                        else: # This is likely a local function defined within this ELF
                            self._tag_function(name, address, 'local')

                elif sym_type == 'STT_OBJECT' and address != 0:
                    pass 

    def get_analysis_result(self) -> Dict[str, Any]:
        result = {
            'function_map': self.function_map,
            'is_stripped': self.elf_info.is_stripped,
            'imported_functions': sorted([f['name'] for f in self.function_map.values() if f['type'] == 'imported']),
            'local_functions': sorted([f['name'] for f in self.function_map.values() if f['type'] == 'local']),
            # Define what constitutes "dangerous" based on your mirai_keywords categories
            'dangerous_functions': sorted(list(set([
                f['name'] for f in self.function_map.values() 
                if any(tag in f['tags'] for tag in ['system', 'attack', 'evasion', 'persistence'])
            ])))
        }
        return result

    def get_report(self) -> str:
        """
        Generates a formatted string report of the symbol analysis.
        Assumes analyze_symbols() has already been called successfully.
        """
        report_lines = []
        report_lines.append("="*80)
        report_lines.append("SYMBOL ANALYSIS REPORT")
        report_lines.append("="*80)

        analysis_result = self.get_analysis_result() # Get the structured results

        report_lines.append(f"\n--- Binary Stripping Status ---")
        report_lines.append(f"  Binary stripped: {'Yes' if analysis_result['is_stripped'] else 'No'}")

        report_lines.append(f"\n--- Identified Functions (Symbol Map) ---")
        if not analysis_result['function_map']:
            report_lines.append("  No functions found via symbol analysis.")
        else:
            report_lines.append(f"{'Address':<10} {'Name':<30} {'Type':<10} {'Tags':<25}")
            report_lines.append(f"{'-'*10} {'-'*30} {'-'*10} {'-'*25}")
            sorted_functions = sorted(analysis_result['function_map'].items(), key=lambda item: item[0])
            for address, details in sorted_functions:
                tags_str = ', '.join(details['tags']) if details['tags'] else 'None'
                report_lines.append(f"0x{address:08x}: {details['name']:<30} {details['type']:<10} {tags_str:<25}")

        report_lines.append(f"\n--- Function Type Summary ---")
        report_lines.append(f"  Total Imported Functions: {len(analysis_result['imported_functions'])}")
        report_lines.append(f"  Total Local Functions: {len(analysis_result['local_functions'])}")

        report_lines.append(f"\n--- Potentially Dangerous Functions (by Keywords) ---")
        if analysis_result['dangerous_functions']:
            report_lines.append(f"  {', '.join(analysis_result['dangerous_functions'])}")
        else:
            report_lines.append("  No overtly dangerous functions identified by keywords.")

        report_lines.append("\n" + "="*80)

        return "\n".join(report_lines)