from elftools.elf.sections import SymbolTableSection
from typing import List, Dict, Any, Optional

FunctionEntry = Dict[str, Any] # {'name': str, 'address': int, 'type': str, 'tags': List[str]}

class SymbolAnalyzer:
    def __init__(self, elf_info: Any):
        self.elf_info = elf_info
        self.function_map: Dict[int, FunctionEntry] = {} 
        
        # Define mirai_keywords as a class instance attribute
        self.mirai_keywords = {
            # System Manipulation 
            "system": [
                "setuid", "daemonize",          # Privilege escalation
                "fork", "execve", "popen",      # Process execution
                "chroot", "unlink",             # Filesystem manipulation
                "ioctl", "mprotect",            # Memory/device control
                "reboot", "kill",               # Host control
            ],

            # Network & C2 Communication 
            "network": [
                "socket", "connect", "bind","connect_cnc","cnc", # Raw TCP/UDP
                "send", "recv", "sendto",                       # Data transmission
                "gethostbyname", "getaddrinfo","c2_domain",      # DNS resolution
                "inet_addr", "htons",                           # Network byte ops
                "http_open", "http_send",                       # HTTP C2 (rare in Mirai)
                "irc_connect", "irc_send",                      # Legacy IRC C2
            ],

            # Attack Vectors 
            "attack": [
                "attack_init", "attack_start",   # DDoS module loader
                "attack_tcp", "attack_udp",      # Flood types
                "attack_syn", "attack_ack",      # TCP flood variants
                "attack_dns", "attack_http",     # Protocol-specific floods
                "attack_ongoing", "attack_kill", # Attack control
                "killer_",
            ],

            # Propagation/Scanner 
            "scanner": [
                "scanner_init", "scanner_kill",  # Propagation control
                "brute_", "telnet_",             # Brute-force (e.g., "brute_telnet")
                "ssh_", "ftp_",                  # Protocol scanners
                "report_working",                # Success callback
                "table_unlock_val",              # Config decryption
                "random_ip",
            ],

            # Anti-Analysis/Evasion 
            "evasion": [
                "vmdetect", "sandbox_check",     # Environment checks
                "ptrace_", "debugger_",          # Anti-debugging
                "string_decrypt", "xor_",        # String obfuscation
                "kill_av", "unhide_",            # Defense disruption
            ],

            # Persistence 
            "persistence": [
                "install_init", "install_rc",    # *nix persistence
                "add_cron", "write_file",        # Cron/file drops
                "pidfile_create",                # Process tracking
            ],

            # Utility Functions 
            "utility": [
                "util_strlen", "util_memcpy",    # Low-level helpers
                "rand_next", "rand_init",        # PRNG for IP/port gen
                "list_add", "list_remove",      # Bot list management
            ],
        }

    def _tag_function(self, func_name: str, address: int, func_type: str):
        # Initialize function entry if it doesn't exist
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

        for category_name, keywords_list in self.mirai_keywords.items():
        
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

    def display_analysis_result(self):
        print("\n--- ELF Symbol Analysis Results ---")
        print(f"[*] Binary stripped: {self.elf_info.is_stripped}")

        print("\n[*] Function Map (Address: Name [Type] (Tags)):")
        if not self.function_map:
            print("    No functions found.")
        else:
            sorted_functions = sorted(self.function_map.items(), key=lambda item: item[0])
            for address, details in sorted_functions:
                tags_str = f" ({', '.join(details['tags'])})" if details['tags'] else ""
                print(f"    0x{address:08x}: {details['name']} [{details['type']}] {tags_str}")

        dangerous_funcs = [
            f['name'] for f in self.function_map.values() 
            if any(tag in f['tags'] for tag in ['system', 'attack', 'evasion', 'persistence'])
        ]
        if dangerous_funcs:
            print("\n[*] Potentially Dangerous Functions:")
            for func_name in sorted(list(set(dangerous_funcs))): 
                print(f"    - {func_name}")
        else:
            print("\n[*] No overtly dangerous functions identified by keywords.")

        num_imports = len([f for f in self.function_map.values() if f['type'] == 'imported'])
        num_locals = len([f for f in self.function_map.values() if f['type'] == 'local'])
        print(f"\n[*] Total Imported Functions: {num_imports}")
        print(f"[*] Total Local Functions: {num_locals}")