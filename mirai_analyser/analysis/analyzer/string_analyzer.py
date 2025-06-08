import re
import math
import base64
from typing import List, Dict, Any, Tuple, Optional
from config import *

class StringAnalyzer:
    def __init__(self, elf_info: Any):
        self.elf_info = elf_info
        self.extracted_strings: Dict[str, List[str]] = {}
        self.xor_decrypted_strings: Dict[str, List[Tuple[str, str, int]]] = {}  # (enc_hex, dec_str, key)
        self.suspicious_strings: Dict[str, List[Tuple[str, float]]] = {}  # (raw_str, entropy)

    def analyze_strings(self) -> None:
        print("\n--- Starting String Analysis ---")
        for section_info in self.elf_info.sections:
            section_name = section_info['name']
            section_data = section_info['data']

            if not section_data:
                continue

            print(f'\n[DEBUG] Analyzing section: {section_name} (size: {len(section_data)} bytes)')
            
            # 1. Extract ASCII strings
            self.extracted_strings[section_name] = self._extract_ascii_strings(section_data)
            
            # 2. Find XOR-encrypted strings (improved)
            xor_results = self._detect_xor_strings(section_data)
            if xor_results:
                self.xor_decrypted_strings[section_name] = xor_results
                print(f'  [DEBUG] Found {len(xor_results)} XOR strings')
            
            # 3. Detect suspicious high-entropy strings
            suspicious = self._find_suspicious_strings(section_data)
            if suspicious:
                self.suspicious_strings[section_name] = suspicious
                print(f'  [DEBUG] Found {len(suspicious)} high-entropy strings')

    def _find_suspicious_strings(self, data: bytes) -> List[Tuple[str, float]]:
        suspicious = []
        for s in self._extract_ascii_strings(data):
            entropy = self._calculate_entropy(s)
            if entropy > SUSPICIOUS_ENTROPY_THRESHOLD and len(s) >= MIN_STRING_LENGTH:
                if not self._is_mirai_string(s):
                    suspicious.append((s, entropy))
        return suspicious

    def _try_decrypt_suspicious(self, s: str) -> Optional[Tuple[str, str, str]]:
        # Try XOR with all keys (improved)
        for key in XOR_KEYS:
            try:
                decrypted = bytes([ord(c) ^ key for c in s])
                dec_str = decrypted.decode('ascii')
                if self._is_mirai_string(dec_str):
                    return (s, dec_str, f"XOR-0x{key:02x}")
            except (UnicodeDecodeError, ValueError):
                continue
        
        # Try Base64 variants
        for variant in [base64.b64decode, base64.urlsafe_b64decode]:
            try:
                decoded = variant(s).decode('latin1')
                if self._is_mirai_string(decoded):
                    return (s, decoded, "base64")
            except:
                continue
        
        return None
    
    def _extract_ascii_strings(self, data: bytes) -> List[str]:
        pattern = rb'[ -~]{%d,}' % MIN_STRING_LENGTH  # More inclusive pattern
        strings = [s.decode('ascii', errors='ignore') for s in re.findall(pattern, data)]
        return [s for s in strings if self._is_plausible_string(s)]
    
    def _detect_xor_strings(self, data: bytes) -> List[Tuple[str, str, int]]:
        results = []
        for key in XOR_KEYS:
            results.extend(self._xor_decrypt_with_key(data, key))
        
        # Filter results
        filtered = []
        for enc_hex, dec_str, key in results:
            # Skip strings that are too short or just numbers
            if len(dec_str) < 6 or dec_str.isdigit():
                continue
            # Skip strings without at least 2 letters
            if sum(c.isalpha() for c in dec_str) < 2:
                continue
            filtered.append((enc_hex, dec_str, key))
        
        return self._filter_unique_results(filtered)
    
    def _xor_decrypt_with_key(self, data: bytes, key: int) -> List[Tuple[str, str, int]]:
        decrypted_strings = []
        i = 0
        while i < len(data) - MIN_STRING_LENGTH:
            # Only skip null bytes, not other non-printables
            if data[i] == 0x00:
                i += 1
                continue

            decrypted = bytearray()
            encrypted = bytearray()
            j = i

            while j < len(data):
                dec_byte = data[j] ^ key
                # More lenient check - only filter truly invalid bytes
                if dec_byte < 0x20 and dec_byte not in {0x09, 0x0A, 0x0D}:  # \t, \n, \r
                    break
                decrypted.append(dec_byte)
                encrypted.append(data[j])
                j += 1

            if len(decrypted) >= MIN_STRING_LENGTH:
                try:
                    dec_str = decrypted.decode('ascii')
                    if self._is_mirai_string(dec_str):
                        decrypted_strings.append((encrypted.hex(), dec_str, key))
                except UnicodeDecodeError:
                    pass

            i = j if j > i else i + 1
        return decrypted_strings
    
    def _filter_xor_results(self, results: List[Tuple[str, str, int]]) -> List[Tuple[str, str, int]]:
        filtered = []
        for enc_hex, dec_str, key in results:
            # Skip strings that are too short or just garbage
            if (len(dec_str) >= 6 and 
                any(c.isalpha() for c in dec_str) and
                not dec_str.isdigit()):
                filtered.append((enc_hex, dec_str, key))
        return filtered
    
    def _is_printable_xor_byte(self, byte: int) -> bool:
        return (32 <= byte <= 126) or byte in {0x09, 0x0A, 0x0D}  # Simplified
    
    def _is_mirai_string(self, s: str) -> bool:
        # Skip test markers
        if s.startswith("===") and s.endswith("==="):
            return False
            
        s_lower = s.lower()
        
        # Check for common C2 patterns
        if any(
            kw in s_lower 
            for kw in ["c2", ".no-ip", ".ddns", "mirai", "bot"]
        ):
            return True
            
        # Check for attack commands
        if any(
            kw in s_lower 
            for kw in ["flood", "scan", "brute", "kill", "attack"]
        ):
            return True
            
        # Check for credentials
        if any(
            kw in s_lower 
            for kw in ["root", "admin", "xc3511", "vizxv", "password"]
        ):
            return True
            
        return False
    
    def _calculate_entropy(self, s: str) -> float:
        if not s:
            return 0.0
        freq = {}
        for c in s:
            freq[c] = freq.get(c, 0) + 1
        entropy = 0.0
        for count in freq.values():
            p = count / len(s)
            entropy -= p * math.log2(p)
        return entropy

    def _is_plausible_string(self, s: str) -> bool:
        if not s or len(s) < MIN_STRING_LENGTH:
            return False
        
        alpha_num = sum(1 for c in s if c.isalnum())
        if alpha_num / len(s) < MIN_ALPHA_NUM_RATIO:
            return False
            
        return True
    
    def _score_string_quality(self, s: str) -> float:
        """Score string based on Mirai indicators (0-3 scale)"""
        if not s:
            return 0.0
            
        score = 0.0
        s_lower = s.lower()
        
        # Keyword matches
        for kw in MIRAI_KEYWORDS:
            if kw in s_lower:
                score += 1.0
                
        # Pattern matches
        for pattern in FUZZY_PATTERNS:
            if re.search(pattern, s_lower):
                score += 0.5
                
        # Structural checks
        for pattern in STRUCTURAL_CHECKS:
            if re.search(pattern, s):
                score += 0.3
                
        # Length bonus
        if len(s) >= 8:
            score += 0.2
            
        return score
    
    def _filter_unique_results(self, results: List[Tuple[str, str, int]]) -> List[Tuple[str, str, int]]:
        unique = []
        seen = set()
        
        for enc_hex, dec_str, key in results:
            if dec_str not in seen:
                unique.append((enc_hex, dec_str, key))
                seen.add(dec_str)
                
        return sorted(unique, key=lambda x: -self._score_string_quality(x[1]))  # Sort by quality
    
    def print_report(self) -> None:
        """Enhanced reporting"""
        print("\n=== ASCII Strings ===")
        for section, strings in self.extracted_strings.items():
            print(f"\n[{section}]")
            for s in strings:
                if self._is_mirai_string(s):
                    print(f"  - [MIRAI] {s}")
                else:
                    print(f"  - {s}")

        print("\n=== XOR-Decrypted Strings ===")
        for section, strings in self.xor_decrypted_strings.items():
            print(f"\n[{section}]")
            for enc_hex, dec_str, key in strings:
                print(f"  - [XOR 0x{key:02x}] {dec_str} (Encrypted: {enc_hex})")

        print("\n=== Suspicious High-Entropy Strings ===")
        for section, strings in self.suspicious_strings.items():
            print(f"\n[{section}]")
            for s, entropy in strings:
                decryption_attempt = self._try_decrypt_suspicious(s)
                if decryption_attempt:
                    print(f"  - [DECRYPTED] {s} → {decryption_attempt[1]} ({decryption_attempt[2]})")
                else:
                    print(f"  - [RAW] {s} (Entropy: {entropy:.2f})")