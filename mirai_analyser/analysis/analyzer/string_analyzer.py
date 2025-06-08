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
        self.suspicious_strings: Dict[str, List[Tuple[str, float]]] = {}  # (raw_hex_bytes, entropy)

    def analyze_strings(self) -> None:
        print("\n--- Starting String Analysis ---")
        for section_info in self.elf_info.sections:
            section_name = section_info['name']
            section_data = section_info['data']

            if not section_data or section_name not in ['.rodata','.data','.text']:
                continue

            #print(f'\n[DEBUG] Analyzing section: {section_name} (size: {len(section_data)} bytes)')
            
            # 1. Extract ASCII strings
            self.extracted_strings[section_name] = self._extract_ascii_strings(section_data)
            
            # 2. Find XOR-encrypted strings
            xor_results = self._detect_xor_strings(section_data)
            if xor_results:
                self.xor_decrypted_strings[section_name] = xor_results
                
                #print(f'  [DEBUG] Found {len(xor_results)} relevant XOR strings')
            
            # 3. Detect suspicious high-entropy byte sequences
            suspicious = self._find_suspicious_strings(section_data)
            if suspicious:
                self.suspicious_strings[section_name] = suspicious
                print(f'  [DEBUG] Found {len(suspicious)} high-entropy byte sequences')

    def _find_suspicious_strings(self, data: bytes) -> List[Tuple[str, float]]:
        suspicious = []
        # Extract raw byte sequences, not just ASCII strings
        byte_sequences = self._extract_raw_byte_sequences(data)
        
        for s_bytes in byte_sequences:
            # Calculate entropy on the raw bytes
            entropy = self._calculate_entropy_bytes(s_bytes) 
            if entropy > SUSPICIOUS_ENTROPY_THRESHOLD:
                # We don't filter out Mirai strings here; we want ALL high-entropy data
                suspicious.append((s_bytes.hex(), entropy)) # Store as hex string
        return suspicious

    
    def _extract_ascii_strings(self, data: bytes) -> List[str]:
        # Pattern to find sequences of printable ASCII characters ending optionally with nulls
        pattern = rb'([ -~]{%d,})\x00*' % MIN_STRING_LENGTH 
        strings = []
        for match in re.finditer(pattern, data):
            s_bytes = match.group(1)
            try:
                s = s_bytes.decode('ascii')
                if self._is_plausible_string(s):
                    strings.append(s)
            except UnicodeDecodeError:
                pass
        return strings
    
    def _extract_raw_byte_sequences(self, data: bytes) -> List[bytes]:
        """Extracts contiguous sequences of non-null bytes.
        Useful for finding potential encrypted/compressed blobs.
        """
        sequences = []
        current_seq = bytearray()
        for byte_val in data:
            if byte_val != 0x00: # Null byte as a separator for potential blobs
                current_seq.append(byte_val)
            else:
                if len(current_seq) >= MIN_STRING_LENGTH:
                    sequences.append(bytes(current_seq))
                current_seq = bytearray()
        if len(current_seq) >= MIN_STRING_LENGTH: # Add the last sequence if not null-terminated
            sequences.append(bytes(current_seq))
        return sequences

    def _detect_xor_strings(self, data: bytes) -> List[Tuple[str, str, int]]:
        results = []
        # Iterate over all possible starting positions in the data
        for i in range(len(data)):
            for key in XOR_KEYS:
                decrypted_candidate = bytearray()
                encrypted_candidate = bytearray()
                
                for j in range(i, min(i + MAX_LENGHT_SCAN, len(data))):
                    enc_byte = data[j]
                    dec_byte = enc_byte ^ key
                    
                    if dec_byte == 0x00: # Found a null terminator in the decrypted stream
                        if len(decrypted_candidate) >= MIN_STRING_LENGTH:
                            try:
                                dec_str = decrypted_candidate.decode('ascii')
                                if self._is_plausible_xor_decrypted_string(dec_str):
                                    results.append((encrypted_candidate.hex(), dec_str, key))
                            except UnicodeDecodeError:
                                pass 
                        break 
                    # Only accept standard printable ASCII characters
                    if 0x20 <= dec_byte <= 0x7E: 
                        decrypted_candidate.append(dec_byte)
                        encrypted_candidate.append(enc_byte)
                    else:
                        # Non-printable character detected before a null, potentially end of string
                        if len(decrypted_candidate) >= MIN_STRING_LENGTH:
                            try:
                                dec_str = decrypted_candidate.decode('ascii')
                                # Use stricter plausibility check for XORed output
                                if self._is_plausible_xor_decrypted_string(dec_str):
                                    results.append((encrypted_candidate.hex(), dec_str, key))
                            except UnicodeDecodeError:
                                pass
                        break 

                # Special case: if a string ends at the end of the data (or max_scan_len) without a null
                if len(decrypted_candidate) >= MIN_STRING_LENGTH and (j == min(i + MAX_LENGHT_SCAN, len(data)) - 1):
                    try:
                        dec_str = decrypted_candidate.decode('ascii')
                        if self._is_plausible_xor_decrypted_string(dec_str):
                            results.append((encrypted_candidate.hex(), dec_str, key))
                    except UnicodeDecodeError:
                        pass
                    
        return self._filter_unique_results(results)
    
    # Removed _xor_decrypt_with_key as its logic is now integrated into _detect_xor_strings
    
    def _is_mirai_string(self, s: str) -> bool:
        """Checks if a string is likely a Mirai-related string."""
        if not s or len(s) < MIN_STRING_LENGTH: # Added length check
            return False
            
        s_lower = s.lower()
        
        # Removed the "===" check as it's for test markers, not general Mirai strings
        
        for kw in MIRAI_KEYWORDS:
            if kw in s_lower:
                return True
        
        # Note: FUZZY_PATTERNS and STRUCTURAL_CHECKS should be sets/lists of compiled regex patterns for efficiency
        for pattern_str in FUZZY_PATTERNS: 
            if re.search(pattern_str, s_lower):
                return True
            
        for pattern_str in STRUCTURAL_CHECKS:
            if re.search(pattern_str, s): # Structural checks may depend on original case
                return True
                    
        return False
    
    def _calculate_entropy_bytes(self, data: bytes) -> float: # Renamed to specify bytes
        """Calculates Shannon entropy for a byte sequence."""
        if not data:
            return 0.0
        freq = {}
        for byte_val in data: # Iterate over bytes, not characters
            freq[byte_val] = freq.get(byte_val, 0) + 1
        entropy = 0.0
        for count in freq.values():
            p = count / len(data)
            entropy -= p * math.log2(p)
        return entropy

    def _is_plausible_string(self, s: str) -> bool:

        if not s or len(s) < MIN_STRING_LENGTH:
            return False
        
        for char_code in map(ord, s):
            if not (0x20 <= char_code <= 0x7E or char_code in {0x09, 0x0A, 0x0D}):
                return False

        alpha_num_count = sum(1 for c in s if c.isalnum())
        if len(s) > 0 and (alpha_num_count / len(s)) < MIN_ALPHA_NUM_RATIO:
            return False
        
        # Avoid strings that are entirely numbers or single repeated characters (e.g., "aaaaaaa", "11111")
        if s.isdigit() or len(set(s)) == 1:
            return False
        
        return True

    def _is_plausible_xor_decrypted_string(self, s: str) -> bool:
        if not s or len(s) < MIN_STRING_LENGTH:
            return False

        for char_code in map(ord, s):
            if not (0x20 <= char_code <= 0x7E or char_code in {0x09, 0x0A, 0x0D}):
                return False
        
        alpha_num_count = sum(1 for c in s if c.isalnum())
        if len(s) > 0 and (alpha_num_count / len(s)) < MIN_ALPHA_NUM_RATIO_XOR_PLAUSIBLE:
            return False

        if len(s) > 0:
            char_counts = {}
            for char in s:
                char_counts[char] = char_counts.get(char, 0) + 1
            
            for char, count in char_counts.items():
                if count / len(s) > MAX_REPETITION_RATIO:
                    return False

        if s.isdigit() or len(set(s)) == 1:
            return False

        return True
    
    def _score_string_quality(self, s: str) -> float:
        if not s:
            return 0.0
            
        score = 0.0
        s_lower = s.lower()
        
        for kw in MIRAI_KEYWORDS:
            if kw in s_lower:
                score += 1.0 
                
        for pattern_str in FUZZY_PATTERNS: 
            if re.search(pattern_str, s_lower):
                score += 0.5 
                
        for pattern_str in STRUCTURAL_CHECKS:
            if re.search(pattern_str, s):
                score += 0.3 
                
        # Length bonus
        if len(s) >= 12:
            score += 0.4
        elif len(s) >= 8:
            score += 0.2
        elif len(s) >= MIN_STRING_LENGTH:
            score += 0.1
            
        # Penalize generic strings
        GENERIC_STRINGS = {"error", "success", "failed", "ok", "true", "false", "init", "data", "value"}
        if s_lower in GENERIC_STRINGS:
            score -= 0.5

        return score
    
    def _filter_unique_results(self, results: List[Tuple[str, str, int]]) -> List[Tuple[str, str, int]]:
        unique = {} 
        for enc_hex, dec_str, key in results:
            score = self._score_string_quality(dec_str)
            
            # Only consider strings that meet a minimum quality threshold
            if score < MIN_REPORT_SCORE_THRESHOLD:
                continue

            if dec_str in unique:
                existing_score = unique[dec_str][3]
                if score > existing_score: # Keep the entry with the better score
                    unique[dec_str] = (enc_hex, dec_str, key, score)
            else:
                unique[dec_str] = (enc_hex, dec_str, key, score)
                
        final_results = []
        for v in unique.values():
            final_results.append((v[0], v[1], v[2]))
            
        return sorted(final_results, key=lambda x: -self._score_string_quality(x[1])) 
    
    def print_report(self) -> None:
        """Enhanced reporting of extracted strings."""
        print("\n=== ASCII Strings ===")
        for section, strings in self.extracted_strings.items():
            print(f"\n[{section}]")
            if not strings:
                print("  - No ASCII strings found.")
                continue
            for s in strings:
                # Decide if you want a [MIRAI] tag for *all* ASCII strings, or only for decrypted/suspicious ones
                # For direct ASCII, it's often better to just list them unless they are *very* strong indicators.
                # I'm removing the tag here as it can be noisy for general ASCII.
                print(f"  - {s}") 

        print("\n=== XOR-Decrypted Strings ===")
        for section, strings in self.xor_decrypted_strings.items():
            print(f"\n[{section}]")
            if not strings:
                print("  - No XOR-decrypted strings found.")
                continue
            for enc_hex, dec_str, key in strings:
                mirai_tag = "[MIRAI] " if self._is_mirai_string(dec_str) else ""
                print(f"  - [XOR 0x{key:02x}] {mirai_tag}{dec_str} (Encrypted: {enc_hex})")

        print("\n=== Suspicious High-Entropy Strings ===")
        for section, strings in self.suspicious_strings.items():
            print(f"\n[{section}]")
            if not strings:
                print("  - No suspicious high-entropy strings found.")
                continue
            for s_hex, entropy in strings:
                decryption_attempt = self._try_decrypt_suspicious(s_hex)
                if decryption_attempt:
                    mirai_tag = "[MIRAI] " if self._is_mirai_string(decryption_attempt[1]) else ""
                    print(f"  - [DECRYPTED] {s_hex} -> {mirai_tag}{decryption_attempt[1]} (Method: {decryption_attempt[2]}, Entropy: {entropy:.2f})")
                else:
                    print(f"  - [RAW] {s_hex} (Entropy: {entropy:.2f})")
    
    def _try_decrypt_suspicious(self, s_hex: str) -> Optional[Tuple[str, str, str]]:
        s_bytes = bytes.fromhex(s_hex) # Convert hex string back to bytes
        
        # Try XOR decryption with predefined keys
        for key in XOR_KEYS:
            try:
                decrypted_bytes = bytes([b ^ key for b in s_bytes])
                
                # Attempt to decode and validate for plausibility
                for encoding in ['ascii', 'utf-8', 'latin1']: 
                    try:
                        temp_str = decrypted_bytes.decode(encoding)
                        # Use stricter XOR plausibility for these attempts
                        if self._is_plausible_xor_decrypted_string(temp_str):
                            # Apply scoring for relevance
                            if self._score_string_quality(temp_str) >= MIN_REPORT_SCORE_THRESHOLD:
                                return (s_hex, temp_str, f"XOR-0x{key:02x}")
                    except UnicodeDecodeError:
                        pass
            except Exception: # Catch broader exceptions during XORing/decoding
                continue
        
        # Try Base64 variants
        # Base64 expects bytes, so we need to ensure s_bytes can form a valid Base64 string
        s_base64_str = s_bytes.decode('latin1', errors='ignore') 
        if re.fullmatch(r'^[A-Za-z0-9+/=]+$', s_base64_str) and len(s_base64_str) % 4 == 0:
            for variant in [base64.b64decode, base64.urlsafe_b64decode]:
                try:
                    decoded_bytes = variant(s_base64_str)
                    for encoding in ['ascii', 'utf-8', 'latin1']:
                        try:
                            temp_str = decoded_bytes.decode(encoding)
                            # Use general plausibility for Base64 (less strict than XOR)
                            if self._is_plausible_string(temp_str): 
                                if self._score_string_quality(temp_str) >= MIN_REPORT_SCORE_THRESHOLD:
                                    return (s_hex, temp_str, "Base64")
                        except UnicodeDecodeError:
                            pass
                except Exception:
                    continue
        
        return None