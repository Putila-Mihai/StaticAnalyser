# analysis/analyzer/string_analyzer.py

import re
import math
import base64
from typing import Any, List, Tuple, Dict, Optional

# Assuming these are imported from your config.py
# Make sure your config.py is correctly structured and accessible
from config import (
    MIN_STRING_LENGTH, MAX_STRING_LENGTH_PLAIN, MAX_XOR_SCAN_LENGTH,
    MIN_ALPHA_NUM_RATIO, MIN_ALPHA_NUM_RATIO_XOR_PLAUSIBLE,
    MAX_REPETITION_RATIO, MAX_CONSECUTIVE_NON_ALNUM,
    SUSPICIOUS_ENTROPY_THRESHOLD, MIN_ENTROPY_BLOB_LENGTH,
    XOR_KEYS, MIRAI_KEYWORDS, FUZZY_PATTERNS, STRUCTURAL_CHECKS,
    MIN_REPORT_SCORE_THRESHOLD
)

class StringAnalyzer:
    def __init__(self, elf_info: Any):
        self.elf_info = elf_info
        self.extracted_strings: Dict[str, List[str]] = {}
        self.xor_decrypted_strings: Dict[str, List[Tuple[str, str, int]]] = {}
        self.suspicious_blobs: Dict[str, List[Tuple[str, float]]] = {}
        self.additional_extracted_from_entropy: Dict[str, List[Tuple[str, str, str]]] = {}

        # Compile regex patterns once for efficiency
        self._compiled_fuzzy_patterns = [re.compile(p, re.IGNORECASE) for p in FUZZY_PATTERNS]
        self._compiled_structural_checks = [re.compile(p) for p in STRUCTURAL_CHECKS]
        # For Mirai keywords, using a set for O(1) lookup is fine, no regex needed there unless patterns are complex


    def analyze_strings(self) -> None:
        print("\n--- Starting String Analysis ---")
        for section_info in self.elf_info.sections:
            section_name = section_info['name']
            section_data = section_info['data']

            # Only process relevant data sections with actual data
            # Added .bss as it can contain initialized data, though often zero-filled
            if not section_data or section_name not in ['.rodata', '.data', '.text', '.bss']:
                continue

            print(f'  [INFO] Analyzing section: {section_name} (size: {len(section_data)} bytes)')
            
            # 1. Extract ASCII strings
            # Filter and score immediately after extraction
            extracted_ascii = self._extract_ascii_strings(section_data)
            self.extracted_strings[section_name] = [
                s for s in extracted_ascii
                if self._score_string_quality(s) >= MIN_REPORT_SCORE_THRESHOLD
            ]
            if self.extracted_strings[section_name]:
                print(f'  [INFO] Found {len(self.extracted_strings[section_name])} relevant ASCII strings in {section_name}')

            # 2. Find XOR-encrypted strings
            xor_results = self._detect_xor_strings(section_data)
            if xor_results:
                # _detect_xor_strings already applies scoring and uniqueness, but let's confirm the threshold
                self.xor_decrypted_strings[section_name] = xor_results # already filtered & sorted by score
                if self.xor_decrypted_strings[section_name]:
                    print(f'  [INFO] Found {len(self.xor_decrypted_strings[section_name])} relevant XOR decrypted strings in {section_name}')
            
            # 3. Detect suspicious high-entropy byte sequences (blobs)
            suspicious_blobs_in_section = self._find_suspicious_blobs(section_data)
            if suspicious_blobs_in_section:
                self.suspicious_blobs[section_name] = suspicious_blobs_in_section
                print(f'  [INFO] Found {len(suspicious_blobs_in_section)} high-entropy blobs in {section_name}')

        # After all sections, attempt to decrypt/decode from suspicious blobs
        # Only add to additional_extracted_from_entropy if successful
        for section_name, blobs in self.suspicious_blobs.items():
            decrypted_from_blobs = []
            if blobs: # Only print if there are blobs to process
                print(f"  [INFO] Attempting to decrypt/decode from {len(blobs)} high-entropy blobs in {section_name}...")
            for s_hex, entropy in blobs:
                result = self._try_decrypt_suspicious(s_hex)
                if result:
                    decrypted_from_blobs.append(result)
            if decrypted_from_blobs:
                self.additional_extracted_from_entropy[section_name] = decrypted_from_blobs
                print(f"  [INFO] Successfully extracted {len(decrypted_from_blobs)} additional strings from blobs in {section_name}")


    def _find_suspicious_blobs(self, data: bytes) -> List[Tuple[str, float]]:
        """
        Extracts contiguous sequences of non-null bytes and checks their entropy.
        Only considers blobs >= MIN_ENTROPY_BLOB_LENGTH.
        """
        suspicious = []
        current_seq = bytearray()
        for byte_val in data:
            if byte_val != 0x00: # Null byte as a separator for potential blobs
                current_seq.append(byte_val)
            else:
                if len(current_seq) >= MIN_ENTROPY_BLOB_LENGTH:
                    entropy = self._calculate_entropy_bytes(bytes(current_seq))
                    if entropy >= SUSPICIOUS_ENTROPY_THRESHOLD: # >= for threshold
                        suspicious.append((bytes(current_seq).hex(), entropy))
                current_seq = bytearray()
        
        # Add the last sequence if not null-terminated and meets criteria
        if len(current_seq) >= MIN_ENTROPY_BLOB_LENGTH:
            entropy = self._calculate_entropy_bytes(bytes(current_seq))
            if entropy >= SUSPICIOUS_ENTROPY_THRESHOLD: # >= for threshold
                suspicious.append((bytes(current_seq).hex(), entropy))
                
        return suspicious

    def _extract_ascii_strings(self, data: bytes) -> List[str]:
        # Pattern to find sequences of printable ASCII characters
        # Using 0x20-0x7E for standard printable, plus common whitespace.
        pattern = rb'([\x20-\x7E\x09\x0A\x0D]{%d,%d})\x00*' % (MIN_STRING_LENGTH, MAX_STRING_LENGTH_PLAIN)
        strings = []
        for match in re.finditer(pattern, data):
            s_bytes = match.group(1)
            try:
                s = s_bytes.decode('ascii')
                # Apply the initial, stricter filter before adding to the list
                if self._is_plausible_string_initial_filter(s):
                    strings.append(s)
            except UnicodeDecodeError:
                pass
        return strings
    
    def _detect_xor_strings(self, data: bytes) -> List[Tuple[str, str, int]]:
        results = []
        # Pre-filter data to avoid unnecessary scanning of large zero blocks etc.
        # This is a simple heuristic, can be more complex.
        search_data = data 
        
        for i in range(len(search_data)):
            for key in XOR_KEYS:
                decrypted_candidate = bytearray()
                encrypted_candidate = bytearray()
                
                # Scan up to MAX_XOR_SCAN_LENGTH or end of data/section
                for j in range(i, min(i + MAX_XOR_SCAN_LENGTH, len(search_data))):
                    enc_byte = search_data[j]
                    dec_byte = enc_byte ^ key
                    
                    # If we find a null terminator in decrypted stream, potential end of string
                    if dec_byte == 0x00: 
                        if len(decrypted_candidate) >= MIN_STRING_LENGTH: # String must meet minimum length
                            try:
                                dec_str = decrypted_candidate.decode('ascii')
                                if self._is_plausible_xor_decrypted_string(dec_str):
                                    results.append((encrypted_candidate.hex(), dec_str, key))
                            except UnicodeDecodeError:
                                pass 
                        break # End of this XOR stream search
                    
                    # Only accept standard printable ASCII characters for decrypted strings
                    if 0x20 <= dec_byte <= 0x7E: # Standard printable ASCII only
                        decrypted_candidate.append(dec_byte)
                        encrypted_candidate.append(enc_byte)
                    else:
                        # Non-printable character detected before a null, potentially end of string
                        if len(decrypted_candidate) >= MIN_STRING_LENGTH:
                            try:
                                dec_str = decrypted_candidate.decode('ascii')
                                if self._is_plausible_xor_decrypted_string(dec_str):
                                    results.append((encrypted_candidate.hex(), dec_str, key))
                            except UnicodeDecodeError:
                                pass
                        break # End of this XOR stream search

                # Special case: if a string ends at the end of the data (or max_scan_len) without a null
                if len(decrypted_candidate) >= MIN_STRING_LENGTH and (j == min(i + MAX_XOR_SCAN_LENGTH, len(search_data)) - 1):
                    try:
                        dec_str = decrypted_candidate.decode('ascii')
                        if self._is_plausible_xor_decrypted_string(dec_str):
                            results.append((encrypted_candidate.hex(), dec_str, key))
                    except UnicodeDecodeError:
                        pass
                    
        return self._filter_unique_results(results) # Apply filtering and scoring here

    def _is_plausible_string_initial_filter(self, s: str) -> bool:
        """
        A strict initial filter for ASCII strings based on length, character set,
        consecutive non-alphanumeric chars, and alphanumeric ratio.
        """
        if not s or len(s) < MIN_STRING_LENGTH or len(s) > MAX_STRING_LENGTH_PLAIN:
            return False

        non_alnum_consecutive = 0
        for char in s:
            char_code = ord(char)
            # Strict check for printable ASCII or common whitespace (tab, newline, carriage return)
            if not (0x20 <= char_code <= 0x7E or char_code in {0x09, 0x0A, 0x0D}):
                return False # Contains non-printable or outside common ASCII range
            
            # Check for consecutive non-alphanumeric characters
            if not char.isalnum():
                non_alnum_consecutive += 1
            else:
                non_alnum_consecutive = 0
            
            if non_alnum_consecutive > MAX_CONSECUTIVE_NON_ALNUM:
                return False # Too many consecutive "weird" chars

        alpha_num_count = sum(1 for c in s if c.isalnum())
        if len(s) > 0 and (alpha_num_count / len(s)) < MIN_ALPHA_NUM_RATIO:
            return False # Not enough alphanumeric characters to be natural language

        # Avoid strings that are entirely numbers or single repeated characters (e.g., "aaaaaaa", "11111")
        if s.isdigit() or len(set(s)) == 1:
            return False
            
        # Check for repetition of any single character or pattern more broadly
        char_counts = {}
        for char in s:
            char_counts[char] = char_counts.get(char, 0) + 1
        for count in char_counts.values():
            if count / len(s) > MAX_REPETITION_RATIO:
                return False # Single character repeats too often

        return True

    def _is_plausible_xor_decrypted_string(self, s: str) -> bool:
        """
        Stricter plausibility check for XOR-decrypted strings, focusing on high text quality.
        """
        if not s or len(s) < MIN_STRING_LENGTH:
            return False

        non_alnum_consecutive = 0
        for char in s:
            char_code = ord(char)
            # For XOR, be very strict: ONLY standard printable ASCII (0x20 to 0x7E)
            if not (0x20 <= char_code <= 0x7E): 
                return False # Contains non-printable or outside strict ASCII range
            
            if not char.isalnum():
                non_alnum_consecutive += 1
            else:
                non_alnum_connum_consecutive = 0
            
            if non_alnum_consecutive > MAX_CONSECUTIVE_NON_ALNUM:
                return False 
        
        alpha_num_count = sum(1 for c in s if c.isalnum())
        if len(s) > 0 and (alpha_num_count / len(s)) < MIN_ALPHA_NUM_RATIO_XOR_PLAUSIBLE:
            return False # Very high alphanumeric requirement for decrypted text

        char_counts = {}
        for char in s:
            char_counts[char] = char_counts.get(char, 0) + 1
        
        for count in char_counts.values():
            if count / len(s) > MAX_REPETITION_RATIO:
                return False # Single character repeats too often

        if s.isdigit() or len(set(s)) == 1: # Still apply these checks
            return False

        return True
    
    def _is_mirai_string(self, s: str) -> bool:
        """Checks if a string is likely a Mirai-related string based on keywords/patterns."""
        if not s:
            return False
            
        s_lower = s.lower()
        
        # Check direct keywords
        for kw in MIRAI_KEYWORDS:
            if kw in s_lower:
                return True
        
        # Check fuzzy patterns (case-insensitive due to compiled regex)
        for pattern in self._compiled_fuzzy_patterns:
            if pattern.search(s_lower):
                return True
            
        # Check structural patterns (case-sensitive as defined in config)
        for pattern in self._compiled_structural_checks:
            if pattern.search(s): # Note: uses original string 's' for structural checks
                return True
                    
        return False

    def _calculate_entropy_bytes(self, data: bytes) -> float:
        """Calculates Shannon entropy for a byte sequence."""
        if not data:
            return 0.0
        freq = {}
        for byte_val in data:
            freq[byte_val] = freq.get(byte_val, 0) + 1
        entropy = 0.0
        for count in freq.values():
            p = count / len(data)
            entropy -= p * math.log2(p)
        return entropy

    def _score_string_quality(self, s: str) -> float:
        """Assigns a quality score to a string based on various heuristics."""
        if not s:
            return 0.0
            
        score = 0.0
        s_lower = s.lower()
        
        # Base score for just passing initial plausibility and length
        score += 0.2 # A small starting bonus for any potentially relevant string

        # Mirai/Keyword related bonus (highest impact)
        if self._is_mirai_string(s):
            score += 1.5 # Significant bonus for strong indicators

        # Length bonus (longer strings are often more meaningful)
        if len(s) >= 32: # Very long strings get a good bonus
            score += 0.6
        elif len(s) >= 16:
            score += 0.4
        elif len(s) >= 10:
            score += 0.2
        
        # Penalize generic/common short strings that might be false positives
        GENERIC_STRINGS = {
            "error", "success", "failed", "ok", "true", "false", "init", "data", "value",
            "exit", "open", "read", "write", "close", "start", "stop", "end",
            "run", "loop", "main", "char", "int", "long", "void", "ptr", "file", "socket",
            "ret", "push", "pop", "mov", "jmp", "call", "xor", "add", "sub", # Assembly mnemonics
            "test", "debug", "version", "info", "config", "param", "status", "ready"
        }
        if s_lower in GENERIC_STRINGS:
            score -= 0.7 # Heavy penalty

        # Penalize strings with too many non-alphanumeric chars (after initial filter)
        num_alnum = sum(1 for c in s if c.isalnum())
        if len(s) > 0 and (num_alnum / len(s)) < 0.8: # If less than 80% alphanumeric, slight penalty
            score -= 0.3
        
        # Penalize strings that are almost all numbers (e.g., "123456789") but not purely digits
        # This helps with IPs, but avoids simple number sequences being highly scored.
        if s_lower.replace('.', '').isdigit() and len(s) > 7 and not s.isdigit(): # "1.2.3.4" is OK, "12345678" still penalized
             score -= 0.4

        # Clamp score to a minimum of 0
        return max(0.0, score)
    
    def _filter_unique_results(self, results: List[Tuple[str, str, int]]) -> List[Tuple[str, str, int]]:
        """
        Filters out duplicate XOR results, applies plausibility, and keeps the one with the highest score.
        Sorts the final list by score (descending).
        """
        unique = {} 
        for enc_hex, dec_str, key in results:
            # Re-check plausibility and then score.
            # This is already done within _detect_xor_strings before adding to results,
            # but a redundant check here ensures robustness if logic changes.
            if not self._is_plausible_xor_decrypted_string(dec_str):
                continue
            
            score = self._score_string_quality(dec_str)
            
            if score < MIN_REPORT_SCORE_THRESHOLD:
                continue

            # Store (enc_hex, dec_str, key, score)
            if dec_str in unique:
                existing_score = unique[dec_str][3] 
                if score > existing_score: # Keep the entry with the better score
                    unique[dec_str] = (enc_hex, dec_str, key, score)
            else:
                unique[dec_str] = (enc_hex, dec_str, key, score)
                
        final_results = []
        # Convert back to (enc_hex, dec_str, key) for external usage
        for v in unique.values():
            final_results.append((v[0], v[1], v[2]))
            
        # Sort by score in descending order
        return sorted(final_results, key=lambda x: -self._score_string_quality(x[1])) 
    
    def _try_decrypt_suspicious(self, s_hex: str) -> Optional[Tuple[str, str, str]]:
        """
        Attempts to decrypt/decode a high-entropy byte sequence using XOR and Base64.
        Returns (original_hex, decrypted_str, method) if successful and passes checks.
        """
        s_bytes = bytes.fromhex(s_hex)
        
        # 1. Try XOR decryption
        for key in XOR_KEYS:
            try:
                decrypted_bytes = bytes([b ^ key for b in s_bytes])
                # Attempt to decode, ignoring errors for a broader initial check, then strict plausibility
                temp_str = decrypted_bytes.decode('ascii', errors='ignore')
                
                # Check for plausibility and score
                if self._is_plausible_xor_decrypted_string(temp_str): # Use stricter XOR plausibility
                    if self._score_string_quality(temp_str) >= MIN_REPORT_SCORE_THRESHOLD:
                        return (s_hex, temp_str, f"XOR-0x{key:02x}")
            except Exception: # Catch broader exceptions during XORing/decoding
                continue
        
        # 2. Try Base64 variants
        # Heuristic: Base64 strings usually look like ASCII and are of a certain length.
        # Check if the raw bytes *could* represent a Base64 string before trying.
        if len(s_bytes) >= MIN_STRING_LENGTH and all(0x20 <= b <= 0x7E for b in s_bytes):
            try:
                # Attempt standard base64decode
                # Use validate=True to fail on malformed Base64 more quickly
                decoded_bytes = base64.b64decode(s_bytes, validate=True)
                temp_str = decoded_bytes.decode('ascii', errors='ignore')
                if self._is_plausible_string_initial_filter(temp_str): # Use regular plausible string check here
                    if self._score_string_quality(temp_str) >= MIN_REPORT_SCORE_THRESHOLD:
                        return (s_hex, temp_str, "Base64")
            except (base64.binascii.Error, UnicodeDecodeError):
                pass
            
            try:
                # Attempt URL-safe base64decode
                decoded_bytes = base64.urlsafe_b64decode(s_bytes, validate=True)
                temp_str = decoded_bytes.decode('ascii', errors='ignore')
                if self._is_plausible_string_initial_filter(temp_str):
                    if self._score_string_quality(temp_str) >= MIN_REPORT_SCORE_THRESHOLD:
                        return (s_hex, temp_str, "Base64-URLSafe")
            except (base64.binascii.Error, UnicodeDecodeError):
                pass
        
        return None
    
    # Inside analysis/analyzer/string_analyzer.py, find and update the get_report method

    def get_report(self) -> List[str]:
        report_lines = []
        report_lines.append("\n" + "="*80)
        report_lines.append("STRING ANALYSIS REPORT")
        report_lines.append("="*80 + "\n")

        # 1. Report Plain ASCII Strings
        if self.extracted_strings:
            report_lines.append("--- Extracted ASCII Strings (Plausible & Scored) ---")
            for section, strings in self.extracted_strings.items():
                if strings:
                    report_lines.append(f"Section: {section}")
                    for s in sorted(strings, key=lambda x: -self._score_string_quality(x)): # Sort by score
                        score = self._score_string_quality(s)
                        report_lines.append(f"  [SCORE {score:.2f}] {s}")
            report_lines.append("\n")
        else:
            report_lines.append("No plausible ASCII strings found.\n")

        # 2. Report XOR-Decrypted Strings
        if self.xor_decrypted_strings:
            report_lines.append("--- XOR Decrypted Strings (Plausible & Scored) ---")
            for section, results in self.xor_decrypted_strings.items():
                if results:
                    report_lines.append(f"Section: {section}")
                    for enc_hex, dec_str, key in results: # Results are already sorted by score
                        score = self._score_string_quality(dec_str)
                        report_lines.append(f"  [XOR 0x{key:02x}] [SCORE {score:.2f}] (Encrypted: {enc_hex[:40]}...) {dec_str}")
            report_lines.append("\n")
        else:
            report_lines.append("No plausible XOR decrypted strings found.\n")

        # 3. Report Strings Extracted from High-Entropy Blobs (e.g., Base64, other decrypts)
        if self.additional_extracted_from_entropy:
            report_lines.append("--- Additional Strings Extracted from High-Entropy Blobs ---")
            for section, results in self.additional_extracted_from_entropy.items():
                if results:
                    report_lines.append(f"Section: {section}")
                    for original_hex, extracted_str, method in results:
                        score = self._score_string_quality(extracted_str)
                        report_lines.append(f"  [{method}] [SCORE {score:.2f}] (Original Hex: {original_hex[:40]}...) {extracted_str}")
            report_lines.append("\n")
        else:
            report_lines.append("No additional strings extracted from high-entropy blobs.\n")


        # 4. Report Raw High-Entropy Blobs (that *couldn't* be decrypted/decoded)
        # This section is for the data that remains 'raw' high-entropy.
        has_raw_blobs = False
        for section, blobs in self.suspicious_blobs.items():
            # Filter out blobs that were successfully decrypted/decoded
            # This is a bit tricky, as we only stored successes in additional_extracted_from_entropy
            # A more robust way would be to mark blobs as 'processed' or 'extracted'
            # For simplicity now, we'll just report all original suspicious_blobs if no decryption happened.
            # OR, only report those *not* found in self.additional_extracted_from_entropy.
            # Let's go with showing them as a separate category, explicitly mentioning if they *might* contain hidden data.
            
            # Create a set of original_hex from successfully decrypted blobs for quick lookup
            successfully_extracted_hex = set()
            for sect_results in self.additional_extracted_from_entropy.values():
                for original_hex, _, _ in sect_results:
                    successfully_extracted_hex.add(original_hex)

            remaining_blobs = [
                (h, e) for h, e in blobs if h not in successfully_extracted_hex
            ]
            
            if remaining_blobs:
                if not has_raw_blobs: # Only print header once
                    report_lines.append("--- Raw High-Entropy Data Blobs (Potential Hidden Data) ---")
                    has_raw_blobs = True
                report_lines.append(f"Section: {section}")
                # Sort by entropy, highest first
                for s_hex, entropy in sorted(remaining_blobs, key=lambda x: -x[1]):
                    report_lines.append(f"  [RAW] (Entropy: {entropy:.2f}) {s_hex[:120]}...") # Limit hex length for readability
            
        if not has_raw_blobs:
            report_lines.append("No raw high-entropy data blobs remaining after decryption attempts.\n")
        else:
            report_lines.append("\n")

        report_lines.append("="*80 + "\n")
        return report_lines