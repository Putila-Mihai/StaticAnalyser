# Constants for StringAnalyzer
# GENERAL STRING FILTERING
MIN_STRING_LENGTH = 7 # Increased from 5. Strings shorter than 7 are often noise or too generic.
MAX_STRING_LENGTH_PLAIN = 128 # Reduced from 256. Very long plain strings are rare for direct C2/commands.
MAX_XOR_SCAN_LENGTH = 256 # Reduced from 512. Most XORed strings in malware are not excessively long.

# CHARACTER PLAUSIBILITY RATIOS & LIMITS
MIN_ALPHA_NUM_RATIO = 0.65  # Increased from 0.5. At least 65% alphanumeric for plain strings.
MIN_ALPHA_NUM_RATIO_XOR_PLAUSIBLE = 0.80 # Increased from 0.65. Very strict for XOR. Decrypted output should look like text.
MAX_REPETITION_RATIO = 0.25 # Reduced from 0.35. No single char should repeat more than 25% of the string (e.g., 'AAAAABBCDE' = 5/10=0.5, too high).
MAX_CONSECUTIVE_NON_ALNUM = 2 # Reduced from 3. Max 2 consecutive non-alphanumeric chars. (e.g., "ab-cd_ef" is okay, "ab___cd" is not).

# ENTROPY-BASED DETECTION
SUSPICIOUS_ENTROPY_THRESHOLD = 6.0 # Increased from 5.0. Higher threshold means more truly "random-looking" data.
MIN_ENTROPY_BLOB_LENGTH = 32 # Increased from 16. Smaller high-entropy blobs are more likely random padding/noise.

# SCORING THRESHOLDS (This is where the final reporting decision is made)
MIN_REPORT_SCORE_THRESHOLD = 1.0 # Increased from 0.8. Only strings with strong indicators pass.

# XOR KEYS (Keep your expanded set, but ensure it's a set/tuple for efficiency if iterated frequently)
XOR_KEYS = (0x37, 0x13, 0x55, 0xFF, 0x01, 0x29, 0x42) # Using a tuple is slightly more efficient than list if not modified.

# MIRAI KEYWORDS (Consolidate and refine - make them lowercase)
# Prioritize truly indicative keywords. Avoid overly generic ones.
MIRAI_KEYWORDS = {
    # Core functionality & DDoS types (highly indicative)
    "mirai", "botnet", "jihad", "okiru", "satori", "gafgyt", # Specific botnet names
    "syn_flood", "udp_flood", "tcp_flood", "http_flood", "gre_flood", "ack_flood",
    "dns_flood", "vse_flood", "nf_flood", "xmas_flood", "null_flood",
    "attack_init", "attack_start", "attack_stop", "attack_kill", "kill_attack",
    "scanner_init", "scanner_kill", "brute_telnet", "brute_ssh", "brute_http",
    "report_working", "table_unlock", # Related to scanner/config
    "random_ip", "set_id", # Bot IDs

    # Common C2 & Network-related (still specific)
    "socket", "connect", "send", "recv", "sendto", "recvfrom", "bind",
    "gethostbyname", "getaddrinfo", "inet_addr", "htons", "ntohs",
    "c2_domain", "cnc_server", "irc_server", "telnet_client", "http_client",
    "busybox", # Often used in IoT malware
    "gpon", "tr-069", "dvr", "camera", "jaws", # Common vulnerable devices
    "infect", "payload", "download", "execute", "upload",

    # Persistence/System Manipulation (often indicative)
    "/bin/busybox", "/etc/init.d", "/var/run", "/dev/null", "/proc/net/dev",
    "cat /proc/cpuinfo", "uname -a", "/bin/sh", "/bin/echo", "system",
    "killall", "rm -rf", "wget", "tftp", "curl", "chmod", "mount", "unlink",
    "daemonize", "fork", "execve", "popen", "setuid", "chroot", "mprotect",
    "reboot", "kill", "pidfile", "install_init", "install_rc", "add_cron",

    # Obfuscation/Evasion (strong indicators)
    "string_decrypt", "xor_decrypt", "decrypt_key", "obfuscated",
    "vmdetect", "sandbox_check", "ptrace", "debugger_detect",
    "kill_av", "unhide_process",

    # Credentials / Common defaults
    "root:root", "admin:admin", "user:user", "guest:guest", # Default creds
    "xc3511", "vizxv", "dreambox", "ZTE", "Huawei", "GPON", "ADSL", # Common device/firmware creds
    "anonymous:anonymous", # FTP/TFTP defaults
    "default", "123456", "password", "support" # Generic common passwords
}

# FUZZY PATTERNS (Use raw strings for regex to avoid backslash issues)
# These are for slightly distorted or partial matches.
FUZZY_PATTERNS = [
    r'm[i1!l]r[a4]i',       # mirai, m1rai, m!rai, m1ra4i
    r'sc[a4]nn?er',         # scaner, scanner, sc4ner
    r'r[o0]o?t',            # root, r0ot, r00t
    r'syn[-_]?fl[o0]od',    # syn_flood, syn-flood, synflood
    r'/(e|3)tc/rc\.',       # /etc/rc., /3tc/rc.
    r'(user|admin|root)[\s:]*(user|admin|root|password|123456)', # Credential-like patterns
    r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?::\d+)?',  # IP:port pattern
    r'[a-f0-9]{16,}',     # Longer hex strings (potential hashes, encrypted blobs)
    r'wget\s+-O\s+',      # `wget -O` to download and save
    r'tftp\s+-g\s+-r',    # `tftp -g -r` to get a file
]

# STRUCTURAL CHECKS (More specific, often full string patterns)
# These should be very strong indicators, potentially leading to a higher score.
STRUCTURAL_CHECKS = [
    r'/etc/rc.local', # Full path for persistence
    r'/dev/(null|zero|urandom)', # Common device files
    r'/bin/busybox', # Common Linux utility
    r'POST /[a-zA-Z0-9_/.-]+ HTTP/1\.[01]', # Generic HTTP POST request
    r'GET /[a-zA-Z0-9_/.-]+ HTTP/1\.[01]',  # Generic HTTP GET request
    r'User-Agent: [a-zA-Z0-9./\s\-()]+', # User-Agent strings
    r'Host: \d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', # Host header with IP
    r'login:[\s\S]*password', # More generic login/password prompts
    r'uname\s+-a', # Specific command
    r'cat\s+/proc/cpuinfo', # Specific command
    r'killall\s+[a-zA-Z0-9_.-]+', # Killall command
    r'rm\s+-rf\s+/[a-zA-Z0-9_/.-]+', # Recursive force delete command
    r'telnet\s+\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', # telnet command
    r'ssh\s+[a-zA-Z0-9@.-]+\s+-p\s+\d+', # ssh command with port
    r'icmp\s+echo\s+request', # ICMP messages
    r'Mirai', 'MIRAI', # Direct "Mirai" string (case sensitive check in _is_mirai_string then)
]

# Function Prologue Patterns (These seem okay as they are, but good to keep in mind for code analysis)
PROLOGUE_PATTERNS = {
    'ARM': [
        (['push', 'sub'], ['lr', 'sp']),
        (['stm', 'sub'], ['!', 'sp']),
    ],
    'MIPS': [
        (['addiu', 'sw'], ['sp', 'ra']),
        (['addiu', 'sw'], ['sp', 's']),
    ]
}
SYMBOL_MIRAI_KEYWORDS = {
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
