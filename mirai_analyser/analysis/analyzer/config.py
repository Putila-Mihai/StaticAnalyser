MIN_STRING_LENGTH = 4
MIRAI_XOR_KEY = 0x37

MIRAI_KEYWORDS = {
    # Core functionality
    "mirai", "botnet", "c2", "command", "infect",
    # Attacks
    "flood", "syn", "ack", "udp", "tcp", "http", 
    "junk", "spoof", "attack", "kill",
    # Credentials
    "root", "admin", "login", "password", "cred",
    "default", "xc3511", "vizxv", "1234",
    # Network
    "scan", "brute", "spread", "worm", "port",
    "conn", "socket", "packet", "raw",
    # Persistence
    "/dev", "/etc/rc.local", "/bin/busybox", 
    ".so", "ld.so", "init.d", "startup",
    # Obfuscation
    "xor", "encrypt", "decode", "hidden",
    # Hardware targeting
    "arm", "mips", "x86", "sh4", "ppc",
    "router", "camera", "dvr", "iot"
}

XOR_KEYS = [0x37, 0x13, 0x55, 0xFF, 0x01, 0x29, 0x42]

FUZZY_PATTERNS = {
    r'm[1i!]r[4a]i',       # m1r4i, mirai
    r'sc[4a]n',            # sc4n, scan
    r'r[0o]0t',            # r00t, root
    r'[5s]yn[-_]flood',    # SYN_FLOOD, syn-flood
    r'/[e3]tc/rc\.',       # /etc/rc., /3tc/rc.
}

STRUCTURAL_CHECKS = [
    r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?::\d+)?\b',  # IP:port
    r'/etc/rc\.local',
    r'/dev/[a-z0-9]+',
    r'xc3511', 'vizxv',  # Common passwords
    r'[a-f0-9]{8,}',     # Hex strings
    r'SYN_?FLOOD',
    r'UDP_?FLOOD',
    r'TCP_?FLOOD'
]

MIN_ALPHA_NUM_RATIO = 0.3
MIN_ALPHA_NUM_RATIO_XOR_PLAUSIBLE = 0.4
SUSPICIOUS_ENTROPY_THRESHOLD = 4.5
MAX_REPETITION_RATIO = 0.7 
MIN_REPORT_SCORE_THRESHOLD = 0.6
MAX_LENGHT_SCAN = 90

# Function Prologue Patterns for identifying function entry points
#   - First element: List of expected mnemonics in sequence.
#   - Second element: List of expected substrings in op_str for corresponding mnemonics.
# This is a heuristic and requires refinement based on sample analysis.
PROLOGUE_PATTERNS = {
    'ARM': [
        # PUSH {..., LR} followed by SUB SP, SP, #imm
        # Example: PUSH {R4, LR}, SUB SP, SP, #0xNN
        (['push', 'sub'], ['lr', 'sp']),
        # STMDB SP!, {regs} followed by SUB SP, SP, #imm (STMDB is the actual instruction for PUSH)
        # Example: STMD SP!, {R4, LR}, SUB SP, SP, #0xNN
        (['stm', 'sub'], ['!', 'sp']), # Using 'stm' for startswith 'stm' (stmdb, stmfd, etc.)

    ],
    'MIPS': [
        # ADDIU $sp, $sp, -imm followed by SW $ra, imm($sp)
        # Example: ADDIU SP,SP,-imm; SW RA,imm(SP)
        (['addiu', 'sw'], ['sp', 'ra']),
        # ADDIU $sp, $sp, -imm followed by SW $s0, imm($sp) (sometimes $ra is saved later)
        (['addiu', 'sw'], ['sp', 's']),
    ]
}