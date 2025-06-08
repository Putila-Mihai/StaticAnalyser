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
        # IP addresses (obfuscated or plain)
        r'\b\d{1,3}[\.\-_]\d{1,3}[\.\-_]\d{1,3}[\.\-_]\d{1,3}\b',
        # Common paths (e.g., /dev/random, /tmp/)
        r'/(dev|tmp|etc|var|proc)/[a-z0-9_\-\.]+',
        # Hex-like sequences (e.g., payloads)
        r'[0-9a-f]{8,}',
        # Common delimiters (:, |, \x13, etc.)
        r'[:|>\x13]',
    ]
MIN_ALPHA_NUM_RATIO = 0.3
SUSPICIOUS_ENTROPY_THRESHOLD = 4.5