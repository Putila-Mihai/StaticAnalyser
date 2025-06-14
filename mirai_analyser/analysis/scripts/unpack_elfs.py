import os
import subprocess
from pathlib import Path

def unpack_elf(input_path, output_dir="unpacked"):
    """Unpack a single ELF file using UPX or GDB."""
    Path(output_dir).mkdir(exist_ok=True)
    output_path = os.path.join(output_dir, f"unpacked_{os.path.basename(input_path)}")

    # Try UPX first
    try:
        subprocess.run(["upx", "-d", input_path, "-o", output_path], 
                      check=True, stderr=subprocess.DEVNULL)
        print(f"[+] UPX unpacked: {output_path}")
        return
    except subprocess.CalledProcessError:
        pass

    # Fallback to GDB memory dump (for custom packers)
    try:
        gdb_cmds = f"""
        set logging file /dev/null
        set logging redirect on
        break *entry
        run
        dump memory {output_path} 0x08048000 0x09000000
        quit
        """
        with open("/tmp/gdb_script", "w") as f:
            f.write(gdb_cmds)
        subprocess.run(
            ["gdb", "-q", "-nh", "-x", "/tmp/gdb_script", input_path],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        if os.path.exists(output_path) and os.path.getsize(output_path) > 0:
            print(f"[+] GDB unpacked: {output_path}")
        else:
            print(f"[-] Failed to unpack: {input_path}")
    except Exception as e:
        print(f"[-] Error with {input_path}: {e}")

def unpack_folder(input_folder):
    """Unpack all ELF files in a folder."""
    for file in os.listdir(input_folder):
        if not file.endswith((".elf", ".bin", "")):  # Add other extensions if needed
            continue
        input_path = os.path.join(input_folder, file)
        if os.path.isfile(input_path):
            unpack_elf(input_path)

if __name__ == "__main__":
   
    unpack_folder("")