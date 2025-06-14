import os
import time
import requests
import subprocess
import shutil

API_KEY = ""
LIMIT = 50
BASE_DIR = "./"
ZIP_DIR = os.path.join(BASE_DIR, "zips")
TAGS_DIRS = ["normal", "packed", "stripped", "unpacked", "gafgyt", "other"]

os.makedirs(ZIP_DIR, exist_ok=True)
for tag_dir in TAGS_DIRS:
    os.makedirs(os.path.join(BASE_DIR, tag_dir), exist_ok=True)

def run_7z_extract(zip_path, out_dir):
    try:
        subprocess.run([
            "7z", "x", f"-p{'infected'}", zip_path,
            f"-o{out_dir}", "-y"
        ], check=True)
        return True
    except subprocess.CalledProcessError:
        print(f"Failed to extract {zip_path} with 7z.")
        return False

response = requests.post(
    "https://mb-api.abuse.ch/api/v1/",
    headers={"API-KEY": API_KEY},
    data={"query": "get_siginfo", "signature": "Mirai", "limit": str(LIMIT)}
)

if response.status_code != 200:
    print("Failed to fetch Mirai samples.")
    exit(1)

data = response.json()
if data.get("query_status") != "ok":
    print("Query failed:", data.get("query_status"))
    exit(1)

for sample in data["data"]:
    sha256_hash = sample["sha256_hash"]
    file_type = sample.get("file_type", "").lower()
    tags = [t.lower() for t in sample.get("tags", [])]

    if "elf" not in file_type:
        continue

    print(f"\nDownloading: {sha256_hash}")

    download_response = requests.post(
        "https://mb-api.abuse.ch/api/v1/",
        headers={"API-KEY": API_KEY},
        data={"query": "get_file", "sha256_hash": sha256_hash}
    )

    if download_response.status_code != 200:
        print(f"Failed to download {sha256_hash}")
        continue

    zip_path = os.path.join(ZIP_DIR, f"{sha256_hash}.zip")
    with open(zip_path, "wb") as f:
        f.write(download_response.content)

    extract_dir = os.path.join(ZIP_DIR, sha256_hash)
    os.makedirs(extract_dir, exist_ok=True)

    if not run_7z_extract(zip_path, extract_dir):
        continue

    for filename in os.listdir(extract_dir):
        src_file = os.path.join(extract_dir, filename)
        if not os.path.isfile(src_file):
            continue

        if "upx" in tags or "packed" in tags:
            folder = "packed"
        elif "stripped" in tags:
            folder = "stripped"
        elif "gafgyt" in tags:
            folder = "gafgyt"
        elif "unpacked" in tags:
            folder = "unpacked"
        elif "mirai" in tags:
            folder = "normal"
        else:
            folder = "other"

        dest_file = os.path.join(BASE_DIR, folder, f"{sha256_hash}_{filename}")
        shutil.move(src_file, dest_file)
        print(f"Saved: {dest_file}")

    shutil.rmtree(extract_dir)
    time.sleep(2)
