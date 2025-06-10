#!/bin/bash

# Check if hash was passed as argument
if [ -z "$1" ]; then
  echo "Usage: $0 <sha256_hash>"
  exit 1
fi

SHA256="$1"
AUTH_KEY=""

# Download the ZIP from MalwareBazaar
echo "[*] Downloading sample for hash: $SHA256"
wget --quiet --header "API-KEY: $AUTH_KEY" \
     --post-data "query=get_file&sha256_hash=$SHA256" \
     https://mb-api.abuse.ch/api/v1/ \
     -O sample.zip

# Check if download succeeded
if [ ! -s sample.zip ]; then
  echo "[!] Download failed or empty response."
  exit 1
fi

# Extract sample
echo "[*] Extracting..."
7z x sample.zip

# Clean up
rm sample.zip

echo "[+] Done."
