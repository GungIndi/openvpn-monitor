#!/bin/bash
# Convert OpenVPN CCD (Client Config Directory) to IPP (ifconfig-pool-persist) format
# Usage: ./ccd2ipp.sh [ccd_directory] [output_file]

CCD_DIR="${1:-/etc/openvpn/ccd}"
OUTPUT_FILE="${2:-ipp.txt}"

if [ ! -d "$CCD_DIR" ]; then
    echo "Error: CCD directory '$CCD_DIR' not found."
    exit 1
fi

echo "Scanning CCD directory: $CCD_DIR"
echo "Writing to: $OUTPUT_FILE"

# Create/Overwrite output file with header
echo "# OpenVPN IPP file generated from CCD" > "$OUTPUT_FILE"

count=0

# Iterate over files in CCD directory
for file in "$CCD_DIR"/*; do
    [ -e "$file" ] || continue
    
    # Filename is the username
    username=$(basename "$file")
    
    # Skip hidden files
    if [[ "$username" == .* ]]; then
        continue
    fi
    
    # Extract IP from ifconfig-push directive
    # Looks for: ifconfig-push <IP> <NETMASK>
    ip=$(grep -E "^\s*ifconfig-push\s+[0-9.]+\s+[0-9.]+" "$file" | awk '{print $2}')
    
    if [ ! -z "$ip" ]; then
        echo "$username,$ip" >> "$OUTPUT_FILE"
        ((count++))
        echo "  Found: $username -> $ip"
    fi
done

echo ""
echo "Success! Wrote $count entries to $OUTPUT_FILE"
