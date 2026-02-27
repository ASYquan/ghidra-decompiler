#!/bin/bash
# Simple Ghidra Decompilation Script
# Usage: ./simple_decompile.sh <binary_file>

if [ $# -eq 0 ]; then
    echo "Usage: $0 <binary_file>"
    exit 1
fi

BINARY="$1"
BINARY_NAME=$(basename "$BINARY")
OUTPUT_DIR="output_${BINARY_NAME}_$(date +%Y%m%d_%H%M%S)"
PROJECT_DIR="${OUTPUT_DIR}/project"
OUTPUT_FILE="${OUTPUT_DIR}/${BINARY_NAME}_decompiled.c"

echo "[+] Ghidra Headless Decompilation"
echo "[+] Binary: $BINARY"
echo "[+] Output: $OUTPUT_FILE"
echo ""

# Create directories
mkdir -p "$PROJECT_DIR"

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Run Ghidra headless
echo "[+] Running Ghidra analysis (this may take a while)..."
/usr/share/ghidra/support/analyzeHeadless \
    "$PROJECT_DIR" \
    "temp_project" \
    -import "$BINARY" \
    -scriptPath "$SCRIPT_DIR" \
    -postScript DecompileAllScript.java "$OUTPUT_FILE" \
    -deleteProject

if [ -f "$OUTPUT_FILE" ]; then
    echo ""
    echo "[+] Decompilation complete!"
    echo "[+] Output: $OUTPUT_FILE"
    echo ""
    echo "[+] Preview (first 50 lines):"
    head -50 "$OUTPUT_FILE"
else
    echo ""
    echo "[!] Decompilation failed - output file not created"
    exit 1
fi
