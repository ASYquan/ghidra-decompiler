#!/usr/bin/env python3
"""
Ghidra Automated Decompilation Script
Author: Security Engineering Team
Purpose: Decompile binaries using Ghidra's headless analyzer
"""

import argparse
import os
import subprocess
import sys
import tempfile
import shutil
from pathlib import Path

class GhidraDecompiler:
    def __init__(self, ghidra_path="/usr/share/ghidra"):
        self.ghidra_path = ghidra_path
        self.analyze_headless = os.path.join(ghidra_path, "support", "analyzeHeadless")

        if not os.path.exists(self.analyze_headless):
            raise FileNotFoundError(f"analyzeHeadless not found at {self.analyze_headless}")

    def decompile(self, binary_path, output_dir=None, project_name="temp_project"):
        """
        Decompile a binary using Ghidra

        Args:
            binary_path: Path to the binary to decompile
            output_dir: Directory for output (default: creates temp dir)
            project_name: Ghidra project name

        Returns:
            Path to decompiled output
        """
        binary_path = os.path.abspath(binary_path)

        if not os.path.exists(binary_path):
            raise FileNotFoundError(f"Binary not found: {binary_path}")

        # Create output directory
        if output_dir is None:
            output_dir = tempfile.mkdtemp(prefix="ghidra_decompile_")
        else:
            output_dir = os.path.abspath(output_dir)
            os.makedirs(output_dir, exist_ok=True)

        # Create project directory
        project_dir = os.path.join(output_dir, "project")
        os.makedirs(project_dir, exist_ok=True)

        # Output file for decompiled code
        output_file = os.path.join(output_dir, f"{os.path.basename(binary_path)}_decompiled.c")

        print(f"[+] Decompiling: {binary_path}")
        print(f"[+] Output directory: {output_dir}")
        print(f"[+] This may take a while depending on binary size...")

        # Get script directory (where DecompileAllScript.java is located)
        script_dir = os.path.dirname(os.path.abspath(__file__))

        # Ghidra headless command
        # -import: Import the binary
        # -scriptPath: Path to custom scripts
        # -postScript: Run this script after analysis
        cmd = [
            self.analyze_headless,
            project_dir,           # Project directory
            project_name,          # Project name
            "-import", binary_path,  # Import the binary
            "-scriptPath", script_dir,  # Path to DecompileAllScript.java
            "-postScript", "DecompileAllScript.java",  # Run decompilation script
            output_file,           # Pass output file as argument
            "-deleteProject"       # Clean up project after
        ]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300  # 5 minute timeout
            )

            # Check for success indicators in output
            if "Decompilation complete!" in result.stdout or "Successfully decompiled:" in result.stdout:
                if os.path.exists(output_file):
                    print(f"[+] Decompilation complete!")
                    print(f"[+] Output saved to: {output_file}")
                    # Show summary if available
                    for line in result.stdout.split('\n'):
                        if "Successfully decompiled:" in line:
                            print(f"[+] {line.strip()}")
                    return output_file

            # Check if it failed
            if result.returncode != 0 or "ERROR" in result.stderr:
                print(f"[!] Ghidra analysis encountered errors")
                print(f"[!] Return code: {result.returncode}")
                # Show relevant error lines
                for line in result.stderr.split('\n'):
                    if "ERROR" in line or "WARN" in line:
                        print(f"    {line.strip()}")
                return None

            if os.path.exists(output_file):
                print(f"[+] Decompilation complete!")
                print(f"[+] Output saved to: {output_file}")
                return output_file
            else:
                print("[!] Decompilation script did not produce output file")
                print("[*] Check if DecompileAllScript.java is in the same directory")
                print(f"[*] Script directory: {script_dir}")
                return None

        except subprocess.TimeoutExpired:
            print("[!] Decompilation timed out (exceeded 5 minutes)")
            return None
        except Exception as e:
            print(f"[!] Error during decompilation: {e}")
            return None

def main():
    parser = argparse.ArgumentParser(
        description="Decompile binaries using Ghidra",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  ./decompile.py binary.elf
  ./decompile.py /path/to/executable -o output_dir
  ./decompile.py malware.exe -p my_analysis
        """
    )

    parser.add_argument("binary", help="Path to binary file to decompile")
    parser.add_argument("-o", "--output", help="Output directory (default: temp directory)")
    parser.add_argument("-p", "--project", default="temp_project", help="Ghidra project name")
    parser.add_argument("-g", "--ghidra-path", default="/usr/share/ghidra",
                       help="Path to Ghidra installation")

    args = parser.parse_args()

    try:
        decompiler = GhidraDecompiler(args.ghidra_path)
        output_file = decompiler.decompile(
            args.binary,
            args.output,
            args.project
        )

        if output_file:
            print(f"\n[+] Success! Decompiled code at: {output_file}")
            sys.exit(0)
        else:
            print("\n[!] Decompilation failed or incomplete")
            sys.exit(1)

    except Exception as e:
        print(f"[!] Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
