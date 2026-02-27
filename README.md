# ghidra-decompiler

A command-line toolkit for automated binary decompilation using [Ghidra's](https://ghidra-sre.org/) headless analyzer. Designed for me because im lazy and want to keep things GUI-free. Running the GUI was so slow, so i decided to create something that used the Ghidra-API to decompile code for my CTFs. 

PS: also tested Claude Code during the development to automate the commit messages, beause I don't wanna use Copilot outside of Latex usage.

---

## Motivation

Ghidra is a powerful reverse engineering tool, but its primary interface is a desktop GUI. When you need to quickly decompile a binary, run batch analysis, or integrate decompilation into a larger workflow, launching the GUI is slow and impractical.

This toolkit wraps Ghidra's headless mode to give you decompiled C-like pseudocode from any supported binary in a single command — no GUI required.

---

## Features

- Decompiles all functions in a binary to a single `.c` output file
- Supports any architecture Ghidra supports (x86, x64, ARM, MIPS, and more)
- Annotates each function with its name, entry point address, and size
- 5-minute timeout prevents hanging on large or complex binaries
- Cleans up temporary Ghidra project files automatically
- Two interfaces: a quick bash script and a full-featured Python script with CLI flags

---

## How It Works

```
Binary  →  Ghidra headless analyzer  →  DecompileAllScript.java  →  decompiled.c
```

1. Ghidra imports the binary and runs automatic analysis
2. `DecompileAllScript.java` iterates every function and calls Ghidra's decompiler API
3. Pseudocode for each function is written to a single output file
4. Temporary project files are deleted on exit

---

## Requirements

- [Ghidra](https://ghidra-sre.org/) installed at `/usr/share/ghidra` (or specify a custom path)
- Java (required by Ghidra — typically bundled)
- Python 3 (for `decompile.py`)

---

## Installation

```bash
git clone https://github.com/yourusername/ghidra-decompiler.git
cd ghidra-decompiler
chmod +x decompile.py simple_decompile.sh
```

Verify Ghidra's headless analyzer is accessible:

```bash
ls /usr/share/ghidra/support/analyzeHeadless
```

---

## Usage

Both scripts call the same Ghidra engine and produce identical output. The difference is in control and safety.

---

### `simple_decompile.sh` — Quick, zero-config

No options, no setup. Give it a binary and it runs.

```bash
./simple_decompile.sh /path/to/binary
```

- Output is auto-saved to `output_<binary>_<timestamp>/` in the current directory
- Prints a 50-line preview of the decompiled code when done
- No timeout — will run until Ghidra finishes (or hang indefinitely on problematic binaries)

**Best for:** quick one-off analysis, CTF challenges, or when you just want to see the output fast without thinking about flags.

---

### `decompile.py` — Full-featured, scriptable

Same decompilation, but with control over where output goes, a hard timeout, and proper error reporting.

```bash
# Basic
./decompile.py /path/to/binary

# Specify output directory
./decompile.py /path/to/binary -o ./analysis_output

# Custom project name and Ghidra path
./decompile.py /path/to/binary -o ./output -p my_project -g /opt/ghidra
```

| Flag | Description |
|---|---|
| `-o`, `--output` | Output directory (default: system temp dir) |
| `-p`, `--project` | Ghidra project name (default: `temp_project`) |
| `-g`, `--ghidra-path` | Path to Ghidra installation (default: `/usr/share/ghidra`) |

- Stops automatically after **5 minutes** if Ghidra gets stuck
- Surfaces specific error and warning lines from Ghidra's output when something fails
- Returns exit code `0` on success and `1` on failure — useful in scripts and pipelines

**Best for:** malware analysis workflows, batch processing multiple binaries, or any situation where you need the output in a specific place and reliable error handling.

---

### Batch processing

```bash
for binary in ./samples/*; do
    ./decompile.py "$binary" -o "output/$(basename $binary)"
done
```

---

## Example Output

Running against a simple ELF password checker:

```bash
$ ./decompile.py example_binary -o demo_output
[+] Decompiling: /home/kali/ghidra_decompiler/example_binary
[+] Output directory: demo_output
[+] This may take a while depending on binary size...
[+] Decompilation complete!
[+] Output saved to: demo_output/example_binary_decompiled.c
[+] Successfully decompiled: 22/30
```

The output file contains annotated pseudocode for every function:

```c
// Function: check_password
// Address: 00101159
// Size: 52 bytes

bool check_password(char *param_1)
{
  int iVar1;

  iVar1 = strcmp(param_1,"secret123");
  return iVar1 == 0;
}

// ----------------------------------------------------------------------

// Function: main
// Address: 0010118d
// Size: 125 bytes

undefined8 main(int param_1,undefined8 *param_2)
{
  int iVar1;
  undefined8 uVar2;

  if (param_1 == 2) {
    iVar1 = check_password(param_2[1]);
    if (iVar1 == 0) {
      puts("Access denied!");
      uVar2 = 1;
    }
    else {
      puts("Access granted!");
      uVar2 = 0;
    }
  }
  else {
    printf("Usage: %s <password>\n",*param_2);
    uVar2 = 1;
  }
  return uVar2;
}
```

---

## Project Structure

```
ghidra-decompiler/
├── decompile.py              # Full-featured Python wrapper
├── simple_decompile.sh       # Quick bash wrapper
├── DecompileAllScript.java   # Ghidra script (core decompilation logic)
└── example_binary            # Sample ELF binary for testing
```

---

## Limitations

- Output is **pseudocode**, not original source. Variable names, comments, and high-level constructs are lost at compile time.
- Packed or obfuscated binaries may produce poor results or fail entirely.
- Very large binaries (>100MB) may hit the 5-minute timeout.
- Ghidra's function detection uses heuristics and can produce false positives/negatives.

---

## Use Cases

- **CTF challenges** — quickly understand validation logic and find flags
- **Malware analysis** — static analysis of suspicious binaries (always in an isolated VM)
- **Vulnerability research** — identify dangerous function calls (`strcpy`, `system`, etc.) at scale
- **Learning** — study how compilers translate C into assembly and back

---

## Security Warning

When analyzing untrusted or malicious binaries:
- Use an isolated VM with no shared folders
- Disconnect from the network
- Never execute the binary directly
- Take a VM snapshot before analysis

---

## License

For educational and security research purposes only.
