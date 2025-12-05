# MAS: Mac Archive Scanner
Specialised security analysis tool for macOS software packages: DMG, PKG, and APP bundles.

_Inspired on the Norwegian verb "å mase" (to nag) because it is annoying having to write a bunch of commands to statically analyse a file, so instead now it is an actual python code!_

## Supported File Types

- **`.dmg`** Disk images (installers)
- **`.pkg`** macOS installer packages
- **`.app`** Application bundles

## Key Features
- Checks if files are properly signed
- Verifies Apple notarisation status
- Checks if macOS will allow execution
- Extracts download source, time, and downloading app
- Can see what permissions the app request (optional)
- Parses the Info.plist for app metadata

## Requirements
> [!NOTE]
> Three are no external dependencies needed, but that means it can only run on macOS.
>  Tested on macOS 15, Silicon/ARM.

- Python 3.6+
- Permissions: read access to files being analysed

## Installation

```bash
# Make MAS executable
chmod +x mas.py

# Ready to use!
python3 mas.py file.dmg

# OR use directly:
./mas.py file.dmg
```

## Quick Start

```bash
# Full security analysis with hashes
python3 mas.py -v ~/Downloads/app.dmg

# Check entitlements (permissions)
python3 mas.py --entitlements App.app

# Scan all DMGs in Downloads
python3 mas.py ~/Downloads/*.dmg
```

## Output Example
(I need to add a pic here)

## Command-Line Options

```
usage: mas.py [-h] [-v] [--entitlements] [--format {text,json,csv,html}]
              [--no-color] [--version] FILE [FILE ...]

positional arguments:
  FILE                  DMG, PKG, or APP file(s) to analyze

options:
  -h, --help            Show help message
  -v, --verbose         Show hashes and timestamps
  --entitlements        Extract and show app entitlements/permissions
  --format FORMAT       Output format: text, json, csv, html (default: text)
  --no-color            Disable colored output
  --version             Show version number
```
---

🔐 Stay safe! Always verify your downloads.
