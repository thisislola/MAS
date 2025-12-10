# MAS: Mac Archive Scanner
Specialised security analysis tool for macOS software packages: DMG, PKG, and APP bundles.

_Inspired on the Norwegian verb "å mase" (to nag) because it is annoying having to write a bunch of commands to statically analyse a file, so instead now it is an actual python code!_

The [What's Your Sign](https://objective-see.org/products/whatsyoursign.html) by Objective See is a way better tool! My tool MAS is just a humble POC.
PS: I'm struggling with checking if a bundle is sandboxed or not :´)


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

## Command-Line Options

<img width="560" height="416" alt="mas-help" src="https://github.com/user-attachments/assets/64def68d-5833-465c-880b-f235018917ac" />

## Troubleshooting

- Under entitlements, if you see: `Details: xcode-select: error: tool 'stapler' requires Xcode, but active developer directory '/Library/Developer/CommandLineTools' is a command line tools instance`
then you will need to install Command Line Tools if you haven't already and enable them:

```bash
xcode-select --install
sudo xcode-select --switch /Library/Developer/CommandLineTools
```

If the error persists, change the path of your installed Xcode:
```bash
sudo xcode-select -s /Applications/Xcode.app/Contents/Developer
```



---

🔐 Stay safe! Always verify your downloads.
