# Plugins

VMDragonSlayer integrates with common reverse engineering tools via optional plugins. This page summarizes supported backends and how to build/install each plugin.

Supported backends:

- Ghidra (Java/Kotlin extension)
- IDA Pro (Python plugin)
- Binary Ninja (Python plugin)

Source locations: `plugins/ghidra`, `plugins/idapro`, `plugins/binaryninja`.

See also: `BUILD_PLUGINS.md` for a full step-by-step build/release guide.

## Ghidra plugin

Prerequisites:
- JDK 17+
- Gradle 7.0+
- Environment variable `GHIDRA_INSTALL_DIR` set to Ghidra install folder

Build (PowerShell):

```pwsh
$env:GHIDRA_INSTALL_DIR = "C:\ghidra_11.4.1_PUBLIC"
cd plugins/ghidra
gradle clean
gradle buildExtension
```

Output: `plugins/ghidra/dist/vmdragonslayer_ghidra_*.zip`.

Install:
- Via Ghidra GUI: File > Install Extensions > select the ZIP > Restart
- Manual: copy ZIP to `$env:GHIDRA_INSTALL_DIR/Extensions/Ghidra/`

## IDA Pro plugin

The IDA plugin is pure Python.

Quick verify and package:

```pwsh
cd plugins/idapro
python -m py_compile vmdragonslayer_ida.py
Compress-Archive -Path vmdragonslayer_ida.py, README.md -DestinationPath vmdragonslayer_ida_plugin.zip -Force
```

Install:
- Windows: `%APPDATA%\Hex-Rays\IDA Pro\plugins\`
- Linux: `~/.idapro/plugins/`
- macOS: `~/.idapro/plugins/`

Copy the file (or unzipped plugin) into the plugins directory and restart IDA.

## Binary Ninja plugin

Quick verify and package:

```pwsh
cd plugins/binaryninja
python -m py_compile vmdragonslayer_bn.py, ui/__init__.py
Compress-Archive -Path * -DestinationPath vmdragonslayer_bn_plugin.zip -Force
```

Install:
- Windows: `%APPDATA%\Binary Ninja\plugins\`
- Linux: `~/.binaryninja/plugins/`
- macOS: `~/Library/Application Support/Binary Ninja/plugins/`

Copy the plugin folder or ZIP contents into the user plugins directory and restart Binary Ninja.

## Tips and troubleshooting

- Match tool versions (e.g., Ghidra 11.x) with your environment; rebuild after upgrades.
- For Ghidra, verify `java -version` (17+) and `gradle --version` (7.0+).
- If packaging for distribution, include a short README and version in filenames.
- Keep the core Python package and plugin versions aligned in your release process.
