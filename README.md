# Auto-Analyzer: Android Dynamic Malware Analysis Pipeline

Auto-Analyzer is a headless dynamic analysis pipeline for Android APKs. It launches a disposable Android emulator, routes device traffic through `mitmproxy`, exercises the app with Android Monkey, captures screenshots, and writes a small JSON report that points to the collected evidence.

The default path is intentionally dynamic-first: it does not need to unpack or statically parse the APK to find the package name. Instead, it installs the app in a fresh emulator and compares installed third-party packages before and after installation.

## Features

- Disposable Docker-based Android emulator for each analysis run.
- Optional public HTTP proxy rotation before traffic reaches `mitmproxy`.
- No-proxy fallback that still captures traffic through local `mitmproxy`.
- Randomized UI stimulation with `adb shell monkey`.
- Screenshot harvesting during interaction.
- Generated evidence grouped under `artifacts/`.

## Prerequisites

- Linux host recommended.
- KVM enabled for usable Android emulator performance.
- Docker.
- Python 3.8+.
- Android Debug Bridge (`adb`).

Check KVM support:

```bash
kvm-ok
```

If KVM is unavailable, enable virtualization or nested virtualization in the host BIOS/hypervisor.

## Installation

Install host dependencies:

```bash
sudo apt-get update
sudo apt-get install -y docker.io adb qemu-kvm cpu-checker python3 python3-venv python3-pip
```

Allow your user to run Docker:

```bash
sudo usermod -aG docker "$USER"
newgrp docker
```

Create a Python environment:

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Usage

Run the analyzer against an APK:

```bash
python analyzer.py path/to/target.apk
```

Useful options:

```bash
python analyzer.py path/to/target.apk --proxies 0 --output-dir artifacts
```

What the script does:

1. Fetches and validates the requested number of public proxies, unless `--proxies 0` is used.
2. Starts `mitmdump` locally and optionally chains it to the selected upstream proxy.
3. Launches the Docker Android emulator and waits for ADB plus boot completion.
4. Sets the emulator HTTP proxy to the host `mitmproxy`.
5. Installs the APK and detects the newly installed package.
6. Runs Android Monkey while pulling screenshots.
7. Stops the emulator and proxy, then writes a JSON summary.

## Output

Generated files are ignored by Git and written under `artifacts/` by default:

- `artifacts/aamt_report.json` - high-level execution report.
- `artifacts/traffic_report_<proxy>.mitm` - captured `mitmproxy` traffic dump.
- `artifacts/<apk_name>/<proxy>/` - screenshots captured during Monkey execution.

## Architecture

See [DESIGN.md](./DESIGN.md) for the component-level design and execution flow.
