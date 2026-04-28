# Auto-Analyzer: Android Dynamic Malware Analysis Pipeline

Auto-Analyzer is a fully automated, headless dynamic analysis pipeline for Android APKs. It automatically routes device traffic through proxies, launches the APK inside a sandboxed Android emulator, performs randomized UI interaction testing, and captures screenshots of the behavior.

This project uses `mitmproxy` to intercept and decrypt HTTP/HTTPS traffic and the `docker-android` image to provide an easily disposable execution environment.

## 🚀 Features
- **Headless Docker Emulator:** Spins up a disposable Android environment (`api-33`) for every analysis.
- **Proxy Rotation:** Automatically scrapes free proxies and routes the emulator's network traffic through them.
- **Dynamic Interaction:** Uses ADB `monkey` to simulate rapid, randomized user interactions to trigger malicious or deeply-buried application logic.
- **Screenshot Harvesting:** Periodically captures and pulls screenshots from the device during the testing phase, organizing them into a designated folder.

## 🛠️ Prerequisites
- **Linux OS** (Recommended)
- **KVM (Kernel Virtual Machine):** Hardware acceleration is strictly required to run the x86_64 Android Emulator. Make sure your CPU supports it and it is enabled in your BIOS.
- **Docker**
- **Python 3.8+**
- **Android ADB (Android Debug Bridge)**

Check if your machine supports KVM:
```bash
kvm-ok
```
*(If the output says "KVM acceleration can NOT be used", you must enable Nested Virtualization / VT-x in your hypervisor or BIOS).*

## 📥 Installation

1. **Install System Dependencies:**
   ```bash
   sudo apt-get update
   sudo apt-get install -y docker.io adb qemu-kvm cpu-checker python3 python3-venv python3-pip
   ```

2. **Add User to Docker Group:**
   ```bash
   sudo usermod -aG docker $USER
   newgrp docker
   ```

3. **Set Up Python Environment:**
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   ```

## 🎮 Usage

Place the target APK file in the root directory of the project, then run the analyzer script.

```bash
python analyzer.py <target_apk_name>.apk
```

**What the script does:**
1. Validates and picks a working proxy.
2. Starts `mitmdump` in the background.
3. Launches the Docker emulator and waits for boot.
4. Identifies the new package name dynamically using `adb shell pm list packages`.
5. Starts the monkey testing in the background.
6. Pulls screenshots continuously and saves them locally.
7. Shuts down the emulator and proxy.

### Output
- **Screenshots:** Found in a directory named after the APK (e.g., `./emi_10.0.0_APKPure/`).
- **Network Traffic:** Saved as an MITM dump file (`traffic_report_<proxy_ip>_<port>.mitm`).
- **JSON Summary:** A high-level execution report named `aamt_report.json`.

## 📜 Architecture
See [DESIGN.md](./DESIGN.md) for a detailed technical overview of the system components and execution flow.
