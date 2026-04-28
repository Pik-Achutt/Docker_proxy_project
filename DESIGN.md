# Auto-Analyzer Design Document

This document outlines the architecture, data flow, and specific technical decisions behind the Auto-Analyzer Android dynamic analysis pipeline.

## 1. System Architecture

The tool is split into three core modules that operate sequentially to spin up infrastructure, capture behavior, and teardown cleanly.

### Core Modules

1. **`analyzer.py` (The Orchestrator)**
   - Acts as the main entry point (`main()`).
   - Handles CLI arguments and determines how many proxies to test.
   - Glues together the Proxy Manager and the Dynamic Analyzer.
   - Generates the final execution report (`artifacts/aamt_report.json` by default).

2. **`proxy_manager.py` (Proxy Rotator)**
   - Responsible for scraping free proxies from public endpoints (`proxyscrape`).
   - Asynchronously tests scraped proxies against a reliable endpoint (`httpbin.org/ip`) using `concurrent.futures.ThreadPoolExecutor`.
   - Returns a verified list of working proxies for the dynamic analyzer to route traffic through.

3. **`dynamic_analysis.py` (Dynamic Execution Engine)**
   - Interfaces directly with the Docker daemon (`docker.from_env()`) to spin up disposable `docker-android` containers.
   - Spawns the `mitmdump` proxy in the background to capture HTTP/HTTPS traffic.
   - Interacts with the sandboxed Android device via `subprocess.run` calls to `adb`.

## 2. Execution Flow

When `analyzer.py` is invoked with a target APK, the execution lifecycle follows these distinct phases:

### Phase 1: Proxy Resolution
The `ProxyManager` scrapes a list of HTTP proxies and tests them concurrently until it secures the requested number of working proxies (default: 2). If no proxies are requested, no proxies are found, or proxy validation times out, the system runs with the `noproxy` profile. This still routes emulator traffic through local `mitmproxy`; it simply avoids an upstream public proxy.

### Phase 2: Infrastructure Spin-Up
For the selected proxy:
1. `mitmdump` is spawned locally, listening on port `8080`, and optionally configured to forward traffic to the upstream proxy. Traffic is actively dumped to an `artifacts/traffic_report_<proxy>.mitm` file.
2. The `docker-android:api-33` container is started using Docker Python SDK. It explicitly binds `/dev/kvm` for hardware acceleration.
3. The engine polls the container via `adb connect` and waits for `sys.boot_completed == 1`.

### Phase 3: Application Analysis
1. **Network Config:** The emulator's global HTTP proxy is set to the host machine (`10.0.2.2:8080`), routing all device traffic into `mitmdump`.
2. **Package Deduction:** The engine takes a snapshot of all installed third-party apps (`adb shell pm list packages -3`).
3. **Installation:** The target APK is installed via `adb install`.
4. **Target Identification:** A post-install snapshot is taken. The difference between the snapshots reliably identifies the newly installed application's `package_name`.

### Phase 4: Dynamic Interaction & Artifact Harvesting
1. **Monkey Testing:** An `adb shell monkey` command is spawned asynchronously to simulate 200 random user actions on the target package. This mimics user behavior to trigger delayed malware execution.
2. **Visual Harvesting:** While the monkey test runs, a polling loop executes `adb shell screencap`, taking periodic snapshots of the application UI. These are pulled to the host and stored in `artifacts/<apk_name>/<proxy>/`.

### Phase 5: Teardown
1. The Docker container is forcefully stopped and removed.
2. The `mitmdump` process is terminated.
3. The captured `.mitm` file is scanned for known suspicious gambling/malicious keywords.

## 3. Technical Constraints & Design Decisions

### Why Dynamic Package Deduction?
Static analysis libraries (like `androguard`) add significant bloat, require large dependencies, and frequently break on heavily obfuscated malware. By comparing the `pm list packages` output before and after installation, the system is 100% agnostic to APK structure and purely relies on the Android OS package manager.

### Why Docker-Android?
Using Docker provides a fresh, uncompromised, and reproducible sandbox for every single run. If a piece of malware manages to break out of the Android OS sandbox, it is contained within the Docker environment, which is instantly destroyed upon completion. KVM is required to ensure the nested virtualization runs at a usable speed for `monkey` testing.
