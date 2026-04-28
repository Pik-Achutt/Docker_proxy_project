import os
import subprocess
import time
import logging
import docker
import shutil
from pathlib import Path

if os.name == 'nt':
    adb_path = r"C:\Users\Achutt\AppData\Local\Android\Sdk\platform-tools"
    if adb_path not in os.environ["PATH"]:
        os.environ["PATH"] += os.pathsep + adb_path

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class DynamicAnalyzer:
    def __init__(self, output_dir="artifacts", adb_serial="127.0.0.1:5555", mitm_port=8080, docker_image=None):
        self.docker_client = docker.from_env()
        self.container = None
        self.mitmproxy_proc = None
        self.output_dir = Path(output_dir)
        self.adb_serial = adb_serial
        self.mitm_port = str(mitm_port)
        self.docker_image = docker_image or os.getenv("AAMT_DOCKER_IMAGE", "halimqarroum/docker-android:api-33")

    def _adb(self, *args, check=False, capture_output=False):
        return subprocess.run(
            ["adb", "-s", self.adb_serial, *args],
            check=check,
            capture_output=capture_output,
            text=True,
        )

    def start_mitmproxy(self, upstream_proxy, output_file):
        """
        Starts mitmproxy with an upstream proxy to capture traffic.
        """
        logging.info(f"Starting mitmproxy with upstream {upstream_proxy} saving to {output_file}")
        mitmdump_path = shutil.which("mitmdump")
        if not mitmdump_path:
            raise RuntimeError("mitmdump was not found on PATH. Install requirements and activate the virtual environment.")
        
        cmd = [
            mitmdump_path,
            "--listen-port", self.mitm_port,
            "-w", str(output_file)
        ]
        if upstream_proxy:
            cmd.extend(["--mode", f"upstream:http://{upstream_proxy}"])
        
        self.mitmproxy_proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(3)

    def stop_mitmproxy(self):
        if self.mitmproxy_proc:
            logging.info("Stopping mitmproxy...")
            self.mitmproxy_proc.terminate()
            try:
                self.mitmproxy_proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.mitmproxy_proc.kill()
                self.mitmproxy_proc.wait()
            self.mitmproxy_proc = None

    def start_emulator(self):
        """
        Starts the docker-android container.
        """
        logging.info("Starting docker-android emulator container...")
        try:
            self.container = self.docker_client.containers.run(
                self.docker_image,
                detach=True,
                privileged=True,
                devices=["/dev/kvm:/dev/kvm"],
                ports={'5555/tcp': 5555},
                environment={"DISABLE_ANIMATION": "true"}
            )
            logging.info(f"Container {self.container.short_id} started. Waiting for boot...")
            
            # Wait for ADB to be available
            max_retries = 30
            adb_connected = False
            for i in range(max_retries):
                self.container.reload()
                if self.container.status != 'running':
                    logging.error("Emulator container stopped unexpectedly.")
                    return False
                res = subprocess.run(["adb", "connect", self.adb_serial], capture_output=True, text=True)
                if "connected" in res.stdout or "already connected" in res.stdout:
                    logging.info("ADB connected successfully.")
                    adb_connected = True
                    break
                time.sleep(5)
            else:
                logging.error("Failed to connect to ADB.")
                return False
            
            # Wait for boot completion
            max_boot_retries = 60
            for i in range(max_boot_retries):
                self.container.reload()
                if self.container.status != 'running':
                    logging.error("Emulator container stopped unexpectedly during boot.")
                    return False
                res = self._adb("shell", "getprop", "sys.boot_completed", capture_output=True)
                if "1" in res.stdout:
                    logging.info("Emulator boot completed.")
                    break
                time.sleep(5)
            else:
                logging.error("Emulator failed to finish booting in time.")
                return False
                
        except Exception as e:
            logging.error(f"Failed to start emulator: {e}")
            return False
            
        return True

    def stop_emulator(self):
        if self.container:
            logging.info("Stopping emulator container...")
            self.container.stop(timeout=10)
            self.container.remove(force=True)
            self.container = None

    def run_analysis(self, apk_path, upstream_proxy):
        apk_path = Path(apk_path).resolve()
        if not apk_path.exists():
            raise FileNotFoundError(f"APK not found: {apk_path}")

        self.output_dir.mkdir(parents=True, exist_ok=True)
        proxy_name = upstream_proxy.replace(':', '_') if upstream_proxy else "noproxy"
        report_file = self.output_dir / f"traffic_report_{proxy_name}.mitm"
        self.start_mitmproxy(upstream_proxy, report_file)
        if not self.start_emulator():
            logging.error("Aborting analysis due to emulator failure.")
            self.stop_mitmproxy()
            return str(report_file)
        
        try:
            # Set proxy on device to host machine's mitmproxy
            # host.docker.internal works on Docker Desktop (Windows/Mac)
            host_ip = "10.0.2.2"  # Android emulator gateway to the host
            logging.info(f"Setting device proxy to {host_ip}:{self.mitm_port}")
            self._adb("shell", "settings", "put", "global", "http_proxy", f"{host_ip}:{self.mitm_port}")
            
            # Get list of packages before installation
            res_before = self._adb("shell", "pm", "list", "packages", "-3", capture_output=True)
            packages_before = set(res_before.stdout.splitlines())
            
            # Install APK
            logging.info(f"Installing APK: {apk_path}")
            install_result = self._adb("install", "-t", "-r", str(apk_path), capture_output=True)
            if install_result.returncode != 0:
                logging.error(f"APK install failed: {install_result.stderr or install_result.stdout}")
                return str(report_file)
            
            # Get list of packages after installation
            res_after = self._adb("shell", "pm", "list", "packages", "-3", capture_output=True)
            packages_after = set(res_after.stdout.splitlines())
            
            new_packages = list(packages_after - packages_before)
            if not new_packages:
                logging.error("Could not determine package name after installation.")
                return str(report_file)
            
            package_name = new_packages[0].replace("package:", "").strip()
            logging.info(f"Detected newly installed package: {package_name}")

            # Prepare screenshot directory
            apk_name = apk_path.stem
            ss_dir = self.output_dir / apk_name / proxy_name
            ss_dir.mkdir(parents=True, exist_ok=True)

            # Run monkey testing asynchronously
            logging.info(f"Running monkey test on {package_name} and taking screenshots")
            monkey_proc = subprocess.Popen(["adb", "-s", self.adb_serial, "shell", "monkey", "-p", package_name, "--throttle", "500", "-v", "200"])
            
            # Take screenshots while monkey runs
            for i in range(5):
                time.sleep(4)
                ss_filename = f"{apk_name}_{proxy_name}_{i}.png"
                device_ss_path = f"/sdcard/{ss_filename}"
                host_ss_path = ss_dir / ss_filename
                
                self._adb("shell", "screencap", "-p", device_ss_path)
                self._adb("pull", device_ss_path, str(host_ss_path))
                self._adb("shell", "rm", device_ss_path)
            
            monkey_proc.wait()
            
        except Exception as e:
            logging.error(f"Error during analysis: {e}")
            
        finally:
            try:
                self._adb("shell", "settings", "put", "global", "http_proxy", ":0")
            except OSError as e:
                logging.warning(f"Could not clear emulator proxy setting: {e}")
            self.stop_emulator()
            self.stop_mitmproxy()
            logging.info(f"Dynamic analysis finished. Traffic saved to {report_file}")
            return str(report_file)

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 2:
        analyzer = DynamicAnalyzer()
        analyzer.run_analysis(sys.argv[1], sys.argv[2])
    else:
        print("Usage: python dynamic_analysis.py <apk_path> <proxy_ip:port>")
