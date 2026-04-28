import os
import subprocess
import time
import logging
import docker
import threading

if os.name == 'nt':
    adb_path = r"C:\Users\Achutt\AppData\Local\Android\Sdk\platform-tools"
    if adb_path not in os.environ["PATH"]:
        os.environ["PATH"] += os.pathsep + adb_path

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class DynamicAnalyzer:
    def __init__(self):
        self.docker_client = docker.from_env()
        self.container = None
        self.mitmproxy_proc = None

    def start_mitmproxy(self, upstream_proxy, output_file):
        """
        Starts mitmproxy with an upstream proxy to capture traffic.
        """
        logging.info(f"Starting mitmproxy with upstream {upstream_proxy} saving to {output_file}")
        import sys
        mitmdump_path = os.path.join(os.path.dirname(sys.executable), "mitmdump")
        
        cmd = [
            mitmdump_path,
            "--listen-port", "8080",
            "-w", output_file
        ]
        if upstream_proxy:
            cmd.extend(["--mode", f"upstream:http://{upstream_proxy}"])
        
        # In a real environment, ensure mitmdump is in PATH.
        self.mitmproxy_proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(3) # Wait for it to start

    def stop_mitmproxy(self):
        if self.mitmproxy_proc:
            logging.info("Stopping mitmproxy...")
            self.mitmproxy_proc.terminate()
            self.mitmproxy_proc.wait()
            self.mitmproxy_proc = None

    def start_emulator(self):
        """
        Starts the docker-android container.
        """
        logging.info("Starting docker-android emulator container...")
        try:
            self.container = self.docker_client.containers.run(
                "halimqarroum/docker-android:api-33",
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
                res = subprocess.run(["adb", "connect", "127.0.0.1:5555"], capture_output=True, text=True)
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
                res = subprocess.run(["adb", "-s", "127.0.0.1:5555", "shell", "getprop", "sys.boot_completed"], capture_output=True, text=True)
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
            self.container.stop()
            self.container.remove()
            self.container = None

    def run_analysis(self, apk_path, upstream_proxy):
        report_file = f"traffic_report_{upstream_proxy.replace(':', '_')}.mitm"
        self.start_mitmproxy(upstream_proxy, report_file)
        if not self.start_emulator():
            logging.error("Aborting analysis due to emulator failure.")
            self.stop_mitmproxy()
            return report_file
        
        try:
            # Set proxy on device to host machine's mitmproxy
            # host.docker.internal works on Docker Desktop (Windows/Mac)
            host_ip = "10.0.2.2" # Default gateway for android emulator to reach host
            logging.info(f"Setting device proxy to {host_ip}:8080")
            subprocess.run(["adb", "-s", "127.0.0.1:5555", "shell", "settings", "put", "global", "http_proxy", f"{host_ip}:8080"])
            
            # Get list of packages before installation
            res_before = subprocess.run(["adb", "-s", "127.0.0.1:5555", "shell", "pm", "list", "packages", "-3"], capture_output=True, text=True)
            packages_before = set(res_before.stdout.splitlines())
            
            # Install APK
            logging.info(f"Installing APK: {apk_path}")
            subprocess.run(["adb", "-s", "127.0.0.1:5555", "install", "-t", "-r", apk_path])
            
            # Get list of packages after installation
            res_after = subprocess.run(["adb", "-s", "127.0.0.1:5555", "shell", "pm", "list", "packages", "-3"], capture_output=True, text=True)
            packages_after = set(res_after.stdout.splitlines())
            
            new_packages = list(packages_after - packages_before)
            if not new_packages:
                logging.error("Could not determine package name after installation.")
                return report_file
            
            package_name = new_packages[0].replace("package:", "").strip()
            logging.info(f"Detected newly installed package: {package_name}")

            # Prepare screenshot directory
            apk_filename = os.path.basename(apk_path)
            apk_name = os.path.splitext(apk_filename)[0]
            ss_dir = os.path.join(os.path.dirname(os.path.abspath(apk_path)), apk_name)
            os.makedirs(ss_dir, exist_ok=True)
            
            proxy_name = upstream_proxy.replace(':', '_') if upstream_proxy else "noproxy"

            # Run monkey testing asynchronously
            logging.info(f"Running monkey test on {package_name} and taking screenshots")
            monkey_proc = subprocess.Popen(["adb", "-s", "127.0.0.1:5555", "shell", "monkey", "-p", package_name, "--throttle", "500", "-v", "200"])
            
            # Take screenshots while monkey runs
            for i in range(5):
                time.sleep(4)
                ss_filename = f"{apk_name}_{proxy_name}_{i}.png"
                device_ss_path = f"/sdcard/{ss_filename}"
                host_ss_path = os.path.join(ss_dir, ss_filename)
                
                subprocess.run(["adb", "-s", "127.0.0.1:5555", "shell", "screencap", "-p", device_ss_path])
                subprocess.run(["adb", "-s", "127.0.0.1:5555", "pull", device_ss_path, host_ss_path])
                subprocess.run(["adb", "-s", "127.0.0.1:5555", "shell", "rm", device_ss_path])
            
            monkey_proc.wait()
            
        except Exception as e:
            logging.error(f"Error during analysis: {e}")
            
        finally:
            self.stop_emulator()
            self.stop_mitmproxy()
            logging.info(f"Dynamic analysis finished. Traffic saved to {report_file}")
            return report_file

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 2:
        analyzer = DynamicAnalyzer()
        analyzer.run_analysis(sys.argv[1], sys.argv[2])
    else:
        print("Usage: python dynamic_analysis.py <apk_path> <proxy_ip:port>")
