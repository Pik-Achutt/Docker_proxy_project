import requests
import logging
import concurrent.futures

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class ProxyManager:
    def __init__(self):
        self.proxies = []

    def fetch_free_proxies(self):
        """
        Fetches free proxies from a public API.
        For simplicity, we use proxyscrape here.
        """
        logging.info("Fetching free proxies...")
        url = "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=http&timeout=10000&country=all&ssl=all&anonymity=all"
        try:
            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                raw_proxies = response.text.strip().split('\r\n')
                self.proxies = [p for p in raw_proxies if p]
                logging.info(f"Fetched {len(self.proxies)} proxies.")
            else:
                logging.error(f"Failed to fetch proxies. Status code: {response.status_code}")
        except Exception as e:
            logging.error(f"Error fetching proxies: {e}")

    def check_proxy(self, proxy):
        """
        Checks if a proxy is alive by making a request through it.
        """
        url = "http://httpbin.org/ip"
        proxies = {
            "http": f"http://{proxy}",
            "https": f"http://{proxy}"
        }
        try:
            response = requests.get(url, proxies=proxies, timeout=5)
            if response.status_code == 200:
                return proxy
        except:
            return None

    def get_working_proxies(self, limit=5):
        """
        Returns a list of working proxies.
        """
        if not self.proxies:
            self.fetch_free_proxies()

        working_proxies = []
        logging.info(f"Testing proxies to find {limit} working ones...")

        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            future_to_proxy = {executor.submit(self.check_proxy, p): p for p in self.proxies}
            for future in concurrent.futures.as_completed(future_to_proxy):
                result = future.result()
                if result:
                    working_proxies.append(result)
                    if len(working_proxies) >= limit:
                        executor.shutdown(wait=False, cancel_futures=True)
                        break
        
        logging.info(f"Found {len(working_proxies)} working proxies.")
        return working_proxies

if __name__ == "__main__":
    pm = ProxyManager()
    working = pm.get_working_proxies(limit=3)
    print("Working proxies:", working)
