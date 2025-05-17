import asyncio
import aiohttp
import aiodns
import random
import argparse
import aiofiles
import logging
import json
from typing import List, Dict

DEFAULT_NAMESERVERS = [
    "8.8.8.8",          # Google
    "8.8.4.4",          # Google Secondary
    "1.1.1.1",          # Cloudflare
    "1.0.0.1",          # Cloudflare Secondary
    "9.9.9.9",          # Quad9
    "149.112.112.112",  # Quad9 Secondary
    "208.67.222.222",   # OpenDNS
    "208.67.220.220",   # OpenDNS Secondary
    "94.140.14.14",     # AdGuard DNS
    "94.140.15.15",     # AdGuard DNS Secondary
    "76.76.2.0",        # ControlD
    "76.76.10.0"         # ControlD Secondary
]

logging.basicConfig(level=logging.ERROR, format='[%(levelname)s] %(message)s')

class AsyncSubBrute:
    def __init__(self, resolvers: List[str] = None, max_retries: int = 3, retry_enabled: bool = True):
        self.loop = asyncio.get_running_loop()
        self.resolver = aiodns.DNSResolver(loop=self.loop)
        self.resolver.nameservers = resolvers if resolvers else DEFAULT_NAMESERVERS
        self.wildcard_ips = set()
        self.max_retries = max_retries
        self.retry_enabled = retry_enabled
        self.host = None 
        
    async def resolve(self, domain: str, record_type: str = 'A') -> Dict[str, str]:
        attempt = 1
        while True:
            try:
                #logging.info(f"Resolving (Attempt {attempt}): {domain}")
                result = await asyncio.wait_for(self.resolver.query(domain, record_type), timeout=5.0)
                resolved_ips = [r.host for r in result]

                if self.wildcard_ips and set(resolved_ips).issubset(self.wildcard_ips):
                    return {"host":self.host, "domain": domain, "record_type": record_type, "status": "wildcard_detected"}

                return {"host":self.host,"domain": domain, "record_type": record_type, "result": resolved_ips, "status": "success"}
            except Exception as e:
                #logging.error(f"Error resolving {domain} (Attempt {attempt}): {e}")
                if not self.retry_enabled or attempt >= self.max_retries:
                    return {"host":self.host,"domain": domain, "record_type": record_type, "error": str(e), "status": "failed"}
                await asyncio.sleep(0.5 * attempt)
                attempt += 1

    async def detect_wildcard(self, domain: str):
        logging.info(f"Detecting wildcard DNS for {domain}")
        test_subdomains = [f"random-{random.randint(100000, 999999)}.{domain}" for _ in range(2)]
        tasks = [self.resolve(sub) for sub in test_subdomains]
        results = await asyncio.gather(*tasks)

        for res in results:
            if res["status"] == "success":
                self.wildcard_ips.update(res["result"])

    async def brute_force(self, domain: str, subdomains: List[str]) -> Dict[str, Dict[str, str]]:
        await self.detect_wildcard(domain)
        tasks = [self.resolve(f"{sub}.{domain}") for sub in subdomains]
        results = await asyncio.gather(*tasks)
        return {res["domain"]: res for res in results if res["status"] == "success"}

    async def recursive_brute_force(self, domain: str, subdomains: List[str], depth: int = 2) -> Dict[str, Dict[str, str]]:
        found_subs = await self.brute_force(domain, subdomains)

        if depth > 0:
            new_subdomains = [f"{sub}.{domain}" for sub in found_subs if found_subs[sub]['status'] == 'success']
            more_results = await self.recursive_brute_force(domain, new_subdomains, depth - 1)
            found_subs.update(more_results)

        return found_subs

    async def load_wordlist(self, filepath: str) -> List[str]:
        try:
            async with aiofiles.open(filepath, mode='r') as file:
                return [line.strip() async for line in file if line.strip()]
        except Exception as e:
            logging.error(f"Error loading wordlist: {e}")
            return []

    async def scan_with_queue(self, domain: str, subdomains: List[str], concurrency: int = 500, batch_size: int = 1000) -> Dict[str, Dict[str, str]]:
        await self.detect_wildcard(domain)
        results = {}
        self.host = domain 
        
        for i in range(0, len(subdomains), batch_size):
            batch = subdomains[i:i+batch_size]
            queue = asyncio.Queue()
            semaphore = asyncio.Semaphore(concurrency)

            for sub in batch:
                await queue.put(f"{sub}.{domain}")

            async def worker():
                while True:
                    sub = await queue.get()
                    async with semaphore:
                        res = await self.resolve(sub)
                        if res["status"] == "success":
                            results[res["domain"]] = res
                    queue.task_done()

            tasks = [asyncio.create_task(worker()) for _ in range(concurrency)]
            await queue.join()

            for task in tasks:
                task.cancel()

        return results

def parse_args():
    parser = argparse.ArgumentParser(
        description="\nAsynchronous Subdomain Bruteforcer",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument("-d", "--domain", required=True, help="Target domain to brute-force")
    parser.add_argument("-w", "--wordlist", help="Path to subdomain wordlist")
    parser.add_argument("--list", nargs='+', help="List of subdomains to test, e.g., --list api www mail")
    parser.add_argument("-c", "--concurrency", type=int, default=500, help="Number of concurrent DNS lookups")
    parser.add_argument("-b", "--batch-size", type=int, default=1000, help="Batch size for smart processing")
    parser.add_argument("--no-retry", action="store_true", help="Disable retrying DNS queries on failure")
    return parser.parse_args()

async def main(domain: str, wordlist: str, sublist: List[str], concurrency: int, batch_size: int, retry_enabled: bool):
    subbrute = AsyncSubBrute(retry_enabled=retry_enabled)
    subdomains = []

    if wordlist:
        subdomains = await subbrute.load_wordlist(wordlist)
    elif sublist:
        subdomains = sublist

    if not subdomains:
        logging.warning("[!] No subdomains provided. Exiting.")
        return

    results = await subbrute.scan_with_queue(domain, subdomains, concurrency, batch_size)
    return results 
    
    #json_output = json.dumps(results, indent=2)
    #print(json_output)

if __name__ == "__main__":
    args = parse_args()
    asyncio.run(main(args.domain, args.wordlist, args.list, args.concurrency, args.batch_size, not args.no_retry))
