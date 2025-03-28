import re
import aiohttp
import asyncio
import math
from urllib.parse import urlparse
from typing import Dict, List, Optional, Set
from bs4 import BeautifulSoup  # For parsing HTML

class SubDomainizer(object):
    def __init__(self, target_url: str, max_depth: int = 2, entropy_threshold: float = 4.0):
        self.target_url = target_url
        self.max_depth = max_depth
        self.entropy_threshold = entropy_threshold  # Threshold for detecting high-entropy strings
        self.visited_urls: Set[str] = set()
        self.results = {
            "subdomains": set(),
            "external_domains": set(),
            "secrets": set(),
            "cloud_providers": set(),
        }
        self.timeout = 5
        
    async def fetch(self, session: aiohttp.ClientSession, url: str) -> Optional[str]:
        """Fetch the content of a URL asynchronously."""
        try:
            async with session.get(url, timeout=self.timeout) as response:
                if response.status == 200:
                    return await response.text()
        except Exception as e:
            print(f"Error fetching {url}: {e}")
        return None

    def extract_subdomains(self, text: str) -> List[str]:
        """Extract subdomains from the text."""
        domain = urlparse(self.target_url).netloc
        base_domain = ".".join(domain.split(".")[-2:])  # Extract base domain (e.g., example.com)
        subdomains = re.findall(rf"(https?://)?([a-zA-Z0-9.-]+\.{re.escape(base_domain)})", text)
        return [sub[1] for sub in subdomains]

    def extract_external_domains(self, text: str) -> List[str]:
        """Extract external domains from the text, including those in <script> tags."""
        external_domains = set()

        # Extract domains from URLs in the text
        urls = re.findall(rf"https?://([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})", text)
        for domain in urls:
            if not domain.endswith(urlparse(self.target_url).netloc):
                external_domains.add(domain)

        # Extract domains from <script> tags
        soup = BeautifulSoup(text, "html.parser")
        for script in soup.find_all("script", src=True):
            src = script["src"]
            if src.startswith(("http://", "https://")):
                domain = urlparse(src).netloc
                if not domain.endswith(urlparse(self.target_url).netloc):
                    external_domains.add(domain)

        return list(external_domains)

    def calculate_entropy(self, string: str) -> float:
        """Calculate the Shannon entropy of a string."""
        if not string:
            return 0.0
        entropy = 0.0
        for char in set(string):
            p = string.count(char) / len(string)
            entropy -= p * math.log2(p)
        return entropy

    def extract_secrets(self, text: str) -> List[str]:
        """Extract potential secrets using regex patterns and entropy analysis."""
        # Regex patterns for common secrets
        secret_patterns = [
            r"api_key=([a-zA-Z0-9]{32})",
            r"token=([a-zA-Z0-9]{32})",
            r"password=([a-zA-Z0-9]{16,})",
        ]
        secrets = []
        for pattern in secret_patterns:
            secrets.extend(re.findall(pattern, text))

        # Entropy-based secret detection
        """
        words = re.findall(r"\b\w{10,}\b", text)  # Look for words longer than 10 characters
        for word in words:
            entropy = self.calculate_entropy(word)
            if entropy > self.entropy_threshold:
                secrets.append(word)
        """
        return secrets

    def detect_cloud_providers(self, text: str) -> Set[str]:
        """Detect cloud providers based on specific patterns and domains."""
        cloud_providers = set()

        # AWS
        if re.search(r"s3\.amazonaws\.com", text) or re.search(r"AKIA[0-9A-Z]{16}", text):
            cloud_providers.add("AWS")

        # Google Cloud
        if re.search(r"storage\.googleapis\.com", text) or re.search(r"AIza[0-9A-Z\-_]{35}", text):
            cloud_providers.add("Google Cloud")

        # Azure
        if re.search(r"blob\.core\.windows\.net", text) or re.search(r"DefaultEndpointsProtocol=https;", text):
            cloud_providers.add("Azure")

        return cloud_providers

    async def crawl(self, session: aiohttp.ClientSession, url: str, depth: int = 0):
        """Recursively crawl the target URL and extract subdomains, external domains, secrets, and cloud providers."""
        if depth > self.max_depth or url in self.visited_urls:
            return

        self.visited_urls.add(url)
        print(f"Crawling: {url}")

        content = await self.fetch(session, url)
        if not content:
            return

        # Extract subdomains, external domains, secrets, and cloud providers
        subdomains = self.extract_subdomains(content)
        external_domains = self.extract_external_domains(content)
        secrets = self.extract_secrets(content)
        cloud_providers = self.detect_cloud_providers(content)

        # Update results
        self.results["subdomains"].update(subdomains)
        self.results["external_domains"].update(external_domains)
        self.results["secrets"].update(secrets)
        self.results["cloud_providers"].update(cloud_providers)

        # Recursively crawl subdomains
        for subdomain in subdomains:
            sub_url = f"https://{subdomain}"
            await self.crawl(session, sub_url, depth + 1)

    async def run(self) -> Dict[str, List[str]]:
        """Run the SubDomainizer tool and return results as a dictionary."""
        async with aiohttp.ClientSession() as session:
            await self.crawl(session, self.target_url)

        # Convert sets to lists for the final result
        return {
            "subdomains": list(self.results["subdomains"]),
            "external_domains": list(self.results["external_domains"]),
            "secrets": list(self.results["secrets"]),
            "cloud_providers": list(self.results["cloud_providers"]),
        }

# Example usage
async def main():
    target_url = "https://example.com"
    subdomainizer = SubDomainizer(target_url, entropy_threshold=4.0)
    results = await subdomainizer.run()
    print(results)

if __name__ == "__main__":
    asyncio.run(main())
