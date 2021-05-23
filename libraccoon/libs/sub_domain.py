import re
from bs4 import BeautifulSoup
from libraccoon.utils.request_handler import RequestHandler
from libraccoon.libs.fuzzer import URLFuzzer
from libraccoon.utils.help_utils import HelpUtilities
from libraccoon.utils.exceptions import RaccoonException
from libraccoon.wordlists.wordlist_helper import get_file

class SubDomainEnumerator(object):

    def __init__(self,
                host,
                sans=None,
                domain_list=None,
                ignored_response_codes="302,400,401,402,403,404,503,504",
                num_threads=2,
                follow_redirects=True,
                no_sub_enum=True):
                     
        self.host = host
        self.target = host.target
        self.sans = sans
        self.domain_list = domain_list
        if not self.domain_list:
            self.domain_list = get_file()
            
        self.ignored_error_codes = tuple(ignored_response_codes.split(","))
        self.num_threads = num_threads
        self.follow_redirects = follow_redirects
        self.no_sub_enum = no_sub_enum
        self.request_handler = RequestHandler()
        
        self.subdomainlist = []
        
    async def run(self):
        print("Enumerating Subdomains")
        if self.sans:
            self._extract_from_sans()
        self._google_dork()
        self._extract_from_dns_dumpster()
        if not self.no_sub_enum:
            await self.bruteforce()
        print("Done enumerating Subdomains")

    def _extract_from_sans(self):
        """Looks for different TLDs as well as different sub-domains in SAN list"""
        print("{} Trying to find Subdomains in SANs list")
        if self.host.naked:
            domain = self.host.naked
            tld_less = domain.split(".")[0]
        else:
            domain = self.host.target.split(".")
            tld_less = domain[1]
            domain = ".".join(domain[1:])

        for san in self.sans:
            if (tld_less in san or domain in san) and self.target != san and not san.startswith("*"):
                print("Subdomain detected: {0}".format(san))

    def _google_dork(self):
        print("Trying to discover subdomains in Google")
        page = self.request_handler.send(
            "GET",
            url="https://www.google.com/search?q=site:{}&num=100".format(self.target)
        )
        soup = BeautifulSoup(page.text, "lxml")
        results = set(re.findall(r"\w+\.{}".format(self.target), soup.text))
        for subdomain in results:
            if "www." not in subdomain:
                self.subdomainlist.append(subdomain.lower())
                
                print("Detected subdomain through Google dorking: {0}".format(subdomain))

    def _extract_from_dns_dumpster(self):
        print("Trying to extract subdomains from DNS dumpster")
        try:
            page = HelpUtilities.query_dns_dumpster(host=self.host)            
            soup = BeautifulSoup(page.text, "lxml")
                        
            hosts_table = soup.select(".table")[-1]
            for row in hosts_table.find_all("tr"):
                tds = row.select("td")
                sub_domain = tds[0].text.split('\n')[0]  # Grab just the URL, truncate other information                
                self.subdomainlist.append(sub_domain.lower())                
        except (RaccoonException, IndexError):
            print("Failed to query DNS dumpster for subdomains")

    async def bruteforce(self):
        path = "{}/subdomain_fuzz.txt".format(self.host.target)

        # If a naked domain exists, use it
        if self.host.naked:
            self.host.target = self.host.naked
        print("Bruteforcing subdomains")
        
        sub_domain_fuzzer = URLFuzzer(
            host=self.host,
            path_to_wordlist=self.domain_list,
            num_threads=self.num_threads,
            ignored_response_codes=self.ignored_error_codes,
            follow_redirects=self.follow_redirects
            )
        await sub_domain_fuzzer.fuzz_all(sub_domain=True, log_file_path=path)
    
    @property
    def get_subdomains(self):
        return self.subdomainlist
