import re
from bs4 import BeautifulSoup
from libraccoon.utils.request_handler import RequestHandler
from libraccoon.libs.fuzzer import URLFuzzer
from libraccoon.utils.help_utils import HelpUtilities
from libraccoon.utils.exceptions import RaccoonException
from libraccoon.wordlists.wordlist_helper import get_file
import socket 
import re
from libraccoon.utils.utils import get_asn
from libraccoon.utils.utils import get_ips

class SubDomainEnumerator(object):

    def __init__(self, host, sans=None, domain_list=None, ignored_response_codes="302,400,401,402,403,404,503,504",
                num_threads=2, follow_redirects=True, no_sub_enum=True, ua=None
                ):
                     
        self.host = host
        self.target = host.target
        self.sans = sans
        self.domain_list = domain_list
        if not self.domain_list:
            self.domain_list = get_file()
        
        self.ua = ua         
        self.ignored_error_codes = tuple(ignored_response_codes.split(","))
        self.num_threads = num_threads
        self.follow_redirects = follow_redirects
        self.no_sub_enum = no_sub_enum
        self.request_handler = RequestHandler(ua=self.ua)
        
        self.subdomainlist = []
        
    async def run(self):
        print("Enumerating Subdomains")
        if self.sans:
            self._extract_from_sans()
        self._extract_from_dns_dumpster()
        if not self.no_sub_enum:
            self.bruteforce()
        print("Done enumerating Subdomains")
        
        subdomain_list = []
        for sub in self.subdomainlist:
            ip = ""
                
            ip_results = await get_ips(sub)
            if(ip_results):
                ip = ip_results[0].get("a_ip")
                 
            asn = ""
            if(ip):
                asn_ojb = get_asn(ip)
                if asn_ojb:
                    asn = asn_ojb.autonomous_system_organization
                        
            subdomain_list.append({
                "host":self.host.target,
                "subdomain":sub,
                "ip":ip,
                "asn":asn
            })
        return subdomain_list
        
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

    def _extract_from_dns_dumpster(self):
        print("Trying to extract subdomains from DNS dumpster")
        try:
            page = HelpUtilities.query_dns_dumpster(host=self.host)
            reg_hosts = re.compile(r'[a-zA-Z0-9.-]*\.' + self.host.target)
            results = reg_hosts.findall(page.text)
            self.subdomainlist = self.unique(results)
            return self.subdomainlist
        
        except (RaccoonException, IndexError):
            print("Failed to query DNS dumpster for subdomains")
    
    def unique(self, result) -> list:
        return list(set(result))
        
    def bruteforce(self):
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
        sub_domain_fuzzer.fuzz_all(sub_domain=True, log_file_path=get_file())
    
    @property
    def get_subdomains(self):
        return self.subdomainlist
        
