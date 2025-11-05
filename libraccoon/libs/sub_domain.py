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
import httpx
from typing import List, Dict, Optional, Any
import json 

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
        self.url = 'https://dnsdumpster.com/'
        self.api = "https://api.dnsdumpster.com/"
        self.headers = {
            "User-Agent": self.ua,
        }
        self.timeout: int = 10
        self.domain = self.target 
        
    async def run(self):
        print("Enumerating Subdomains")
        if self.sans:
            self._extract_from_sans()
        await self._extract_from_dns_dumpster()
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
    
    def extract_domains(self, resp: str) -> List[str]:
        reg_hosts = re.compile(r'[a-zA-Z0-9.-]*\.' + re.escape(self.domain))
        results = reg_hosts.findall(resp)
        
        reg_hosts = re.compile(r'[a-zA-Z0-9.-]*\.' + re.escape(self.domain.replace('www.', '')))
        results = reg_hosts.findall(resp)
        subdomains = self.unique(results)
        return subdomains

    def get_forms_data(self, resp: str) -> Dict[str, str]:
        soup = BeautifulSoup(resp, 'html.parser')
        form = soup.find('form')
        hx_post = form.get('hx-post')
        hx_headers = form.get('hx-headers')
        if not hx_headers:
            print("[DNSdumpster] hx-headers not found")
            return {}
        hx_headers = json.loads(hx_headers)
        return {
            "hx_post": hx_post,
            "Authorization": hx_headers.get("Authorization")
        }
    
    def unique(self, result: List[str]) -> List[str]:
        return list(set(result))
        
    async def _extract_from_dns_dumpster(self):
        print("Trying to extract subdomains from DNS dumpster")
        try:
            self.domain = self.host.naked 
            if not self.domain:
                self.domain = self.host.target 
                
            sublist = []
            async with httpx.AsyncClient(verify=False) as client:
                resp = await client.get(self.url, headers=self.headers, timeout=self.timeout)
                if resp.status_code != 200:
                    return []
                
                form_data = self.get_forms_data(resp.text)
                if not form_data:
                    print("[DNSdumpster] form data not found")
                    return []

                self.headers.update({
                    "Origin": self.url,
                    "Referer": self.url,
                    'HX-Current-URL': self.url,
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Authorization": form_data.get("Authorization"),
                    "Host": 'api.dnsdumpster.com',
                })

                resp = await client.post(form_data.get("hx_post"), headers=self.headers, data={'target': self.domain})
                if resp.status_code != 200:
                    print(f"[DNSdumpster] status code {resp.status_code}")
                    return []
                
                self.subdomainlist = self.extract_domains(resp.text)
            return self.subdomainlist
            
        except Exception as e: # (RaccoonException, IndexError):
            raise 
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
        
