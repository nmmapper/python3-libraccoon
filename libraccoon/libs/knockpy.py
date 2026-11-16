import httpx, requests
from libraccoon.utils.utils import get_user_agent
from libraccoon.utils.utils import get_asn
from libraccoon.utils.utils import get_ips
from tld import get_tld
from bs4 import BeautifulSoup
from tld.exceptions import TldDomainNotFound, TldBadUrl
import asyncio
import json 

class KnockPY(object):
    HACKER_TARGET = "https://api.hackertarget.com/hostsearch/?q={domain}"
    def __init__(self, domain, wordlist=None, 
                    virustotalapi=None, 
                    discoveryapi=None, 
                    securitytrail=None,
                    binary_edge_api=None,
                    ua=None):
                        
        self.domain = domain 
        self.wordlist = wordlist
        self.virustotalapi = virustotalapi
        self.discoveryapi = discoveryapi
        self.securitytrail = securitytrail
        self.binary_edge_api = binary_edge_api
        self.ua=ua
        self.timeout = 10
        
        if(not self.ua):
            self.ua = get_user_agent()
        
        self.headers = {"User-Agent":self.ua}
    
    def _is_subdomain(self, host: str, domain: str, include_apex: bool) -> bool:
        if host == domain:
            return include_apex
        return host.endswith("." + domain)
    
    def _clean_name(self, name: str) -> str:
        n = name.strip().lower()
        if n.startswith("*."):
            n = n[2:]
        if n.endswith("."):
            n = n[:-1]
        if n.startswith("."):
            n = n[1:]
        return n
    
    async def waybackurl(self):
        """@return List[str]"""
        try:
            url = f"https://web.archive.org/cdx/search/cdx?url={self.domain}&matchType=domain&fl=original&collapse=urlkey&limit=1000&output=json"
            # 1. Use a set initially for O(1) deduplication instead of list conversion at the end
            subdomains = set()

            async with httpx.AsyncClient() as client:
                req = await client.get(url, timeout=15)
                req.raise_for_status()  # 2. Catch 503/403 Wayback API errors before parsing JSON
                data = req.json()
                
                # 3. The CDX API JSON output puts the column headers in the first array index
                if data and data[0] == ["original"]:
                    data = data[1:]
                
                for d in data:
                    if not d:
                        continue
                        
                    target_url = d[0]
                    
                    if target_url.startswith("http"):
                        try:
                            # 4. Wrap in try/except: A single malformed historical URL shouldn't crash the loop
                            tld_info = get_tld(target_url, as_object=True, fix_protocol=True)
                            
                            if tld_info.subdomain:
                                sub = f"{tld_info.subdomain}.{tld_info.fld}"
                                subdomains.add(sub)
                        except (TldDomainNotFound, TldBadUrl):
                            continue
            
            return list(subdomains)
        
        except Exception as e:
            # 5. Removed the rogue `raise` that was turning this and the return into dead code
            print(f"[Knockpy waybackurl ERROR] {e}", flush=True)
            return []
    
    async def virustotal_subdomain(self):
        try:
            if not self.virustotalapi:
                return []
                
            url = "https://www.virustotal.com/api/v3/domains/{domain}/subdomains".format(domain=self.domain)
            headers= {"x-apikey":self.virustotalapi}
            
            subdomains = []
            
            async with httpx.AsyncClient() as client:
                req = await client.get(url, headers=headers, timeout=self.timeout)
                data = req.json().get("data")
                for d in data:
                    subdomains.app(d.get("id"))
            return subdomains 
        except Exception as e:
            print("[Knockpy virustotal_subdomain ERROR, Fallback failed]", e, flush=True)
            return []
            
    async def virustotal(self):
        """@return List"""
        try:
            if not self.virustotalapi: 
                return []
                
            url = "https://www.virustotal.com/vtapi/v2/domain/report"
            params = {"apikey": self.virustotalapi,"domain": self.domain}
            resp = {} 
            
            async with httpx.AsyncClient() as client:
                req = await client.get(url, params=params, timeout=self.timeout)
                resp = req.json()
                
            subdomains = resp.get("subdomains", [])
            return subdomains
            
        except Exception as e:
            print("[Knockpy virustotal ERROR, Using fallback]", e, flush=True)
            return await self.virustotal_subdomain()
    
    async def hackertarget(self):
        """@return List"""
        try:            
            subdomains = []
            async with httpx.AsyncClient() as client:
                url = self.HACKER_TARGET.format(domain=self.domain)

                response = await client.get(url, headers=self.headers)
                if(response.status_code == 200):
                    response = response.text
                    hostnames = [result.split(",")[0] for result in response.split("\n")]

                    for hostname in hostnames:
                        if (hostname) and (self.domain in hostname):
                            subdomains.append(hostname)

                subdomains = list(set(subdomains))
            return subdomains

        except Exception as e:
            print("[Knockpy hackertarget ERROR]", e, flush=True)
            return []
            
    async def projectdiscovery(self):
        """@return List"""
        try:
            if not self.discoveryapi:
                return [] 
                
            headers = {"Authorization":self.discoveryapi}
            url="https://dns.projectdiscovery.io/dns/{domain}/subdomains".format(domain=self.domain)
            resp = None
            
            async with httpx.AsyncClient() as client:
                resp = await client.get(url, headers=headers, timeout=self.timeout)
                
            subdomains = []
            
            if(resp is not None):
                if(resp.status_code == 200):
                    data = resp.json()
                    subdomain_data = data.get("subdomains")
                    subdomain_domain = data.get("domain")
                    
                    for subs in subdomain_data:
                        subdomains.append(subs+"."+subdomain_domain)
                    return subdomains
            return subdomains
        except Exception as e:
            print("[Knockpy projectdiscovery ERROR]", e, flush=True)
            return []
            
    async def securitytrails(self):
        """@return List"""
        try:
            if not self.securitytrail:
                return [] 
                
            querystring = {"children_only":"false","include_inactive":"true"}
            headers = {"Accept": "application/json", "apikey":self.securitytrail}
            url = "https://api.securitytrails.com/v1/domain/{domain}/subdomains".format(domain=self.domain)
            resp = None
            
            async with httpx.AsyncClient() as client:
                resp = await client.get(url, headers=headers, params=querystring, timeout=self.timeout)
                        
            subdomains = []
            
            if(resp is not None):
                if(resp.status_code == 200):
                    data = resp.json()
                    subdomain_data = data.get("subdomains")
                    
                    for subs in subdomain_data:
                        subdomains.append(subs+"."+self.domain)
                   
            return subdomains
        except Exception as e:
            print("[Knockpy securitytrails ERROR]", e, flush=True)
            return []
            


    async def crt(self):
        """@return List[str]"""
        # 1. Base setup
        url = f"https://crt.sh/json?q=%.{self.domain}"
        subdomains = set()
        timeout_val = getattr(self, 'timeout', 15)
        
        # 2. Configure retry limits
        max_retries = 3
        
        for attempt in range(max_retries):
            try:
                async with httpx.AsyncClient() as client:
                    req = await client.get(url, timeout=timeout_val)
                    req.raise_for_status()
                    
                    try:
                        data = req.json()
                    except json.JSONDecodeError:
                        return []
                    
                    if isinstance(data, list):
                        for entry in data:
                            name_value = entry.get('name_value', '')
                            for sub in name_value.split('\n'):
                                sub = sub.strip().lower()
                                
                                if sub.startswith('*.'):
                                    sub = sub[2:]
                                sub = self._clean_name(sub)
                                
                                if not sub:
                                    continue 
                                    
                                if self._is_subdomain(sub, self.domain, False):
                                    subdomains.add(sub)
                                    
                    return sorted(list(subdomains))

            except httpx.HTTPStatusError as e:
                # 3. Catch proxy/gateway errors from crt.sh explicitly
                if e.response.status_code in (502, 503, 504) and attempt < max_retries - 1:
                    wait_time = 2 ** attempt  # Backoff: 1s, 2s, 4s...
                    print(f"[Knockpy crt WARNING] crt.sh returned {e.response.status_code}. Retrying in {wait_time}s...", flush=True)
                    await asyncio.sleep(wait_time)
                    continue
                
                # Bubble up if out of retries or if it's a 4xx error (e.g., 400 Bad Request)
                raise e
                
            except httpx.RequestError as e:
                # 4. Handle client-side connection drops or read timeouts
                if attempt < max_retries - 1:
                    wait_time = 2 ** attempt
                    print(f"[Knockpy crt WARNING] crt.sh connection error. Retrying in {wait_time}s...", flush=True)
                    await asyncio.sleep(wait_time)
                    continue
                    
                raise e

            except Exception as e:
                # Catch-all for our original try/except wrapper
                print(f"[Knockpy crt ERROR] {e}", flush=True)
                return []
                
    async def api_subdomain_center(self):
        """@return List"""
        try:
            url = "https://api.subdomain.center/?domain={domain}".format(domain=self.domain)
            subdomains = []
            
            async with httpx.AsyncClient() as client:
                resp = await client.get(url,timeout=self.timeout)
                if(resp.status_code == 200):
                    subdomains = resp.json()
            return list(set(subdomains)) 
            
        except Exception as e:
            print("[Knockpy api_subdomain_center ERROR]", e, flush=True)
            return []
        
    async def urlscan(self):
        """@return List"""
        try:
            url = "https://urlscan.io/api/v1/search/?q=domain:{domain}".format(domain=self.domain)
            subdomains = []
            
            async with httpx.AsyncClient() as client:
                req = await client.get(url,timeout=self.timeout)
                
                if(req.status_code == 200):
                    data = req.json()
                    results = data.get('results')
                    for r in results:
                        task = r.get("task")
                        domain = task.get("domain")
                        if(self.domain in domain):
                            subdomains.append(domain)
            return list(set(subdomains))
            
        except Exception as e:
            print("[Knockpy urlscan ERROR]", e, flush=True)
            return []
    
    async def dnsrepo(self) -> list[str]:
        try:
            url = f"https://dnsrepo.noc.org/?search={self.domain}"
            
            async with httpx.AsyncClient(verify=False) as client:
                resp = await client.get(url,  timeout=self.timeout)
                if resp.status_code != 200:
                    print(f"[DNSRepo] status code {resp.status_code}")
                    return []
                return self.extract_domains(resp.text)
           
        except Exception as e:
            print("[Knockpy DNSRepo ERROR]", e, flush=True)
            return []
            
    async def ip_thc(self) -> list[str]:
        try:
            url = "https://ip.thc.org/api/v1/lookup/subdomains"
            subdomains: list = []
            
            async with httpx.AsyncClient(timeout=30.0) as client:
                res = await client.post(
                    url,
                    json={"domain": self.domain, "page_state": "", "limit": 10},
                    headers={'Accept': 'application/json'}
                )
                res.raise_for_status()
                domains = res.json()
                if(domains):
                    domains = domains.get('domains')
                    
                    for d in domains:
                        if d.get('domain') != self.domain:
                            subdomains.append(d.get('domain'))
                            
            return subdomains
            
        except Exception as e:
            print("[Knockpy DNSRepo ERROR]", e, flush=True)
            return []
    
    def extract_domains(self, resp: str) -> list[str]:
        soup = BeautifulSoup(resp, "html.parser")
        table = soup.find("table", class_="table")
        found_subdomains = set()
        if table:
            rows = table.find("tbody").find_all("tr")
            for row in rows:
                cols = row.find_all("td")
                if cols:
                    domain_cell = cols[0]
                    a_tag = domain_cell.find("a")
                    if a_tag:
                        subdomain = a_tag.get_text(strip=True).replace('\n', '').replace('\r', '')
                        subdomain = subdomain.rstrip('.')
                        if subdomain.endswith(self.domain) and subdomain != self.domain:
                            found_subdomains.add(subdomain)
        return sorted(list(found_subdomains))
        
    async def search(self, resolve=False, return_dict=True):
        subdomains = []
        
        print("Searching urlscan")
        subdomains = await self.urlscan()
        
        print("Searching api_subdomain_center")
        subdomains = await self.api_subdomain_center()
        
        print("Searching waybackurl")
        subdomains = await self.waybackurl()
        
        print("Searching crt")
        crt_subdomains = await self.crt()
        
        if crt_subdomains:
            subdomains += crt_subdomains
            
        print("Searching virustotal")
        subdomains += await self.virustotal()
        
        print("project discovery")
        subdomains += await self.projectdiscovery()
        
        print("project securitytrails")
        subdomains += await self.securitytrails()
        
        print("project hackertarget")
        subdomains += await self.hackertarget()
        
        print("project dnsrepo")
        subdomains += await self.dnsrepo()
        
        if not resolve and not return_dict:
            print("Returning nothing")
            return subdomains 
            
        subdomains_generator = (sub for sub in list(set(subdomains)))
                
        if(resolve):
            subdomain_list = []
            for sub in subdomains_generator:
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
                    "host":self.domain,
                    "subdomain":sub,
                    "ip":ip,
                    "asn":asn
                })
            return subdomain_list
        
        # If the return should be dictionary
        if(return_dict):
            subdomain = []
            
            for sub in subdomains_generator:
                subdomain.append({
                    "host":self.domain,
                    "subdomain":sub,
                    "ip":"",
                    "asn":""
                })
            return subdomain
        
        # If neither resolve or return_dict, return the default
        return subdomains
        

class KnockPYSync(KnockPY):
    def __init__(self, domain, wordlist=None, 
                    virustotalapi=None, 
                    discoveryapi=None, 
                    securitytrail=None,
                    binary_edge_api=None,
                    ua=None):
                        
        self.domain = domain 
        self.wordlist = wordlist
        self.virustotalapi = virustotalapi
        self.discoveryapi = discoveryapi
        self.securitytrail = securitytrail
        self.binary_edge_api = binary_edge_api
        self.ua=ua
        self.timeout = 50
        
        if(not self.ua):
            self.ua = get_user_agent()
        
        self.headers = {"User-Agent":self.ua}
        
    def waybackurl(self):
        """@return List"""
        try:
            url = f"https://web.archive.org/cdx/search/cdx?url={self.domain}&matchType=domain&fl=original&collapse=urlkey&limit=1000&output=json"
            # 1. Use a set initially for O(1) deduplication instead of list conversion at the end
            subdomains = set()

            with requests.Session() as client:
                req = client.get(url, timeout=15)
                req.raise_for_status()  # 2. Catch 503/403 Wayback API errors before parsing JSON
                data = req.json()
                
                # 3. The CDX API JSON output puts the column headers in the first array index
                if data and data[0] == ["original"]:
                    data = data[1:]
                
                for d in data:
                    if not d:
                        continue
                        
                    target_url = d[0]
                    
                    if target_url.startswith("http"):
                        try:
                            # 4. Wrap in try/except: A single malformed historical URL shouldn't crash the loop
                            tld_info = get_tld(target_url, as_object=True, fix_protocol=True)
                            
                            if tld_info.subdomain:
                                sub = f"{tld_info.subdomain}.{tld_info.fld}"
                                subdomains.add(sub)
                        except (TldDomainNotFound, TldBadUrl):
                            continue
            
            return list(subdomains)
        
        except Exception as e:
            # 5. Removed the rogue `raise` that was turning this and the return into dead code
            print(f"[Knockpy waybackurl ERROR] {e}", flush=True)
            return []
       
    def virustotal_subdomain(self):
        try:
            if not self.virustotalapi:
                return []
                
            url = "https://www.virustotal.com/api/v3/domains/{domain}/subdomains".format(domain=self.domain)
            headers= {"x-apikey":self.virustotalapi}
            
            subdomains = []
            
            with requests.Session() as client:
                req = client.get(url, headers=headers, timeout=self.timeout)
                data = req.json().get("data")
                for d in data:
                    subdomains.app(d.get("id"))
            return subdomains 
        except Exception as e:
            print("[Knockpy virustotal_subdomain ERROR, Fallback failed]", e, flush=True)
            return []
            
    def virustotal(self):
        """@return List"""
        try:
            if not self.virustotalapi: 
                return []
                
            url = "https://www.virustotal.com/vtapi/v2/domain/report"
            params = {"apikey": self.virustotalapi,"domain": self.domain}
            resp = {} 
            
            with requests.Session() as client:
                req = client.get(url, params=params, timeout=self.timeout)
                resp = req.json()
                
            subdomains = resp.get("subdomains", [])
            return subdomains
            
        except Exception as e:
            print("[Knockpy virustotal ERROR, Using fallback]", e, flush=True)
            return self.virustotal_subdomain()
    
    def hackertarget(self):
        """@return List"""
        try:            
            subdomains = []
            with requests.Session() as client:
                url = self.HACKER_TARGET.format(domain=self.domain)

                response = client.get(url, headers=self.headers)
                if(response.status_code == 200):
                    response = response.text
                    hostnames = [result.split(",")[0] for result in response.split("\n")]

                    for hostname in hostnames:
                        if (hostname) and (self.domain in hostname):
                            subdomains.append(hostname)

                subdomains = list(set(subdomains))
            return subdomains

        except Exception as e:
            print("[Knockpy hackertarget ERROR]", e, flush=True)
            return []
            
    def projectdiscovery(self):
        """@return List"""
        try:
            if not self.discoveryapi:
                return [] 
                
            headers = {"Authorization":self.discoveryapi}
            url="https://dns.projectdiscovery.io/dns/{domain}/subdomains".format(domain=self.domain)
            resp = None
            
            with requests.Session() as client:
                resp = client.get(url, headers=headers, timeout=self.timeout)
                
            subdomains = []
            
            if(resp is not None):
                if(resp.status_code == 200):
                    data = resp.json()
                    subdomain_data = data.get("subdomains")
                    subdomain_domain = data.get("domain")
                    
                    for subs in subdomain_data:
                        subdomains.append(subs+"."+subdomain_domain)
                    return subdomains
            return subdomains
        except Exception as e:
            print("[Knockpy projectdiscovery ERROR]", e, flush=True)
            return []
            
    def securitytrails(self):
        """@return List"""
        try:
            if not self.securitytrail:
                return [] 
                
            querystring = {"children_only":"false","include_inactive":"true"}
            headers = {"Accept": "application/json", "apikey":self.securitytrail}
            url = "https://api.securitytrails.com/v1/domain/{domain}/subdomains".format(domain=self.domain)
            resp = None
            
            with requests.Session() as client:
                resp = client.get(url, headers=headers, params=querystring, timeout=self.timeout)
                        
            subdomains = []
            
            if(resp is not None):
                if(resp.status_code == 200):
                    data = resp.json()
                    subdomain_data = data.get("subdomains")
                    
                    for subs in subdomain_data:
                        subdomains.append(subs+"."+self.domain)
                   
            return subdomains
        except Exception as e:
            print("[Knockpy securitytrails ERROR]", e, flush=True)
            return []
            
    def binary_edge(self):
        """@return List"""
        try:
            if not self.binary_edge_api:
                return [] 
                
            headers = {"X-KEY":self.binary_edge_api, "User-Agent":self.ua}
            url = "https://api.binaryedge.io/v2/query/domains/subdomain/{domain}".format(domain=self.domain)
            subdomains = []
            
            with requests.Session() as client:
                resp = client.get(url, headers=headers, timeout=self.timeout)
                
                if(resp.status_code == 200):
                    data = resp.json()
                    page = data.get("page")
                    subdomains += data.get("events")
            
            print("BINARY EDGE ", subdomains)
            return subdomains 
            
        except Exception as e:
            print("[Knockpy binary_edge ERROR]", e, flush=True)
            return []
            
    def api_subdomain_center(self):
        """@return List"""
        try:
            url = "https://api.subdomain.center/?domain={domain}".format(domain=self.domain)
            subdomains = []
            
            with requests.Session() as client:
                resp = client.get(url,timeout=self.timeout)
                if(resp.status_code == 200):
                    subdomains = resp.json()
            return list(set(subdomains)) 
            
        except Exception as e:
            print("[Knockpy api_subdomain_center ERROR]", e, flush=True)
            return []
            
    def urlscan(self):
        """@return List"""
        try:
            url = "https://urlscan.io/api/v1/search/?q=domain:{domain}".format(domain=self.domain)
            subdomains = []
            
            with requests.Session() as client:
                req = client.get(url,timeout=self.timeout)
                
                if(req.status_code == 200):
                    data = req.json()
                    results = data.get('results')
                    for r in results:
                        task = r.get("task")
                        domain = task.get("domain")
                        if(self.domain in domain):
                            subdomains.append(domain)
            return list(set(subdomains))
            
        except Exception as e:
            print("[Knockpy urlscan ERROR]", e, flush=True)
            return []
            
    def crt(self):
        """@return List"""
        try:
            url = "https://crt.sh/json?q={domain}".format(domain=self.domain)
            subdomains = set()
            
            with requests.Session() as client:
                req = client.get(url, timeout=10)
                if(req.status_code == 200):
                    data = req.json()
                    
                    for entry in data:
                        name_value = entry.get('name_value', '')
                        for sub in name_value.split('\n'):
                            sub = self._clean_name(sub.strip().lower())
                            if(not sub):
                                continue 
                                
                            # Skip wildcard entries and empty strings
                            if self._is_subdomain(sub, self.domain, False):
                                # Remove any wildcard prefix if present at beginning
                                subdomains.add(sub)
                
            return sorted(subdomains)
        
        except Exception as e:
            print("[Knockpy crt ERROR]", e, flush=True)
            return []
    
    def dnsrepo(self) -> list[str]:
        try:
            url = f"https://dnsrepo.noc.org/?search={self.domain}"
            
            with requests.Session() as client:
                resp = client.get(url, timeout=self.timeout)
                if resp.status_code != 200:
                    print(f"[DNSRepo] status code {resp.status_code}")
                    return []
                return self.extract_domains(resp.text)
           
        except Exception as e:
            print("[Knockpy DNSRepo ERROR]", e, flush=True)
            return []
    
    def ip_thc(self) -> list[str]:
        try:
            url = "https://ip.thc.org/api/v1/lookup/subdomains"
            subdomains: list = []
            
            with requests.Session() as client:
                res = client.post(url, timeout=self.timeout, headers={'Accept': 'application/json'}, data=json.dumps({"domain": self.domain, "page_state": "", "limit": 10}))
                res.raise_for_status()
                domains = res.json()
                
                if(domains):
                    domains = domains.get('domains')
                    
                    for d in domains:
                        if d.get('domain') != self.domain:
                            subdomains.append(d.get('domain'))
                            
            return subdomains
            
        except Exception as e:
            print("[Knockpy DNSRepo ERROR]", e, flush=True)
            return []
            
    def search(self, resolve=False, return_dict=True):
        subdomains = []
        
        print("Searching urlscan")
        subdomains = self.urlscan()
        
        print("Searching api_subdomain_center")
        subdomains = self.api_subdomain_center()
        
        print("Searching waybackurl")
        subdomains = self.waybackurl()
        
        print("Searching crt")
        crt_subdomains = self.crt()
        
        if crt_subdomains:
            subdomains += crt_subdomains
            
        print("Searching virustotal")
        subdomains += self.virustotal()
        
        print("project discovery")
        subdomains +=  self.projectdiscovery()
        
        print("project securitytrails")
        subdomains += self.securitytrails()
        
        print("project hackertarget")
        subdomains += self.hackertarget()
        
        print("project hackertarget")
        subdomains += self.dnsrepo()
        
        if not resolve and not return_dict:
            print("Returning nothing")
            return subdomains 
            
        subdomains_generator = (sub for sub in list(set(subdomains)))
                
        # If the return should be dictionary
        if(return_dict):
            subdomain = []
            
            for sub in subdomains_generator:
                subdomain.append({
                    "host":self.domain,
                    "subdomain":sub,
                    "ip":"",
                    "asn":""
                })
            return subdomain
        
        # If neither resolve or return_dict, return the default
        return subdomains
