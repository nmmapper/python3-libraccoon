import httpx
from libraccoon.utils.utils import get_user_agent
from libraccoon.utils.utils import get_asn
from libraccoon.utils.utils import get_ips

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
        self.timeout = 50
        
        if(not self.ua):
            self.ua = get_user_agent()
        
        self.headers = {"User-Agent":self.ua}
        
    async def bufferover_run(self):
        """@return List"""
        try:            
            return []
        except Exception as e:
            print("[Knockpy bufferover_run ERROR]", e, flush=True)
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
            
    async def binary_edge(self):
        """@return List"""
        try:
            if not self.binary_edge_api:
                return [] 
                
            headers = {"X-KEY":self.binary_edge_api, "User-Agent":self.ua}
            url = "https://api.binaryedge.io/v2/query/domains/subdomain/{domain}".format(domain=self.domain)
            subdomains = []
            
            async with httpx.AsyncClient() as client:
                resp = await client.get(url, headers=headers, timeout=self.timeout)
                
                if(resp.status_code == 200):
                    data = resp.json()
                    page = data.get("page")
                    subdomains += data.get("events")
            
            print("BINARY EDGE ", subdomains)
            return subdomains 
            
        except Exception as e:
            print("[Knockpy binary_edge ERROR]", e, flush=True)
            return []
            
    async def search(self, resolve=False, return_dict=True):
        subdomains = []

        print("Searching binary_edge")
        binary_subdomains = await self.binary_edge()
        
        if binary_subdomains:
            subdomains += binary_subdomains
            
        print("Searching virustotal")
        subdomains += await self.virustotal()
        
        print("project discovery")
        subdomains += await self.projectdiscovery()
        
        print("project securitytrails")
        subdomains += await self.securitytrails()
        
        print("project bufferover_run")
        subdomains += await self.bufferover_run()
        
        print("project hackertarget")
        subdomains += await self.hackertarget()
        
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
        
