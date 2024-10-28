import os
import re
from random import choice
import bs4
import httpx
import asyncio
from libraccoon.wordlists.wordlist_helper import get_file

class Scanless(object):
    OUTPUT_TEMPLATE = "PORT      STATE  SERVICE\n{lines}"
    
    def __init__(self, hostname):
        self.hostname = hostname 
        self.hackertarget_re = r'(\d{1,5})\/(tcp|udp)[ \t]+(\S+)[ \t]+(.*)'
        self.timeout = 30
        
    def parse(self, output):
        """Parse the returned data"""
        parsed_output = list()
        for line in output.split("\n"):
            if "/tcp" in line or "/udp" in line:
                port_str, state, service = line.split()
                port, protocol = port_str.split("/")
                parsed_output.append(
                    {
                        "port": port,
                        "state": state,
                        "service": service,
                        "protocol": protocol,
                    }
                )
        return parsed_output
    
    def lookup_service(self, port):
        nmap_file = get_file("nmap-services.txt")
        NMAP_SERVICES = open(nmap_file).read().splitlines()
        
        for line in NMAP_SERVICES:
            if f"{port}/tcp" in line:
                return line.split()[0]
            
    def generate_output(self, raw_data):
        lines = list()
        for raw in raw_data:
            p, state = raw
            service = self.lookup_service(p)
            port = f"{p}/tcp"
            lines.append(f"{port:<9} {state:<6} {service}")
        return self.OUTPUT_TEMPLATE.format(lines="\n".join(lines))
    
    async def scan_hackertarget(self, target:str = None):
        """Scan using hackertarget"""
        if (target):
            self.hostname = target 
        
        BASE_URL = 'https://hackertarget.com/nmap-online-port-scanner/'
        payload = { 'theinput': self.hostname,
                    'thetest': 'nmap',
                    'name_of_nonce_field': '0fbb307e85',
                    '_wp_http_referer': '/nmap-online-port-scanner/'
                }
        
        async with httpx.AsyncClient() as client:
            try:
                r = await client.post(BASE_URL, data=payload, timeout=self.timeout)
                
                if(r.status_code == 200):
                    page = r.content
                    soup = bs4.BeautifulSoup(page, 'html.parser')
                    data_strings = soup.findAll('pre', {'id': 'formResponse'})[0].string
                    
                    re_compiled = re.compile(self.hackertarget_re)
                    ports = re_compiled.findall(data_strings)
                    data = list()
                    
                    for port in ports:
                        port = list(port)
                        data.append({
                            "port":port[0],
                            "protocol":port[1],
                            "state":port[2],
                            "service":port[3],
                        })
                    return data
                    
                else:
                    print("Scanless method[scan_hackertarget] status code ", r.status_code)
            except Exception as e:
                print(e)
                msg = "ERROR Scanless method[scan_hackertarget] {msg}".format(msg=str(e))
                print(msg)
                return []
                
    async def scan_ipfingerprints(self, target:str = None):
        """Scan using hackertarget"""
        if (target):
            self.hostname = target 
        
        BASE_URL = 'https://www.ipfingerprints.com/scripts/getPortsInfo.php'
        payload = {
            "remoteHost": self.hostname,
            "start_port": 20,
            "end_port": 512,
            "normalScan": "No",
            "scan_type": "connect",
            "ping_type": "none",
            "os_detect": "on",
        }
        
        async with httpx.AsyncClient() as client:
            try:
                print("Requesting this one here!")
                r = await client.post(BASE_URL, data=payload, timeout=self.timeout)
                if(r.status_code == 200):
                    print("Status is okay")
                    output = re.sub("<[^<]+?>", "", r.content.decode())
                    raw_output = output.replace("\\n", "\n").replace("\\/", "/")[36:-46].strip()
                    data = self.parse(raw_output)
                    print(data)
                    return data
                else:
                    print("Scanless method[scan_ipfingerprints] status code ", r.status_code)
                    return []
                    
            except Exception as e:
                print(e)
                msg = "ERROR Scanless method[scan_ipfingerprints] {msg}".format(msg=str(e))
                print(msg)
                return []
    
    async def spiderip(self, target:str = None):
        if (target):
            self.hostname = target 
        ports = [
            21,22, 25,80,110,143,443,465,993,995,1433,3306,3389,5900,8080, 8443,
        ]
        
        NETWORK_ERROR_MSG = "Network error, see --debug for details."
        BASE_URL = "https://spiderip.com/inc/port_scan.php"
        payload = {"ip": self.hostname, "language[]": ports}
        
        async with httpx.AsyncClient() as client:
            try:
                r = await client.post(BASE_URL, data=payload, timeout=self.timeout)
                if(r.status_code == 200):
                    scan_results = r.content.decode()
                    scan_results = scan_results.split("/images/")
                    scan_results.pop(0)
                    
                    raw_data = list()
                    for result, port in zip(scan_results, ports):
                        if "open" in result:
                            raw_data.append((port, "open"))
                        else:
                            raw_data.append((port, "closed"))
                                        
                    raw_output = self.generate_output(raw_data)
                    parsed_output = self.parse(raw_output)
                    print(parsed_output)
                    return parsed_output
                else:
                    print("Scanless method[spiderip] status code ", r.status_code)
                    return []
                    
            except Exception as e:
                msg = "ERROR Scanless method[spiderip] {msg}".format(msg=str(e))
                return []
                
    async def standingtech(self, target:str = None):
        if (target):
            self.hostname = target 

        ports = [21, 22,23,25,80,110,139,143,443,445,1433,3306,3389,5900]
        BASE_URL = 'https://portscanner.standingtech.com/portscan.php?port={0}&host={1}&protocol=TCP'
        data = list()
        port_service_pattern = r"\([^()]*?[^)]*\)"
        closed_service_pattern = r'(>)closed(<)'
        open_service_pattern = r'(>)open(<)'
        
        async with httpx.AsyncClient() as client:
            try:
                for p in ports:
                    tmp_url = BASE_URL.format(p, self.hostname)                    
                    ret = await client.get(tmp_url, timeout=self.timeout)
                    
                    data_dict = {}
                    
                    if(ret.status_code == 200):
                        service = re.search(port_service_pattern, ret.text)
                        closed_service = re.search(closed_service_pattern, ret.text)
                        open_service = re.search(open_service_pattern, ret.text)
                        
                        if(service):
                            service = service.group().replace("(", "").replace(")", "")
                            data_dict["service"]=service
                        else:
                            print("NO pattern found!")
                            
                        if(open_service):
                            data_dict["state"]="open"
                            
                        if(closed_service):
                            data_dict["state"]="closed"
                            
                        data_dict["protocol"]="tcp"
                        data_dict["port"]=p
                        
                        data.append(data_dict)
                        
                    else:
                        print("Scanless method[spiderip] status code ", r.status_code)
                        return []
                
                print(data)
                return data
                
            except Exception as e:
                msg = "ERROR Scanless method[spiderip] {msg}".format(msg=str(e))
                return []
        
    async def viewdns(self, target:str = None):
        if (target):
            self.hostname = target 

        ports = [ 21,22, 23,25,53,80,110,139,143,443,445,1433,1521,3306,3389]
        BASE_URL = f'https://viewdns.info/portscan/?host={self.hostname}'
        data = list()
        port_pattern = r'(<td>).*?\d+(</td>)'
        service_pattern = r'(<td>)\b[^\W\d]+\b(</td>)'
        
        async with httpx.AsyncClient() as client:
            try:                
                ret = await client.get(BASE_URL, timeout=self.timeout)
                if(ret.status_code == 200):
                    soup = bs4.BeautifulSoup(ret.text, "html.parser")
                    table, rows = soup.find("table"), soup.findAll("tr") 
                    
                    for tr, port in zip(rows[7:22], ports):
                        tmp_data = {}
                        
                        port = re.search(port_pattern, str(tr))
                        if(port):
                            port = port.group().replace("</td>", "").replace("<td>", "")
                            tmp_data["port"]=port
                        else:
                            print("Missing port ", tr)
                        
                        service = re.search(service_pattern, str(tr))
                        if(service):
                            service = service.group().replace("</td>", "").replace("<td>", "")
                            tmp_data["service"]=service.lower()
                        else:
                            #Missing service <tr><td>110</td><td>POP3</td><td><center><img alt="closed" height="20" src="/images/error.GIF"/></center></td></tr>
                            #Missing service <tr><td>3389</td><td>Remote Desktop</td><td><center><img alt="closed" height="20" src="/images/error.GIF"/></center></td></tr>
                            print("Missing service", tr)
                            
                        cols = str(tr.findAll("td"))
                        if "error.GIF" in cols:
                            tmp_data["state"]='closed'
                        else:
                            tmp_data["state"]='open'
                        
                        # Add protocol
                        tmp_data["protocol"]="protocol"
                        
                        # Put inside a list
                        data.append(tmp_data)
                else:
                    msg = "STATUS Scanless method[viewdns] {status}".format(status=ret.status_code)
                    print(msg)
                
                print(data)
                
            except Exception as e:
                msg = "ERROR Scanless method[spiderip] {msg}".format(msg=str(e))
                print(msg)
                return []
                
    async def yougetsignal(self, target:str = None):
        if (target):
            self.hostname = target 

        ports = [21,22,23,25,53,80,110,115,135,139,143,194,443,445,1433,3306,3389,5632,5900,6112]
        BASE_URL = 'https://ports.yougetsignal.com/short-scan.php'
        data = list()
        
        async with httpx.AsyncClient() as client:
            try:
                payload = {"remoteAddress": self.hostname}
                ret = await client.post(BASE_URL, data=payload, timeout=self.timeout)
                
                if(ret.status_code == 200):
                    soup = bs4.BeautifulSoup(ret.text, "html.parser")
                    imgs = soup.findAll("img")
                    raw_data = list()
                    
                    for img, port in zip(imgs, ports):
                        if "red" in str(img):
                            raw_data.append((port, "closed"))
                        else:
                            raw_data.append((port, "open"))
                    
                    raw_output = self.generate_output(raw_data)
                    data = self.parse(raw_output)
                    print(data)
                    return data
                    
                else:
                    msg = "STATUS Scanless method[yougetsignal] {status}".format(status=ret.status_code)
                    print(msg)
                                
            except Exception as e:
                msg = "ERROR Scanless method[yougetsignal] {msg}".format(msg=str(e))
                print(msg)
                return []
        
if __name__=="__main__":
    r  = Scanless("github.com")
    loop = asyncio.get_event_loop()
    coro = r.scan_ipfingerprints(None)
    resultsresult = loop.run_until_complete(coro)

