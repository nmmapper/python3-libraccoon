import requests
import re
from bs4 import BeautifulSoup
from httpx import ReadTimeout, ConnectTimeout
import httpx
import asyncio
from libraccoon.utils.utils import get_user_agent

class BingIp2Host(object):
    """Performs virtualhost searching"""
    def __init__(self, ip, ua=None):
        self.url = "https://www.bing.com/search"
        self.domain = "https://www.bing.com"
        self.ip = ip
        self.qs = "n"
        self.first = 0
        self.form = "PERE"
        self.lang = "en-us"
        self.prefix = "ip"
        self.param = self.set_param()
        self.ua = ua
        if(not self.ua):
            self.ua = get_user_agent()
                
        self.next_pages = list()
        self.hosts = list() # were we shall store
        self.headers = {"User-Agent":self.ua}
        
    async def get_host(self):
        return self.hosts
        
    def set_param(self):
        """Set's parameters"""
        self.param = {"q":self.format_ip(),
                      "qs":self.qs,
                      "first":self.first,
                      "FORM":self.form,
                      "setlang":self.lang
                    }
        return self.param 
        
    def format_ip(self, ip=None):
        """Format the IP ready for search"""
        if(ip):
            self.ip = ip
        return "{0}:{1} .".format(self.prefix, self.ip)
        
    async def clean_domain(self, domain):
        """remove https://"""
        https = re.compile(r"https?://")
        http = re.compile(r"http?://")
        sub = https.sub('', domain.lower()).strip().strip("/")
        
        url = http.sub('', sub.lower()).strip().strip("/")
        return url.split("/")[0]
    
    async def get_paginations(self, soup):
        pagination = soup.find("nav")
        
        if(not pagination):
            return self.next_pages
        pages = pagination.findAll("a")
        
        for page in pages:
            href = page.get("href")
            if(href):
                self.next_pages.append(self.domain+href)
        return self.next_pages
        
    async def search(self):
        """Perform the searching"""
        try:
            async with httpx.AsyncClient(headers=self.headers, timeout=24) as client:
                response = await client.get(self.url, params=self.param)
                
                if(response.status_code == 200):
                    soup = BeautifulSoup(response.text, "html.parser")
                    response_body = soup.find(id="b_results")
                    
                    await self.search_hosts(response_body)
                    await self.get_paginations(response_body)
                    await asyncio.sleep(2)
                    
                    for url in self.next_pages:
                        response = await client.get(url)
                        
                        if(response.status_code == 200):
                            soup = BeautifulSoup(response.text, "html.parser")
                            response_body = soup.find(id="b_results")
                            await self.search_hosts(response_body)
                        await asyncio.sleep(3)

        except ReadTimeout as e:
            print("READ TIMEOUT ",)
            
        except ConnectTimeout as e:
            print("ConnectTimeout ", e)
            
        except Exception as e:
            raise 
            
    async def search_hosts(self, soup):
        """Find host"""
        results =  soup.findAll("h2")
        for r in results:
            a = r.find("a")
            if(a):
                href = a.get("href")
                if(href):
                    self.hosts.append(await self.clean_domain(href))
    
    async def get_domains(self):
        """Core function to call all methods that search for virtualhost"""
        try:
            data = []
            domains = list(set(self.hosts)) # filter duplicates
            
            for d in domains:
                data.append({"ip":self.ip, "domain":d, "source":"bing"})
            return data
            
        except Exception as e:
            raise 
