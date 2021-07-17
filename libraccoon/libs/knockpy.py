#!/usr/bin/python3

from os import path
import socket
import requests
import random
import bs4 
import time
import sys
import re
import os
from libraccoon.utils.utils import get_user_agent
import socket 

class Request():
    def dns(target):
        try:
            return socket.gethostbyname_ex(target)
        except:
            return []

    def https(url, ua):
        headers = {"user-agent": ua}
        try:
            resp = requests.get("https://"+url, headers=headers, timeout=5)
            return [resp.status_code, resp.headers["Server"] if "Server" in resp.headers.keys() else ""]
        except:
            return []
    def http(url, ua):
        headers = {"user-agent":ua}
        try:
            resp = requests.get("http://"+url, headers=headers, timeout=5)
            return [resp.status_code, resp.headers["Server"] if "Server" in resp.headers.keys() else ""]
        except:
            return []

    def bs4scrape(params):
        target, url, headers = params
        resp = requests.get(url, headers=headers, timeout=5)
        
        pattern = "http(s)?:\/\/(.*)\.%s" % target
        subdomains = []
        if resp.status_code == 200:
            soup = bs4.BeautifulSoup(resp.text, "html.parser")
            for item in soup.find_all("a", href=True):
                if item["href"].startswith("http") and item["href"].find(target) != -1 and item["href"].find("-site:") == -1:
                    match = re.match(pattern, item["href"])
                    if match and re.match("^[a-zA-Z0-9-]*$", match.groups()[1]):
                        subdomains.append(match.groups()[1])
        return list(dict.fromkeys(subdomains))

class KnockPY(object):
    def __init__(self, domain, wordlist=None, virustotalapi=None, discoveryapi=None, ua=None):
        self.domain = domain 
        self.wordlist = wordlist
        self.virustotalapi = virustotalapi
        self.discoveryapi = discoveryapi
        self.ua=ua
        
        if(not self.ua):
            self.ua = get_user_agent()
                
    def local(self):
        try:
            wlist = open(filename,'r').read().split("\n")
        except:
            _ROOT = os.path.abspath(os.path.dirname(__file__))
            filename = os.path.join(_ROOT, "", filename)
            wlist = open(filename,'r').read().split("\n")
        return filter(None, wlist)
    
    def google(self):
        headers = {"user-agent": self.ua}
        dork = "site:%s -site:www.%s" % (self.domain, self.domain)
        url = "https://google.com/search?q=%s&start=%s" % (dork, str(5))
        params = [self.domain, url, headers]
        
        subdomains = []
        try:
            subs =  Request.bs4scrape(params)
            for sub in subs:
                subdomains.append(sub+"."+self.domain)
            return subdomains
        except Exception as e:
            return subdomains

    def duckduckgo(self):
        headers = {"user-agent": self.ua}
        dork = "site:%s -site:www.%s" % (self.domain, self.domain)
        url = "https://duckduckgo.com/html/?q=%s" % dork
        params = [self.domain, url, headers]
        
        subdomains = []
        try:
            subs =  Request.bs4scrape(params)
            for sub in subs:
                subdomains.append(sub+"."+self.domain)
            return subdomains
        except Exception as e:
            return subdomains

    def virustotal(self):
        try:
            if not self.virustotalapi: 
                return []
                
            url = "https://www.virustotal.com/vtapi/v2/domain/report"
            params = {"apikey": self.virustotalapi,"domain": self.domain}
            resp = requests.get(url, params=params)
            resp = resp.json()
            subdomains = resp.get("subdomains", [])        
            return subdomains
            
        except Exception as e:
            print("virustotalO ERROR ", e)
            return []
            
    def projectdiscovery(self):
        try:
            if not self.discoveryapi:
                return [] 
                
            headers = {"Authorization":self.discoveryapi}
            url="https://dns.projectdiscovery.io/dns/{domain}/subdomains".format(domain=self.domain)
            resp = requests.get(url, headers=headers)
            subdomains = []
            
            if(resp.status_code == 200):
                data = resp.json()
                subdomain_data = data.get("subdomains")
                subdomain_domain = data.get("domain")
                
                for subs in subdomain_data:
                    subdomains.append(subs+"."+subdomain_domain)
                return subdomains 
            return []
        except Exception as e:            
            return []
            
    def search(self, resolve=False, return_dict=True):
        subdomains = []
                
        print("Searching google")
        subdomains += self.google()
        print("Searching duckduck go")
        subdomains += self.duckduckgo()
        print("Searching virustotal")
        subdomains += self.virustotal()
        print("project discovery")
        
        subdomains += self.projectdiscovery()
        subdomains = list(set(subdomains))
        
        if(resolve):
            subdomain_list = []
            for sub in subdomains:
                subdomain_list.append({
                    "host":self.domain,
                    "subdomain":sub,
                    "ip":self.get_ip(sub)
                })
            return subdomain_list
        
        # If the return should be dictionary
        if(return_dict):
            subdomain_list = []
            for sub in subdomains:
                subdomain_list.append({
                    "host":self.domain,
                    "subdomain":sub,
                    "ip":""
                })
            return subdomain_list
        
        # If neither resolve or return_dict, return the default
        return subdomains
        
    def get_ip(self, sub):
        """Return the IP"""
        try:
            return socket.gethostbyname(sub)
        except socket.gaierror as e:
            return ""
