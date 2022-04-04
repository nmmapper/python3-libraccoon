import os
import re
import json
import httpx
import urllib3
from urllib.parse import urlparse
import asyncio

DATA={
    "wildcard value" : {
        "class" : "wildcard value",
        "description" : "This host allows requests made from any origin. However, browsers will block all requests to this host by default.",
        "severity" : "low",
        "exploitation" : "Not possible"
    },
    "third party allowed" : {
        "class" : "third party allowed",
        "description" : "This host has whitelisted a third party host for cross origin requests.",
        "severity" : "Medium",
        "exploitation" : "If the whitelisted host is a code hosting platform such as codepen.io or has an XSS vulnerability, it can be used to exploit this misconfiguration."

    },
    "origin reflected": {
        "class" : "origin reflected",
        "description" : "This host allows any origin to make requests to it.",
        "severity" : "high",
        "exploitation" : "Make requests from any domain you control."
    },
    "invalid value" : {
        "class" : "invalid value",
        "description" : "Header's value is invalid, this CORS implementation doesn't work at all.",
        "severity" : "low",
        "exploitation" : "Not possible"
    },
    "post-domain wildcard" : {
        "class" : "post-domain wildcard",
        "description" : "The origin verification is flawed, it allows requests from a host that has this host as a prefix.",
        "severity" : "high",
        "exploitation" : "Make requests from target.com.attacker.com"
    },
    "pre-domain wildcard" : {
        "class" : "pre-domain wildcard",
        "description" : "The origin verification is flawed, it allows requests from a host that has this host as a suffix.",
        "severity" : "high",
        "exploitation" : "Make requests from attacker-target.com"
    },
    "null origin allowed" : {
        "class" : "null origin allowed",
        "description" : "This host allows requests from 'null' origin.",
        "severity" : "high",
        "exploitation" : "Make requests from a sandboxed iframe."
    },
    "http origin allowed" : {
        "class" : "http origin allowed",
        "description" : "This host allows sharing resources over an unencrypted (HTTP) connection.",
        "severity" : "low",
        "exploitation" : "Sniff requests made over the unencrypted channel."
    },
    "unrecognized underscore" : {
        "class" : "unrecognized underscore",
        "description" : "The origin verification is flawed and can be bypassed using a underscore (_).",
        "severity" : "high",
        "exploitation" : "Set the 'Origin' header to target.com_.example.com"
    },
    "broken parser" : {
        "class" : "broken parser",
        "description" : "The origin verification is flawed and can be bypassed using a backtick (`).",
        "severity" : "high",
        "exploitation" : "Set the 'Origin' header to %60.example.com"
    },
    "unescaped regex" : {
        "class" : "unescaped regex",
        "description" : "The regex used for origin verification contains an unescaped dot (.) character.",
        "severity" : "high",
        "exploitation" : "If the target is sub.example.com, make requests from subxexample.com"
    }
}

class CorsSannerUtils(object):
    """Utilities for cors scanner"""
    def __init__(self, domain):
        self.domain = domain
        self.delay=1
        self.header_dict = {
            'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:97.0) Gecko/20100101 Firefox/97.0',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip',
            'DNT': '1',
            'Connection': 'close',
        }

    def host(self, string):
        if string and '*' not in string:
            return urlparse(string).netloc

    def format_result(self, result):
        new_result = {}
        for each in result:
            if each:
                for i in each:
                    new_result[i] = each[i]
        return new_result

    def extractHeaders(self, headers: str):
        sorted_headers = {}
        for header in headers.split('\\n'):
            name, value = header.split(":", 1)
            name = name.strip()
            value = value.strip()
            if len(value) >= 1 and value[-1] == ',':
                value = value[:-1]
            sorted_headers[name] = value
        return sorted_headers

    def cors(self, target, header_dict, delay):
        url = target
        root = self.host(url)
        parsed = urlparse(url)
        netloc = parsed.netloc
        scheme = parsed.scheme
        url = scheme + '://' + netloc + parsed.path
        try:
            return active_tests(url, root, scheme, self.header_dict, delay)
        except ConnectionError as exc:
            print('Unable to connect to ')

    async def requester(self, url, scheme, headers, origin):
        headers['Origin'] = origin
        print("Requesting ", url)
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(url, headers=headers)
                headers = response.headers
                for key, value in headers.items():
                    if key.lower() == 'access-control-allow-origin':
                        return headers
                        
        except Exception as e:
            print("ERROR ", e)
        return {}

    async def passive_tests(self, url, headers):
        root = self.host(url)
        acao_header, acac_header = headers.get('access-control-allow-origin', None), headers.get('access-control-allow-credentials', None)
        
        if acao_header == '*':
            info = DATA['wildcard value']
            info['acao_header'] = acao_header
            info['acac_header'] = acac_header
            info['url'] = url
            return info
        else:
            return {}
            
        if root:
            if self.host(acao_header) and root != self.host(acao_header):
                info = DATA['third party allowed']
                info['acao_header'] = acao_header
                info['acac_header'] = acac_header
                info['url'] = url
                return info
            print("No hosts ")
            return {}
        else:
            return {}
            
    async def active_tests(self, url, root, scheme, header_dict, delay):
        origin = scheme + '://' + root
        headers = await self.requester(url, scheme, self.header_dict, origin)
        acao_header, acac_header = headers.get('access-control-allow-origin', None), headers.get('access-control-allow-credentials', None)
        if acao_header is {}:
            return

        origin = scheme + '://' + 'example.com'
        headers = await self.requester(url, scheme, self.header_dict, origin)
        acao_header, acac_header = headers.get('access-control-allow-origin', None), headers.get('access-control-allow-credentials', None)
        if acao_header and acao_header == (origin):
            info = DATA['origin reflected']
            info['acao_header'] = acao_header
            info['acac_header'] = acac_header
            info['url'] = url
            return info
        await asyncio.sleep(delay)

        origin = scheme + '://' + root + '.example.com'
        headers = await self.requester(url, scheme, self.header_dict, origin)
        acao_header, acac_header = headers.get('access-control-allow-origin', None), headers.get('access-control-allow-credentials', None)
        if acao_header and acao_header == (origin):
            info = DATA['post-domain wildcard']
            info['acao_header'] = acao_header
            info['acac_header'] = acac_header
            info['url'] = url
            return info
        await asyncio.sleep(delay)

        origin = scheme + '://d3v' + root
        headers = await self.requester(url, scheme, self.header_dict, origin)
        acao_header, acac_header = headers.get('access-control-allow-origin', None), headers.get('access-control-allow-credentials', None)
        if acao_header and acao_header == (origin):
            info = DATA['pre-domain wildcard']
            info['acao_header'] = acao_header
            info['acac_header'] = acac_header
            info['url'] = url
            return info
        await asyncio.sleep(delay)

        origin = 'null'
        headers = await self.requester(url, '', self.header_dict, origin)
        acao_header, acac_header = headers.get('access-control-allow-origin', None), headers.get('access-control-allow-credentials', None)
        if acao_header and acao_header == 'null':
            info = DATA['null origin allowed']
            info['acao_header'] = acao_header
            info['acac_header'] = acac_header
            info['url'] = url
            return info
        await asyncio.sleep(delay)

        origin = scheme + '://' + root + '_.example.com'
        headers = await self.requester(url, scheme, self.header_dict, origin)
        acao_header, acac_header = headers.get('access-control-allow-origin', None), headers.get('access-control-allow-credentials', None)
        if acao_header and acao_header == origin:
            info = DATA['unrecognized underscore']
            info['acao_header'] = acao_header
            info['acac_header'] = acac_header
            info['url'] = url
            return info
        await asyncio.sleep(delay)

        origin = scheme + '://' + root + '%60.example.com'
        headers = await self.requester(url, scheme, self.header_dict, origin)

        acao_header, acac_header = headers.get('access-control-allow-origin', None), headers.get('access-control-allow-credentials', None)
        if acao_header and '`.example.com' in acao_header:
            info = DATA['broken parser']
            info['acao_header'] = acao_header
            info['acac_header'] = acac_header
            info['url'] = url
            return info
        await asyncio.sleep(delay)

        if root.count('.') > 1:
            origin = scheme + '://' + root.replace('.', 'x', 1)
            headers = await self.requester(url, scheme, self.header_dict, origin)
            acao_header, acac_header = headers.get('access-control-allow-origin', None), headers.get('access-control-allow-credentials', None)
            if acao_header and acao_header == origin:
                info = DATA['unescaped regex']
                info['acao_header'] = acao_header
                info['acac_header'] = acac_header
                info['url'] = url
                return info
            await asyncio.sleep(delay)
        origin = 'http://' + root
        headers = await self.requester(url, 'http', self.header_dict, origin)

        acao_header, acac_header = headers.get('access-control-allow-origin', None), headers.get('access-control-allow-credentials', None)
        if acao_header and acao_header.startswith('http://'):
            info = DATA['http origin allowed']
            info['acao_header'] = acao_header
            info['acac_header'] = acac_header
            info['url'] = url
            return info
        else:
            print("Found staff in passive tests")
            return await self.passive_tests(url, headers)

    async def run(self):
        root = self.host(self.domain)
        parsed = urlparse(self.domain)
        netloc = parsed.netloc
        scheme = parsed.scheme
        url = scheme + '://' + netloc + parsed.path

        # Begin running tests
        ret = await self.active_tests(url, root, scheme, self.header_dict, self.delay)
        return ret 
        print(ret)
        
if __name__=="__main__":
    core =CorsSannerUtils("https://www.nmmapper.com")
    #core =CorsSannerUtils("https://www.kali.org/")
    #core =CorsSannerUtils("https://www.cyberpunk.rs")
    #core =CorsSannerUtils("https://www.geeksforgeeks.org")
    asyncio.run(core.run())
