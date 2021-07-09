



# libraccoon

libraccon a library for high performance offensive security tool for reconnaissance based on raccoon scanner. This library is based on Raccoon A high performance offensive security tool for reconnaissance and vulnerability scanning. The difference is we are providing a library to be used as a module.

This is because we wanted to integrated raccoon to our nmmapper, but we couldn't do it easily, so we just had to re-write this tool to provide module level import.

## Installing the module


## How to use python3-libraccoon
As mentioned this module is designed to be used like a module in other python scripts

```py
from libraccoon.libs import waf
from libraccoon.libs.sub_domain import SubDomainEnumerator
from libraccoon.libs.storage_explorer import StorageExplorer
```
This is how we intended to use this module.

### Detecting WAF
WAF Stands for web application firewall.

```py
from libraccoon.libs.host import Host
from libraccoon.libs import waf

# Initiate host
host = Host(target="nmmapper.com")

# Begin the waf
w = waf.WAF(host)
await w.detect()
results = w.get_waf # Returns dict

print(results)
{'waf': 'Cloudflare'}
```
You will always get results in dict or list

### Querying subdomains
```py
from libraccoon.libs.host import Hos
from libraccoon.libs.sub_domain import SubDomainEnumerator


host = Host(target="nmmapper.com")
subs = SubDomainEnumerator(host)
await subs.run()

# Enumerating Subdomains
# Trying to discover subdomains in Google
.....
# Done enumerating Subdomains

subs.get_subdomains

['nmmapper.com',
 'mail.nmmapper.com',
 'upstream.nmmapper.com',
 'flower.nmmapper.com',
 'analytics.nmmapper.com',
 'www.nmmapper.com']
```
Once again this is module type, can be used in any other external python programs

## Querying virtual-host with bingip2host
If you want to find which ips are hosted on the same network, you can use bingip2host, this tool still requires improvements.
```py
ip="172.67.209....." # CloudFlare
from libraccoon.libs.bingip2host import BingIp2Host
bing = BingIp2Host(ip)
await bing.search()

print(await bing.get_domains())
[{'ip': '172.67.209....', 'domain': 'www.------.fi', 'source': 'bing'},
 {'ip': '172.67.209....',
  'domain': '-----.uk',
  'source': 'bing'},
  .......
  # More results are hidden
  .....
]
```
### Querying Whois information
This is how you can query whos information
```py
from libraccoon.libs.dns_handler import DNSHandler
who = DNSHandler("nmmapper.com")

# Registrar
r = await who.grab_whois("nmmapper.com")
{'domain_name': 'NMMAPPER.COM',
 'registrar': 'NameCheap, Inc.',
 'whois_server': 'whois.namecheap.com',
#... More records truncated
}

# Querying invididual records
txt = await who.query_dns("google.com", "TXT")
A = await who.query_dns("google.com", "A")
Ipv6 = await who.query_dns("google.com", "AAAA")
```
### Fierce Perform A DNS reconnaissance tool for locating non-contiguous IP space.
This module is a port of the fierce tool, we wanted something non commandline we wanted something that can be used as a module, so we had to re-write it to support being used as a module.

```py
#!/usr/bin/python3/
#  Basic search
from libraccoon.libs.fierce import LibFierce
lib   = LibFierce("facebook.com")
ret = lib.search("www")

{'102.132.96.16': 'edge-shortwave-shv-01-mba1.facebook.com.',
 '102.132.96.35': 'edge-star-mini-shv-01-mba1.facebook.com.',
 '102.132.96.19': 'edge-stun-shv-01-mba1.facebook.com.',
 '102.132.96.22': 'edge-z-p1-shv-01-mba1.facebook.com.',
 #....More result has been truncated
}
```
The module is not yet fully complete.

Traverse IPs near discovered domains to search for contiguous blocks
```py
#!/usr/bin/python3/
#  Basic search
from libraccoon.libs.fierce import LibFierce
lib   = LibFierce("facebook.com")
ret = lib.search("www", 10)

{'102.132.96.16': 'edge-shortwave-shv-01-mba1.facebook.com.',
 '102.132.96.35': 'edge-star-mini-shv-01-mba1.facebook.com.',
 '102.132.96.19': 'edge-stun-shv-01-mba1.facebook.com.',
 '102.132.96.22': 'edge-z-p1-shv-01-mba1.facebook.com.',
 #....More result has been truncated
}
```

