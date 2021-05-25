
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
