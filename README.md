
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
