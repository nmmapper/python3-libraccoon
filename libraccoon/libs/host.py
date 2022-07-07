import os
from ipaddress import ip_address
from dns.exception import Timeout
from libraccoon.libs.dns_handler import DNSHandler
from libraccoon.utils.exceptions import HostHandlerException
from libraccoon.utils.help_utils import HelpUtilities

class Host(object):
    """
    Host parsing, IP to host resolution (and vice verse), etc
    Sets domain/IP, port, protocol. also tries to parse FQDN, naked domain, if possible.
    """
    def __init__(self, target, dns_records=None):
        self.target = target.strip()
        self.dns_records = dns_records
        if not self.dns_records:
            self.dns_records = tuple("A,MX,NS,CNAME,SOA,TXT".split(","))
            
        self.port = 80
        self.protocol = "https"
        self.is_ip = False
        self.fqdn = None
        self.naked = None
        self.dns_results = {}
        self.dnshandler = DNSHandler(self.target)
        
    def __str__(self):
        return self.target

    def __repr__(self):
        return self.__dict__

    def validate_ip(self, addr=None):
        if not addr:
            addr = self.target
        try:
            ip_address(addr.strip())
            return True
        except ValueError:
            return

    def _extract_port(self, addr):
        try:
            self.target, self.port = addr.split(":")
            try:
                self.port = int(self.port)
            except ValueError:
                # Probably has a path after the port, e.g - localhost:3000/home.asp
                raise HostHandlerException("Failed to parse port {}. Is there a path after it ?".format(
                    self.port
                ))
            print("Port detected: {0}".format(self.port))
        except IndexError:
            print("Did not detect port. Using default port 80")
            return
        return

    def _is_proto(self, domain=None):
        if not domain:
            domain = self.target
        if "://" in domain:
            if any(domain.startswith(proto) for proto in ("https", "http")):
                return True
            else:
                raise HostHandlerException("Unknown or unsupported protocol: {}".format(self.target.split("://")[0]))
        return

    async def parse(self):
        """Try to extract domain (full, naked, sub-domain), IP and port."""
        if self.target.endswith("/"):
            self.target = self.target[:-1]

        if self._is_proto(self.target):
            try:
                self.protocol, self.target = self.target.split("://")
                print("Protocol detected: {0}".format(self.protocol))
                if self.protocol.lower() == "https" and self.port == 80:
                    self.port = 443
            except ValueError:
                raise HostHandlerException("Could not make domain and protocol from host")

        if ":" in self.target:
            self._extract_port(self.target)

        if self.validate_ip(self.target):
            print("Detected {0} as an IP address.".format(self.target))
            self.is_ip = True
        else:
            domains = []
            if self.target.startswith("www."):
                # Obviously an FQDN
                domains.extend((self.target, self.target.split("www.")[1]))
                self.fqdn = self.target
                self.naked = ".".join(self.fqdn.split('.')[1:])
            else:
                domains.append(self.target)
                domain_levels = self.target.split(".")
                if len(domain_levels) == 2 or (len(domain_levels) == 3 and domain_levels[1] == "co"):
                    print("Found {0} to be a naked domain".format(self.target))
                    self.naked = self.target

            try:
                self.dns_results = await self.dnshandler.query_dns(self.target, self.dns_records)
            except Timeout:
                raise HostHandlerException("DNS Query timed out. Maybe target has DNS protection ?")

            if self.dns_results.get("CNAME"):
                # Naked domains shouldn't hold CNAME records according to RFC regulations
                print("Found {0} to be an FQDN by CNAME presence in DNS records".format(self.target))

                self.fqdn = self.target
                self.naked = ".".join(self.fqdn.split('.')[1:])
