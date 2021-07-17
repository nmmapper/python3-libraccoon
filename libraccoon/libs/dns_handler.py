import aiodns
import simplejson as json
import whois 

class DNSHandler(object):
    """Handles DNS queries and lookups"""
    def __init__(self, host=None):
        self.host = host 
        self.results = {}
        self.resolver = aiodns.DNSResolver()
        self.flags = 0
        self.flags = self.flags | whois.NICClient.WHOIS_QUICK
        
    async def query_dns(self, domain, record):
        """
        Query DNS records for host.
        :param domains: Iterable of domains to get DNS Records for
        :param records: Iterable of DNS records to get from domain.
        """
        try:
            self.results = {}
            result = await self.resolver.query(domain, record)
            if(record == "TXT"):
                self.results[record]=self.parse_txt(result)
                
            elif(record == "SOA"):
                self.results[record]=self.parse_soa(result)
                
            elif(record == "NS"):
                self.results[record]=self.parse_ns(result)
                
            elif(record == "A" or record == "AAAA"):
                self.results[record]=self.parse_ns(result)
                
            elif(record == "MX"):
                self.results[record]=self.parse_ns(result)
                
        except Exception as e:
            print("ERROR ", e)
        else:
            return self.results
        
    def parse_ns(self, ns_record):
        """Naively parse ns records"""
        ns_list = []
        for ns in ns_record:
            ns_list.append({
                "host":ns.host,
                "type":ns.type,
                "ttl":ns.ttl,
            })
        return ns_list
        
    def parse_txt(self, txt_record):
        """Naively parse txt_records"""
        txt_list = []
        for txt in txt_record:
            txt_list.append({
                "text":txt.text,
                "ttl":txt.ttl,
                "type":txt.type,
            })
        return txt_list
        
    def parse_soa(self, soa_record):
        """Naively parse soa records"""
        return {
            "expires":soa_record.expires,
            "nsname":soa_record.nsname,
            "serial":soa_record.serial,
            "hostmaster":soa_record.hostmaster,
            "refresh":soa_record.refresh,
            "ttl":soa_record.ttl,
            "minttl":soa_record.minttl,
            "retry":soa_record.retry,
            "type":soa_record.type,
        }
        
    async def grab_whois(self, host):
        try:
            whoisresults = whois.whois(host, flags=self.flags)
            return whoisresults
        except Exception:
            return {}
