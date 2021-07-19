import geoip2.database
import aiodns
from aiodns.error import DNSError
GEOLITE2_CITYDB="/usr/share/GeoIP/GeoLite2-City.mmdb"
GEOLITE2_ASN="/usr/share/GeoIP/GeoLite2-ASN.mmdb"
GEOLITE2_COUNTRY="/usr/share/GeoIP/GeoLite2-Country.mmdb"

def get_user_agent():
    return "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0"

def get_asn(ip, db=None):
    """Return api Autonomous system number"""
    try:
        if not db:
            db = GEOLITE2_ASN
            
        db_reader = geoip2.database.Reader(db)
        return db_reader.asn(ip)
    except Exception as e:
        return ''
        

async def get_ips(host, default="A"):
    """Host can be subdomain"""
    try:
        resolver  = aiodns.DNSResolver()
        records = await resolver.query(host, default)
        
        list_records = list()
            
        for r in records:
            a_dict = dict()

            a_dict["domain"]=host
            a_dict["a_ip"]=r.host
            a_dict["address"]=r.host
            a_dict["type"]=r.type
            a_dict["ttl"]=r.ttl
            a_dict["time"]=0.0
            list_records.append(a_dict)
        return list_records
    except DNSError as e:
        pass 
        
    except Exception as e:
        raise 
        return []
