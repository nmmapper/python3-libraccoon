from requests.exceptions import TooManyRedirects, ConnectionError
from libraccoon.utils.web_server_validator import WebServerValidator
from libraccoon.utils.exceptions import WAFException, WebServerValidatorException
from libraccoon.utils.request_handler import RequestHandler
from libraccoon.utils.help_utils import HelpUtilities
import socket 

SERVER = "Server"

class WAFApplicationMethods(object):

    @classmethod
    def detect_cloudfront(cls, res):
        service = "CloudFront"
        waf_headers = ("Via", "X-cache")
        if any(h in res.headers.keys() for h in waf_headers) and any(service.lower() in val for val in res.headers.values()):
            return True
        if res.headers.get(SERVER) == service:
            return True
        return

    @classmethod
    def detect_incapsula(cls, res):
        if "X-Iinfo" in res.headers.keys() or res.headers.get("X-CDN") == "Incapsula":
            return True
        return

    @classmethod
    def detect_distil(cls, res):
        if res.headers.get("x-distil-cs"):
            return True
        return

    @classmethod
    def detect_cloudflare(cls, res):
        if "CF-RAY" in res.headers.keys() or res.headers.get(SERVER) == "cloudflare":
            return True
        return

    @classmethod
    def detect_edgecast(cls, res):
        if SERVER in res.headers.keys() and "ECD" in res.headers[SERVER]:
            return True
        return

    @classmethod
    def detect_maxcdn(cls, res):
        if SERVER in res.headers.keys() and "NetDNA-cache" in res.headers[SERVER]:
            return True
        return

    @classmethod
    def detect_sucuri(cls, res):
        if any((
                res.headers.get(SERVER) == "Sucuri/Cloudproxy",
                "X-Sucuri-ID" in res.headers.keys(),
                "X-Sucuri-Cache"in res.headers.keys(),
                "Access Denied - Sucuri Website Firewall" in res.text)):
            return True
        return

    @classmethod
    def detect_reblaze(cls, res):
        if res.headers.get(SERVER) == "Reblaze Secure Web Gateway" or res.cookies.get("rbzid"):
            return True
        return

class WAF(object):

    def __init__(self, host, ua=None):
        self.host = host
        self.cnames = host.dns_results.get('CNAME')
        self.ua = ua
        self.request_handler = RequestHandler(ua=self.ua)
        self.web_server_validator = WebServerValidator()
        self.waf_present = False
        self.waf_cname_map = {
            "incapdns": "Incapsula",
            "edgekey": "Akamai",
            "akamai": "Akamai",
            "edgesuite": "Akamai",
            "distil": "Distil Networks",
            "cloudfront": "CloudFront",
            "netdna-cdn": "MaxCDN"
        }
        self.waf_app_method_map = {
            "CloudFront": WAFApplicationMethods.detect_cloudfront,
            "Cloudflare": WAFApplicationMethods.detect_cloudflare,
            "Incapsula": WAFApplicationMethods.detect_incapsula,
            "MaxCDN": WAFApplicationMethods.detect_maxcdn,
            "Edgecast": WAFApplicationMethods.detect_edgecast,
            "Distil Networks": WAFApplicationMethods.detect_distil,
            "Sucuri": WAFApplicationMethods.detect_sucuri,
            "Reblaze": WAFApplicationMethods.detect_reblaze
        }
        
        self.waf_results = {}
        
    def _waf_detected(self, name, where):
        print("Detected WAF presence in {0}:{1}".format(where,name))
        self.waf_results["waf"]=name 
        self.waf_present = True

    def _detect_by_cname(self):
        for waf in self.waf_cname_map:
            if any(waf in str(cname) for cname in self.cnames):
                self._waf_detected(self.waf_cname_map.get(waf), "CNAME record")

    async def _detect_by_application(self):
        try:
            session = self.request_handler.get_new_session()
            response = session.get(
                timeout=20,
                allow_redirects=True,
                url="{}://{}".format(
                    self.host.protocol,
                    self.host.target,
                )
            )
            for waf, method in self.waf_app_method_map.items():
                result = method(response)
                if result:
                    self._waf_detected(waf, "web application")

        except (ConnectionError, TooManyRedirects) as e:
            raise WAFException("Couldn't get response from server.\n"
                               "Caused due to exception: {}".format(str(e)))

    async def detect(self):
        print("Trying to detect WAF presence in {0}".format(self.host))
        if self.cnames:
            self._detect_by_cname()
        try:
            self.web_server_validator.validate_target_webserver(self.host)
            await self._detect_by_application()

            if not self.waf_present:
                print("Did not detect WAF presence in target")
        except WebServerValidatorException as e:
            raise 
            #print("Failed!")
    
    @property
    def get_waf(self):
        self.waf_results["ip"]=self.get_ip(self.host.target)
        self.waf_results["host"]=self.host.target
        self.waf_results["asn"]=""
        return self.waf_results
        
    def get_ip(self, host):
        """Return IP"""
        try:
            return socket.gethostbyname(host)
        except socket.gaierror as e:
            return ""
