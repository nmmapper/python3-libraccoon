import requests
from bs4 import BeautifulSoup
from requests.exceptions import ConnectionError, TooManyRedirects
from libraccoon.utils.web_server_validator import WebServerValidator
from libraccoon.libs.storage_explorer import StorageExplorer
from libraccoon.utils.request_handler import RequestHandler
from libraccoon.utils.help_utils import HelpUtilities
from libraccoon.utils.exceptions import WebAppScannerException, WebServerValidatorException

class WebApplicationScanner(object):

    def __init__(self, host, ua=None):
        self.host = host
        self.ua=ua
        self.request_handler = RequestHandler(ua=self.ua)
        self.web_server_validator = WebServerValidator()
        self.headers = None
        self.robots = None
        self.forms = None
        self.fuzzable_urls = set()
        self.emails = set()
        self.storage_explorer = StorageExplorer(host)
        self.results = {}
        
    def _detect_cms(self, tries=0):
        """
        Detect CMS using whatcms.org.
        Has a re-try mechanism because false negatives may occur
        :param tries: Count of tries for CMS discovery
        """
        # WhatCMS is under CloudFlare which detects and blocks proxied/Tor traffic, hence normal request.
        page = requests.get(url="https://whatcms.org/?s={}".format(self.host.target))
        soup = BeautifulSoup(page.text, "lxml")
        found = soup.select(".panel.panel-success")
        if found:
            try:
                cms = [a for a in soup.select("a") if "/c/" in a.get("href")][0]
                print("CMS detected: target is using {0}".format(cms.get("title")))
            except IndexError:
                if tries >= 4:
                    return
                else:
                    self._detect_cms(tries=tries + 1)
        else:
            if tries >= 4:
                return
            else:
                self._detect_cms(tries=tries + 1)

    def _cookie_info(self, jar):
        for cookie in jar:
            key = cookie.__dict__.get("name")
            domain = cookie.__dict__.get("domain")
            secure = cookie.__dict__.get("secure")
            http_only = cookie.has_nonstandard_attr("HttpOnly")
            try:
                if domain in self.host.target or self.host.target in domain:
                    if not secure or not http_only:
                        current = "Cookie: {0} -".format(key)
                        if not secure and not http_only:
                            current += " both secure and HttpOnly flags are not set"
                        elif not secure:
                            current += " secure flag not set"
                        else:
                            current += " HttpOnly flag not set"
                        print(current)

            except TypeError:
                continue

    def _server_info(self):
        if self.headers.get("server"):
            self.results["webserver"]=self.headers.get("server")
            print("Web server detected: {0}".format(self.headers.get("server")))
        else:
            self.results["webserver"]=""
            
    def _x_powered_by(self):
        if self.headers.get("X-Powered-By"):
            self.results["x_powered_by"]=self.headers.get("X-Powered-By")
            print("X-Powered-By header detected: {0}".format(self.headers.get("X-Powered-By")))
        else:
            self.results["x_powered_by"]=""
            
    def _anti_clickjacking(self):
        if not self.headers.get("X-Frame-Options"):
            self.results["x_frame_option"]=self.headers.get("X-Frame-Options")
            print("X-Frame-Options header not detected - target might be vulnerable to clickjacking")
        else:
            self.results["x_frame_option"]=self.headers.get("X-Frame-Options")
            
    def _xss_protection(self):
        xss_header = self.headers.get("X-XSS-PROTECTION")
        if xss_header and "1" in xss_header:
            print("Found X-XSS-PROTECTION header")
        self.results["x_xss_protection"]=self.headers.get("X-XSS-PROTECTION")
        
    def _cors_wildcard(self):
        if self.headers.get("Access-Control-Allow-Origin") == "*":
            print("CORS wildcard detected")
        self.results["access_control_llow_origin"]=self.headers.get("Access-Control-Allow-Origin")
        
    def get_robot_url(self):
        return "{}://{}:{}/robots.txt".format(
            self.host.protocol,
            self.host.target,
            self.host.port
        )
            
    def _robots(self):
        url = self.get_robot_url()
        
        res = self.request_handler.send(
            "GET",
            url=url
        )
        if res.status_code != 404 and res.text and "<!DOCTYPE html>" not in res.text:
            print("Found robots.txt")
            self.results["robot"]=url
        else:
            self.results["robot"]=""
    
    def get_sitemap_url(self):
        return "{}://{}:{}/sitemap.xml".format(
            self.host.protocol,
            self.host.target,
            self.host.port
        )
    def _sitemap(self):
        url = self.get_sitemap_url()
        
        res = self.request_handler.send(
            "GET",
            url=url
        )
        if res.status_code != 404 and res.text and "<!DOCTYPE html>" not in res.text:
            print("Found sitemap")
            self.results["sitemap"]=url
        else:
            self.results["sitemap"]=""

    def _analyze_hrefs(self, href):
        if all(("?" in href, "=" in href, not href.startswith("mailto:"))):
            if any(((self.host.naked and self.host.naked in href), self.host.target in href, href.startswith("/"))):
                self.fuzzable_urls.add(href)
        elif href.startswith("mailto:"):
            self._add_to_emails(href)

    def _log_fuzzable_urls(self):
        base_target = "{0}://{1}:{2}".format(self.host.protocol, self.host.target, self.host.port)
        for url in self.fuzzable_urls:
            if url.startswith("/"):
                print("\t{0}{1}".format(base_target, url))
            else:
                print("\t{0}".format(url))

    def _log_emails(self):
        for email in self.emails:
            print("\t{0}".format(email[7:]))

    def _find_urls(self, soup):
        urls = soup.select("a")
        if urls:
            for url in urls:
                href = url.get("href")
                if href:
                    self._analyze_hrefs(href)

            if self.fuzzable_urls:
                print("{0} fuzzable URLs discovered".format(len(self.fuzzable_urls)))

            if self.emails:
                print("{0} email addresses discovered".format(len(self.emails)))

    def _find_forms(self, soup):
        # TODO: Analyze interesting input names/ids/params
        self.forms = soup.select("form")
        if self.forms:
            print("{0} HTML forms discovered".format(len(self.forms)))
            for form in self.forms:
                form_action = form.get("action")
                if form_action == "#":
                    continue
                form_id = form.get("id")
                form_class = form.get("class")
                form_method = form.get("method")
                print("\tForm details: ID: {0}, Class: {1}, Method: {2}, action: {3}".format(
                    form_id, form_class, form_method, form_action
                ))

    def _add_to_emails(self, href):
        self.emails.add(href)

    async def get_web_application_info(self):
        session = self.request_handler.get_new_session()
        try:
            with session:
                # Test if target is serving HTTP requests
                response = session.get(
                    timeout=20,
                    url="{}://{}:{}".format(
                        self.host.protocol,
                        self.host.target,
                        self.host.port
                    )
                )
                self.headers = response.headers
                self._detect_cms()
                self._robots()
                self._sitemap()
                self._server_info()
                self._x_powered_by()
                self._cors_wildcard()
                self._xss_protection()
                self._anti_clickjacking()
                self._cookie_info(session.cookies)

                soup = BeautifulSoup(response.text, "lxml")
                self._find_urls(soup)
                self._find_forms(soup)
                #self.storage_explorer.run(soup)

        except (ConnectionError, TooManyRedirects) as e:
            raise WebAppScannerException("Couldn't get response from server.\n"
                                         "Caused due to exception: {}".format(str(e)))

    async def run_scan(self):
        print("Trying to collect {0} web application data".format(self.host))
        try:
            self.web_server_validator.validate_target_webserver(self.host)
            await self.get_web_application_info()
        except WebServerValidatorException:
            print("Target does not seem to have an active web server on port: {0}.No web application data will be gathered.".format(self.host.port))
            return
    
    def get_results(self):
        return self.results
