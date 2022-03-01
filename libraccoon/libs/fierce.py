#!/usr/bin/env python3

import concurrent.futures
import ipaddress
import multiprocessing
import os
import sys
import dns.exception
import dns.name
import dns.query
import dns.resolver
import dns.reversename
import dns.zone
import json
from dns.resolver import Resolver

class LibFierce(object):
    def __init__(self, domain, resolver=None):
        self.resolver = resolver
        self.domain = domain 
        
        if(not self.resolver):
            self.resolver = Resolver()
            
    def unvisited_closure(self):
        visited = set()

        def inner(l):
            nonlocal visited
            result = set(l).difference(visited)
            visited.update(l)
            return result

        return inner

    def concatenate_subdomains(self, domain, subdomains):
        subdomains = [
            nested_subdomain
            for subdomain in subdomains
            for nested_subdomain in subdomain.strip('.').split('.')
        ]

        result = dns.name.Name(tuple(subdomains) + domain.labels)

        if not result.is_absolute():
            result = result.concatenate(dns.name.root)

        return result

    def query(self, domain, record_type='A', tcp=False):
        try:
            resp = self.resolver.resolve(domain, record_type, raise_on_no_answer=False, tcp=tcp)
            if resp.response.answer:
                return resp

            # If we don't receive an answer from our current resolver let's
            # assume we received information on nameservers we can use and
            # perform the same query with those nameservers
            if resp.response.additional and resp.response.authority:
                ns = [
                    rdata.address
                    for additionals in resp.response.additional
                    for rdata in additionals.items
                ]
                resolver.nameservers = ns
                return query(resolver, domain, record_type, tcp=tcp)

            return None
        except (dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, dns.exception.Timeout, ValueError):
            return None

    def reverse_query(self, ip, tcp=False):
        print("IP ", ip)
        print("TCP ", tcp)
        
        return self.query(dns.reversename.from_address(ip), record_type='PTR', tcp=tcp)

    def recursive_query(self, domain, record_type='NS', tcp=False):
        query_domain = str(domain)
        query_response = None
        try:
            while query_response is None:
                query_response = query(resolver, query_domain, record_type, tcp=tcp)
                query_domain = query_domain.split('.', 1)[1]
        except IndexError:
            return None

        return query_response

    def zone_transfer(self, address, domain):
        try:
            return dns.zone.from_xfr(dns.query.xfr(address, domain))
        except (ConnectionError, EOFError, TimeoutError, dns.exception.DNSException):
            return None

    def get_class_c_network(self, ip):
        ip = int(ip)
        floored = ipaddress.ip_address(ip - (ip % (2**8)))
        class_c = ipaddress.IPv4Network('{}/24'.format(floored))

        return class_c

    def default_expander(self, ip):
        return [ip]

    def traverse_expander(self, ip, n=5):
        ip = int(ip)
        class_c_floor = ip - (ip % 256)
        class_c_ceiling = class_c_floor + 255

        ip_min = max(ip - n, class_c_floor)
        ip_max = min(ip + n, class_c_ceiling)
        return [ipaddress.IPv4Address(i) for i in range(ip_min, ip_max + 1)]
        
    def wide_expander(self, ip):
        class_c = get_class_c_network(ip)

        result = list(class_c)
        return result

    def range_expander(self, ip):
        try:
            network = ipaddress.IPv4Network(ip)
        except ipaddress.AddressValueError:
            print("Invalid IPv4 CIDR: {0}".format(ip))

        result = list(network)

        return result

    def default_filter(self, address):
        return True

    def search_filter(self, domains, address):
        return any(domain in address for domain in domains)

    def find_nearby(self, ips, filter_func=None):
        if filter_func is None:
            filter_func = self.default_filter

        str_ips = [str(ip) for ip in ips]
        max_workers = multiprocessing.cpu_count() * 5
        
        print("self.reverse_query ",self.reverse_query)
        print("self.str_ips ",str_ips)
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            reversed_ips = {
                ip: query_result
                for ip, query_result in zip(
                    str_ips,
                    executor.map(
                        self.reverse_query,
                        str_ips
                    )
                )
            }
        
        print("reversed_ips",reversed_ips)
        
        reversed_ips = {
            k: v[0].to_text()
            for k, v in reversed_ips.items()
            if v is not None and filter_func(v[0].to_text())
        }
        return reversed_ips

    def get_stripped_file_lines(self, filename):
        """
        Return lines of a file with whitespace removed
        """
        try:
            lines = open(filename).readlines()
        except FileNotFoundError:
            print("Could not open file: {0}".format(filename))

        return [line.strip() for line in lines]

    def get_subdomains(self, subdomains, subdomain_filename):
        """
        Return subdomains with the following priority:
            1. Subdomains list provided as an argument
            2. A filename containing a list of subdomains
        """
        if subdomains:
            return subdomains
        elif subdomain_filename:
            return get_stripped_file_lines(subdomain_filename)
        return []
    
    def search(self, subdomain, traverse=None):
        """Search"""
        domain = self.get_domain_text()
        url = self.concatenate_subdomains(domain, [subdomain])
        print("URL ", url)
        print("\n")
        record = self.query(url, record_type='A', tcp=False)
        print("Record", record)
        print("\n")
        
        if record is None or record.rrset is None:
            return []
            
        ips = [rr.address for rr in record.rrset]
        ip = ipaddress.IPv4Address(ips[0])
        
        if(traverse):
            ips = self.traverse_expander(ip, traverse)
        else:
            ips = self.traverse_expander(ip)
        
        unvisited = self.unvisited_closure()
        unvisited_ips = unvisited(ips)
        
        print("UNVISITED ", unvisited)
        print("\n")
        print("UNVISITED IP", unvisited_ips)
        
        print("\n")
        nearby = self.find_nearby(unvisited_ips, None)
        print("Nearby", nearby)
        print("\n")
        return nearby
                
    def get_domain_text(self):
        return dns.name.from_text(self.domain)
        
