#!/usr/bin/env python
from __future__ import print_function
import requests
import netaddr

# For blocking by country list
cidr_by_country_url_mask = 'http://www.ipdeny.com/ipblocks/data/countries/{}.zone'

blocked_countries = ['cn', 'kr']
blocked_prefixes = {}

for country in blocked_countries:
    with requests.get(cidr_by_country_url_mask.format(country)) as r:
        if r.ok:
            blocked_prefixes[country] = netaddr.cidr_merge(r.text.split())

for country in blocked_prefixes:
    print('{}: Blocked {} addresses'.format(country.upper(), len(blocked_prefixes[country])))
