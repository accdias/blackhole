#!/usr/bin/env python
from __future__ import print_function
import requests
import netaddr

# For blocking by country list
cidr_by_country_url_mask = 'http://www.ipdeny.com/ipblocks/data/countries/{}.zone'

blocked_countries = ['cn', 'kr']
blocked_prefixes = {}

for country in blocked_countries:
    r = requests.get(cidr_by_country_url_mask.format(country))
    if r.ok:
        blocked_prefixes[country] = netaddr.cidr_merge(r.text.split())
r.close()

for country in blocked_prefixes:
    print('{}: Blocked {} addresses'.format(country.upper(), len(blocked_prefixes[country])))
