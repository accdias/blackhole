#!/usr/bin/env python
import requests
import netaddr

# For blocking by country list
cidr_by_country_url_mask = 'http://www.ipdeny.com/ipblocks/data/countries/%s.zone'

blocked_countries = ['cn', 'kr']
blocked_countries_prefixes = {}

for country in blocked_countries:
    r = requests.get(cidr_by_country_url_mask % country)
    if r.ok:
        blocked_countries_prefixes[country] = netaddr.cidr_merge(r.text.split())

for country in blocked_countries_prefixes:
    print country
    print blocked_countries_prefixes[country]
