#!/usr/bin/env python3

import os
import sys
import re
import shutil  # for shutil.copy()
from ipaddress import ip_network, collapse_addresses
from pyroute2 import IPRoute  # yum/dnf install -y python-pyroute2 python3-pyroute2
from pathlib import Path

__author__ = 'Antonio Dias'
__email__ = 'accdias@gmail.com'
__copyright__ = 'Copyright 2017, Antonio Dias'
__license__ = 'GPL'
__version__ = '0.1'
__status__ = 'Development'

fail_strings_list = (
    'vchkpw-smtp: password fail',
    'dovecot: imap-login: Disconnected (auth failed',
    'FAIL LOGIN: Client',
    'Failed password for invalid user',
    'vchkpw-smtp: vpopmail user not found admin@',
    'vchkpw-smtp: vpopmail user not found info@'
)


# Use findall() method to return IPv4 addresses found in a string
extract_ip_addresses_regex = re.compile(
    r'''
        \b
        (?:
            (?:
               25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]  # 0-255
            ?)\.                                    # .
        ){3}                                        # 3 times
        (?:
            25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]     # 0-255
        ?)
        \b
    ''', re.VERBOSE)

# Match lines starting with a valid CIDR network
is_cidr_regex = re.compile(
    r'''
        \b
        (?:
            (?:
                (?:
                    25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]  # 0-255
                ?)\.                                     # .
            ){3}                                         # 3 times
            (?:
                25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]      # 0-255
            ?)
            /                                            # /
            (?:
                [1-3]){1}                                # 1-3
                (?:
                    [0-2]                                # 0-2
                )?
            ?)
        ?)
        \b
    ''', re.VERBOSE)

# For blocking by country list
cidr_by_country_url_mask = 'http://www.ipdeny.com/ipblocks/data/countries/%s.zone'


def is_cidr(s):
    return is_cidr_regex.match(s) and True or False


# Match lines starting with comments markers
is_comment_regex = re.compile(r'^\s*[#;].*$')


def is_comment(s):
    return is_comment_regex.match(s) and True or False


# Match empty lines
is_blank_regex = re.compile(r'^\s*$')


def is_blank(s):
    return is_blank_regex.match(s) and True or False


def is_whitelisted(ip):
    if ip.is_global:
        for prefix in whitelisted_prefixes:
            if ip.subnet_of(prefix):
                return True
    return False


def is_blacklisted(ip):
    for prefix in blacklisted_prefixes:
        if ip.subnet_of(prefix):
            return True
    return False


def check_log_line(line):
    line = line.strip()
    ip = None

    if any([fail_string in line for fail_string in fail_strings_list]):
        ip = extract_ip_addresses_regex.findall(line)[0]

    if ip:
        ip = ip_network(ip)
        if is_whitelisted(ip):
            print('Ignoring whitelisted address: {}'.format(ip))
        elif not is_blacklisted(ip):
            print('Blacklisting address: {}'.format(ip))
            blacklisted_prefixes.append(ip)


def file_as_array(filename):
    print('Reading {} ... '.format(filename))
    array = []
    if filename.exists():
        with filename.open() as f:
            for line in f:
                line = line.strip()
                if any((is_comment(line), is_blank(line))):
                    if is_cidr(line) and line not in array:
                        array.append(line)
    return collapse_addresses(array)


def blackhole_routes_as_array():
    ip = IPRoute()
    array = []

    # Blackhole routes are type 6
    for r in ip.get_routes(type=6):
        array.append(ip_network('{}/{}'.format(r['attrs'][1][1], r['dst_len'])))
    return collapse_addresses(array)


if __name__ == '__main__':
    os.geteuid() == 0 or sys.exit('Script must be run as root')

    blacklist_file = Path('/etc/spamdyke/blacklist.d/ip')
    whitelist_file = Path('/etc/spamdyke/whitelist.d/ip')
    backup_suffix = 'backup'

    logfiles = (
        Path('/var/log/maillog'),
        Path('/var/log/vsftpd.log'),
        Path('/var/log/secure')
    )

    whitelisted_prefixes = file_as_array(whitelist_file)
    blacklisted_prefixes = file_as_array(blacklist_file)
    blackhole_prefixes = blackhole_routes_as_array()

    for logfile in logfiles:
        print('Processing {} ... '.format(logfile))
        with logfile.open() as f:
            for line in f:
                check_log_line(line)

    # summarize and sort the blacklisted_prefixes array
    blacklisted_prefixes = collapse_addresses(blacklisted_prefixes)

    # backup the old blacklist file
    print('Copying {} to {}.{} ...'.format(blacklist_file, blacklist_file, backup_suffix))
    shutil.copy(blacklist_file, '{}.{}'.format(blacklist_file, backup_suffix))

    # save the new blacklist file
    print('Saving blacklist to {} ...'.format(blacklist_file))
    with blacklist_file.open(mode='w') as f:
        for prefix in blacklisted_prefixes:
            f.write('{}\n'.format(prefix))

    print('Flushing blackhole routes out ...')
    for prefix in (set(blackhole_prefixes) - set(blacklisted_prefixes)):
        try:
            print('Removing blackhole route to {} ...'.format(prefix))
            # ip.route('del', dst=prefix, type='blackhole')
            os.system('/sbin/ip route del blackhole {}'.format(prefix))
        except:
            print('Error removing blackhole route for {}'.format(prefix))
            continue

    print('Installing new blackhole routes ...')
    for prefix in (set(blacklisted_prefixes) - set(blackhole_prefixes)):
        try:
            print('Adding blackhole route to {} ...'.format(prefix))
            # ip.route('add', dst=prefix, type='blackhole')
            os.system('/sbin/ip route add blackhole {}'.format(prefix))
        except:
            print('Error installing blackhole route for {}'.format(prefix))
            continue

    print('Done.')
