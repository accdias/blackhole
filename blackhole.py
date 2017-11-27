#!/usr/bin/env python
import os
import sys
import re
import shutil # for shutil.copy()
import netaddr # yum/dnf install -y python-netaddr python3-netaddr

if not os.geteuid() == 0:
    sys.exit('Script must be run as root')

blacklist_file = '/etc/spamdyke/blacklist.d/ip'
whitelist_file = '/etc/spamdyke/whitelist.d/ip'

backup_suffix = 'backup'

whitelisted_prefixes = []
blacklisted_prefixes = []

logfiles = (
    '/var/log/maillog',
    '/var/log/vsftpd.log',
    '/var/log/secure'
)

smtp_login_fail_string = 'vchkpw-smtp: password fail'
imap_login_fail_string = 'dovecot: imap-login: Disconnected (auth failed'
ftpd_login_fail_string = 'FAIL LOGIN: Client'
sshd_login_fail_string = 'Failed password for invalid user'

# Use findall() method to return IPv4 addresses found in a string
extract_ip_addresses_regex = re.compile(r'[0-9]+(?:\.[0-9]+){3}')

# Match lines starting with comments markers
is_comment_regex = re.compile(r'^\s*[#;].*$')

# Match empty lines
is_blank_regex = re.compile(r'^\s*$')

def is_whitelisted(ip=netaddr.IPNetwork('127.0.0.1/8')):
    if ip.is_loopback() or ip.is_multicast() or ip.is_private():
        return True
    for prefix in whitelisted_prefixes:
        if ip.ip in netaddr.IPNetwork(prefix):
            return True
    return False


def check_log_line(line):
    ip = ''
    s  = line.strip()

    if smtp_login_fail_string in s:
        # Jan 12 12:34:56 hostname vpopmail[1234]: vchkpw-smtp: password fail (pass: 'xxxxxxxxxx') user@example.com:203.0.113.1
        ip = extract_ip_addresses_regex.findall(s)[0]
    elif imap_login_fail_string in line:
        # Jan 12 12:34:56 hostname dovecot: imap-login: Disconnected (auth failed, 1 attempts): user=<user@example.com>, method=PLAIN, rip=203.0.113.1, lip=192.168.1.1
        ip = extract_ip_addresses_regex.findall(s)[0]
    elif ftpd_login_fail_string in line:
        # Sun Jan 12 12:34:56 2017 [pid 1234] [username] FAIL LOGIN: Client '203.0.113.1'
        ip = extract_ip_addresses_regex.findall(s)[0]
    elif sshd_login_fail_string in line:
        # Jan 12 12:34:56 hostname sshd[1234]: Failed password for invalid user username from 203.0.113.1 12345 ssh2
        ip = extract_ip_addresses_regex.findall(s)[0]

    if ip:
        if is_whitelisted(netaddr.IPNetwork(ip)):
            print 'Ignoring whitelisted address: %s' % ip
        elif not ip in blacklisted_prefixes:
            print 'Blacklisting address: %s' % ip
            blacklisted_prefixes.append(ip)


def read_file_into_array(filename, array):
    print 'Reading %s ... ' % filename
    f = open(filename)
    for line in f:
        line = line.strip()
        if not (is_comment_regex.match(line) or is_blank_regex.match(line)):
            if not line in array:
                array.append(line)
    f.close()


read_file_into_array(whitelist_file, whitelisted_prefixes)

read_file_into_array(blacklist_file, blacklisted_prefixes)

for logfile in logfiles:
    print 'Processing %s ... ' % logfile
    try:
       f = open(logfile)
       for line in f:
           check_log_line(line)
       f.close()
    except:
        print "Error opening %s ..." % logfile

# summarize and sort the blacklisted_prefixes array
blacklisted_prefixes = netaddr.cidr_merge(blacklisted_prefixes)

# backup the old blacklist file
print 'Copying %s to %s.%s ...' % (blacklist_file, blacklist_file, backup_suffix)
shutil.copy(blacklist_file, '%s.%s' % (blacklist_file, backup_suffix))

# save the new blacklist file
print 'Saving blacklist to %s ...' % blacklist_file
f = open(blacklist_file, 'wb')
for prefix in blacklisted_prefixes:
    # spamdyke doesn't like /32 address
    if prefix.prefixlen == 32:
        f.write('%s\n' % prefix.network)
    else:
        f.write('%s/%s\n' % (prefix.network, prefix.prefixlen))
f.close()

print 'Flushing blackhole routes out...'
try:
    os.system('/sbin/ip route flush type blackhole')
except:
    print 'Error flushing blackhole routes out ...'

print 'Installing new blackhole routes ...'
for prefix in blacklisted_prefixes:
    try:
        os.system('/sbin/ip route add blackhole %s' % prefix.cidr)
    except:
        print 'Error installing blackhole route for %s' % prefix.cidr
        continue

print 'Done.'
