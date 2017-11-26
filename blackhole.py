#!/usr/bin/env python
import os
import sys
import re
import shutil # for shutil.copy()
import netaddr # yum/dnf install -y python-netaddr python3-netaddr

if not os.geteuid() == 0:
    sys.exit('Script must be run as root')

blacklist_file = '/etc/spamdyke/blacklist.d/ip'
blacklist_file_backup = '%s.backup' % blacklist_file

logfiles = (
    '/var/log/maillog',
    '/var/log/vsftpd.log',
    '/var/log/secure'
)

whitelisted_prefixes = (
    '0.',
    '10.',
    '127.',
    '169.254',
    '172.16.',
    '172.17.',
    '172.18.',
    '172.19.',
    '172.20.',
    '172.21.',
    '172.22.',
    '172.23.',
    '172.24.',
    '172.25.',
    '172.26.',
    '172.27.',
    '172.28.',
    '172.29.',
    '172.30.',
    '172.31.',
    '192.168.',
    '255.255.255.255'
)

blacklisted_prefixes = []

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

def is_whitelisted(ip=''):
    return ip.startswith(whitelisted_prefixes) and True or False


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
        prefix = "%s/%s" % (ip, 32)
        if is_whitelisted(ip):
            print 'Ignoring whitelisted address: %s' % ip
        elif not prefix in blacklisted_prefixes:
            print 'Blacklisting address: %s' % prefix
            blacklisted_prefixes.append(prefix)

print 'Processing %s ... ' % blacklist_file
f = open(blacklist_file)
for line in f:
    line = line.strip()
    if not (is_comment_regex.match(line) or is_blank_regex.match(line)):
        if '/' in line:
            prefix = line
        else:
            prefix = "%s/%s" % (line, 32)

        if not prefix in blacklisted_prefixes:
            blacklisted_prefixes.append(prefix)
f.close()

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
print 'Copying %s to %s ...' % (blacklist_file, blacklist_file_backup)
shutil.copy(blacklist_file, blacklist_file_backup)

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
