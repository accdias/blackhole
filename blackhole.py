#!/usr/bin/env python
import os
import sys
import re
import shutil # for shutil.copy()
import netaddr # yum/dnf install -y python-netaddr python3-netaddr

smtp_login_fail_string = 'vchkpw-smtp: password fail'
imap_login_fail_string = 'dovecot: imap-login: Disconnected (auth failed'
ftpd_login_fail_string = 'FAIL LOGIN: Client'
sshd_login_fail_string = 'Failed password for invalid user'
spam_trap_admin_string = 'vchkpw-smtp: vpopmail user not found admin@'
spam_trap_info_string = 'vchkpw-smtp: vpopmail user not found info@'


# Use findall() method to return IPv4 addresses found in a string
extract_ip_addresses_regex = re.compile(r'[0-9]+(?:\.[0-9]+){3}')

# Match lines starting with comments markers
is_comment_regex = re.compile(r'^\s*[#;].*$')

# Match empty lines
is_blank_regex = re.compile(r'^\s*$')


def is_whitelisted(ip):
    if ip.is_loopback() or ip.is_multicast() or ip.is_private():
        return True
    for prefix in whitelisted_prefixes:
        if ip in prefix:
            return True
    return False


def is_blacklisted(ip):
    for prefix in blacklisted_prefixes:
        if ip in prefix:
            return True
    return False


def check_log_line(line):
    line = line.strip()

    if smtp_login_fail_string in line:
        # Jan 12 12:34:56 hostname vpopmail[1234]: vchkpw-smtp: password fail (pass: 'xxxxxxxxxx') user@example.com:203.0.113.1
        prefix = extract_ip_addresses_regex.findall(line)[0]
    elif spam_trap_admin_string in line:
        # Jan 12 12:34:56 hostname vpopmail[1234]: vchkpw-smtp: vpopmail user not found admin@example.com:203.0.113.1
        prefix = extract_ip_addresses_regex.findall(line)[0]
    elif spam_trap_admin_string in line:
        # Jan 12 12:34:56 hostname vpopmail[1234]: vchkpw-smtp: vpopmail user not found info@example.com:203.0.113.1
        prefix = extract_ip_addresses_regex.findall(line)[0]
    elif imap_login_fail_string in line:
        # Jan 12 12:34:56 hostname dovecot: imap-login: Disconnected (auth failed, 1 attempts): user=<user@example.com>, method=PLAIN, rip=203.0.113.1, lip=192.168.1.1
        prefix = extract_ip_addresses_regex.findall(line)[0]
    elif ftpd_login_fail_string in line:
        # Sun Jan 12 12:34:56 2017 [pid 1234] [username] FAIL LOGIN: Client '203.0.113.1'
        prefix = extract_ip_addresses_regex.findall(line)[0]
    elif sshd_login_fail_string in line:
        # Jan 12 12:34:56 hostname sshd[1234]: Failed password for invalid user username from 203.0.113.1 12345 ssh2
        prefix = extract_ip_addresses_regex.findall(line)[0]
    else:
        prefix = ''

    if prefix:
        if is_whitelisted(netaddr.IPAddress(prefix)):
            print 'Ignoring whitelisted address: %s' % prefix
        elif not is_blacklisted(netaddr.IPAddress(prefix):
            print 'Blacklisting address: %s' % prefix
            blacklisted_prefixes.append(netaddr.IPNetwork(prefix))


def file_to_array(filename):
    try:
        print 'Reading %s ... ' % filename
        f = open(filename)
    except:
        print "Error opening %s" % filename

    array = []
    for line in f:
        line = line.strip()
        if not (is_comment_regex.match(line) or is_blank_regex.match(line) or line in array):
            array.append(line)
    f.close()
    return netaddr.cird_merge(array)


if __name__ == '__main__':
    os.geteuid() == 0 or sys.exit('Script must be run as root')

    blacklist_file = '/etc/spamdyke/blacklist.d/ip'
    whitelist_file = '/etc/spamdyke/whitelist.d/ip'
    backup_suffix = 'backup'

    logfiles = (
        '/var/log/maillog',
        '/var/log/vsftpd.log',
        '/var/log/secure'
    )

    whitelisted_prefixes = file_to_array(whitelist_file)
    blacklisted_prefixes = file_to_array(blacklist_file)

    for logfile in logfiles:
        print 'Processing %s ... ' % logfile
        try:
            f = open(logfile)
        except:
            print "Error opening %s ..." % logfile

        for line in f:
            check_log_line(line)
        f.close()

    # summarize and sort the blacklisted_prefixes array
    blacklisted_prefixes = netaddr.cidr_merge(blacklisted_prefixes)

    # backup the old blacklist file
    print 'Copying %s to %s.%s ...' % (blacklist_file, blacklist_file, backup_suffix)
    shutil.copy(blacklist_file, '%s.%s' % (blacklist_file, backup_suffix))

    # save the new blacklist file
    print 'Saving blacklist to %s ...' % blacklist_file
    f = open(blacklist_file, 'wb')
    for prefix in blacklisted_prefixes:
        f.write('%s\n' % prefix)
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

    print 'Done.'
