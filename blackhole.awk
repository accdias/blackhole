#!/usr/bin/gawk -f
BEGIN {
	FS = ":"
	blacklist = "/etc/spamdyke/blacklist.d/ip"
	blacklist_backup = blacklist ".backup"
	maillog = "/var/log/maillog"
	ipv4_regex = "([0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3})"

	whitelist_ips["10."] = 1
	whitelist_ips["127."] = 1
	whitelist_ips["172.16."] = 1
	whitelist_ips["172.17."] = 1
	whitelist_ips["172.18."] = 1
	whitelist_ips["172.19."] = 1
	whitelist_ips["172.20."] = 1
	whitelist_ips["172.21."] = 1
	whitelist_ips["172.22."] = 1
	whitelist_ips["172.23."] = 1
	whitelist_ips["172.24."] = 1
	whitelist_ips["172.25."] = 1
	whitelist_ips["172.26."] = 1
	whitelist_ips["172.27."] = 1
	whitelist_ips["172.28."] = 1
	whitelist_ips["172.29."] = 1
	whitelist_ips["172.30."] = 1
	whitelist_ips["172.31."] = 1
	whitelist_ips["192.168."] = 1
	whitelist_ips["200.153.43."] = 1
	whitelist_ips["201.28.58."] = 1

	print "Reading files and building lists..."

	while ((getline <blacklist) > 0) {
		if (/^[[:space:]]*$/) continue
		blacklist_ips[$1] = 1
	}
	close(blacklist)

	while ((getline <maillog) > 0) {
        if (/vchkpw-smtp: password fail/) {
			if (/^[[:space:]]*$/) continue
			maillog_ips[$7] = 1
		}
	}
	close(maillog)

	print "Checking " blacklist
	print "Saving old blacklist to " blacklist_backup
	print ""> blacklist_backup
	for (ip in blacklist_ips) {
		print ip >> blacklist_backup
		for (white_ip in whitelist_ips) {
			if (index(ip, white_ip) == 1) {
				print "Removing local IP " ip " from " blacklist
				delete blacklist_ips[ip]
			}
		}
	}
	fflush(blacklist_backup)
	close(blacklist_backup)

	print "Checking " maillog
	for (ip in maillog_ips) {
		for (white_ip in whitelist_ips) {
			if (index(ip, white_ip) == 1) {
				print "Ignoring local IP " ip " from " maillog
				delete maillog_ips[ip]
			}
		}
	}

	print "Building new blacklist"
	for (ip in maillog_ips) {
		if (blacklist_ips[ip] != 1) {
			print "Blacklisting new entry: "  ip
			blacklist_ips[ip] = 1
		}
	}

	print "Flushing blackhole routes out..."
	system("/sbin/ip route flush type blackhole 2&1>/dev/null")

	print "Saving new blacklist to " blacklist
	print ""> blacklist
	for (ip in blacklist_ips) {
		print ip >> blacklist
		system("/sbin/ip route add blackhole " ip " 2&1>/dev/null")
	}
	fflush(blacklist)
	close(blacklist)
}
