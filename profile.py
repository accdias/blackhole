import cProfile
import netaddr
import ipaddr
import ipaddress

f = open('ip.txt', 'r')
a = f.read().splitlines()
f.close()

a = map(unicode, a)

x = map(netaddr.IPNetwork, a)
y = map(ipaddr.IPNetwork, a)
z = map(ipaddress.ip_network, a)

print('netaddr.cidr_merge(x)')
cProfile.run('xx=netaddr.cidr_merge(x)')

print('ipaddr.collapse_address_list(y)')
cProfile.run('yy=ipaddr.collapse_address_list(y)')

print('ipaddress.collapse_addresses(z)')
cProfile.run('zz=ipaddress.collapse_addresses(z)')

print('len(xx) = ', len(set(xx)))
print('len(yy) = ', len(set(yy)))
print('len(zz) = ', len(set(zz)))
