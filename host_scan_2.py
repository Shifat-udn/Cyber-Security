import nmap
nm = nmap.PortScanner()
#import nmap
#nm = nmap.PortScanner()
nm.scan(hosts='10.0.0.200/32', arguments='-p1-1000 -sS -sV -D 202.65.11.1,99.79.18.26', sudo=True)

for host in nm.all_hosts():
    print('----------------------------------------------------')
    print('Host : %s (%s)' % (host, nm[host].hostname()))
    print('State : %s' % nm[host].state())
    for proto in nm[host].all_protocols():
        print('----------')
        print('Protocol : %s' % proto)
        lport = nm[host][proto].keys()
        #lport.sort()
        for port in lport:
            print ('port : %s\tstate : %s product : %s ver- : %s\t' % (port, nm[host][proto][port]['state'], nm[host][proto][port]['product'], nm[host][proto][port]['version']))
