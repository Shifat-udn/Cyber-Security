import nmap
nm = nmap.PortScanner()
nm.scan('10.0.0.200', '19-900')

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
            print ('port : %s\tstate : %s product : %s\- : %s\t' % (port, nm[host][proto][port]['state'], nm[host][proto][port]['product'], nm[host][proto][port]['version']))
