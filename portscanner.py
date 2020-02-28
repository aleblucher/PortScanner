#!/usr/bin/env python3
import optparse
import socket
import nmap

def port_scan(target_host, target_ports, protocol):
    target_ip = socket.gethostbyname(target_host)

    try:
        target_name = socket.gethostbyaddr(target_ip)
        print ('\nScanning host: ' + target_name[0])
    except:
        print ('\nScanning host: ' + target_ip)
    socket.setdefaulttimeout(10)

    for tg in target_ports:
        print ('\nAt port:' + tg)
        if protocol == "tcp":
            tcp_scan(target_host, int(tg))
        elif protocol == "udp":
            udp_scan(target_host, tg)
        else:
            print("\nProtocol not recognized. Please try again.")
        

def tcp_scan(target_host, target_port):
    try:
        sock = socket.socket()
        sock.connect((target_host, target_port))

        print('TCP connection established at port %d' % target_port)
        sock.close()
    except Exception as e:
        print (e)
        print('[Error] No TCP connection established')

        
def udp_scan(target, port):
    nm = nmap.PortScanner()
    try:
        nm.scan(hosts=target, ports=str(port), arguments='-Pn -sU ', sudo=True)
        print(nm['scan'][target])
        print("\n Port State:")
        print(nm['udp'][port]['state'])
    except Exception as err:
        print(err)
        return None 
    

def main():
    parser = optparse.OptionParser('usage %prog –H'+\
        '<target host> -p <target port> -P <protocol> ')
    parser.add_option('-H', dest='target_host', type='string', \
        help='Write proper targer host')
    parser.add_option('-p', dest='target_ports', type='string', \
        help='Write proper target ports separeted by comma')
    parser.add_option('-P', dest='protocol', type='string', \
        help='Write the protocol tcp or udp')

    options, args = parser.parse_args()
    target_host = options.target_host
    # write in read me that ports must be split with ','
    target_ports = options.target_ports.strip().split(',') 
    protocol = options.protocol.lower()

    if (target_host == None) or (target_ports == None):
        exit(0)

    port_scan(target_host, target_ports, protocol)


if __name__ == '__main__':
    main()