#!/usr/bin/env python3
import optparse
import socket
import nmap3
import os
from scapy.all import *

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
        # create a socket called sock
        sock = socket.socket()
        # use the user input target host and port
        sock.connect((target_host, target_port))

        print('TCP connection established at port %d' % target_port)
        sock.close()
    except Exception as e:
        # print (e)
        print('[Error] No TCP connection established')

        
def udp_scan(dst_ip,dst_port):
    udp_scan_resp = sr1(IP(dst=dst_ip)/UDP(dport=dst_port),timeout=10)
    if (str(type(udp_scan_resp))=="<type 'NoneType'>"):
        retrans = []
        for count in range(0,3):
            retrans.append(sr1(IP(dst=dst_ip)/UDP(dport=dst_port),timeout=dst_timeout))
        for item in retrans:
            if (str(type(item))!="<type 'NoneType'>"):
                udp_scan(dst_ip,dst_port,10)
        return "Open|Filtered"
    elif (udp_scan_resp.haslayer(UDP)):
        return "Open"
    elif(udp_scan_resp.haslayer(ICMP)):
        if(int(udp_scan_resp.getlayer(ICMP).type)==3 and int(udp_scan_resp.getlayer(ICMP).code)==3):
            return "Closed"
        elif(int(udp_scan_resp.getlayer(ICMP).type)==3 and int(udp_scan_resp.getlayer(ICMP).code) in [1,2,9,10,13]):
            return "Filtered"
    else:
        return "CHECK"

# def udp_scan(target_host, target_port):
#     try:

#         res = os.system("nc -vnzu "+target_host+target_port+" > /dev/null 2>&1")
#         if res == 0:
#             print("port alive")
#         else:
#             print("port dead")
#         # udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
#         # udp_sock.sendto(b'PING', (target_host,target_port))
#         # data, addr = udp_sock.recvfrom(1024)

#         # print('UDP connection established at port %d' % target_port)
#         # print(data,addr)
#         #udp_sock.close()
#     except Exception as e:
#         print (e)
#         print('[Error] No UDP connection established')

    

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