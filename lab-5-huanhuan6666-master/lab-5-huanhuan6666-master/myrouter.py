#!/usr/bin/env python3

'''
Basic IPv4 router (static routing) in Python.
'''

import time
import switchyard
from switchyard.lib.userlib import *
from switchyard.lib.address import *

class Router(object):
    def __init__(self, net: switchyard.llnetbase.LLNetBase):
        self.net = net
        self.arp_table = {} #the arp table
        self.myIPs = [intf.ipaddr for intf in self.net.interfaces()] # all IPs for each port in myrouter
        # other initialization stuff here
        #TODO: constract the forward_table
        self.wait_Queue = {} # the item is <nextHop : [time, send_counts, out_inft, arp_request, [packet, from_intf]] >
        self.fw_table = [] #constract the forward table
        for intf in self.net.interfaces():  #from the ports in router
            netaddr = IPv4Network(str(IPv4Address(int(intf.ipaddr) & int(intf.netmask))) + '/' + str(intf.netmask)) # get the netaddr
            self.fw_table.append([netaddr, intf.netmask, None, intf.name])
        for line in open("forwarding_table.txt"): #from the txt file
            item = line.split()
            item[0] = IPv4Network(item[0] + '/' + item[1])
            item[1] = IPv4Address(item[1])
            item[2] = IPv4Address(item[2])
            self.fw_table.append(item)
        self.fw_table.sort(key = lambda x:x[1], reverse = True) # the longest prefix in head
        for i in self.fw_table:
            print(i)
    
    def print_table(self):
        print('\033[1;35m=\033[0m'*18,'\033[1;32mARP_TABLE\033[0m','\033[1;35m=\033[0m'*18)
        print('|','\033[1;36mIP\033[0m'.center(31),'|','\033[1;36mMAC\033[0m'.center(31),'|')
        print("+" + "-" * 45 + "+")
        for ip,mac in self.arp_table.items():
            print('| {0} | {1} |'.format(str(ip).center(20), str(mac).center(20)))
            print("+" + "-" * 45 + "+")
        print('\033[1;35m=\033[0m'*47)

    def send_mypacket(self, packet, from_intf, normally = 0):
        ipv4 = packet.get_header(IPv4)
        for item in self.fw_table:
            if ipv4.dst in item[0]: # the dst addr is belong item's netaddr
                nextHop = item[2] if item[2] is not None else ipv4.dst
                out_intf = self.net.interface_by_name(item[3])
                if nextHop in self.arp_table.keys(): #nextHop is in arp_table,  send directly
                    print(f"\033[1;35mthe nextHop's IP:{nextHop} has been in arp_table\033[0m")
                    packet.get_header(Ethernet).src = out_intf.ethaddr
                    packet.get_header(Ethernet).dst = self.arp_table[nextHop]
                    if normally == 0:
                        packet.get_header(IPv4).src = out_intf.ipaddr
                    print(f"\033[1;35msend the packet in {out_intf}\033[0m")
                    self.net.send_packet(out_intf, packet) #send the new pkt in out intf
                else: #nextHop is not in arp_table, make ARP request for nextHop's IP
                    if  nextHop not in self.wait_Queue:
                        print(f"\033[1;35mthe nextHop's IP:{nextHop} is not in waitQueue\033[0m")
                        arp_request = create_ip_arp_request(out_intf.ethaddr, out_intf.ipaddr, nextHop)
                        self.net.send_packet(out_intf, arp_request)
                        self.wait_Queue[nextHop] = [time.time(), 1, out_intf, arp_request, [[packet, from_intf]]]
                        print(f"\033[1;36madd a nextHop's IP: {nextHop} in waitQueue\033[0m")
                    else: #nextHop is in wait queue, add the packet in the pkt queue
                        print(f"\033[1;35mthe nextHop's IP:{nextHop} has been in waitQueue\033[0m")
                        self.wait_Queue[nextHop][4].append([packet, from_intf])
                break #FUCK!!!    
    
    def make_ICMP(self, hwsrc, hwdst, ipsrc, ipdst, icmp_type, icmp_code, origpkt):
        ether = Ethernet()
        ether.src = EthAddr(hwsrc)
        ether.dst = EthAddr(hwdst)
        ether.ethertype = EtherType.IP

        ippkt = IPv4()
        ippkt.src = IPAddr(ipsrc)
        ippkt.dst = IPAddr(ipdst)
        ippkt.protocol = IPProtocol.ICMP
        ippkt.ttl = 64

        icmppkt = ICMP()
        icmppkt.icmptype = icmp_type
        icmppkt.icmpcode = icmp_code
    
        i = origpkt.get_header_index(Ethernet)
        del origpkt[i]
        icmppkt.icmpdata.data = origpkt.to_bytes()[:28]

        print(f"\033[1;36mconstruct a ICMP error packet\033[0m")
        return ether + ippkt + icmppkt

    def handle_packet(self, recv: switchyard.llnetbase.ReceivedPacket):
        timestamp, ifaceName, packet = recv
        log_info(f"received packet {packet} on {ifaceName}")
        from_intf = self.net.interface_by_name(ifaceName)
        if(packet.has_header(Arp)): #must be a ARP packet
            arp = packet.get_header(Arp) #get the arp header
            if arp.operation == ArpOperation.Request: # must be a request packet
                next_ip = arp.senderprotoaddr
                next_mac = arp.senderhwaddr
                print(f"\033[1;36mreceive a arp_request from the IP:{next_ip}\033[0m")
                self.arp_table[next_ip] = next_mac #add or update the arp_table
                self.print_table()
                if arp.targetprotoaddr in self.myIPs: #the dest's IP be in my ports
                    for intf in self.net.interfaces():
                        if intf.ipaddr == arp.targetprotoaddr:
                            intf_dest = intf #find the intf of the dest's IP
                            arp_reply = create_ip_arp_reply(intf_dest.ethaddr, arp.senderhwaddr, intf_dest.ipaddr, arp.senderprotoaddr)
                            self.net.send_packet(ifaceName, arp_reply) #construct the reply arp and send it by get's port
                #print(f"\033[1;31mthe waitQueue's keys: {self.wait_Queue.keys()}\033[0m")
                print(f"\033[1;31mthe waitQueue's keys: {self.wait_Queue.keys()}\033[0m")
                if next_ip in self.wait_Queue.keys(): #if this ip is waited
                    print(f"\033[1;36marp_request reply the waited nextHop's IP:{next_ip}\033[0m")
                    for wait_pkt, from_intf in self.wait_Queue[next_ip][4]: # release the packets which wait ip's(nextHop) MAC
                        eth_head = wait_pkt.get_header(Ethernet)
                        eth_head.dst = next_mac
                        eth_head.src =  self.wait_Queue[next_ip][2].ethaddr
                        next_packet = eth_head + wait_pkt.get_header(IPv4) + wait_pkt.get_header(ICMP)
                        self.net.send_packet(self.wait_Queue[next_ip][2],  next_packet)
                    self.wait_Queue.pop(next_ip) #delete this ip
            #TODO:add the content for arp_reply
            elif arp.operation == ArpOperation.Reply:
                next_ip = arp.senderprotoaddr
                next_mac = arp.senderhwaddr
                print(f"\033[1;36mreceive a arp_reply for the nextHop's IP:{next_ip}\033[0m")
                self.arp_table[next_ip] = next_mac
                #print(f"\033[1;31mthe waitQueue's keys: {self.wait_Queue.keys()}\033[0m")
                print(f"\033[1;31mthe waitQueue's keys: {self.wait_Queue.keys()}\033[0m")
                if next_ip in self.wait_Queue.keys(): #if this ip is waited
                    print(f"\033[1;36marp_reply reply the waited nextHop's IP:{next_ip}\033[0m")
                    for wait_pkt in self.wait_Queue[next_ip][4]: # release the packets which wait ip's(nextHop) MAC
                        wait_pkt[0].get_header(Ethernet).src = self.wait_Queue[next_ip][2].ethaddr
                        wait_pkt[0].get_header(Ethernet).dst = next_mac
                        print(f"\033[1;35msend the packet in {self.wait_Queue[next_ip][2]}\033[0m")
                        self.net.send_packet(self.wait_Queue[next_ip][2],  wait_pkt[0]) #send the new pkt in out intf
                    self.wait_Queue.pop(next_ip) #delete this ip
            #TODO: find in the fw_table and forward the IP pkt
        elif(packet[Ethernet].ethertype == EtherType.IPv4): #a IP packet
            eth_head  = packet.get_header(Ethernet)
            ipv4 = packet.get_header(IPv4)
            #ICMP_header = packet.get_header(ICMP)
            if ipv4.dst not in self.myIPs: # the dest is not in router
                normally = True
                in_fw_table = False
                for item in self.fw_table:
                    if ipv4.dst in item[0]:
                        in_fw_table = True
                if in_fw_table == False: #if dst's IP can't find in fw_table
                    normally = False
                    print(f"\033[1;36mthe dst's IP: {ipv4.dst} can't find in fw_table\033[0m")
                    my_packet = self.make_ICMP(eth_head.dst, eth_head.src, from_intf.ipaddr, ipv4.src, 
                                                                                ICMPType.DestinationUnreachable, 0,  packet)
                    print(f"\033[1;36msend a ICMP_error for the src:{ipv4.src}\033[0m")                                                            
                    self.send_mypacket(my_packet, from_intf)                                                            
                elif in_fw_table == True: #the dst's IP is not in router and the TTL is 0 
                    packet.get_header(IPv4).ttl -= 1
                    if packet.get_header(IPv4).ttl == 0:
                        normally = False
                        print(f"\033[1;36mthe packet's TTL is 0 and dst isnot router\033[0m")
                        my_packet = self.make_ICMP(eth_head.dst, eth_head.src, from_intf.ipaddr, ipv4.src,
                                                                                    ICMPType.TimeExceeded, 0, packet)
                        print(f"\033[1;36msend a ICMP_error for the src:{ipv4.src}\033[0m")                                                              
                        self.send_mypacket(my_packet, from_intf)
                if normally == True:
                    print(f"\033[1;36mreceive a normal packet and foward it normally\033[0m")
                    self.send_mypacket(packet, from_intf, normally = 1) #or foward the packet
            elif ipv4.dst in self.myIPs: #the dest is in router
                #print(type(ICMP_header))
                if packet.has_header(ICMP):
                    ICMP_header = packet.get_header(ICMP)
                    if  ICMP_header.icmptype == ICMPType.EchoRequest: #construct a ICMP echo reply
                        print(f"\033[1;36mreceive a echo_requst for port's IP: {ipv4.dst}\033[0m")
                        ICMPpkt = ICMP()
                        ICMPpkt.icmptype = ICMPType.EchoReply
                        ICMPpkt.icmpcode = ICMPCodeEchoReply.EchoReply
                        ICMPpkt.icmpdata.data = ICMP_header.icmpdata.data
                        ICMPpkt.icmpdata.sequence = ICMP_header.icmpdata.sequence
                        ICMPpkt.icmpdata.identifier = ICMP_header.icmpdata.identifier

                        IP_pkt = IPv4()
                        IP_pkt.protocol = IPProtocol.ICMP
                        IP_pkt.ttl = 64
                        IP_pkt.dst = ipv4.src
                        IP_pkt.src = ipv4.dst

                        eth_pkt = Ethernet()
                        eth_pkt.ethertype = EtherType.IPv4
                        eth_pkt.dst = eth_head.src
                        eth_pkt.src = eth_head.dst
                        my_packet = eth_pkt + IP_pkt + ICMPpkt
                        print(f"\033[1;36msend a ICMP_reply for the src:{IP_pkt.dst}\033[0m")
                        self.send_mypacket(my_packet, from_intf, normally = 1)
                else: #is not ICMP request
                        print(f"\033[1;36mthe packet for router isnot ICMP_request\033[0m")
                        my_packet = self.make_ICMP(eth_head.dst, eth_head.src, from_intf.ipaddr, ipv4.src, 
                                                                                ICMPType.DestinationUnreachable, 3,  packet)
                        print(f"\033[1;36msend a ICMP_error for the src:{ipv4.src}\033[0m")                                                          
                        self.send_mypacket(my_packet, from_intf)
                    

    def start(self):
        '''A running daemon of the router.
        Receive packets until the end of time.
        '''
        while True:
            #TODO: update the wait_Queue
            for nextHop in list(self.wait_Queue):
                if(time.time() - self.wait_Queue[nextHop][0] > 1): #this arp_request wait for longer than 1s
                    print(f"\033[1;36mrepeat a arp_request for nextHop's IP:{nextHop} because of timeout\033[0m")
                    send_counts = self.wait_Queue[nextHop][1]
                    if(send_counts <= 4):#repeat again
                        self.net.send_packet(self.wait_Queue[nextHop][2], self.wait_Queue[nextHop][3]) 
                        self.wait_Queue[nextHop][0] = time.time()
                        self.wait_Queue[nextHop][1] = send_counts + 1
                    else: #ARP failure, construct a ICMP error
                        print(f"\033[1;36ma ARP failure for nextHop's IP:{nextHop}\033[0m")
                        have_done = []
                        for wait_pkt, from_intf in self.wait_Queue[nextHop][4]: # release the packets which wait ip's(nextHop) MAC
                            eth_head = wait_pkt.get_header(Ethernet)
                            ipv4 = wait_pkt.get_header(IPv4)
                            if ipv4.src not in have_done:
                                my_packet = self.make_ICMP(from_intf.ethaddr, eth_head.src, from_intf.ipaddr, ipv4.src, 
                                                                                        ICMPType.DestinationUnreachable, 1,  wait_pkt)
                                self.send_mypacket(my_packet, from_intf)
                                have_done.append(ipv4.src)
                        self.wait_Queue.pop(nextHop) #delete this ip

            try:
                recv = self.net.recv_packet(timeout=1.0)
            except NoPackets:
                continue
            except Shutdown:
                break
            
            self.handle_packet(recv)

        self.stop()

    def stop(self):
        self.net.shutdown()


def main(net):
    '''
    Main entry point for router.  Just create Router
    object and get it going.
    '''
    router = Router(net)
    router.start()