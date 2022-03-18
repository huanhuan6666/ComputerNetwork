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
        self.wait_Queue = {} # the item is <nextHop : [time, send_counts, out_inft, arp_request, [packet]] >
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

    def handle_packet(self, recv: switchyard.llnetbase.ReceivedPacket):
        timestamp, ifaceName, packet = recv
        log_info(f"received packet {packet} on {ifaceName}")
        if(packet.has_header(Arp)): #must be a ARP packet
            arp = packet.get_header(Arp) #get the arp header
            if arp.operation == ArpOperation.Request: # must be a request packet
                self.arp_table[arp.senderprotoaddr] = arp.senderhwaddr #add or update the arp_table
                if arp.targetprotoaddr in self.myIPs: #the dest's IP be in my ports
                    for intf in self.net.interfaces():
                        if intf.ipaddr == arp.targetprotoaddr:
                            intf_dest = intf #find the intf of the dest's IP
                            arp_reply = create_ip_arp_reply(intf_dest.ethaddr, arp.senderhwaddr, intf_dest.ipaddr, arp.senderprotoaddr)
                            self.net.send_packet(ifaceName, arp_reply) #construct the reply arp and send it by get's port
                self.print_table()
            #TODO:add the content for arp_reply
            elif arp.operation == ArpOperation.Reply:
                next_ip = arp.senderprotoaddr
                next_mac = arp.senderhwaddr
                print(f"\033[1;36mreceive a arp_reply for the nextHop's IP:{next_ip}\033[0m")
                self.arp_table[next_ip] = next_mac
                print(f"\033[1;31mthe waitQueue's keys: {self.wait_Queue.keys()}\033[0m")
                if next_ip in self.wait_Queue.keys(): #if this ip is waited
                    print(f"\033[1;36marp_reply reply the waited nextHop's IP:{next_ip}\033[0m")
                    for wait_pkt in self.wait_Queue[next_ip][4]: # release the packets which wait ip's(nextHop) MAC
                        eth_head = wait_pkt.get_header(Ethernet)
                        eth_head.dst = next_mac
                        eth_head.src =  self.wait_Queue[next_ip][2].ethaddr
                        next_packet = eth_head + wait_pkt.get_header(IPv4) + wait_pkt.get_header(ICMP)
                        self.net.send_packet(self.wait_Queue[next_ip][2],  next_packet)
                    self.wait_Queue.pop(next_ip) #delete this ip
            #TODO: find in the fw_table and forward the IP pkt
        elif(packet.has_header(IPv4)): #a IP packet
            packet.get_header(IPv4).ttl -= 1
            ipv4 = packet.get_header(IPv4)
            if ipv4.dst not in self.myIPs: # the dest is not in router
                for item in self.fw_table:
                    if ipv4.dst in item[0]: # the dst addr is belong item's netaddr
                        nextHop = item[2] if item[2] is not None else ipv4.dst
                        out_intf = self.net.interface_by_name(item[3])
                        if nextHop in self.arp_table.keys(): #nextHop is in arp_table,  send directly
                            print(f"\033[1;35mthe nextHop's IP:{nextHop} has been in arp_table\033[0m")
                            eth_head = packet.get_header(Ethernet) # modify the ethernet head
                            eth_head.src = out_intf.ethaddr
                            eth_head.dst = self.arp_table[nextHop] # use the arp_table here
                            next_packet = eth_head + ipv4 + packet.get_header(ICMP)
                            self.net.send_packet(out_intf, next_packet) #send the new pkt in out intf
                        else: #nextHop is not in arp_table, make ARP request for nextHop's IP
                            if  nextHop not in self.wait_Queue:
                                print(f"\033[1;35mthe nextHop's IP:{nextHop} is not in waitQueue\033[0m")
                                arp_request = create_ip_arp_request(out_intf.ethaddr, out_intf.ipaddr, nextHop)
                                self.net.send_packet(out_intf, arp_request)
                                self.wait_Queue[nextHop] = [time.time(), 1, out_intf, arp_request, [packet]]
                                print(f"\033[1;36madd a nextHop's IP: {nextHop} in waitQueue\033[0m")
                            else: #nextHop is in wait queue, add the packet in the pkt queue
                                print(f"\033[1;35mthe nextHop's IP:{nextHop} has been in waitQueue\033[0m")
                                self.wait_Queue[nextHop][4].append(packet)
                        break #FUCK!!!    
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
                    else: #send_counts more 5
                        self.wait_Queue.pop(nextHop)
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
