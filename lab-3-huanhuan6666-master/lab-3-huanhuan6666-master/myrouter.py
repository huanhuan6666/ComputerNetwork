#!/usr/bin/env python3

'''
Basic IPv4 router (static routing) in Python.
'''

import time
import switchyard
from switchyard.lib.userlib import *


class Router(object):
    def __init__(self, net: switchyard.llnetbase.LLNetBase):
        self.net = net
        self.arp_table = {} #the arp table
        self.myIPs = [intf.ipaddr for intf in self.net.interfaces()] # all IPs for each port in myrouter
        # other initialization stuff here

    def print_table(self):
        print('\033[1;35m=\033[0m'*18,'\033[1;32mARP_TABLE\033[0m','\033[1;35m=\033[0m'*18)
        print('|','\033[1;36mIP\033[0m'.center(31),'|','\033[1;36mMAC\033[0m'.center(31),'|')
        print("+" + "-" * 45 + "+")
        for ip,mac in self.arp_table.items():
            #print('| {0} | {1} |'.format(str(ip).center(20), str(mac[0]).center(20)))
            print('| {0} | {1} |'.format(str(ip).center(20), str(mac).center(20)))
            print("+" + "-" * 45 + "+")
        print('\033[1;35m=\033[0m'*47)

    def handle_packet(self, recv: switchyard.llnetbase.ReceivedPacket):
        timestamp, ifaceName, packet = recv
        # TODO: your logic here
        #for key in list(self.arp_table):  #remove the out time items
        #    if time.time() - self.arp_table[key][1] > 30:
        #        log_info(f"remove item {key}:{self.arp_table[key]}")
        #        self.arp_table.pop(key)
        log_info(f"received packet {packet} on {ifaceName}")
        if(packet.has_header(Arp)): #must be a ARP packet
            arp = packet.get_header(Arp) #get the arp header
            if arp.operation == ArpOperation.Request: # must be a request packet
                self.arp_table[arp.senderprotoaddr] = arp.senderhwaddr #add or update the arp_table
                #self.arp_table[arp.senderprotoaddr] = [arp.senderhwaddr, time.time()]
                if arp.targetprotoaddr in self.myIPs: #the dest's IP be in my ports
                    for intf in self.net.interfaces():
                        if intf.ipaddr == arp.targetprotoaddr:
                            intf_dest = intf #find the intf of the dest's IP
                            arp_reply = create_ip_arp_reply(intf_dest.ethaddr, arp.senderhwaddr, intf_dest.ipaddr, arp.senderprotoaddr)
                            self.net.send_packet(ifaceName, arp_reply) #construct the reply arp and send it by get's port
                self.print_table()

    def start(self):
        '''A running daemon of the router.
        Receive packets until the end of time.
        '''
        while True:
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
