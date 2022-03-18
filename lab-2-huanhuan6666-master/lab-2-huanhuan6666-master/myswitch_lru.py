'''
Ethernet learning switch in Python.

Note that this file currently has the code to implement a "hub"
in it, not a learning switch.  (I.e., it's currently a switch
that doesn't learn.)
'''
import switchyard
from collections import deque
from switchyard.lib.userlib import *


def main(net: switchyard.llnetbase.LLNetBase):
    my_interfaces = net.interfaces()
    mymacs = [intf.ethaddr for intf in my_interfaces]
    mytable = deque(maxlen= 5 ) #TO DO: the item is  [MAC, port]
    while True:
        try:
            _, fromIface, packet = net.recv_packet()
        except NoPackets:
            continue
        except Shutdown:
            break
        log_debug (f"In {net.name} received packet {packet} on {fromIface}")
        eth = packet.get_header(Ethernet)
        #learn or update the table
        be_in  = False
        for i, item in enumerate(mytable):
                if item[0] == eth.src: # if in, only update the item
                        mytable[i] = [eth.src, fromIface]
                        be_in = True
        if be_in == False: # if not in, add it in table and make it MRU
            mytable.append([eth.src, fromIface])

        if eth is None:
            log_info("Received a non-Ethernet packet?!")
            return
        if eth.dst in mymacs:
            log_info("Received a packet intended for me")
        else:
            Find = False
            for item in list(mytable):# find the dst's mac in table
                if  item[0] == eth.dst:
                    Find = True # if find, send it directly and make the item MRU
                    log_info(f"(in table)send packet {packet} to {item[1]}")
                    net.send_packet(item[1],  packet)
                    mytable.remove(item)
                    mytable.append(item)
            if Find == False:
                for intf in my_interfaces:
                    if fromIface!= intf.name:
                        log_info (f"Flooding packet {packet} to {intf.name}")
                        net.send_packet(intf, packet)
        #print('\033[1;35m=================== \033[0m')
        #print('\033[1;32m>>>\033[0m' , mytable)
        #print('\033[1;35m=================== \033[0m')
    net.shutdown()
