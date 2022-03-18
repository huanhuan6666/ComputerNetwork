'''
Ethernet learning switch in Python.

Note that this file currently has the code to implement a "hub"
in it, not a learning switch.  (I.e., it's currently a switch
that doesn't learn.)
'''
import switchyard
from switchyard.lib.userlib import *


def main(net: switchyard.llnetbase.LLNetBase):
    my_interfaces = net.interfaces()
    mymacs = [intf.ethaddr for intf in my_interfaces]
    mytable = {} # the item is <MAC: [port, traffic]>
    while True:
        try:
            _, fromIface, packet = net.recv_packet()
        except NoPackets:
            continue
        except Shutdown:
            break
        #print('\033[1;35m=================== \033[0m')
        #print('\033[1;32m>>>\033[0m' , mytable)
        #print('\033[1;35m=================== \033[0m')
        log_debug (f"In {net.name} received packet {packet} on {fromIface}")
        eth = packet.get_header(Ethernet)
        if eth.src in mytable:#if src's MAC is in table
            mytable[eth.src][0] = fromIface #keep the  same traffic volume count for the host
        else:# if not in table
            if len(mytable) < 5: #table is not full, add it directly with traffic_volume 0
                mytable[eth.src] = [fromIface, 0]
            else: #table is full
                least  = float('inf')
                for key in list(mytable):
                    if mytable[key][1] < least:
                        least = mytable[key][1]
                        rm_key = key #get the key whose traffic is least and remove it
                mytable.pop(rm_key)
                mytable[eth.src] = [fromIface, 0]

        if eth is None:
            log_info("Received a non-Ethernet packet?!")
            return
        if eth.dst in mymacs:
            log_info("Received a packet intended for me")
        else:
            if eth.dst in mytable:#if dst is in table, send it directly and traffic_volume++
                mytable[eth.dst][1] += 1
                log_info(f"(in table)send packet {packet} to {mytable[eth.dst][0]}")
                net.send_packet(mytable[eth.dst][0],  packet)
            else:#broadcast
                for intf in my_interfaces:
                    if fromIface!= intf.name:
                        log_info (f"Flooding packet {packet} to {intf.name}")
                        net.send_packet(intf, packet)

    net.shutdown()
