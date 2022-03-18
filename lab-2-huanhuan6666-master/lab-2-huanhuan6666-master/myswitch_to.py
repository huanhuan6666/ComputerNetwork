'''
Ethernet learning switch in Python.

Note that this file currently has the code to implement a "hub"
in it, not a learning switch.  (I.e., it's currently a switch
that doesn't learn.)
'''
import switchyard
import time
from switchyard.lib.userlib import *


def main(net: switchyard.llnetbase.LLNetBase):
    my_interfaces = net.interfaces()
    mymacs = [intf.ethaddr for intf in my_interfaces]
    mytable = {} #TO DO: create the table,the item is <MAC:[port, time]>
    while True:
        #TO DO: remove the outdata items
        for key in list(mytable):
            if time.time() - mytable[key][1] > 10:
                mytable.pop(key)
                #log_info(f"REMOVE: {key} in mytable")
        try:
            _, fromIface, packet = net.recv_packet()
        except NoPackets:
            continue
        except Shutdown:
            break

        log_debug (f"In {net.name} received packet {packet} on {fromIface}")
        eth = packet.get_header(Ethernet)
       #TO DO: learn the <src's MAC's  : [port, time]>, if have been in table, update it's time
        mytable[eth.src] = [fromIface, time.time()]
        
        if eth is None:
            log_info("Received a non-Ethernet packet?!")
            return
        if eth.dst in mymacs:
            log_info("Received a packet intended for me")
        else:
            if eth.dst in mytable.keys():#TO DO:if the MAC's address is in table, send it directly
                log_info(f"(in table)send packet {packet} to {mytable[eth.dst][0]}")
                net.send_packet(mytable[eth.dst][0],  packet)
            else:#broadcast the packet
                for intf in my_interfaces:
                    if fromIface!= intf.name:
                        log_info (f"Flooding packet {packet} to {intf.name}")
                        net.send_packet(intf, packet)

    net.shutdown()
