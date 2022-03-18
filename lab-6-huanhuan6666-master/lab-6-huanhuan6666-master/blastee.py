#!/usr/bin/env python3

import time
import threading
from struct import pack
import switchyard
from switchyard.lib.address import *
from switchyard.lib.packet import *
from switchyard.lib.userlib import *


class Blastee:
    def __init__(
            self,
            net: switchyard.llnetbase.LLNetBase,
            blasterIp,
            num
    ):
        self.net = net
        # TODO: store the parameters
        self.blasterIp = blasterIp
        self.num = num

    def handle_packet(self, recv: switchyard.llnetbase.ReceivedPacket):
        _, fromIface, packet = recv
        log_debug(f"I got a packet from {fromIface}")
        log_debug(f"Pkt: {packet}")
        raw = packet.get_header(RawPacketContents)
        seqnum = raw.data[:4]
        print(f"\033[1;36mreceive a pkt with seqnum: {int.from_bytes(seqnum, 'big')}\033[0m")
        payload = raw.data[6:]
        if len(payload) < 8: 
            payload += b'\x00'*(8-len(payload))
        else:
            payload = payload[0:8]
        eth = Ethernet()
        eth.src = "10:00:00:00:00:01"
        eth.dst = "40:00:00:00:00:01"

        ip = IPv4(protocol = IPProtocol.UDP)
        ip.src = '192.168.200.1'
        ip.dst = self.blasterIp
        ip.ttl = 64

        udp = UDP()
        ACK = eth + ip + udp + seqnum + payload
        print(f"\033[1;32msend a ACK for seqnum:{int.from_bytes(seqnum, 'big')}\033[0m")
        self.net.send_packet(fromIface, ACK)
    
    def start(self):
        '''A running daemon of the blastee.
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

        self.shutdown()

    def shutdown(self):
        self.net.shutdown()


def main(net, **kwargs):
    blastee = Blastee(net, **kwargs)
    blastee.start()
