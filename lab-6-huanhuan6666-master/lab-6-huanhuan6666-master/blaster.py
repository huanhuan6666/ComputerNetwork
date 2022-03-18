#!/usr/bin/env python3

import time
from random import randint
import os
from collections import deque
import switchyard
from switchyard.lib.address import *
from switchyard.lib.packet import *
from switchyard.lib.userlib import *

class pkt_win:
    def __init__(self, seqnum, pkt):
        self.pkt = pkt
        self.seqnum = seqnum
        self.ACKed = False
        self.recounts = 0
        self.sendTime = time.time()

class Blaster:
    def __init__(
            self,
            net: switchyard.llnetbase.LLNetBase,
            blasteeIp,
            num,
            length="100",
            senderWindow="5",
            timeout="300",
            recvTimeout="100"
    ):
        self.net = net
        # TODO: store the parameters
        ...
        self.blasteeIp = blasteeIp
        self.allcount = int(num) #the packets's count blaster needs to send
        self.length = int(length) #the payload's length
        self.maxsize = int(senderWindow) #the window's maxsize
        self.timeout = int(timeout)/1000
        self.recvTimeout = int(recvTimeout)/1000
        self.window = deque(maxlen = self.maxsize)
        self.timer = 0 #the coarse timer of window
        self.firstSend = -1.0
        self.lastACK = 0
        self.TOs = 0
        self.allsend_count = 0
        self.allre_count = 0
    
    def make_packet(self, seqnum):
        eth = Ethernet()
        eth.src = '20:00:00:00:00:01'
        eth.dst = '40:00:00:00:00:02'
        ip = IPv4(protocol = IPProtocol.UDP)
        ip.src = '192.168.100.1'
        ip.dst = self.blasteeIp
        ip.ttl = 0
        udp = UDP()
        #print(f"the length of payload is {self.length}")
        pkt = eth + ip + udp + seqnum.to_bytes(4, 'big') + self.length.to_bytes(2, 'big') + os.urandom(self.length)
        return pkt


    def handle_packet(self, recv: switchyard.llnetbase.ReceivedPacket):
        _, fromIface, packet = recv
        log_debug("I got a packet")
        #first complete the ACK's work
        raw = packet.get_header(RawPacketContents)
        this_seqnum = int.from_bytes(raw.data[:4], 'big')
        print(f"\033[1;31mreceive the ACK's seqnum is: {this_seqnum}\033[0m")
        for i, v in enumerate(self.window):
            if v.seqnum == this_seqnum:
                v.ACKed = True
                print(f"\033[1;30mpkt with seqnum {this_seqnum} located in current window[{i + 1}] is ACKed!\033[0m")
                self.lastACK = max(self.lastACK, time.time())
        #then send one pkt in this loop
        self.window_send()

    def window_send(self):
        #first if need resend a packet
        RESEND = False
        if len(self.window) > 0:
            if time.time() - self.timer > self.timeout: #the window's timer is timeout
                self.TOs += 1
                print("\033[1;35mthe window's timer is timeout!\033[0m")
                for v in self.window:
                    if v.ACKed == False:
                        RESEND = True
                        print(f"\033[1;36mresend a unACKed packet whose seqnum is {v.seqnum}\033[0m")
                        self.net.send_packet(self.net.interface_by_name("blaster-eth0"), v.pkt)
                        v.sendTime = time.time()
                        self.timer = v.sendTime #update window's timer -> resend
                        v.recounts += 1
                        self.allre_count += 1
                        self.allsend_count += 1
                        break #only send one in a loop
        #if don't need resend, then send a next pkt in this loop
        if RESEND == False and self.allcount > 0 and (len(self.window) < self.maxsize or self.window[0].ACKed == True):
            next_seq = 1
            if len(self.window) > 0: #get the last seq in window
                next_seq  = self.window[-1].seqnum + 1
            pkt = self.make_packet(next_seq) #create next pkt
            pktWindow = pkt_win(next_seq, pkt)
            self.net.send_packet(self.net.interface_by_name('blaster-eth0'), pkt)
            print(f"\033[1;36msend the packet whose seqnum is {next_seq}\033[0m")

            if len(self.window) == 0:#LHS change
                self.window.append(pktWindow) #add pkt in window
                self.timer = pktWindow.sendTime #update window's timer
            elif len(self.window) < self.maxsize and self.window[0].ACKed == True:#LHS change
                self.window.popleft() #pop the left ACKed pkt
                self.window.append(pktWindow) 
                self.timer = pktWindow.sendTime 
            elif len(self.window) < self.maxsize:#LHS not change
                self.window.append(pktWindow)
            elif self.window[0].ACKed == True: #LHS change
                self.window.popleft() 
                self.window.append(pktWindow) 
                self.timer = pktWindow.sendTime 

            if self.firstSend == -1.0: #the first send pkt's time
                self.firstSend = pktWindow.sendTime
            self.allsend_count += 1
            self.allcount -= 1
    
    def handle_no_packet(self):
        log_debug("Didn't receive anything")
        #need resend or send in this loop
        self.window_send()
    
    def check_over(self):
        if self.allcount > 0:
            return False
        for  v in self.window:
            if v.ACKed == False:
                return False
        totalTXtime = self.lastACK - self.firstSend
        print('\033[1;35m=\033[0m' * 80)
        print(f"\033[1;32mTotal TX time (in seconds): {totalTXtime}\033[0m")
        print(f"\033[1;32mNumber of reTX: {self.allre_count}\033[0m")
        print(f"\033[1;32mNumber of coarse TOs: {self.TOs}\033[0m")
        print(f"\033[1;32mThroughput (Bps): {self.allsend_count * self.length / totalTXtime}\033[0m")
        print(f"\033[1;32mGoodput (Bps): {(self.allsend_count - self.allre_count) * self.length / totalTXtime}\033[0m")
        print('\033[1;35m=\033[0m' * 80)
        return True

    def start(self):
        '''A running daemon of the blaster.
        Receive packets until the end of time.
        '''
        while True:
            try:
                recv = self.net.recv_packet(timeout=self.recvTimeout)
            except NoPackets:
                self.handle_no_packet()
                continue
            except Shutdown:
                break
            self.handle_packet(recv)

            if self.check_over():
                print("\033[1;35mthe transmition is overed!!!\033[0m")
                self.shutdown()
        self.shutdown()

    def shutdown(self):
        self.net.shutdown()


def main(net, **kwargs):
    blaster = Blaster(net, **kwargs)
    blaster.start()
