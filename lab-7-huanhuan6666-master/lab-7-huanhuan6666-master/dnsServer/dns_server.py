'''DNS Server for Content Delivery Network (CDN)
'''

import sys
from socketserver import UDPServer, BaseRequestHandler
from utils.dns_utils import DNS_Request, DNS_Rcode
from utils.ip_utils import IP_Utils
from datetime import datetime
import math
import random
import re
from collections import namedtuple


__all__ = ["DNSServer", "DNSHandler"]


class DNSServer(UDPServer):
    def __init__(self, server_address, dns_file, RequestHandlerClass, bind_and_activate=True):
        super().__init__(server_address, RequestHandlerClass, bind_and_activate=True)
        self._dns_table = {}
        self.parse_dns_file(dns_file)
        
    def parse_dns_file(self, dns_file):
        # ---------------------------------------------------
        # TODO: your codes here. Parse the dns_table.txt file
        # and load the data into self._dns_table.
        # --------------------------------------------------
        for line in open(dns_file):
            item = line.split()
            print(item[0])
            domain = item[0]
            if domain[-1] == '.':
                domain = domain[:-1]
            if domain[0] == '*':
                domain = domain[1:]
            self._dns_table[domain] = [item[1], []] #<domain : [type, [ip1, ip2,...]]>
            for i  in range(2, len(item)):
                if item[i][-1] == '.':
                    self._dns_table[domain][1].append(item[i][:-1])
                else:
                    self._dns_table[domain][1].append(item[i])
            #print(self._dns_table)        

    @property
    def table(self):
        return self._dns_table


class DNSHandler(BaseRequestHandler):
    """
    This class receives clients' udp packet with socket handler and request data. 
    ----------------------------------------------------------------------------
    There are several objects you need to mention:
    - udp_data : the payload of udp protocol.
    - socket: connection handler to send or receive message with the client.
    - client_ip: the client's ip (ip source address).
    - client_port: the client's udp port (udp source port).
    - DNS_Request: a dns protocl tool class.
    We have written the skeleton of the dns server, all you need to do is to select
    the best response ip based on user's infomation (i.e., location).

    NOTE: This module is a very simple version of dns server, called global load ba-
          lance dns server. We suppose that this server knows all the ip addresses of 
          cache servers for any given domain_name (or cname).
    """
    
    def __init__(self, request, client_address, server):
        self.table = server.table
        super().__init__(request, client_address, server)

    def calc_distance(self, pointA, pointB):
        ''' TODO: calculate distance between two points '''
        locA = IP_Utils.getIpLocation(pointA)
        locB = IP_Utils.getIpLocation(pointB)
        return ((locA[0] - locB[0])**2 + (locA[1] - locB[1])**2)** 0.5        

    def get_response(self, request_domain_name):
        response_type, response_val = (None, None)
        # ------------------------------------------------
        # TODO: your codes here.
        # Determine an IP to response according to the client's IP address.
        #       set "response_ip" to "the best IP address".
        client_ip, _ = self.client_address
        #response_type, response_val = ("A", "10.1.1.1")        
        for key, value in self.table.items():
            #print(request_domain_name, '+', key)
            if request_domain_name.find(key) != -1: #the request domain in table TODO:how to match the ip and domain?
                if value[0] == "CNAME":
                    response_type = "CNAME"
                    response_val = value[1][0]
                    break
                elif value[0] == "A":
                    response_type = "A"
                    if len(value[1]) == 1: #only 1 ip in list
                        response_val = value[1][0]
                        break
                    else: #have some ips to get best
                        if IP_Utils.getIpLocation(client_ip) == None: #the client ip don's in table, get random
                            response_val = random.choice(value[1])
                            break
                        else: #get best IP in list
                            bestIP = value[1][0]
                            bestdis = float('inf')
                            for ip in value[1]:
                                curdis = self.calc_distance(client_ip, ip)   
                                if curdis < bestdis:
                                    bestdis = curdis
                                    bestIP = ip
                                response_val = bestIP
                            break
        return (response_type, response_val)

    def handle(self):
        """
        This function is called once there is a dns request.
        """
        ## init udp data and socket.
        udp_data, socket = self.request

        ## read client-side ip address and udp port.
        client_ip, client_port = self.client_address

        ## check dns format.
        valid = DNS_Request.check_valid_format(udp_data)
        if valid:
            ## decode request into dns object and read domain_name property.
            dns_request = DNS_Request(udp_data)
            request_domain_name = str(dns_request.domain_name)
            self.log_info(f"Receving DNS request from '{client_ip}' asking for "
                          f"'{request_domain_name}'")

            # get caching server address
            response = self.get_response(request_domain_name)

            # response to client with response_ip
            if None not in response:
                dns_response = dns_request.generate_response(response)
            else:
                dns_response = DNS_Request.generate_error_response(
                                             error_code=DNS_Rcode.NXDomain)
        else:
            self.log_error(f"Receiving invalid dns request from "
                           f"'{client_ip}:{client_port}'")
            dns_response = DNS_Request.generate_error_response(
                                         error_code=DNS_Rcode.FormErr)

        socket.sendto(dns_response.raw_data, self.client_address)

    def log_info(self, msg):
        self._logMsg("Info", msg)

    def log_error(self, msg):
        self._logMsg("Error", msg)

    def log_warning(self, msg):
        self._logMsg("Warning", msg)

    def _logMsg(self, info, msg):
        ''' Log an arbitrary message.
        Used by log_info, log_warning, log_error.
        '''
        info = f"[{info}]"
        now = datetime.now().strftime("%Y/%m/%d-%H:%M:%S")
        sys.stdout.write(f"{now}| {info} {msg}\n")
