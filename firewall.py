#!/usr/bin/env python

from main import PKT_DIR_INCOMING, PKT_DIR_OUTGOING
from math import ceil
import re
import socket
import struct
import time
import binascii

# TODO: Feel free to import any Python standard moduless as necessary.
# (http://docs.python.org/2/library/)
# You must NOT use any 3rd-party libraries, though.

class Firewall:

    class Connection():
        def __init__(self, ext_ip = None, int_port = None, seqnoA = None, seqnoB = None):
            self.request_stream = ""
            self.response_stream = ""
            self.ext_ip = ext_ip
            self.int_port = int_port
            self.seqnoA = seqnoA
            self.seqnoB = seqnoB

        def set_ext_ip(self, ext_ip):
            self.ext_ip = ext_ip
        
        def set_int_port(self, int_port):
            self.int_port = int_port

        def set_seqnoA(self, seqno):
            self.seqnoA = seqno

        def set_seqnoB(self, seqno):
            self.seqnoB = seqno
 
        def get_seqnoA(self):
            return self.seqnoA

        def get_seqnoB(self):
            return self.seqnoB

        def get_ext_ip(self):
            return self.ext_ip

        def get_int_port(self):
            return self.int_port

        def add_to_requestStream(self, data):
            self.request_stream += data

        def get_request_stream(self):
            return self.request_stream

        def set_request_stream(self, newStream):
            self.request_stream = newStream

        def add_to_responseStream(self, data):
            self.response_stream += data

        def get_response_stream(self):
            return self.response_stream

        def set_response_stream(self, newStream):
            self.response_stream = newStream

        def same_connection(self, ext_ip, int_port):
            return self.ext_ip == ext_ip and self.int_port == int_port

    def __init__(self, config, iface_int, iface_ext):
        self.iface_int = iface_int
        self.iface_ext = iface_ext
        self.lst = []
        self.countries = {}
        self.connection_objs = [] # a list of connection objects.
        self.connect = None
        self.mode = -1
        self.expected = 2
        self.log = False

        for line in open(config['rule']):
            if (len(line) != 0 and (not line.isspace())):
                line = line.lstrip()
                line = line.rstrip()
                if(line[0] != '%' and line != '\n'):
                    line = re.sub(' +', ' ', line.lower())
                    line = line.rstrip('\n')
                    parts = line.split(" ")
                    self.lst.append(parts)

        for line in open('geoipdb.txt'):
            if (len(line) != 0 and (not line.isspace())):
                line = line.lstrip()
                line = line.rstrip()
                if(line[0] != '%' and line != '\n'):
                    line = re.sub(' +', ' ', line.lower())
                    line = line.rstrip('\n')
                    src_ip, dest_ip, country = line.split(" ")
                    src_ip_num = struct.unpack('!L', socket.inet_aton(src_ip))[0]
                    dest_ip_num = struct.unpack('!L', socket.inet_aton(dest_ip))[0]
                    self.update_dict(country, src_ip_num, dest_ip_num, self.countries)

    """ Updates the dictionary."""
    def update_dict(self, code, src_ip_num, dest_ip_num, countries):
        if (code not in countries.keys()):
            countries[code] = []
        countries[code].append((src_ip_num, dest_ip_num))

    """ Performs binary search on the countries and returns True
         if the ip_address is in range, else it returns False. """
    def binary_search(self, countries, code, ip_address):
        imax = len(countries[code]) - 1
        imin = 0
        while(imax >= imin):
            imid = int(ceil(imin + ((imax - imin) / 2)))
            if(ip_address >= countries[code][imid][0]
                and ip_address <= countries[code][imid][1]):
                return True #in the range.
            elif(ip_address < countries[code][imid][0]):
                imax = imid - 1
            else:
                imin = imid + 1
        return False #'code not found in range'

    """ Checks the packet to make sure the IPv4 address is valid. Upon
        verifying that the addresses in the IP packet are valid, method
        returns True. Else, it returns False. """
    def valid_IP_address(self, ext_addr):
        try:
           socket.inet_ntoa(ext_addr)
           return True
        except socket.error:
           return False

    def obtain_fields(self, pckt):
        try:
            protocol = struct.unpack('!B', pckt[9:10]) # (integer,)
            total_length = struct.unpack('!H', pckt[2:4])
            return self.strip_format(protocol), self.strip_format(total_length)
        except struct.error:
            return None, None

    def valid_ip_header(self, pckt):
        try:
            ip_header = struct.unpack('!B', pckt[0:1])
            return self.strip_format(ip_header)
        except struct.error:
            return None

    def get_udp_length(self, pckt, startIndex):
        try:
            length = struct.unpack('!H', pckt[startIndex + 4 : startIndex + 6])
            return self.strip_format(length)
        except struct.error:
            return None

    def handle_packet(self, pckt_dir, pckt):
        ip_header = self.valid_ip_header(pckt)
        if (ip_header == None):
            return
        ip_header = ip_header & 0x0f
        if (ip_header < 5):
            return

        protocol, total_length = self.obtain_fields(pckt)
        if (protocol == None and total_length == None):
            return

        if (total_length != len(pckt)):
            return
        
        if (self.protocol_selector(protocol) == None):
            self.send_packet(pckt, pckt_dir)
            return

        src_addr, dst_addr, pckt_dir = pckt[12:16], pckt[16:20], self.packet_direction(pckt_dir)
        if (pckt_dir == 'incoming'):
            external_addr = src_addr
        else:
            external_addr = dst_addr
        if not (self.valid_IP_address(external_addr)): # check valid address.
            return

        if (protocol == 6): # TCP
            if (pckt_dir == 'incoming'):
                external_port = self.handle_external_port(pckt, (ip_header) * 4)
            else:
                external_port = self.handle_external_port(pckt, ((ip_header) * 4) + 2)
            if (external_port == None): # drop packet due to port socket error.
                return

        elif (protocol == 1): # ICMP
            type_field = self.handle_icmp_packet(pckt, (ip_header * 4))
            if (type_field == None):
                return

        elif (protocol == 17): # UDP
            udp_length = self.get_udp_length(pckt, (ip_header * 4))
            if (udp_length == None or udp_length < 8):
                return
            if (pckt_dir == 'incoming'):
                external_port = self.handle_external_port(pckt, (ip_header) * 4)
                if (external_port == None):
                    return
            else:
                external_port = self.handle_external_port(pckt, ((ip_header) * 4) + 2)
                if (external_port == None):
                    return
                if (self.strip_format(external_port) == 53):
                    dns_offset = (ip_header * 4) + 8
                    QDCOUNT, pckt_domain_name, QTYPE, QCLASS = self.parseDNS(dns_offset, pckt) # Check this.
                    if not (self.check_dns_fields(QDCOUNT, QTYPE, QCLASS)):
                        return
                    else:
                        QDCOUNT = self.strip_format(QDCOUNT)
                        QTYPE = self.strip_format(QTYPE)
                        QCLASS = self.strip_format(QCLASS)

        verdict = "pass"
        for rule in self.lst:
            if (len(rule) == 4):
                verdict_rule, rule_protocol, ext_IP, ext_port = rule[0], rule[1], rule[2], rule[3]
                if (ext_IP == '0.0.0.0/0'):
                    ext_IP = "any"
                # Check if the pckt protocol matches the rules protocol.
                if (self.protocol_selector(protocol) != rule_protocol):
                    continue
                # Checking the IP field
                if (ext_IP != 'any'):
                    if not (self.check_externalIP(ext_IP, external_addr)):
                        continue
                # Checking the port field
                if (ext_port != 'any'):
                    if (self.protocol_selector(protocol) != 'icmp'):
                        if not (self.check_externalPort(ext_port, self.strip_format(external_port))):
                            continue
                    else:
                        if not (self.check_externalPort(ext_port, type_field)):
                            continue
            elif (len(rule) == 3):
                verdict_rule, rule_p, domain_name = rule[0], rule[1], rule[2]
                if (rule_p == 'dns' and self.protocol_selector(protocol) == 'udp'): # rule == DNS
                    if (pckt_dir == 'outgoing' and self.strip_format(external_port) == 53):
                        if not (self.matches_dns_rules(pckt_domain_name, domain_name, QDCOUNT, QTYPE, QCLASS)):
                            continue
                    else:
                        continue
                elif (protocol ==6 and rule_p == 'http'):
                    self.grab_http_fields(pckt, pckt_dir, external_addr, ip_header, domain_name)
                else:
                    continue

            verdict = verdict_rule

        if (verdict == 'pass'):
            self.send_packet(pckt, pckt_dir)
        elif (verdict == 'deny'):
            if (self.protocol_selector(protocol) == 'tcp'):
                rst_pckt = self.deny_tcp(pckt, ip_header)
                self.send_packet(rst_pckt, 'incoming')
            elif (self.protocol_selector(protocol) == 'udp'): # deny dns
                if (pckt_dir == 'outgoing' and self.strip_format(external_port) == 53):
                    if (QTYPE != 28):
                        dns_rst_pckt = self.deny_dns(pckt, ip_header, dns_offset)
                        self.send_packet(dns_rst_pckt, 'incoming')


    def grab_http_fields(self, pckt, pckt_dir, ext_ip, ip_header, rules_domain_name):
        iph = ip_header * 4 # length of IP header.
        if (self.mode == -1):
            self.tcp_handshake(pckt, pckt_dir, ext_ip, iph)
        elif(self.mode == 0):
            tcp_offset = self.strip_format(struct.unpack("!B", pckt[iph + 12 : iph + 13]))
            tcp_offset = tcp_offset >> 4
            tcph = tcp_offset * 4
            start_index, payload = (iph + tcph), len(pckt) - (iph + tcph) # start index for the tcp payload.
            self.tcp_data(pckt, pckt_dir, ext_ip, iph, start_index, payload, rules_domain_name)
        elif(self.mode == 1):
            self.tcp_finish(pckt, pckt_dir, ext_ip, iph)

    def tcp_handshake(self, pckt, pckt_dir, ext_ip, iph):
        
        """ Parsing the packet """
        self.log = False
        max_num = ((2**32) - 1)
        ext_ip = socket.inet_ntoa(ext_ip) # 1.2.3.4
        flag = self.strip_format(struct.unpack("!B", pckt[iph + 13]))# flag of pckt.
        pckt_seqno = self.strip_format(struct.unpack("!L", pckt[iph + 4 : iph + 8]))
        pckt_ackno = self.strip_format(struct.unpack("!L", pckt[iph + 8 : iph + 12]))
        if (pckt_dir == 'outgoing'):
            int_port = self.strip_format(struct.unpack("!H", pckt[iph : iph + 2])) # internal port
        else:
            int_port = self.strip_format(struct.unpack("!H", pckt[iph + 2 : iph + 4])) # internal port

        """ Setting up connection """
        if (len(self.connection_objs) == 0):
            connection = Firewall.Connection()
            self.connection_objs.append(connection)
            self.connect = connection

        """ Handshake """
        if (flag == 2): # syn packet. client A
            self.connect.set_seqnoA((pckt_seqno + 1) % max_num)
            self.connect.set_ext_ip(ext_ip)
            self.connect.set_int_port(int_port)
            self.send_packet(pckt, pckt_dir)
        elif (flag == 18 and (pckt_ackno % max_num) == self.connect.get_seqnoA()): # client B
            self.send_packet(pckt, pckt_dir)
            self.connect.set_seqnoB((pckt_seqno + 1) % max_num)
        elif (flag == 16 and (pckt_seqno % max_num) == self.connect.get_seqnoA()
              and (pckt_ackno % max_num) == self.connect.get_seqnoB()): # client A
            self.send_packet(pckt, pckt_dir)
            self.mode = 0

    def tcp_data(self, pckt, pckt_dir, ext_ip, iph, start_index, payload, rules_domain_name):
        """ Packet information """
        max_num = ((2**32) - 1)
        ext_ip = socket.inet_ntoa(ext_ip) # 1.2.3.4
        flag = self.strip_format(struct.unpack("!B", pckt[iph + 13]))# flag of pckt.
        pckt_seqno = self.strip_format(struct.unpack("!L", pckt[iph + 4 : iph + 8]))
        pckt_ackno = self.strip_format(struct.unpack("!L", pckt[iph + 8 : iph + 12]))

        if (pckt_dir == 'outgoing'):
            int_port = self.strip_format(struct.unpack("!H", pckt[iph : iph + 2])) # internal port
            exp_seqno, exp_ackno = self.connect.get_seqnoA(), self.connect.get_seqnoB()
            stream = self.connect.get_request_stream()
        else:
            int_port = self.strip_format(struct.unpack("!H", pckt[iph + 2 : iph + 4])) # internal port
            exp_seqno, exp_ackno = self.connect.get_seqnoB(), self.connect.get_seqnoA()
            stream = self.connect.get_response_stream()

        if (self.connect.same_connection(ext_ip, int_port) 
            and ((pckt_seqno % max_num) <= exp_seqno)
            and ((pckt_ackno % max_num) == exp_ackno)):
            if (pckt_dir == 'incoming'):
                new_seqno = (self.connect.get_seqnoB() + payload) % max_num
                self.connect.set_seqnoB(new_seqno)
            else:
                new_seqno = (self.connect.get_seqnoA() + payload) % max_num
                self.connect.set_seqnoA(new_seqno)
            while(start_index < len(pckt) and stream.find('\r\n\r\n') == -1):
                if(pckt_dir == 'incoming'):
                    self.connect.add_to_responseStream(pckt[start_index])
                else:
                    self.connect.add_to_requestStream(pckt[start_index])
                start_index += 1
            if (self.connect.get_request_stream().find('\r\n\r\n') > -1
                and self.connect.get_response_stream().find('\r\n\r\n') > -1
                and (not self.log)):
                self.log = True
                self.parsePacket(rules_domain_name)
                self.connect.set_response_stream('')
                self.connect.set_request_stream('')


            self.send_packet(pckt, pckt_dir)
            if (flag == 17 and pckt_dir == 'outgoing'): #FIN ACK
                self.mode = 1


    def parsePacket(self, rules_domain_name):
        index = self.connect.get_response_stream().find('\r\n\r\n')
        response_lst = self.connect.get_response_stream()[0:index].split('\r\n')
        request_lst = self.connect.get_request_stream().split('\r\n')
        method, path, version, host_name = self.requestInfo(request_lst)
        status_code, object_size = self.responseInfo(response_lst)
        if (object_size == None):
            object_size = -1
        if (host_name == ""):
            host_name = self.connect.get_ext_ip()

        """ Log information """
        if (self.dns_match(host_name, rules_domain_name)):
            f = open('http.log', 'a')
            info = host_name + " " + method + " " + path + " " + version
            info += status_code + " " + object_size + '\n'
            f.write(info)
            f.flush()

    def requestInfo(self, request_lst):
        method, path, version, host_name = "", "", "", ""
        for item in request_lst:
            if ((item.lower().find('http/1.1') > -1
                or item.lower().find('http/1.0') > -1)
                and path == ""):
                lst = item.split(" ")
                method, path, version = lst[0], lst[1], lst[2]
            if (item.lower().find("host") > - 1
                and host_name == ""):
                lst = item.split(" ")
                if (len(lst) > 1):
                    host_name = lst[1]

        return method, path, version, host_name

    def responseInfo(self, response_lst):
        status_code, object_size = "", None
        for item in response_lst:
            if ((item.lower().find('http/1.1') > -1
                or item.lower().find('http:/1.0') > -1)
                and status_code == ""):
                lst = item.split(" ")
                status_code = lst[1]
            if (item.lower().find('content-length') > -1
                and object_size == None):
                lst = item.split(" ")
                object_size = lst[1]
        return status_code, object_size


    def tcp_finish(self, pckt, pckt_dir, ext_ip, iph):
        max_num = ((2**32) - 1)
        ext_ip = socket.inet_ntoa(ext_ip) # 1.2.3.4
        flag = self.strip_format(struct.unpack("!B", pckt[iph + 13]))# flag of pckt.
        pckt_seqno = self.strip_format(struct.unpack("!L", pckt[iph + 4 : iph + 8]))
        pckt_ackno = self.strip_format(struct.unpack("!L", pckt[iph + 8 : iph + 12]))

        if (pckt_dir == 'outgoing'):
            int_port = self.strip_format(struct.unpack("!H", pckt[iph : iph + 2])) # internal port
            exp_seqno, exp_ackno = self.connect.get_seqnoA(), self.connect.get_seqnoB()
        else:
            int_port = self.strip_format(struct.unpack("!H", pckt[iph + 2 : iph + 4])) # internal port
            exp_seqno, exp_ackno = self.connect.get_seqnoB(), self.connect.get_seqnoA()

        if (self.connect.same_connection(ext_ip, int_port)
            and ((pckt_seqno % max_num) <= exp_seqno)
            and ((pckt_ackno % max_num) == exp_ackno)
            and int_port == self.connect.get_int_port()):

            if (pckt_dir == 'incoming'):
                new_seqnoB = (self.connect.get_seqnoB()) % max_num
                self.connect.set_seqnoB(new_seqnoB) 
                new_seqnoA = (self.connect.get_seqnoA() + 1) % max_num
                self.connect.set_seqnoA(new_seqnoA)  
            else:
                new_seqnoA = (self.connect.get_seqnoA() + 1) % max_num
                self.connect.set_seqnoA(new_seqnoA)
                new_seqnoB = (self.connect.get_seqnoB() + 1) % max_num
                self.connect.set_seqnoB(new_seqnoB) 
            
            self.send_packet(pckt, pckt_dir)

            if (flag == 16):
                self.mode = -1
                self.connection_objs.remove(self.connect)
                self.connect = None

    def deny_dns(self, pckt, ip_header, dns_offset):
        iph = ip_header * 4 # 20
        """ IP parts """
        src_addr = pckt[16:20]
        dest_addr = pckt[12:16]
        TTL_ip = struct.pack("!B", 64)
        orig_ip_checksum = struct.pack("!H", 0)
        
        """ UDP parts """
        src_port, dest_port = pckt[iph: iph + 2], pckt[iph + 2: iph + 4]
        dest_port, src_port = src_port, dest_port
        orig_udp_checksum = struct.pack("!H", 0)

        """ DNS parts """

        """ Header """
        header_fields1 = struct.unpack("!B", pckt[dns_offset + 2: dns_offset + 3])
        header_fields1 = self.strip_format(header_fields1) | 128 # QR --> RD.
        header_fields1 = struct.pack("!B", header_fields1)
        header_fields2 = struct.pack("!B", 128)
        QDCOUNT = struct.pack("!H", 1)
        ANCOUNT = struct.pack("!H", 1)
        NSCOUNT = pckt[dns_offset + 8 : dns_offset + 10]
        ARCOUNT = pckt[dns_offset + 10 : dns_offset + 12]

        """ Question """
        q_offset = dns_offset + 12
        domain_name, qname_len = self.assemble_domain_name(pckt, q_offset)
        QNAME = pckt[q_offset: q_offset + qname_len + 1]
        QTYPE_offset = q_offset + qname_len + 1 
        QTYPE = pckt[QTYPE_offset : QTYPE_offset + 2]
        QCLASS_offset = QTYPE_offset + 2
        QCLASS = pckt[QCLASS_offset : QCLASS_offset + 2]

        """ Answer """
        TYPE = QTYPE
        NAME = QNAME
        CLASS = QCLASS        
        TTL = struct.pack("!L", 1)
        RDATA =  socket.inet_aton("54.173.224.150")
        RDLENGTH = struct.pack("!H", 4)

        dns_payload = pckt[dns_offset : dns_offset + 2] + header_fields1 + header_fields2
        dns_payload += QDCOUNT + ANCOUNT + NSCOUNT + ARCOUNT
        dns_payload += QNAME + QTYPE + QCLASS
        dns_payload += NAME + TYPE + CLASS + TTL + RDLENGTH + RDATA

        udp_length = 8 + len(dns_payload)
        total_length = struct.pack("!H", udp_length + iph)

        """ Creating packet """
        ip_head = pckt[0:2] + total_length + pckt[4:6] + struct.pack("!H", 0) 
        ip_head += TTL_ip + pckt[9:10] + orig_ip_checksum + src_addr + dest_addr
        dns_ip_checksum = struct.pack("!H", self.compute_IPchecksum(ip_head, 0, iph))

        udp_head = src_port + dest_port + struct.pack("!H", udp_length) + orig_udp_checksum
        udp_data = dns_payload
        udp_pckt = udp_head + udp_data
        dns_udp_checksum = struct.pack("!H", self.compute_UDPchecksum(ip_head + udp_pckt, ip_header, iph, iph + udp_length, udp_length))

        dns_ip_head = pckt[0:2] + total_length + pckt[4:6] + struct.pack("!H", 0)
        dns_ip_head += TTL_ip + pckt[9:10] + dns_ip_checksum + src_addr + dest_addr
        dns_udp_pckt =  src_port + dest_port + struct.pack("!H", udp_length) + dns_udp_checksum + dns_payload

        return dns_ip_head + dns_udp_pckt


    def deny_tcp(self, pckt, ip_header):
        iph = ip_header * 4

        """ IP parts """
        total_length = struct.pack('!H', 40)
        TTL = struct.pack("!B", 64)
        orig_ip_checksum = struct.pack("!H", 0)
        src_addr, dst_addr = pckt[12:16], pckt[16:20]
        dst_addr, src_addr = src_addr, dst_addr

        """ TCP parts """
        tcp_offset = self.strip_format(struct.unpack("!B", pckt[iph + 12 : iph + 13]))
        tcp_offset = tcp_offset >> 4
        tcph = tcp_offset * 4

        src_port = pckt[iph : iph + 2]
        dst_port = pckt[iph + 2 : iph + 4]
        src_port, dst_port = dst_port, src_port
        seqno = pckt[iph + 8 : iph + 12]
        payload = len(pckt) - (iph + tcph)
        ack = struct.unpack("!L", pckt[iph + 4 : iph + 8])
        ack = struct.pack("!L", self.get_ack(ack, payload))

        flag = struct.unpack('!B', pckt[iph + 13 : iph + 14])
        flag = struct.pack('!B', 20)
        orig_tcp_checksum = struct.pack("!H", 0)

        """ Constructing rst packet """
        ip_head = pckt[0:2] + total_length + pckt[4:6] + struct.pack("!H", 0) 
        ip_head += TTL + pckt[9:10] + orig_ip_checksum + src_addr + dst_addr
        rst_ip_checksum = struct.pack("!H", self.compute_IPchecksum(ip_head, 0, iph))

        tcp_head = src_port + dst_port + seqno + ack + struct.pack("!B", 80) + flag + pckt[iph + 14 : iph + 16]
        tcp_head += orig_tcp_checksum + pckt[iph + 18 : iph + 20]
        new_tcp_checksum = self.compute_TCPchecksum(ip_head + tcp_head, ip_header, iph, iph + 20)
        rst_tcp_checksum = struct.pack("!H", new_tcp_checksum)

        final_ip_head = pckt[0:2] + total_length + pckt[4:6] + struct.pack("!H", 0)
        final_ip_head += TTL + pckt[9:10] + rst_ip_checksum + src_addr + dst_addr

        final_tcp_head = src_port + dst_port + seqno + ack + struct.pack("!B", 80) + flag + pckt[iph + 14 : iph + 16]
        final_tcp_head += rst_tcp_checksum + pckt[iph + 18 : iph + 20]

        return final_ip_head + final_tcp_head

    def get_ack(self, ack, payload):
        new_ack = str(ack)
        if (new_ack.find('L') > -1):
            new_ack = int(new_ack[1: len(new_ack) - 3]) + 1
        else:
            new_ack = int(new_ack[1: len(new_ack) - 2]) + 1
        return new_ack

    def compute_UDPchecksum(self, pckt, ip_header, start_index, end_index, udp_length):
        total = "0000000000000000"

        """ Pseudo-header """
        src_addr_low = self.strip_format(struct.unpack('!H', pckt[12:14]))
        src_addr_high = self.strip_format(struct.unpack('!H', pckt[14:16]))
        dest_addr_low = self.strip_format(struct.unpack('!H', pckt[16:18]))
        dest_addr_high = self.strip_format(struct.unpack("!H", pckt[18:20]))
        protocol = 17 #17
        total_length = self.strip_format(struct.unpack('!H', pckt[2:4]))
        ip_header_len = ip_header * 4
        udp_segment = udp_length
        
        lst = [src_addr_low, src_addr_high, dest_addr_low, dest_addr_high, protocol, udp_segment]
        for num in lst:
            bin_num = bin(num)
            bin_num = (bin(num))[2:].zfill(16)
            total = (bin(int(total, 2) + int(bin_num, 2)))[2:].zfill(16)
            tmp_total = hex(int(total, 2))
            if (len(tmp_total[2:]) > 4):
                total = (bin(int(total[1:], 2) + int(total[0], 2)))[2:].zfill(16)

        """ UDP segment """
        #checksum = struct.unpack('!H', pckt[(ip_header * 4) + 16: (ip_header * 4) + 18])
        #checksum = self.strip_format(checksum) # integer number.
        while start_index < end_index:
            if (start_index != ((ip_header * 4) + 6)):
                if (end_index - start_index == 1):
                    stuff = struct.unpack('!B', pckt[start_index : start_index + 1])
                else:
                    stuff = struct.unpack('!H', pckt[start_index : start_index + 2])

                int_num = self.strip_format(stuff)
                bin_num = bin(int_num)
                bin_num = (bin(int_num))[2:].zfill(16)
                total = (bin(int(total, 2) + int(bin_num, 2)))[2:].zfill(16)
                tmp_total = hex(int(total, 2))
                if (len(tmp_total[2:]) > 4):
                    total = (bin(int(total[1:], 2) + int(total[0], 2)))[2:].zfill(16)
            start_index += 2

        total = total.replace('0', 'x')
        total = total.replace('1', '0')
        total = total.replace('x', '1')
        total = total.replace('1b', '0b')
        return int(total, 2)

    def compute_TCPchecksum(self, pckt, ip_header, startIndex, endIndexm):
        total = "0000000000000000"

        """ Pseudo-header """
        src_addr_low = self.strip_format(struct.unpack('!H', pckt[12:14]))
        src_addr_high = self.strip_format(struct.unpack('!H', pckt[14:16]))
        dest_addr_low = self.strip_format(struct.unpack('!H', pckt[16:18]))
        dest_addr_high = self.strip_format(struct.unpack("!H", pckt[18:20]))
        protocol = 6 # 6
        total_length = self.strip_format(struct.unpack('!H', pckt[2:4]))
        ip_header_len = ip_header * 4
        tcp_segment = len(pckt) - ip_header_len
        
        lst = [src_addr_low, src_addr_high, dest_addr_low, dest_addr_high, protocol, tcp_segment]
        for num in lst:
            bin_num = bin(num)
            bin_num = (bin(num))[2:].zfill(16)
            total = (bin(int(total, 2) + int(bin_num, 2)))[2:].zfill(16)
            tmp_total = hex(int(total, 2))
            if (len(tmp_total[2:]) > 4):
                total = (bin(int(total[1:], 2) + int(total[0], 2)))[2:].zfill(16)

        """ TCP segment """
        checksum = struct.unpack('!H', pckt[(ip_header * 4) + 16: (ip_header * 4) + 18])
        checksum = self.strip_format(checksum) # integer number.
        start_index = ip_header_len
        end_index = len(pckt)
        while start_index < end_index:
            if (start_index != ((ip_header * 4) + 16)):
                if (end_index - start_index == 1):
                    stuff = struct.unpack('!B', pckt[start_index : start_index + 1])
                else:
                    stuff = struct.unpack('!H', pckt[start_index : start_index + 2])

                int_num = self.strip_format(stuff)
                bin_num = bin(int_num)
                bin_num = (bin(int_num))[2:].zfill(16)
                total = (bin(int(total, 2) + int(bin_num, 2)))[2:].zfill(16)
                tmp_total = hex(int(total, 2))
                if (len(tmp_total[2:]) > 4):
                    total = (bin(int(total[1:], 2) + int(total[0], 2)))[2:].zfill(16)
            start_index += 2

        total = total.replace('0', 'x')
        total = total.replace('1', '0')
        total = total.replace('x', '1')
        total = total.replace('1b', '0b')
        return int(total, 2)
 
    def compute_IPchecksum(self, pckt, start_index, end_index):
        total = "0000000000000000"
        while start_index < end_index:
            if (start_index != 10):
                if(end_index - start_index == 1):
                    stuff = struct.unpack("!B", pckt[start_index: start_index + 1])
                else:
                    stuff = struct.unpack('!H', pckt[start_index : start_index + 2])
                int_num = self.strip_format(stuff)
                bin_num = bin(int_num)
                bin_num = (bin(int_num))[2:].zfill(16)
                total = (bin(int(total, 2) + int(bin_num, 2)))[2:].zfill(16)
                tmp_total = hex(int(total, 2))
                if (len(tmp_total[2:]) > 4):
                    total = (bin(int(total[1:], 2) + int(total[0], 2)))[2:].zfill(16)
            start_index += 2

        total = total.replace('0', 'x')
        total = total.replace('1', '0')
        total = total.replace('x', '1')
        total = total.replace('1b', '0b')
        total = int(total, 2)
        return total

    """ Sends the packet in the correct direction."""
    def send_packet(self, pckt, pckt_dir):
        if (pckt_dir == 'incoming'):
            self.iface_int.send_ip_packet(pckt)
        else:
            self.iface_ext.send_ip_packet(pckt)

    """ Protocol Selector."""
    def protocol_selector(self, protocol):
        if (protocol == 1):
            return "icmp"
        elif (protocol == 6):
            return 'tcp'
        elif (protocol == 17):
            return 'udp'
        return None

    """ IP Protocol Rules """

    """ Returns True if the protocol of the packet is either TCP, UDP, or ICMP.
        Else, the method returns False. """
    def check_protocol(self, protocol):
        return (protocol == 'tcp') or (protocol == 'udp') or (protocol == 'icmp') 

    """ Checks the external IP address field. Returns True if it is valid, else it
        return False. """
    def check_externalIP(self, data, external_ip):
        # Convert from bytes to IP address string.
        external_ip = socket.inet_ntoa(external_ip) # 1.2.3.4
        # if it is a 2 - byte country code
        if (len(data) == 2):
            # Convert from string to integer.
            try:
                external_ip = struct.unpack('!L', socket.inet_aton(external_ip))[0]
                if not (data.lower() in self.countries.keys()):
                   return False
                return self.binary_search(self.countries, data.lower(), external_ip)
            except struct.error:
                return False
        else:
            # if it is a single IP address.
            if(self.is_IP_Prefix(data) == -1): # 1.2.3.4
                return data == external_ip
            else: # if data is IP prefix.
                return self.range_for_CIDR(data, external_ip)

    """ Returns True if the external IP address is within the range of the
        IP prefix."""
    def within_range(self, start_port, end_port, external_ip):
        return external_ip >= start_port and external_ip <= end_port

    """ Check if the data is an IP prefix."""
    def is_IP_Prefix(self, data):
        return data.find('/')

    """ Checks the External port. If the external port meets the requirements,
        then True is returned. Else, False is returned."""
    def check_externalPort(self, data, external_port):
        # A single value.
        if(data.find('-') == -1):
            return external_port == int(data)
        else: # if it is in a range.
            lst = data.split('-')
            lst[0] = lst[0].lstrip().rstrip()
            lst[1] = lst[1].lstrip().rstrip()
            return self.within_range(int(lst[0]), int(lst[1]), external_port)

    """ Returns True if packet info matches DNS Protocol Rules, else returns False."""
    def matches_dns_rules(self, dns_domain_name, rules_domain_name, QDCOUNT, QTYPE, QCLASS):
        return self.dns_match(dns_domain_name, rules_domain_name) and QDCOUNT == 1 and (QTYPE == 1 or QTYPE == 28) and (QCLASS == 1)

    """ Returns the direction of the packet in a string."""
    def packet_direction(self, direction):
        if (direction == PKT_DIR_OUTGOING):
            return 'outgoing'
        else:
            return 'incoming'

    def check_dns_fields(self, QDCOUNT, QTYPE, QCLASS):
        return QDCOUNT != None and QTYPE != None and QCLASS != None

    """Parse DNS packet and returns the QDCOUNT, QTYPE, QCLASS."""
    def parseDNS(self, dns_offset, pckt):
        try:
            QDCOUNT = struct.unpack('!H', pckt[dns_offset + 4 : dns_offset + 6])
            q_offset = dns_offset + 12
            domain_name, qname_len = self.assemble_domain_name(pckt, q_offset)
            QTYPE_offset = q_offset + qname_len + 1
            QTYPE = struct.unpack('!H', pckt[QTYPE_offset : QTYPE_offset + 2])
            QCLASS_offset = QTYPE_offset + 2
            QCLASS = struct.unpack('!H', pckt[QCLASS_offset : QCLASS_offset + 2])
            return QDCOUNT, domain_name.lower(), QTYPE, QCLASS
        except struct.error:
            return None, None, None, None

    """ Assembles the domain name from the DNS QNAME Field """
    def assemble_domain_name(self, pckt, startIndex):
        domain_name = ""
        i, qname_length = startIndex, 0
        while((ord(pckt[i]) != 0)  and (i < len(pckt))):
            length = ord(pckt[i])
            count = 0
            i += 1
            qname_length += 1
            while (count < length):
                domain_name += chr(ord(pckt[i]))
                i += 1
                count += 1
                qname_length += 1
            domain_name += '.'
        return domain_name[0: len(domain_name) - 1], qname_length

    """ Strips the parentheses and comma off the number and converts string to int."""
    def strip_format(self, format_str):
        new_str = str(format_str)
        if (new_str.find('L') > - 1):
            return int(new_str[1: len(new_str) - 3])
        return int(new_str[1: len(new_str) - 2])

    """ Returns the external port and checks to see if there is a socket error. If
        the port is valid, then it returns a number, else it returns 'None'. """
    def handle_external_port(self, pckt, startIndex):
        try:
            ext_port = pckt[startIndex : startIndex + 2]
            ext_port = struct.unpack('!H', ext_port)
            return ext_port
        except struct.error:
            return None

    """ Returns the TYPE field for the IMCP packet."""
    def handle_icmp_packet(self, pckt, startIndex):
        try:
            type_field = pckt[startIndex : startIndex + 1]
            type_field = struct.unpack('!B', type_field)
            return self.strip_format(type_field)
        except struct.error:
            return None

    """ Checks to see if the dns domain name == rules domain name. """
    def dns_match(self, dns_domain_name, rules_domain_name):
        if (rules_domain_name.find('*') == -1):
            return  rules_domain_name == dns_domain_name
        else:
            index = rules_domain_name.find('*')
            if (len(rules_domain_name) == 1 and index == 0):
                return True
            start = dns_domain_name.find(rules_domain_name[index + 1:])
            if ((start) >= 0):
                if (dns_domain_name[start:] == rules_domain_name[index + 1:]):
                    return True
                else:
                    return False
            return False

    def range_for_CIDR(self, ip_cidr, ip_addr):

        ip, network = ip_cidr.split('/')
        network = int(network)
        host =  32 - network

        ip_split = [format(int(x), '08b') for x in ip.split('.')]
        ip_value = str(ip_split[0]) + str(ip_split[1]) + str(ip_split[2]) + str(ip_split[3])
        ip_int = int(ip_value, 2)

        i = host + 1
        bk = 1 << host
        while i < 32:
            bk += 1 << i
            i+=1

        bottom_int = ip_int & bk
        i = 0
        tk = 0
        while i < host:
            tk += 1 << i
            i+=1

        top_int = bottom_int + tk
        ip_addr_split = [format(int(x), '08b') for x in ip_addr.split('.')]
        ip_addr_value = str(ip_addr_split[0]) + str(ip_addr_split[1]) + str(ip_addr_split[2]) + str(ip_addr_split[3])
        ip_addr_int = int(ip_addr_value, 2)

        if (ip_addr_int>=bottom_int) and (ip_addr_int <= top_int):
           return True
        else:
            return False
