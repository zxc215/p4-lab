from scapy.all import *
import threading
import binascii
import socket
import time


try:
    # running from tools
    from nfp_pif_rte.RTEInterface import RTEInterface
except ImportError, err:
    # running inplace
    from RTEInterface import RTEInterface

RTEInterface.Connect('127.0.0.1', 20206)
print RTEInterface.Counters.ListP4Counters()


class FuncThread(threading.Thread):
    def __init__(self, target, *args):
        self._target = target
        self._args = args
        threading.Thread.__init__(self)

    def run(self):
        self._target(*self._args)

def processPacketInNewThread(x) :
    t1 = FuncThread(processPacket, x)
    t1.start()

def processPacket(packet):
    if packet[Ether]:
        eth_src,eth_dst = parse_Ether(packet)

        if packet[IP]:
            #decimal string
            ip_src,ip_dst,proto = parse_IP(packet)
            #hex string
            ip_src_hex = convert_ip_to_hex(ip_src)
            ip_dst_hex = convert_ip_to_hex(ip_dst)
            proto_hex = '{0:#0{1}x}'.format(packet[IP].proto,4)

            if int(packet[IP].proto) == 6:
                #decimal string
                sport,dport = parse_TCP(packet)
                #hex string
                sport_hex = '{0:#0{1}x}'.format(packet[TCP].sport,6)
                dport_hex = '{0:#0{1}x}'.format(packet[TCP].dport,6)
            elif int(packet[IP].proto) == 17:
                #decimal string
                sport,dport = parse_UDP(packet)
                #hex string
                sport_hex = '{0:#0{1}x}'.format(packet[UDP].sport,6)
                dport_hex = '{0:#0{1}x}'.format(packet[UDP].dport,6)


            try:
                print "Start Adding Rule:"
                print 'table_add flow _nop %s %s %s %s %s =>' % (ip_src,ip_dst,proto,sport,dport)

                tbl_id = 'flow'
                rule_name = 'set_by_controller' + time.time()
                default_rule = False
                actions = '{  "type" : "_nop"  }'
                match = '{ "ipv4.srcAddr" : {  "value" : "%s" }, "ipv4.dstAddr" : {  "value" : "%s" }, "ipv4.protocol" : {  "value" : "%d" }, "l4.sport" : {  "value" : "%d" }, "l4.dport" : {  "value" : "%d" } }' % \
                        (ip_src, ip_dst, proto, sport, dport)
                with threading.Lock():
                    RTEInterface.Tables.AddRule(tbl_id, rule_name, default_rule, match, actions, 1)


            except Exception, err:
                print("Exception")
                print(err)


def parse_Ether(packet):
    eth_src = str(packet[Ether].src)
    eth_dst = str(packet[Ether].dst)
    return eth_src,eth_dst

def parse_IP(packet):
    ip_src = str(packet[IP].src)
    ip_dst = str(packet[IP].dst)
    proto = str(packet[IP].proto)
    return ip_src,ip_dst,proto

def parse_TCP(packet):
    sport = str(packet[TCP].sport)
    dport = str(packet[TCP].dport)
    return sport,dport

def parse_UDP(packet):
    sport = str(packet[UDP].sport)
    dport = str(pakcet[UDP].dport)
    return sport,dport

def convert_ip_to_hex(string):
    return '0x'+binascii.hexlify(socket.inet_aton(string))

#def main():
#    global CONTROLLER_PORT
#    sniff(iface=CONTROLLER_PORT, prn=lambda x: processPacketInNewThread(x))


#if __name__ == '__main__':
#    main()