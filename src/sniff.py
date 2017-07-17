from scapy.all import *

class DNSSniff(object):
    def __init__(self, local_ip, interface):
        self.local_ip = local_ip
        self.ip_len = 0
	self.interface = interface
        self.last_ip = ""

    def dns_sniff(self):
        def callback(packet):
            ip = packet[IP].src
            if not packet.haslayer(DNSRR) and ip != self.local_ip:
                content = packet[DNSQR].qname[:-1]
                content = content.split(".")
                content[-2] = "{Y}{cnt}{N}".format(Y=YELLOW, N=NORMAL, cnt=content[-2])
                content = ".".join(content)
                if not self.ip_len:
                    self.ip_len = len(ip)
                if self.ip_len == len(ip):
                    space = 12
                else:
                    space = 12 + (self.ip_len - len(ip))
                
                opt = ""
                if self.last_ip != ip:
                    opt = "\n"
                self.last_ip = ip

                print("{opt}{Y}{ip}{N}{space}{content}".format(opt=opt, ip=ip, space=" "*space, content=content, Y=YELLOW, N=NORMAL))

        sniff(prn=callback, iface=self.interface, filter="port 53", lfilter=lambda x: x.haslayer(DNSQR), store=0)
