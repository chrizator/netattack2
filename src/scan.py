import nmap
import sys
import netifaces
from time import sleep
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR) # scapy, psst!
from scapy.all import *
import subprocess
import os
import printings

RED = "\033[1;31m"  
NORMAL = "\033[0;0m"
GREEN = "\033[1;32m"
YELLOW = "\033[1;93m"

conf.verb = 0 # shhh scapy...

class HostScan(object):
    def __init__(self, interface):
        self.interface = interface
        self.hosts = {}
        self.advanced_scan = False
        try:
            self.local_ip = netifaces.ifaddresses(interface)[netifaces.AF_INET][0]['addr']
        except KeyError:
            self.local_ip = raw_input("\n{R}ERROR: Unable to retrieve local IP address\n{N}Please enter manually: ".format(R=RED, N=NORMAL))
        try:
            self.gateway_ip = netifaces.gateways()["default"][netifaces.AF_INET][0]
        except KeyError:
            self.gateway_ip = raw_input("\n{R}ERROR: Unable to retrieve gateway IP address\n{N}Please enter manually: ".format(R=RED, N=NORMAL))

    def get_range(self):
        try:
            netmask = netifaces.ifaddresses(self.interface)[netifaces.AF_INET][0]["netmask"]
        except KeyError:
            netmask = raw_input("\n{R}ERROR: Unable to retrieve subnetmask.\n{N}Please enter manually: ".format(R=RED, N=NORMAL))
        cidr = sum((bin(int(x)).count("1")) for x in str(netmask).split("."))
        ip = ".".join(self.local_ip.split(".")[:-1]) + ".0"
        return "{}/{}".format(ip, cidr)

    def do_scan(self, ip_range):
        nm = nmap.PortScanner()
        if self.advanced_scan:
            result = nm.scan(hosts=ip_range, arguments="-sS -O")
        else:
            result = nm.scan(hosts=ip_range, arguments="-sP")

        for _, item in result["scan"].iteritems():
            if item["status"]["state"] == "up":
                try:
                    ip = item["addresses"]["ipv4"]
                    if ip == self.local_ip:
                        continue
                except KeyError:
                    ip = "Unknown IP"
                try:
                    mac = item["addresses"]["mac"].lower()
                except KeyError:
                    mac = "Unknown MAC"
                name = item["hostnames"][0]["name"]
                try:
                    vendor = item["vendor"][mac.upper()]
                except KeyError:
                    vendor = "Unknown Vendor"

                if not ip:
                    ip = "Unknown IP"
                if not mac:
                    mac = "Unknown MAC"
                if not name:
                    name = "Unknown Name"
                if not vendor:
                    vendor = "Unknown Vendor"

                gateway = False
                if ip == self.gateway_ip:
                    gateway = True
                

                if self.advanced_scan:
                    try:
                        osmatch = item["osmatch"]
                        os_list = []

                        for os in osmatch:
                            for x in os["osclass"]:
                                try:
                                    os_list.append([x["osfamily"], x["osgen"]])
                                except KeyError:
                                    continue
                    except KeyError:
                        os_list = None
                    try:
                        open_ports = {}
                        for port in item["tcp"]:
                            try:
                                open_ports[port] = item["tcp"][port]["name"]
                            except KeyError:
                                open_ports[port] = None
                                continue
                    except KeyError:
                        open_ports = None


                if mac not in self.hosts:
                    if self.advanced_scan:
                        self.hosts[mac] = {"ip": ip, "name": name, "vendor": vendor, "gateway": gateway, "os": os_list, "open_ports": open_ports}
                    else:
                        self.hosts[mac] = {"ip": ip, "name": name, "vendor": vendor, "gateway": gateway}
                else:
                    continue

    def get_hosts(self):
        return self.hosts


class WifiScan(object):
    def __init__(self, interface):
        self.interface = interface
        self.channelhop_active = True
        self.do_output = True
        self.timeout = 0
        self.access_points = {}

    def channelhop(self):
        # check if interface supports channel hopping by checking the output of iwconfig
        try:
            DEVNULL = open(os.devnull, "w")
            subprocess.check_output("iwconfig {} channel {}".format(self.interface, 13), shell=True, stderr=DEVNULL)
        except subprocess.CalledProcessError:  # raised by subprocess if error occurred
            sys.exit("\n{R}ERROR: Your selected interface doesn't support channel hopping.{N}\n".format(R=RED, N=NORMAL))

        channel = 1
        while channel < 12 and self.channelhop_active:
            subprocess.call("sudo iwconfig {} channel {}".format(self.interface, channel), shell=True)
            sleep(0.2)
            
            if channel >= 11:
                channel = 1
                continue

            channel += 1

    def stop_channelhop(self):
        self.channelhop_active = False


    def do_scan(self):
        def callback(packet):
            bssid = packet[Dot11].addr2
            if bssid not in self.access_points:
                packet_elt = packet[Dot11Elt]
                essid = ""
                encryption = ""
                channel = 0
                wps = "{R}No{N}".format(R=RED, N=NORMAL)
                try:
                    strength = ord(packet[RadioTap].notdecoded[-4]) -256
                    if strength < 0:
                        strength += 100
                except IndexError:
                    strength = "?"

                while isinstance(packet_elt, Dot11Elt):
                    #ID 0 = SSID
                    if packet_elt.ID == 0:
                        essid = packet_elt.info
                        if essid == "":
                           essid = "Hidden ESSID"

                    # ID 3 = Channel
                    if packet_elt.ID == 3:
                        try:
                            channel = ord(packet_elt.info)
                        except TypeError:
                            channel = "?"

                    # ID 48 = RSNinfo -> cypher and enc. informations
                    if packet_elt.ID == 48:
                        encryption = "WPA2"

                    # ID 221 = vendor informations
                    if packet_elt.ID == 221 and "No" in wps:
                        try:
                            if packet_elt.info[3] == "\x04":
                                wps = "{G}Yes{N}".format(G=GREEN, N=NORMAL)
                        except IndexError:
                            pass
                    if not encryption and packet_elt.ID == 221 and packet_elt.info.startswith("\x00P\xf2\x01\x01\x00"):
                        encryption = "WPA1"
                    
                    packet_elt = packet_elt.payload

                if not encryption:
                    beacon_cap = packet.sprintf("%Dot11Beacon.cap%")
                    if "+privacy+" in beacon_cap:
                        # definitly encrypted, but not sure if WEP or higher
                        encryption = "WEP+"
                    else:
                        encryption = "OPEN"
                if not channel:
                    channel = "?"

                if self.do_output:
                    WifiScan.output(self, bssid.upper(), essid, channel, encryption, strength, wps)
                self.access_points[bssid] = {"essid": essid, "enc": encryption, "ch": channel, "stren": strength, "wps": wps}

        if self.do_output:
            subprocess.call("sudo clear", shell=True)
            printings.ap_scan()
            print("[{G}*{N}] Channel-Hopping\n".format(G=GREEN, N=NORMAL))
            print("BSSID{}CH   ENC    STRENG  WPS  ESSID".format(" "*15))
            print("-----{}--   ---    ------  ---  -----\n".format(" "*15))

        try:
            if not self.timeout:
                sniff(prn=callback, iface=str(self.interface), lfilter=lambda x: Dot11Beacon in x, store=0)
            else:
                sniff(prn=callback, iface=str(self.interface), lfilter=lambda x: Dot11Beacon in x, timeout=self.timeout, store=0)
        except Exception as e:
            print("\nAn unexpected error occurred: {}\n".format(e))
            sys.exit(0)

    def output(self, bssid, essid, channel, encryption, strength, wps):
        channel_space = " "*4
        wps_space = " "*3
        strength_space = " "*2
        if channel > 9 and not channel == "?":
            channel_space = " "*3
        if "Yes" in wps:
            wps_space = " "*2

        if str(strength).isdigit():
            if strength < 10:
                strength_space = " "*3
            if strength < 50:
                strength = "{R}{strength}{N}".format(R=RED, strength=strength, N=NORMAL)
            elif strength < 75:
                strength = "{Y}{strength}{N}".format(Y=YELLOW, strength=strength, N=NORMAL)
            elif strength <= 100:
                strength = "{G}{strength}{N}".format(G=GREEN, strength=strength, N=NORMAL)

            print("{bssid}   {ch}{ch_s}{enc}   {stren}{str_s}dB  {wps}{wps_s}{essid}".format(bssid=bssid, ch=channel, ch_s=channel_space,
                                                                                         enc=encryption, essid=essid, stren=strength,
                                                                                         wps=wps, wps_s=wps_space, str_s=strength_space))
        else:
	    print("{bssid}   {ch}{ch_s}{enc}   {stren}{str_s}    {wps}{wps_s}{essid}".format(bssid=bssid, ch=channel, ch_s=channel_space,
                                                                                         enc=encryption, essid=essid, stren=strength,
                                                                                         wps=wps, wps_s=wps_space, str_s=strength_space))
    def get_access_points(self):
        return self.access_points
