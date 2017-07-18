#!/usr/bin/env python

# imports that won't cause errors
import sys
import os
import signal
import subprocess
from threading import Thread
from time import sleep
import datetime
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR) # scapy, please shut up..

# terminal colors
RED = "\033[1;31m"  
BLUE = "\033[1;34m"
CYAN = "\033[1;36m"
GREEN = "\033[1;32m"
YELLOW = "\33[1;93m"
NORMAL = "\033[0;0m"
BOLD = "\033[;1m"

def auto_installer():
    '''
    Just installing required modules
    if they do not already exist
    '''
    print("{R}ERROR: Modules missing.{N}".format(R=RED, N=NORMAL))
    inst = raw_input("Do you want to automatically install all requirements? (y/n): ").lower()

    if inst in ('y', 'yes'):
        print("[{Y}*{N}] Installing requirements, please stand by...".format(Y=YELLOW, N=NORMAL))
        subprocess.call("sudo pip install netifaces", shell=True)
        subprocess.call("sudo apt-get install python-scapy -y > {}".format(os.devnull), shell=True)
        subprocess.call("sudo apt-get install python-nmap -y > {}".format(os.devnull), shell=True)
        subprocess.call("sudo apt-get install python-nfqueue -y > {}".format(os.devnull), shell=True)
	subprocess.call("sudo apt-get install nmap -y > {}".format(os.devnull), shell=True)
        sys.exit("\n[{G}+{N}] Requirements installed.\n".format(G=GREEN, N=NORMAL))

    sys.exit(0)

'''
Usually modules that need to be installed
'''
try:
    import netifaces
    from scapy.all import *
    import nfqueue
    import nmap
except ImportError:
    auto_installer()

from src import *
def get_option():
    '''
    Handling the user's input
    '''
    while True:
        raw_option = raw_input("{N}#{R}>{N} ".format(N=NORMAL, R=RED)).lower()
        if raw_option == "help":
            return raw_option

        try:
            option = int(raw_option)
        except ValueError:
            print("{R}ERROR: Option is invalid.{N}".format(R=RED, N=NORMAL))
            continue

        if 0 < option <= 12:
            return option
        else:
            print("{R}ERROR: Option is invalid.{N}".format(R=RED, N=NORMAL))
            continue

def handle_option(option):
    '''
    Assgning functions depending on what the user chose
    '''
    if option == 1:
        host_scan(False)
    if option == 2:
        host_scan(True)
    if option == 3:
        wifi_scan()
    if option == 4:
        arp_spoof()
    if option == 5:
        dns_sniff()
    if option == 6:
        deauth_attack()
    if option == 7:
        deauth_all_attack()
    if option == 8:
        arp_kick()
    if option == "help":
        printings.print_help()

def clear_screen():
    '''
    Simply calling 'clear'''
    subprocess.call("sudo clear", shell=True)

def get_interface():
    clear_screen()

    print("{Y}Select a suitable network interface:\n{N}".format(Y=YELLOW, N=NORMAL))

    available_interfaces = netifaces.interfaces()

    for x in range(len(available_interfaces)):
        print("   {N}[{R}{num}{N}] {iface}".format(N=NORMAL, R=RED, num=x+1, iface=available_interfaces[x]))

    print("\n")

    while True:
        raw_interface = raw_input("{N}#{R}>{N} ".format(N=NORMAL, R=RED))

        try:
            interface = int(raw_interface)
        except ValueError:
            print("{R}ERROR: Please enter a number.{N}".format(R=RED, N=NORMAL))
            continue

        if 0 < interface <= len(available_interfaces):
            return available_interfaces[interface-1]
        else:
            print("{R}ERROR: Wrong number.{N}".format(R=RED, N=NORMAL))

def enable_mon_mode(interface):
    # enable monitoring mode to capture and send packets

    try:
        subprocess.call("sudo ip link set {} down".format(interface), shell=True)
        mon = subprocess.Popen(["sudo", "iwconfig", interface, "mode", "monitor"], stderr=subprocess.PIPE)
        for line in mon.stderr:
            if "Error" in line:
                sys.exit("\n{R}The selected interface can't be used.{N}\n".format(R=RED, N=NORMAL))

        subprocess.call("sudo ip link set {} up".format(interface), shell=True)
    except Exception:
        sys.exit("\n{R}ERROR: Not able to activate monitor mode on selected interface.{N}\n".format(R=RED, N=NORMAL))

def enable_ip_forwarding():
    ipfwd = open('/proc/sys/net/ipv4/ip_forward', 'r+')
    ipfwd.write('1\n')
    ipfwd.close()

def disable_ip_forwarding():
    ipfwd = open('/proc/sys/net/ipv4/ip_forward', 'r+')
    ipfwd.write('0\n')
    ipfwd.close()

def get_gateway_ip():
    # get the 'default' gateway

    try:
        return netifaces.gateways()['default'][netifaces.AF_INET][0]
    except KeyError:
        print("\n{R}ERROR: Unable to retrieve gateway IP address.\n{N}".format(R=RED, N=NORMAL))
        return raw_input("Please enter gateway IP address manually: ")

def get_local_ip(interface):
    try:
        local_ip = netifaces.ifaddresses(interface)[netifaces.AF_INET][0]['addr']
        if local_ip == "127.0.0.1" or local_ip == "ff:ff:ff:ff:ff:ff":
            sys.exit("\n{R}ERROR: Invalid network interface.{N}\n".format(R=RED, N=NORMAL))
        return local_ip
    except KeyError:
        print("\n{R}ERROR: Unable to retrieve local IP address.{N}\n")
        return raw_input("Please enter your local IP address manually: ")

def get_mac_by_ip(ipaddr):
    # get the MAC by sending ARP packets to the desired IP

    ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ipaddr), retry=2, timeout=7)
    for snd, rcv in ans:
        try:
            return rcv[Ether].src
        except KeyError:
            print("\n{R}ERROR: Unable to retrieve MAC address from IP address: {N}{ip}\n".format(R=RED, N=NORMAL, ip=ipaddr))
            return raw_input("Please enter MAC address manually: ")

def host_scan(advanced_scan=False):
    '''
    This searches for hosts in the network using python-nmap.
    Informations like: IP, MAC, Vendor, OS and open ports can be gathered.
    The function uses 'scan.py' located in the local 'build' folder.
    '''

    interface = get_interface()
    
    hostscan = scan.HostScan(interface)
    ip_range = hostscan.get_range()

    if advanced_scan:
        hostscan.advanced_scan = True

    clear_screen()
    
    print("{N}The following IP range will be scanned with NMAP: {G}{ipr}{N}".format(G=GREEN, N=NORMAL, ipr=ip_range))
    print("Press {Y}'Enter'{N} to agree or enter your custom IP range.".format(Y=YELLOW, N=NORMAL))
    ipr_change = raw_input("{N}#{R}>{N} ".format(N=NORMAL, R=RED))
    if ipr_change:
        ip_range = ipr_change
    
    clear_screen()

    if advanced_scan:
        # print a different message, since the advanced scan can take up to several minutes
        print("[{Y}*{N}] Scanning the network. This will take some time.".format(Y=YELLOW, N=NORMAL))
    else:
        print("[{Y}*{N}] Scanning the network...".format(Y=YELLOW, N=NORMAL))
        
    hostscan.do_scan(ip_range)
    hosts = hostscan.get_hosts()

    clear_screen()
    printings.host_scan()

    for mac in hosts:
        # print out gathered informations for each host in the network

        print("<<<-----------------------   {Y}{ip}{N}   ----------------------->>>\n".format(Y=YELLOW, N=NORMAL, ip=hosts[mac]["ip"]))

        if hosts[mac]["gateway"]:
            print("{R}IP:{N}      {Y}{ip} {R}(gateway){N}\n{R}MAC:{N}     {mac}\n{R}Name:{N}    {name}\n{R}Vendor:{N}  {vendor}".format(
                R=RED,
                N=NORMAL,
                Y=YELLOW,
		ip=hosts[mac]['ip'],
            	mac=mac.upper(),
            	vendor=hosts[mac]['vendor'],
            	name=hosts[mac]['name']))
        else:
            print("{R}IP:{N}      {Y}{ip}\n{R}MAC:{N}     {mac}\n{R}Name:{N}    {name}\n{R}Vendor:{N}  {vendor}".format(
                R=RED,
            	N=NORMAL,
	        Y=YELLOW,
            	ip=hosts[mac]['ip'],
            	mac=mac.upper(),
            	vendor=hosts[mac]['vendor'],
            	name=hosts[mac]['name']))

        if advanced_scan:
            if not hosts[mac]["os"]:
                print("{R}OS:{N}      Unknown Operating System\n".format(R=RED, N=NORMAL))
            else:
                '''
                The following dict is created by python-nmap.
                It really is a mess
                '''
                os_list = {}
		
                for item in hosts[mac]["os"]:
                    if not item[0] or not item[1]:
                        continue
                    if item[0] in os_list:
                        if item[1] not in os_list[item[0]]:
                            os_list[item[0]].append(item[1])
                    else:
                        os_list[item[0]] = [item[1]]

                    os_str = "{R}OS:     {N} "
                    for os in os_list:
                        os_str += "{} ".format(os)
                        for gen in os_list[os]:
                            if gen == os_list[os][-1]:
                                os_str += "{}\n         ".format(gen)
                            else:
                                os_str += "{}/".format(gen)

                    if not os_list:
                        os_str = "{R}OS:{N}      Unknown Operating System\n".format(R=RED, N=NORMAL)

                print(os_str.format(R=RED, N=NORMAL))

            if not hosts[mac]["open_ports"]:
                print("{R}Ports:{N}   No open ports".format(R=RED, N=NORMAL))
            else:
                open_ports = hosts[mac]["open_ports"]
                port_str = "{R}Ports:{N}   ".format(R=RED, N=NORMAL)
                port_len = len(port_str)

                for port in open_ports.keys()[1:]:
                    name = open_ports[port]
                    if not name:
                        name = "Unkown Port"

                    if port == open_ports.keys()[1]:
                        port_str += "{G}open   {Y}{p}{N} ({name})\n".format(G=GREEN, Y=YELLOW, N=NORMAL, p=port, name=name)
                    elif port == open_ports.keys()[-1]:
                        port_str += "         {G}open   {Y}{p}{N} ({name})".format(G=GREEN, Y=YELLOW, N=NORMAL, p=port, name=name)
                    else:
                        port_str += "         {G}open   {Y}{p}{N} ({name})\n".format(G=GREEN, Y=YELLOW, N=NORMAL, p=port, name=name)
		
                if port_len == len(port_str):
                    print("{R}Ports:{N}   No open ports".format(R=RED, N=NORMAL))
                else:
                    print(port_str)

        print("\n")

    print("{R}{num}{N} hosts up.\n".format(R=RED, N=NORMAL, num=len(hosts)))

def wifi_scan():
    '''
    This will perform a basic Access-Point scan.
    Informations like WPS, Encryption, Signal Strength, ESSID, ... will be shown for every available AP.
    The function uses 'scan.py' located in the local 'build' folder.
    '''

    interface = get_interface()
    enable_mon_mode(interface)

    wifiscan = scan.WifiScan(interface)
    wifiscan.do_output = True

    hopT = Thread(target=wifiscan.channelhop, args=[])
    hopT.daemon = True
    hopT.start()

    # This decay is needed to avoid issues concerning the Channel-Hop-Thread
    sleep(0.2)
    
    try:
        wifiscan.do_scan()
    except socket.error:
        print("{R}ERROR: Network-Interface is down.{N}".format(R=RED, N=NORMAL))
        sys.exit(0)

def get_targets_from_hosts(interface):
    '''
    This will scan the network for hosts and print them out.
    It lets you choose the targets for your attack.
    '''

    targets = {}
    available_hosts = {}
    cntr = 1

    hostscan = scan.HostScan(interface)
    ip_range = hostscan.get_range()

    clear_screen()
    
    print("{N}The following IP range will be scanned with NMAP: {G}{ipr}{N}".format(G=GREEN, N=NORMAL, ipr=ip_range))
    print("Press {Y}'Enter'{N} to agree or enter your custom IP range.".format(Y=YELLOW, N=NORMAL))
    
    ipr_change = raw_input("{N}#{R}>{N} ".format(N=NORMAL, R=RED))
    if ipr_change:
        ip_range = ipr_change
    
    clear_screen()
    
    print("[{Y}*{N}] Scanning the network...".format(Y=YELLOW, N=NORMAL))
    
    hostscan.do_scan(ip_range)
    hosts = hostscan.get_hosts()
    
    clear_screen()
    
    if len(hosts) < 1:
        print("\n{R}No hosts found :({N}\n".format(R=RED, N=NORMAL))
        sys.exit(0)
    
    print("{Y}Available hosts:{N}\n\n".format(Y=YELLOW, N=NORMAL))

    for mac in hosts.keys():
        if hosts[mac]['gateway']:
            del hosts[mac]
            continue
        else:
            available_hosts[len(available_hosts)+1] = mac
            print("   {R}[{N}{ID}{R}] {N}{mac} ({ip}) | {name}".format(
                R=RED,
                N=NORMAL,
                ID=len(available_hosts),
                mac=mac.upper(),
                ip=hosts[mac]['ip'],
                name=hosts[mac]['name']))

    print("\n\nChoose the target(s) seperated by {R}','{N} (comma).\nType {R}'all'{N} to choose everything listed.".format(R=RED, N=NORMAL))

    while True:
        targets_in = raw_input("{N}#{R}>{N} ".format(N=NORMAL, R=RED)).lower()
        targets_in = targets_in.replace(" ", "")

        if targets_in == "all":
            for mac in hosts:
                targets[mac] = hosts[mac]["ip"]
            return targets

        if "," in targets_in:
            targets_list = targets_in.split(",")

            if all(x.isdigit() for x in targets_list) and all(0 < int(y) <= len(available_hosts) for y in targets_list):
                for target in targets_list:
                    for num in available_hosts:
                        if int(target) == num:
                            targets[available_hosts[num]] = hosts[available_hosts[num]]["ip"]
                return targets
            else:
                print("{R}ERROR: Invalid input.{N}".format(R=RED, N=NORMAL))
                continue
        else:
            if targets_in.isdigit() and 0 < int(targets_in) <= len(available_hosts):
                targets[available_hosts[int(targets_in)]] = hosts[available_hosts[int(targets_in)]]["ip"]
                return targets
            else:
                print("{R}ERROR: Invalid input.{N}".format(R=RED, N=NORMAL))
                continue


def arp_kick():
    interface = get_interface()
    targets = get_targets_from_hosts(interface)
    gateway_ip = get_gateway_ip()
    gateway_mac = get_mac_by_ip(gateway_ip)
    local_ip = get_local_ip(interface)
    
    arpspoof = spoof.ARPSpoof(targets, gateway_ip, gateway_mac, interface)

    printings.arp_kick()

    for mac in targets:
        print("{G} ->{N}  {mac} ({ip})".format(G=GREEN, N=NORMAL, mac=mac.upper(), ip=targets[mac]))

    disable_ip_forwarding()

    try:
        arpspoof.arp_spoof()
    except:
        print("\n{R}RESTORING TARGETS. PLEASE STAND BY!{N}".format(R=RED, N=NORMAL))
        arpspoof.restore_arp()

def arp_spoof():
    interface = get_interface()
    targets = get_targets_from_hosts(interface)
    gateway_ip = get_gateway_ip()
    gateway_mac = get_mac_by_ip(gateway_ip)

    arpspoof = spoof.ARPSpoof(targets, gateway_ip, gateway_mac, interface)

     #printings.arp_spoof()

    for mac in targets:
        print(" {G}->{N}  {mac} ({ip})".format(G=GREEN, N=NORMAL, mac=mac.upper(), ip=targets[mac]))

    enable_ip_forwarding()

    try:
        arpspoof.arp_spoof()
    except:
        print("\n{R}RESTORING TARGETS. PLEASE STAND BY!{N}".format(R=RED, N=NORMAL))
        arpspoof.restore_arp()

def dns_sniff():
    interface = get_interface()
    targets = get_targets_from_hosts(interface)
    gateway_ip = get_gateway_ip()
    gateway_mac = get_mac_by_ip(gateway_ip)
    local_ip = get_local_ip(interface)

    enable_ip_forwarding()
    
    arpspoof = spoof.ARPSpoof(targets, gateway_ip, gateway_mac, interface)
    dnssniff = sniff.DNSSniff(local_ip, interface)

    spoofT = Thread(target=arpspoof.arp_spoof, args=[])
    spoofT.daemon = True
    spoofT.start()

    clear_screen()
    printings.dns_sniff()
    print("\n[{Y}*{N}] Listening for DNS packets...\n".format(Y=YELLOW, N=NORMAL))
    
    try:
        dnssniff.dns_sniff()
    except:
        print("\n{R}RESTORING TARGETS. PLEASE STAND BY!{N}".format(R=RED, N=NORMAL))
        arpspoof.restore_arp()
        disable_ip_forwarding()
        
def deauth_attack():
    interface = get_interface()
    enable_mon_mode(interface)

    wifiscan = scan.WifiScan(interface)
    wifiscan.do_output = False
    wifiscan.timeout = 8

    hopT = Thread(target=wifiscan.channelhop, args=[])
    hopT.daemon = True
    hopT.start()

    clear_screen()
    print("[{Y}*{N}] Searching for WiFi-Networks... (10 sec.)\n".format(Y=YELLOW, N=NORMAL))

    wifiscan.do_scan()
    wifiscan.channelhop_active = False
    access_points = wifiscan.get_access_points()

    if len(access_points) < 1:
        print("{R}No networks found :({N}".format(R=RED, N=NORMAL))
        sys.exit(0)

    print("{Y}Available networks:{N}\n".format(Y=YELLOW, N=NORMAL))

    num = 1
    for bssid in access_points.keys():
        space = 2
        if num > 9:
            space = 1

        essid = access_points[bssid]["essid"]
        access_points[bssid]["num"] = num
        print("   [{R}{num}{N}]{sp}{bssid} | {essid}".format(num=num, R=RED, N=NORMAL, bssid=bssid.upper(), essid=essid, sp=" "*space))

        num += 1
    
    print("\nSeperate multiple targets with {R}','{N} (comma).".format(R=RED, N=NORMAL))

    while True:
        ap_in = raw_input("#{R}>{N} ".format(R=RED, N=NORMAL))
        ap_in = ap_in.replace(" ", "")

        if not "," in ap_in:
            ap_list_in = [ap_in]
        else:
             ap_list_in = ap_in.split(",")

        if not all(x.isdigit() for x in ap_list_in) or not all(int(x) in range(len(access_points)+1) for x in ap_list_in):
            print("{R}ERROR: Invalid input.{N}".format(R=RED, N=NORMAL))
            continue

        break

    clear_screen()
    printings.deauth_ap()

    ap_list = {}

    for bssid in access_points:
        for num in ap_list_in:
            if int(num) == access_points[bssid]["num"]:
                print(" ->   {bssid} | {essid}".format(bssid=bssid.upper(), essid=access_points[bssid]["essid"]))
                ap_list[bssid] = access_points[bssid]["ch"]

    print("\n")

    deauthent = deauth.Deauth(ap_list, interface)
    deauthent.start_deauth()

def deauth_all_attack():
    interface = get_interface()
    enable_mon_mode(interface)

    deauthent_all = deauth.DeauthAll(interface)
    deauthent_all.start_deauth_all()

def main():
    # Signal handler to catch KeyboardInterrupts
    def signal_handler(signal, frame):
        print("")
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)

    conf.verb = 0 # scapy, QUITE

    clear_screen()
    printings.print_banner()
    printings.print_options()

    option = get_option()
    handle_option(option)

if __name__ == "__main__":
    main()
