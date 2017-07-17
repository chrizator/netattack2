RED = "\033[1;31m"  
BLUE = "\033[1;34m"
CYAN = "\033[1;36m"
GREEN = "\033[1;32m"
YELLOW = "\33[1;93m"
NORMAL = "\033[0;0m"
BOLD = "\033[;1m"

def print_banner():
    print("{Y}    _   _________________  _______________   ________ __{R}___ \n" \
          "{Y}   / | / / ____/_  __/   |/_  __/_  __/   | / ____/ //_/{R}__ \\\n" \
          "{Y}  /  |/ / __/   / / / /| | / /   / / / /| |/ /   / ,<  _{R}_/ /\n" \
          "{Y} / /|  / /___  / / / ___ |/ /   / / / ___ / /___/ /| |{R}/ __/ \n" \
          "{Y}/_/ |_/_____/ /_/ /_/  |_/_/   /_/ /_/  |_\____/_/ |_{R}/____/{N}\n" \
          "                   {R}b y   c h r i z a t o r{N}\n\n".format(Y=YELLOW, N=NORMAL, R=RED))

def print_options():
    print("{Y}SCANNING                      {Y}DEAUTHING\n" \
          "{N}[{R}1{N}]  Host Scan                {N}[{R}6{N}]  Deauth Access-Point(s)\n" \
          "{N}[{R}2{N}]  Advanced Host Scan       {N}[{R}7{N}]  Deauth All Access-Points\n" \
          "{N}[{R}3{N}]  Access-Point Scan\n" \
          "                              {Y}KICKING\n" \
          "{Y}SPOOFING/SNIFFING             {N}[{R}8{N}]  Kick Hosts (ARP-Spoof)\n" \
          "{N}[{R}4{N}]  ARP Spoofing\n" \
          "{N}[{R}5{N}]  DNS Sniffing\n\n\n" \
          "Type {R}'help'{N} to get detailed informations.".format(Y=YELLOW, R=RED, N=NORMAL))

def print_help():
    print("""
------------
| SCANNING |
------------

  -> Host Scan
     ---------
     It will search your network for online hosts using python-nmap. It prints out 
     MAC, IP, Hostaname and Vendor Informations for each host found.
     
  -> Advanced Host Scan
     ------------------
     It does basically the same as the Host Scan, but collects more detailed informations such as
     Operating System and Open Ports.

  -> Wifi Scan
     ---------
     This obviously scans your area for available WiFi-Networks by sniffing for beacon frames.
     The following informations will be extracted from the beacon frame: 
     ESSID, BSSID, Encryption Type, Channel, WPS and Signal Strength

-----------
| KICKING |
-----------

  -> Kick Hosts
     ----------
     This will ARP-Spoof your targets (ARP-Spoofing is explained below) but disable
     IP-Forwarding. So the packets sent by the targets won't even reach the gateway.

-----------------------
| SPOOFING / SNIFFING |
-----------------------

  -> ARP-Spoofing
     ------------
     ARP-Packets will be sent to your targets and your gateway with wrong informations.
     Your targets traffic will be redirected to you and afterwards to the gateway.

  -> DNS-Sniffing
     ------------
     It performs a simple ARP-Spoofing attack and filters out DNS-Queries.

-------------
| DEAUTHING |
-------------

  -> Deauth Access-Points
     --------------------
     Deauthentication frames will be sent to the selected Access-Points, which
     will disconnect the users wirelessly connected to the Access-Point.

  -> Deauth All Access-Points
     ------------------------
     It basically does the same as the Deauth Access-Points option, but
     it will Deauth every found Access-Point. After 120 seconds, a rescan
     will automatically happen.\n""")

def arp_kick():
    print("\n  ___   ______  ______            _   ___      _    \n" \
          " / _ \  | ___ \ | ___ \          | | / (_)    | |   \n" \
          "/ /_\ \ | |_/ / | |_/ /  ______  | |/ / _  ___| | __\n" \
          "|  _  | |    /  |  __/  |______| |    \| |/ __| |/ /\n" \
          "| | | | | |\ \  | |              | |\  \ | (__|   < \n" \
          "\_| |_/ \_| \_| \_|              \_| \_/_|\___|_|\_\\\n")

def dns_sniff():
    print("______   _   _   _____            _____       _  __  __ \n" \
          "|  _  \ | \ | | /  ___|          /  ___|     (_)/ _|/ _|\n" \
          "| | | | |  \| | \ `--.   ______  \ `--. _ __  _| |_| |_ \n" \
          "| | | | | . ` |  `--. \ |______|  `--. \ '_ \| |  _|  _|\n" \
          "| |/ /  | |\  | /\__/ /          /\__/ / | | | | | | |  \n" \
          "|___/   \_| \_/ \____/           \____/|_| |_|_|_| |_|  \n")

def ap_scan():
    print("  ___   ______            _____                 \n" \
          " / _ \  | ___ \          /  ___|                \n" \
          "/ /_\ \ | |_/ /  ______  \ `--.  ___ __ _ _ __  \n" \
          "|  _  | |  __/  |______|  `--. \/ __/ _` | '_ \ \n" \
          "| | | | | |              /\__/ / (_| (_| | | | |\n" \
          "\_| |_/ \_|              \____/ \___\__,_|_| |_|\n\n")

def host_scan():
    print(" _   _           _     _____                 \n" \
          "| | | |         | |   /  ___|                \n" \
          "| |_| | ___  ___| |_  \ `--.  ___ __ _ _ __  \n" \
          "|  _  |/ _ \/ __| __|  `--. \/ __/ _` | '_ \ \n" \
          "| | | | (_) \__ \ |_  /\__/ / (_| (_| | | | |\n" \
          "\_| |_/\___/|___/\__| \____/ \___\__,_|_| |_|\n\n")

def deauth_ap():
    print("______                 _   _        ___  ______ \n" \
          "|  _  \               | | | |      / _ \ | ___ \\\n" \
          "| | | |___  __ _ _   _| |_| |__   / /_\ \| |_/ /\n" \
          "| | | / _ \/ _` | | | | __| '_ \  |  _  ||  __/ \n" \
          "| |/ /  __/ (_| | |_| | |_| | | | | | | || |    \n" \
          "|___/ \___|\__,_|\__,_|\__|_| |_| \_| |_/\_|    \n")

def deauth_all():
    print("______                 _   _            ___  _ _ \n" \
          "|  _  \               | | | |          / _ \| | |\n" \
          "| | | |___  __ _ _   _| |_| |__ ______/ /_\ \ | |\n" \
          "| | | / _ \/ _` | | | | __| '_ \______|  _  | | |\n" \
          "| |/ /  __/ (_| | |_| | |_| | | |     | | | | | |\n" \
          "|___/ \___|\__,_|\__,_|\__|_| |_|     \_| |_/_|_|\n")

