import netfilterqueue
import scapy.all as scapy

def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())  # This will convert the packet payload to scapy packet
    if scapy_packet.haslayer(scapy.Raw):
        print(scapy_packet.show())
        if scapy_packet[scapy.TCP].dport == 80:
            print("HTTP Request")
            if ".exe" in scapy_packet[scapy.Raw].load:
                print("[+] exe Request")
                print(scapy_packet.show())
        elif scapy_packet[scapy.TCP].sport == 80:
            print("HTTP Response")
            print(scapy_packet.show())
    packet.accept() # This will accept the packet and forward it to the client computer allowing him to go that perticular website

queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packet)
queue.run()