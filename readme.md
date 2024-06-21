This project was started to gain an understanding of how network analysis is done, specifically through capturing network packets and analysing these packets to understand what information is being sent through the network.

using npcap to capture packages - https://npcap.com/

Packet structure

Ethernet frame - (layer 2):
Destination MAC address - 6 bytes
Source MAC Address: 6 bytes
EtherType: 2 bytes (e.g., 0x0800 for IPv4)
Payload: Contains the encapsulated data (IP packet, ARP, etc.)

IP Packet - (Layer 3):
Version: 4 bits
Header Length: 4 bits
Type of Service (ToS): 1 byte
Total Length: 2 bytes
Identification: 2 bytes
Flags and Fragment Offset: 2 bytes
Time to Live (TTL): 1 byte
Protocol: 1 byte (e.g., 6 for TCP, 17 for UDP)
Header Checksum: 2 bytes
Source IP Address: 4 bytes
Destination IP Address: 4 bytes
Options and Padding: Variable length (if any)
Payload: Contains the encapsulated data (TCP segment, UDP datagram, etc.)

TCP Segment - (Layer 4):
Source Port: 2 bytes
Destination Port: 2 bytes
Sequence Number: 4 bytes
Acknowledgment Number: 4 bytes
Data Offset: 4 bits
Flags: 12 bits (e.g., SYN, ACK, FIN)
Window Size: 2 bytes
Checksum: 2 bytes
Urgent Pointer: 2 bytes
Options and Padding: Variable length (if any)
Payload: Contains the application data

UDP Datagram - (Layer 4):
Source Port: 2 bytes
Destination Port: 2 bytes
Length: 2 bytes
Checksum: 2 bytes
Payload: Contains the application data



The ethernet header tells us how to interpret the rest of the file

The protocol refers to how the data is processed at the transport layer


Some good resources for understanding pcap functions - https://www.tcpdump.org/pcap.html
