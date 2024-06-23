This project was started to gain an understanding of how network analysis is done, specifically through capturing network packets and analysing these packets to understand what information is being sent through the network.

using npcap to capture packages - https://npcap.com/


Physical Layer (Layer 1):
The physical layer deals with the physical transmission of data over a physical medium (e.g., copper wires, fiber optics, wireless radio frequencies).
It defines the electrical, mechanical, procedural, and functional specifications for transmitting raw bits (0s and 1s) over a physical medium.
Examples include Ethernet, Wi-Fi (IEEE 802.11), and SONET.

Data Link Layer (Layer 2):
The data link layer provides reliable data transfer across a physical link.
It ensures that data is transmitted without errors over the physical layer.
It handles framing, error detection and correction, and flow control.
Examples include Ethernet (IEEE 802.3), PPP (Point-to-Point Protocol), and ATM (Asynchronous Transfer Mode).

Network Layer (Layer 3):
The network layer provides logical addressing, routing, and forwarding of packets between different networks.
It handles packet forwarding, routing, and congestion control.
Examples include IPv4, IPv6, ICMP (Internet Control Message Protocol), and ARP (Address Resolution Protocol).

Transport Layer (Layer 4):
The transport layer ensures reliable end-to-end communication between devices across a network.
It provides error recovery, flow control, and retransmission of lost data.
Examples include TCP (Transmission Control Protocol) and UDP (User Datagram Protocol).

Session Layer (Layer 5):
The session layer establishes, manages, and terminates sessions between applications.
It handles synchronization, checkpointing, and recovery of data exchange.
Examples include NetBIOS (Network Basic Input/Output System) and RPC (Remote Procedure Call).

Presentation Layer (Layer 6):
The presentation layer translates, encrypts, or compresses data into a format that is suitable for the application layer.
It handles data formatting, encryption/decryption, and data compression.
Examples include encryption algorithms, ASCII, JPEG, and MPEG.

Application Layer (Layer 7):
The application layer enables communication between applications and provides user interfaces and network services.
It supports a variety of protocols used by applications for tasks such as file transfer, email, and web browsing.
Examples include HTTP, FTP (File Transfer Protocol), SMTP (Simple Mail Transfer Protocol), and DNS (Domain Name System).



Packet header structures

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

The transport protocol refers to how the data is sent across networks

The application protocol refers to the rules and conventions for communication between applications (such as web browsers and servers) over a network. These rely on the transport protocol to establish connections and trasmit data reliably.

Encapsulation - Each layer adds its own header information to the data payload received from the layer above. This process is known as encapsulation.
Decapsulation - At the receiving end, each layer strips off its respective header information to extract and process the payload intended for its higher layer.


Some good resources for understanding pcap functions - https://www.tcpdump.org/pcap.html
