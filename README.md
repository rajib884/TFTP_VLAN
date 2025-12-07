# TFTP_VLAN

A C-based utility for handling TFTP (Trivial File Transfer Protocol) traffic over VLAN-tagged networks. This project provides packet-level network I/O, TFTP protocol handling, and integration with libpcap/wpcap for live capture and file-based packet analysis.

## Quick Start

### Prerequisites

- **Windows:** npcap or WinPcap installed. Download from [npcap.com](https://npcap.com).

## Architecture

### High-Level Components

- **`main.c`:** Bootstrap, event loop orchestration.
- **`tftp.c`:** TFTP handling (RRQ, ACK, ERROR); transfer state management.
- **`packet.c`:** Ethernet frame assembly, VLAN tag insertion/removal, IP/UDP header construction, checksum calculation, payload extraction.
- **`pcap_fun.c`:** Interface to libpcap/wpcap for capturing live traffic or reading/writing PCAP files.
- **`queue.c`:** Packet queue with fast access to recently accessed item.

## Configuration

Configuration constants (timeouts, retry limits, buffer sizes) are defined in source files. Future versions will consolidate these for easier customization.

## Platform Support

- **Windows:** Requires npcap/WinPcap. Uses `wpcap` headers from vendored files.

## Known Limitations

- IPv4 only.
- TFTP RRQ only (WRQ planned).

## References

- **RFC 1350:** TFTP (Trivial File Transfer Protocol) specification.
- **RFC 2347:** TFTP Option Extension
- **RFC 2348:** TFTP Blocksize Option
- **RFC 2349:** TFTP Timeout Interval and Transfer Size Options
- **RFC 7440:** TFTP Windowsize Option
- **libpcap:** [https://www.tcpdump.org/](https://www.tcpdump.org/)
- **npcap (Windows):** [https://npcap.com/](https://npcap.com/)
- **802.1Q VLAN Tagging:** IEEE 802.1Q standard.
