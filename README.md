# TFTP_VLAN

A Windows-only, raw packet-level TFTP server supporting VLAN-tagged networks with optional asynchronous FTP file sourcing. Unlike traditional socket-based TFTP servers, this implementation operates at the Ethernet frame level via libpcap/wpcap, enabling transparent VLAN tag handling, IP spoofing, and advanced packet-level control. Supports modern TFTP option extensions (RFC 2348, 2349, 7440) including sliding window transfers for high-performance file delivery.

## Quick Start

### Prerequisites

- **Npcap:** Required for packet capture/transmission. Download from [npcap.com](https://npcap.com).
- **Build Dependencies:** MinGW gcc, libcurl 8.x or higher (pre-built), Windows SDK headers.

### Building

```bash
make              # Build release and debug versions
make release      # Build optimized release version (O2, checksum validation)
make debug        # Build debug version with symbols and verbose output
make clean        # Clean build artifacts
```

### Basic Usage

```bash
# Interactive mode (select interface from list)
main.exe

# Specify interface by name
main.exe -i "Ethernet"

# Server IP/port for TFTP service
main.exe -a 192.168.1.10 -p 69

# Enable verbose logging
main.exe -v
```

Configuration file `tftp.conf` is loaded automatically if present in the working directory.

## How It Works

This application functions as a **raw packet-level TFTP server**, differing fundamentally from traditional socket-based servers:

1. **Packet Capture:** Monitors network interface via libpcap/wpcap, intercepts ARP, ICMP and UDP packets
2. **Frame-Level Processing:** Extracts and assembles Ethernet frames, handles VLAN tags, validates IP/UDP checksums
3. **Session Management:** Creates isolated TFTP sessions per unique client (5-tuple: IP, port, MAC, VLAN ID)
4. **File Sourcing:** Serves files from either:
   - Local filesystem (direct path)
   - Remote FTP server (async download)
5. **Packet Response:** Constructs raw Ethernet frames with proper checksums and transmits back through the same interface

This design enables:
- VLAN preservation and transparent tagging of untagged packets
- IP/MAC spoofing capabilities
- Direct control over packet timing and transmission
- Concurrent multi-session support with configurable block sizes and windowing

## Architecture

### Core Components

- **`main.c`**: Windows event loop bootstrap, interface selection, mutex-based single-instance prevention, WaitForMultipleObjects event handling
- **`packet.c`**: Ethernet/VLAN frame assembly/disassembly, IPv4 header construction, UDP packet generation, ARP/ICMP protocol handlers, checksum calculation
- **`tftp.c`**: TFTP state machine (RRQ/WRQ/DATA/ACK/ERROR/OACK opcodes), option negotiation, session lifecycle, packet queueing, retransmission logic with 5-retry limit
- **`queue.c`**: Linked-list packet queue with fast-access caching for sequential block retrieval
- **`pcap_fun.c`**: libpcap interface abstraction (device enumeration, handle management, packet read/write loops)
- **`ftp_handler.c`**: Asynchronous FTP downloads via libcurl multi-handle, metadata fetching, reference-counted file sharing
- **`cli_config.c`**: CLI argument parsing, configuration file loading, option validation, interface discovery
- **`fast_log.c`**: High-performance logging, terminal color support (auto-detected)

### Data Flow

```
[ Incoming Packet ] 
    ↓
[ pcap_handler() reads frame ]
    ↓
[ Ethernet/VLAN detection & normalization ]
    ↓
[ IPv4/UDP/TFTP parsing ]
    ↓
[ handle_tftp() - State machine dispatch ]
           ↓
       [ RRQ: Establish session, open/fetch file, send OACK or ACK ]
       [ WRQ: Create write session, send ACK ]
       [ ACK: Mark blocks as delivered, send next batch ]
       [ DATA: Receive upload data, send DATA ACK ]
       [ ERROR: Terminate session, log error ]
    ↓
[ Construct response Ethernet frame (with checksums) ]
    ↓
[ Queue packet for transmission, pre-generate next batch ]
    ↓
[ pcap_sendpacket() writes frame via libpcap ]
```

For FTP-sourced files:
```
[ Client RRQ for "ftp://username:password@link/file.bin" ]
    ↓
[ Server calls ftp_request_file() ]
    ↓
[ libcurl metadata fetch ]
    ↓
[ Pre-allocate buffer to exact file size ]
    ↓
[ Start async download via curl_multi, return immediately ]
    ↓
[ Begin TFTP transfer, serve data as it arrives in buffer ]
    ↓
[ FTP handler throttles TFTP if buffer underrun occurs ]
```

## Protocol Support

### TFTP Operations

| Opcode | Mode | Description |
|--------|------|-------------|
| **RRQ** | Server | Read request - client downloads file from server |
| **WRQ** | Server | Write request - client uploads file to server |
| **DATA** | Bidirectional | File data block transmission (1-65535 bytes per block) |
| **ACK** | Bidirectional | Acknowledgment of received DATA block(s) |
| **ERROR** | Bidirectional | Terminate transfer with error code and message |
| **OACK** | Server | Option acknowledgment (RFC 2347) - confirms negotiated parameters |

### TFTP Options (Modern Extensions)

- **RFC 2348 - Blocksize Negotiation** (`blksize`)
  - Allows larger transfer blocks than standard 512 bytes
  - Range: 8 to 65,535 bytes
  - Default: 512 bytes
  - Enables high-speed transfers over low-latency links

- **RFC 2349 - Transfer Size & Timeout** (`tsize`, `timeout`)
  - `tsize`: File size advertisement (bytes). Client declares total file size being requested for validation
  - `timeout`: Retry timeout in seconds (1-60). Configurable packet retransmission interval
  - Default timeout: 1 second

- **RFC 7440 - Sliding Window** (`windowsize`)
  - Multiple blocks sent before waiting for ACK (pipelining)
  - Range: 1 to 65,535 blocks
  - Default: 1 block (stop-and-wait mode)
  - Dramatically improves throughput on high-latency links
  - Example: windowsize=16 allows 16 blocks in-flight simultaneously

### Network Protocols

- **IPv4 only** - No IPv6 support
- **UDP** - Port 69 for incoming RRQ/WRQ; dynamic ports (20001-21015) for active transfers
- **Ethernet II frames** with optional:
  - **VLAN tagging** (IEEE 802.1Q, 802.1ad)
  - **ARP request/reply** - Responds to ARP queries for spoofed IPs
  - **ICMP echo** - Responds to ping (ICMP echo request)
- **Checksum validation** - IPv4, UDP checksums verified (enforced in debug build, optional in release)

## Configuration

Configuration is loaded in priority order: **CLI arguments > config file (tftp.conf) > hardcoded defaults**.

### CLI Arguments

```
-i, --interface <name|GUID>      Network interface to bind to
                                 Can be interface name or GUID
                               
-a, --address <IP>               IP address server advertises (spoofing support)
                                 If different from interface IP, enables IP spoofing mode
                               
-p, --port <port>                UDP port for TFTP service (default: 69)

-l, --list                       Show a list all available interfaces

-bs, --default-block-size <size>  Default block size if client doesn't request
                                 (default: 512 bytes, range: 8-65535)

-mbs, --max-block-size <size>    Maximum block size server will accept from client
                                 (default: 65535)

-fbs, --force-block-size <size>  Override client blocksize requests
                                 If set, all transfers use this size (0 = disabled)

-r, --root <path>                Root directory for file access (CURRENTLY IGNORED)

-v, --verbose                    Enable verbose logging

-h, --help                       Show usage information
```

### Config File Format (tftp.conf)

```
# Example tftp.conf in working directory
interface=Ethernet
address=192.168.1.10
port=69
default-block-size=512
max-block-size=65535
force-block-size=0
verbose=1
```

### Selection rules

- If `--interface` is given, that interface is selected.
- If `--address` is given, an interface in the same subnet is selected.
- If the given address differs from the selected interface's primary IP, it will spoof that address on that interface.
- If neither is given, the user is asked to select interface

### FTP Integration Configuration

FTP file requests use the syntax: `ftp://username:pasword@url/filename.ext` as filename

Example: A client requesting the file `ftp://share:shared@192.168.90.22/BDCOM0053/firmware.bin` triggers async download with metadata fetch, which is then server to the client on the fly.

### Concurrent Session Limits

- Maximum: 15 simultaneous TFTP sessions
- Port range: 20001-21015 (1015 ports available)
- If limit reached, new RRQ/WRQ requests receive no response

## Key Features

### Raw Packet-Level TFTP Server

Unlike socket-based implementations, this operates at the raw Ethernet frame level, enabling:

- **VLAN transparency:** Preserves VLAN tags (802.1Q) through transfers; automatically tags/untags frames
- **IP/MAC spoofing:** Server can advertise a different IP/MAC than the interface
- **ARP/ICMP handling:** Responds to ARP queries and ping requests for spoofed IPs

### Advanced Session Management

- **Up to 15 concurrent TFTP sessions** with per-session tracking:
  - Unique session IDs for debugging/logging
  - Duplicate detection via 5-tuple (client IP, port, MAC, VLAN ID)
  - Per-session statistics: processing time, packets sent, transmission rate (MB/s)
  - Individual timeouts and retransmission counters

- **Automatic cleanup:** Idle sessions terminated after timeout (default 1 second)
- **Progress reporting:** Every 5 seconds, logs transfer progress (% complete, speed, client info)

### Packet Queuing & Pipelining

- **Pre-allocation:** Server pre-generates packets ahead of ACKed blocks
- **Block caching:** Linked-list with optimization for fast sequential access
- **Block wrap-around:** Internally uses int64_t to safely handle block number rollovers at 65536
- **Automatic purging:** Acknowledged packets removed from queue immediately

### Asynchronous FTP File Sourcing

- **Non-blocking downloads:** Files fetched from remote FTP server without blocking TFTP transfers
- **Memory-efficient:** Single unified buffer pre-allocated to exact file size from metadata
- **Concurrent requests:** Multiple clients for same FTP file share single download
- **Transparent to client:** TFTP transfer appears normal; FTP fetch happens in background
- **Error handling:** Network errors, timeouts, 404s reported back to client via TFTP ERROR packet

### VLAN Tag Handling

- **Automatic conversion:** Non-VLAN packets internally tagged with invalid TCI `0xFFFF` for uniform processing
- **Preservation:** VLAN IDs maintained throughout transfer
- **Dual-mode:** Single interface transparently serves both VLAN-tagged and untagged clients

## Platform Support & Requirements

### System Requirements

- **OS:** Windows 7 SP1 or later (minimum `_WIN32_WINNT=0x0600`)
- **Architecture:** x64 (64-bit only)
- **Network:** Any Ethernet adapter supported by npcap/WinPcap

### Dependencies

| Library | Version | Purpose |
|---------|---------|---------|
| **npcap or WinPcap** | Latest | Raw packet capture/transmission via libpcap API |
| **libcurl** | 8.x | FTP file downloads with async multi-handle support |
| **Windows SDK** | Any | Winsock2, IPHLPAPI, Windows Event APIs |
| **MinGW/GCC** | 4.9+ | C compiler with Windows cross-compilation support |

## Known Limitations & Unimplemented Features

- **IPv4 only:** No IPv6 support
- **Single-threaded:** Event loop blocks on long operations
- **Memory pre-allocation:** Entire FTP files loaded to RAM (no streaming/chunked downloads for large files)
- **Windows-specific:** Winsock2, IPHLPAPI, Windows Event APIs - platform-tied

### Unimplemented Features

- **No file access restrictions:** Directory traversal attacks possible
- **No upload validation:** WRQ can write arbitrary files with no restrictions
- **No disk space validation:** WRQ write requests don't check available disk space before accepting upload

## Security Implications

1. **Unauthenticated Access:** Any client can read/write files via TFTP
2. **No Authorization:** All files on system accessible (including system files)
3. **IP Spoofing:** Server can impersonate arbitrary IPs

**Safe Deployment Scenarios:**

1. **Device Provisioning Lab** - Isolated test network, known devices, single operator
2. **Firmware Distribution** - Point-to-point VLAN, access restricted by physical network wiring
3. **Configuration Deployment** - Air-gapped network segment, no external connectivity
4. **Development/Testing** - Local machine only, never expose to public networks

## References

- **RFC 1350:** TFTP (Trivial File Transfer Protocol) specification.
- **RFC 2347:** TFTP Option Extension
- **RFC 2348:** TFTP Blocksize Option
- **RFC 2349:** TFTP Timeout Interval and Transfer Size Options
- **RFC 7440:** TFTP Windowsize Option
- **libpcap:** [https://www.tcpdump.org/](https://www.tcpdump.org/)
- **npcap (Windows):** [https://npcap.com/](https://npcap.com/)
- **802.1Q VLAN Tagging:** IEEE 802.1Q standard.
