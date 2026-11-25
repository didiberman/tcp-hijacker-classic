# TCP Hijacker Classic

> Historical code by **spwny**, from 1999. Recovered for archival and defensive educational purposes.

This repository contains a TCP connection tooling experiment written in 1999 using **libnet** and **libpcap**. It demonstrates packet capture, TCP sequence/acknowledgment discovery, checksum construction, and raw packet injection from the era of pre-modern network security practices.

The source currently targets legacy C APIs and may not compile unchanged on a modern system.

## ⚠️ Authorized use only

TCP connection hijacking and spoofing can disrupt, intercept, or alter communications. Only use this code:

- On systems and networks you own
- On networks where you have explicit written authorization
- In an isolated lab or containerized test environment
- Against test sessions created specifically for the exercise

Do not use it against public systems, production networks, shared networks, or devices belonging to third parties.

The author does not endorse unauthorized interception or misuse of network traffic.

## Background

The original program was written in 1999 by `spwny`, with inspiration credited to `cyclozine`. Its original purpose was to experiment with:

- Capturing live packets with libpcap
- Identifying TCP packets by IP address and port
- Reading TCP sequence and acknowledgment numbers
- Constructing TCP/IP packets with libnet
- Injecting acknowledgment, push, reset, or fin packets
- Hijacking an interactive TCP connection by maintaining sequence state
- Optionally terminating a connection with TCP RST

The code was designed for portability across Linux, FreeBSD, and Sun Sparc systems.

## What the program does

Given a network interface and two endpoint IP/port pairs, the program:

1. Opens the interface in promiscuous mode
2. Captures packets in real time
3. Searches for an ACK packet matching the source/destination tuple
4. Records the packet's TCP sequence and acknowledgment values
5. Sends an initial payload to advance the connection sequence
6. Relays text entered at standard input as TCP payload
7. Sends a TCP FIN or RST when it finishes or receives an interrupt

It contains a `-r` option that resets the connection instead of entering interactive mode.

## Legacy implementation details

The original source uses APIs that are no longer portable or necessarily available:

- `libnet-config`
- Legacy libnet 1.x packet construction APIs
- `pcap_next()`
- `random()` / `srandom()`
- BSD network structures
- Host-order and network-order assumptions
- Raw socket/IP forwarding assumptions
- 1999-era compiler and operating-system behavior

Modern operating systems often require elevated privileges for packet capture and raw socket operations. Interface names, link-layer headers, checksums, fragmentation, and TCP state handling also differ significantly from the assumptions in the original code.

## Building

This file is preserved as a historical source, not as a maintained or production-ready security utility.

Modern build environments would typically require a compatible legacy libnet/libpcap installation. The original build command was:

```sh
gcc -o hijack hijacktcp.c -lpcap `libnet-config --libs --defines --cflags`
```

Compilation may fail because libnet 1.x APIs are obsolete or unavailable.

## Modern replacement directions

For an authorized lab:

- Use **Wireshark/tshark** or **libpcap** to observe TCP traffic
- Use **Scapy** for packet-generation experiments
- Use **Mininet**, containers, or virtual machines to create isolated networks
- Use a test application with authenticated, encrypted transport
- Build a small TCP proxy in **Python**, **Go**, or **Rust**
- Demonstrate sequence state and connection teardown with synthetic packets
- Test network reset behavior in an isolated environment
- Use tools such as **TC** or **netem** to simulate latency and packet loss

A modern, safe rewrite should avoid sending arbitrary payloads to real endpoints. Prefer a local mock server and explicit environment checks.

## Code facts

- Original language: C
- Main dependencies: libpcap and libnet
- Historical target platforms: Linux, FreeBSD, Sun Sparc
- Packet link types: Ethernet, FDDI, SLIP, PPP, null, and raw
- Termination behavior: SIGINT/SIGTERM sends a reset
- Interactive payload size: bytes read from `stdin`

## Repository contents

- `hijacktcp.c` — original 1999 source
- `README2.md` — historical and defensive usage context

## Historical note

This README was added to provide provenance, context, and safety guidance. The source is preserved as an artifact of 1999-era network programming and should not be assumed to be secure or reliable under modern networks.
