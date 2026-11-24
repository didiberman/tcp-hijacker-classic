# shijack

A lightweight, cross-platform TCP connection hijacker and session resetter written in C around **2000–2001**.

## Overview

Built during the era of unencrypted plain-text protocols (Telnet, FTP, IRC) and shared broadcast networks, `shijack` demonstrates how an attacker on the same local network or subnet can take over or terminate an active TCP session. 

Instead of relying on OS-specific raw socket implementations, this version was refactored to use **`libpcap`** and **`libnet` (1.0 API)** for portability across **Linux** (Slackware 7.0), **FreeBSD** (4.2), and **Solaris** (SunOS 5.7 / SPARC).

## How It Works

1. **Sequence/Acknowledgment Sniffing (`libpcap`):** Opens the network interface in promiscuous mode to capture a live packet matching the target source/destination IPs and ports, extracting the current TCP `SEQ` and `ACK` numbers.
2. **Stream Desynchronization:** Injects `1024` null bytes into the stream to advance the server's expected `SEQ` counter, locking the legitimate client out of the session.
3. **Interactive Packet Injection (`libnet`):** Reads standard input (`stdin`) and crafts forged `PSH+ACK` TCP/IP packets on the fly, allowing real-time command injection into the hijacked session.
4. **Session Termination (`-r` / `SIGINT`):** Supports an immediate connection reset mode (`-r`) or graceful teardown on exit (`Ctrl+C`) by forging a `TCP RST` packet.

## Build & Usage

### Compilation
```bash
gcc -o shijack shijack.c -lpcap `libnet-config --libs --defines --cflags`
```

### Usage
```bash
./shijack <interface> <src_ip> <src_port> <dst_ip> <dst_port> [-r]
```

* `<interface>`: Network interface to sniff and inject on (e.g., `eth0`, `fxp0`)
* `<src_ip>` / `<src_port>`: Client IP and port to impersonate
* `<dst_ip>` / `<dst_port>`: Target server IP and port
* `-r`: Optional flag to immediately reset (`RST`) the connection instead of hijacking it

---
*Originally written by **spwny** (EFnet), inspired by cyclozine.*
