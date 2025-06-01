# TCP Hijacker Classic

🧠 Rebuilding the legend: this is an educational, single-file TCP connection hijacker written in C, originally created by a 12-year-old hacker in the early 2000s.

## 🚀 What It Does

- Crafts raw TCP packets with spoofed IPs and ports
- Forges correct ACK/SEQ numbers
- Injects fake packets into active TCP streams
- Sends a packet pretending to be another client (e.g., to simulate a command injection)

## ⚠️ Disclaimer

This tool is provided **strictly for educational purposes** and self-study in TCP/IP networking. **Do not use on public or unauthorized systems.**

## 🛠️ Requirements

- Linux or FreeBSD system
- `gcc` or `clang`
- Root privileges (required for raw socket access)

## 🧰 How to Compile

```bash
gcc -o tcp_hijack tcp_hijack.c
