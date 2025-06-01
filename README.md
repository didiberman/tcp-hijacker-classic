# TCP Hijacker Classic

🔥 A reconstruction of a legendary tool built by a 12-year-old hacker — this program lets you disrupt or hijack TCP connections using raw sockets and handcrafted SEQ/ACK spoofing.

> 🛑 For **educational use only**. Unauthorized network access is illegal.

---

## ⚙️ Features

- 🧨 **Disrupt Mode**: Breaks active TCP connections by sending forged RST packets
- 🎮 **Hijack Mode (WIP)**: Placeholder for interactive session takeover
- 🧪 Manual input of IPs, ports, and sequence numbers
- 💻 Works on **Linux** and **FreeBSD**
- 🧵 One-file C program, zero dependencies

---

## 🔧 How to Use

### 1. Compile the Program

```bash
gcc -o tcp_hijack tcp_hijacker.c
