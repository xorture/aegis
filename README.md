# 🛡️ AEGIS: Advanced Engine for Global Interception & Security

> **Kernel-Level Network Traffic Inspector & Threat Neutralizer**
> *Built for Windows | Python 3.10+*

[![License](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Platform](https://img.shields.io/badge/Platform-Windows-lightgrey)](https://microsoft.com)
[![Status](https://img.shields.io/badge/Status-Active-success)]()

## 📖 Overview

**AEGIS** is a high-performance network interception engine designed to monitor and filter outbound traffic at the packet level. Unlike traditional host-file blockers, AEGIS leverages the **Windows Filtering Platform (WFP)** via the `WinDivert` driver to intercept packets before they leave the network interface.

It features a custom-engineered **Deep Packet Inspection (DPI)** module capable of parsing **TLS Client Hello** handshakes (SNI) and **DNS Queries** in real-time, allowing it to identify and block malicious infrastructure even within encrypted traffic streams.

---

## 🚀 Key Technical Features

### 1. Kernel-Level Interception
AEGIS does not operate as a proxy. It hooks directly into the Windows network stack.
- **Zero-Latency Monitoring:** Uses `WinDivert` to capture packets with minimal overhead.
- **Selective Filtering:** The engine only intercepts traffic on ports **53 (DNS)** and **443 (HTTPS)**, leaving high-bandwidth traffic (video/gaming) untouched to preserve CPU resources.

### 2. Custom TLS SNI Parser
The core engine includes a manual pointer-arithmetic parser for the TLS 1.2/1.3 Handshake Protocol.
- **Library-Free:** Does not rely on `scapy` or heavy external libraries for parsing.
- **Logic:** It manually unpacks the TCP payload, traverses the Record Layer, and extracts the **Server Name Indication (SNI)** extension (Type `0x00`) to identify the destination domain without decrypting the payload.

### 3. O(1) Threat Intelligence
The blocklist engine uses optimized Hash Sets and Suffix Trees for constant-time lookups, ensuring that checking a domain against thousands of rules does not introduce network lag.

---

## ⚙️ Architecture

The system operates in a linear, procedural pipeline:

1.  **Capture:** The kernel driver diverts outbound packets matching the filter rule.
2.  **Parse:**
    * **UDP/53:** Decodes DNS Query Name (QNAME).
    * **TCP/443:** Decodes TLS Client Hello Extensions (SNI).
3.  **Inspect:** The extracted domain is checked against `domains.py` (Tier 1-4 Threat Categories).
4.  **Verdict:**
    * **Clean:** Packet is re-injected into the network stack.
    * **Threat:** Packet is dropped (silently) or logged.

---

## 📦 Installation & Setup

### Prerequisites
* **OS:** Windows 10 or 11 (64-bit).
* **Python:** Version 3.10 or higher.
* **Privileges:** **Administrator rights are mandatory** (required to load the WinDivert driver).

### Step-by-Step Guide

1.  **Clone the Repository**
    ```bash
    git clone [https://github.com/yourusername/aegis.git](https://github.com/yourusername/aegis.git)
    cd aegis
    ```

2.  **Install Dependencies**
    ```bash
    pip install pydivert dnslib colorama
    ```
    *Note: `pydivert` includes the necessary `.dll` and `.sys` driver files automatically.*

---

## 💻 Usage Manual

To run AEGIS, open your terminal (Command Prompt or PowerShell) **as Administrator**.

### 1. Monitoring Mode (Default)
In this mode, AEGIS logs all detected threats to the console but **does not block** traffic. Useful for auditing network activity.

```bash
python main.py
