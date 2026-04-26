# 🚀 Radar: Future Improvements & Tactical Roadmap

This document outlines the planned upgrades for Project Radar, moving it from a monitoring tool to a comprehensive stealth intelligence and network manipulation platform.

---

## 1. 🕵️ Deeper Network Intelligence (The "Hacker" Upgrades)

### A. Passive OS Fingerprinting (p0f-style)
**Goal:** Identify device types (iPhone, Android, Windows, Linux) without sending a single packet to the target.
*   **Method:** Analyze TCP/IP headers of incoming packets.
*   **Key Indicators:**
    *   **TTL (Time To Live):** Windows usually uses 128, while Linux/Android/macOS use 64.
    *   **Window Size:** Different operating systems use unique initial window sizes.
    *   **TCP Options:** The order and presence of options like SACK and Window Scaling are unique signatures.
*   **Benefit:** 100% stealthy identification.

### B. Passive DNS Sniffing
**Goal:** Capture real-time web browsing activity.
*   **Method:** Sniff traffic on Port 53 (DNS).
*   **Implementation:** Extract the `QD` (Query Domain) field from DNS requests.
*   **Benefit:** Build a "Domain Profile" for every device, knowing exactly which services (Netflix, WhatsApp, TikTok) they are using without decrypting HTTPS traffic.

---

## 2. 🥷 Advanced Stealth & Evasion

### A. eBPF Process Hiding
**Goal:** Make the Radar process invisible to the system owner.
*   **Method:** Use **eBPF (Extended Berkeley Packet Filter)** to hook the `getdents64` system call.
*   **Implementation:** When the user runs `ps`, `top`, or `htop`, the kernel will skip the Radar process ID, making it literally invisible to standard Linux tools.
*   **Benefit:** Zero-footprint persistence.

### B. Remote C2 (Telegram Control)
**Goal:** Manage Radar from anywhere in the world.
*   **Method:** Integrate the `python-telegram-bot` library.
*   **Features:**
    *   **Alerts:** Get a text message when a specific "VIP" device joins the network.
    *   **Reports:** Text `/report` to get a PDF summary of the last 24 hours.
    *   **Control:** Text `/intercept 192.168.1.5` to start a tactical attack remotely.
*   **Benefit:** No need for local dashboard access.

---

## 3. 🌐 Dashboard & Real-Time Upgrades

### A. Live WebSockets
**Goal:** Zero-latency data streaming.
*   **Method:** Replace polling with **FastAPI WebSockets**.
*   **Benefit:** Traffic logs and bandwidth meters will move like a live stock ticker, showing data the millisecond it is captured.

### B. Interactive Network Map (D3.js)
**Goal:** Visual situational awareness.
*   **Method:** Use **D3.js** to create a force-directed graph.
*   **Visualization:** 
    *   Center node = Router.
    *   Satellite nodes = Devices.
    *   Line thickness = Bandwidth usage.
    *   Color = Device type or status.

---

## ⚔️ Offensive & Tactical Capabilities

### A. Wi-Fi Deauthentication (The "Kicker")
**Goal:** Forced disconnection of any device.
*   **Method:** Use Scapy to send `Dot11Deauth` frames.
*   **Requirement:** Wireless card must support **Monitor Mode**.
*   **Tactical Use:** Force a device to disconnect and reconnect, allowing Radar to capture its "Handshake" or force it onto an Evil Twin.

### B. LAN Manipulation (MITM Suite)
**Goal:** Full control over the target's internet experience.
*   **DNS Spoofing:** Redirect requests for `google.com` to a local phishing page or a custom message.
*   **Captive Portal Trigger:** Intercept connectivity checks (`captive.apple.com`) to force a phone to automatically pop up a browser window with your custom content.
*   **HTML Injection:** Inject custom JavaScript or CSS into non-encrypted (HTTP) traffic.

---

## 📈 Development Phases

1.  **Phase 1 (Intelligence):** Implement DNS Sniffing and OS Fingerprinting.
2.  **Phase 2 (Tactical):** Implement the Captive Portal and DNS Spoofer.
3.  **Phase 3 (Stealth):** Implement the Telegram Bot and eBPF hiding.
4.  **Phase 4 (Visual):** Complete the D3.js Map and WebSocket integration.
