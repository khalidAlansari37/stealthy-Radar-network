# 🛰️ Radar: Your Ultimate Linux Stealth Intelligence Guide

Welcome to **Radar**! This guide is designed to help you set up and run the Radar system with ease. Whether you are a security enthusiast or just want to keep an eye on your home network, this document will walk you through everything you need to know in simple, plain language.

---

## 🔍 What is Radar?

Imagine having a silent, invisible security guard living inside your computer. **Radar** is exactly that. It runs quietly in the background (stealth mode) and gathers intelligence about two main things:

1.  **Your Local Network:** It scans your Wi-Fi to see every device connected to it (Phones, Laptops, Smart TVs, IoT devices). It can even tell you the manufacturer of the device (like Apple, Samsung, or Sony).
2.  **Your Computer Usage:** It monitors which applications you are using, how much time you spend on them, and even takes "health snapshots" of your system (CPU, RAM, and Battery).

All of this data is stored locally on your machine—never in the cloud—and is presented to you through a sleek, professional web dashboard.

---

## 🛠️ Prerequisites (What you need)

Before we start, make sure you have:
- A computer running **Linux** (Ubuntu, Mint, Debian, etc.).
- A working **Internet connection**.
- **Administrator (Root) Access:** Since Radar needs to "listen" to your network hardware, you will need your computer's password.

---

## 🧠 The Two Parts of Radar

Radar is split into two separate "programs" that work together:

1.  **The Brain (The Daemon):** This is the engine that does all the heavy lifting. It scans the network, tracks your apps, and saves everything to a secure database. It has no "face"—it just works in the background.
2.  **The Eyes (The Dashboard):** This is the web page you see in your browser. It reads the database and shows you pretty charts and maps of your data.

---

## 🚀 How to Run Radar (The Step-by-Step Way)

### 1. Open Your Command Center (Terminal)
The Terminal is where the magic happens. You can usually open it by pressing `Ctrl + Alt + T` on your keyboard.

### 2. Enter the Radar Directory
You need to tell the terminal where the Radar files are. If you downloaded it to your Desktop, type:
```bash
cd ~/Desktop/Radar
```

### 3. The Initial Setup (First Time Only)
Radar needs a few tools and "libraries" to work correctly. We have simplified this into a single command:
```bash
make setup
```
*Wait for this to finish. It will create a "virtual environment" so Radar doesn't interfere with your other computer programs.*

### 4. Turning on "The Brain" (The Daemon)
To start collecting data, you need to turn on the "Intelligence Daemon." Since it needs to scan your Wi-Fi, you **must** use `sudo`:

```bash
make brain
```
*   **What it does:** This starts the monitoring loops. You will see text scrolling by as it finds devices and tracks your activity.
*   **Keep this open:** You must leave this terminal window open for the Brain to stay awake.

### 5. Turning on "The Eyes" (The Dashboard)
In a **new terminal window** (keep the first one running!), go to the Radar folder again and run:

```bash
make live-root
```
*   **What it does:** This starts the local web server so you can view your data.
*   **Why `sudo`?** Even the dashboard needs root rights to allow you to trigger manual network scans from the web interface.

---

## 📊 Viewing Your Intelligence Dashboard

Once both parts are running:

1.  Open your Web Browser (Chrome, Firefox, etc.).
2.  In the address bar at the top, type: `http://localhost:8000`
3.  Press **Enter**.

You should now see the **Radar Intelligence Dashboard**! You can see live network activity, app usage charts, and system health metrics.

---

## 🛡️ The "One Command" Way (Recommended)

If you don't want to keep two terminal windows open, you can install Radar as a **Permanent Background Service**. This is the most "pro" way to run it.

Run this command:
```bash
make install
```
*   **What happens?** Radar will merge the Brain and the Dashboard together and run them silently in the background.
*   **Stealth:** It will disguise its process name as something generic (like `kworker/sys`) so it stays hidden.
*   **Auto-Start:** Radar will now start automatically every time you turn on your computer!

---

## 📜 Summary of Commands

| Goal | Command | What it does |
| :--- | :--- | :--- |
| **Setup** | `make setup` | Installs everything for the first time. |
| **Start Engine** | `make brain` | Starts the "Brain" to gather data (Requires Root). |
| **Start View** | `make live-root` | Starts the "Dashboard" to see data (Requires Root). |
| **Full Install** | `make install` | Runs everything silently in the background forever. |
| **Check Logs** | `make logs` | See what the Brain is thinking right now. |
| **Check Status** | `make status` | Is Radar running right now? |
| **Stop** | `make stop` | Stops the background service. |
| **Uninstall** | `make uninstall` | Completely removes Radar from your system. |

---

## ❓ Troubleshooting (If things go wrong)

*   **"Permission Denied":** This means you forgot to use a command that requires `sudo` or didn't enter the correct password.
*   **"Command not found":** Make sure you are inside the Radar folder. Type `pwd` to check your current location.
*   **"Port 8000 already in use":** This means Radar is already running. Run `make stop` to clear it out.
*   **Dashboard is empty:** Give Radar a few minutes. It needs time to perform its first network sweep and gather enough data to show you a chart.

Enjoy your new stealthy network intelligence tool! 📡
