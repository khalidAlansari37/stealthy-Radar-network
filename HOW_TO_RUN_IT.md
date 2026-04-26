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

### 4. Running Radar with Root Rights (CRITICAL)
Radar needs to perform deep network scans to find other devices. To do this, it requires **Root Privileges** (also known as `sudo`). This is why you must run the following command:

```bash
make live-root
```
*   **Why `sudo`?** Standard users aren't allowed to look at raw network traffic for security reasons. By using `sudo`, you are giving Radar permission to see who is on your Wi-Fi.
*   **Password:** When you run this, the terminal will ask for your password. **Note:** When you type your password, you won't see any stars or characters. This is normal! Just type it and hit **Enter**.

---

## 📊 Viewing Your Intelligence Dashboard

Once Radar is running, it starts a local web server. To see your data:

1.  Open your Web Browser (Chrome, Firefox, etc.).
2.  In the address bar at the top, type: `http://localhost:8000`
3.  Press **Enter**.

You should now see the **Radar Intelligence Dashboard**! You can see live network activity, app usage charts, and system health metrics.

---

## 🛡️ Advanced: Installing as a Permanent Background Service

If you love Radar and want it to run **automatically** every time you turn on your computer, you can install it as a "System Service."

1.  In your terminal, run:
    ```bash
    make install
    ```
2.  Radar will now be "cloaked." It will run in the background without any terminal window open.
3.  It will even disguise its process name as something generic (like `kworker/sys`) to stay hidden from casual observation.

**To stop or remove it later:**
- To check status: `make status`
- To stop it: `make stop`
- To completely uninstall: `make uninstall`

---

## ❓ Troubleshooting (If things go wrong)

*   **"Permission Denied":** This means you forgot to use `make live-root` or didn't enter the correct password.
*   **"Command not found":** Make sure you are inside the Radar folder. Type `pwd` to check your current location.
*   **"Port 8000 already in use":** This means Radar is already running, or another program is using that slot. Try restarting your computer or running `make stop`.
*   **Dashboard is empty:** Give Radar a few minutes. It needs time to perform its first network sweep and gather enough data to show you a chart.

---

## 📜 Summary of Commands

| Goal | Command |
| :--- | :--- |
| **Setup** | `make setup` |
| **Run (Dashboard)** | `make live-root` |
| **Install Permanently** | `make install` |
| **Check Logs** | `make logs` |
| **Clean Up** | `make uninstall` |

Enjoy your new stealthy network intelligence tool! 📡
