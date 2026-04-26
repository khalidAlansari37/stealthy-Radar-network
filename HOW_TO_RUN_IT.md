# How to Run Radar (Easy Guide)

Welcome to **Radar**! This guide will explain what Radar is and how you can easily run it on your Linux computer without needing to be a software developer.

## What is Radar?

Radar is a smart, invisible assistant that monitors your computer and your local Wi-Fi network. It runs quietly in the background and helps you answer questions like:
- **Who is on my Wi-Fi?** It detects phones, computers, smart TVs, and other devices connected to your network.
- **What am I spending time on?** It tracks which apps you use and how long you spend on them.
- **How is my computer doing?** It keeps an eye on your battery, CPU, and RAM to make sure everything is healthy.

All of this information is collected privately and shown to you in a beautiful, easy-to-read web dashboard.

---

## How to Use Radar on Linux

We've made starting Radar as simple as possible. Just follow these steps:

### Step 1: Open your Terminal
On your Linux system (like Ubuntu), press `Ctrl + Alt + T` to open your Terminal window.

### Step 2: Go to the Radar Folder
You need to be in the folder where Radar is located. If it's on your Desktop, you would type:
```bash
cd ~/Desktop/Radar
```
*(Press Enter after typing the command)*

### Step 3: Install the Requirements (One-time only)
Before running Radar for the first time, it needs to download some standard tools to do its job. Type this command and press Enter:
```bash
make setup
```
Wait a minute or two for this to finish. You only ever have to do this once!

### Step 4: Start Radar and the Dashboard
Now, let's turn it on so you can see your data. Type this command:
```bash
make live-root
```
*Note: Because Radar needs to scan the network, it will ask for your computer's administrator password (sudo password). Type it in and press Enter.*

### Step 5: View Your Data!
Open your favorite web browser (like Chrome or Firefox) and go to this exact address:
👉 **http://localhost:8000**

You will now see the Radar Dashboard with all your network and computer statistics!

---

## Advanced (But Still Easy): Make it Run Forever

If you want Radar to run in the background automatically every time you turn on your computer (so you never have to open the terminal again), do this:

1. Open the Terminal and go to the Radar folder (`cd ~/Desktop/Radar`).
2. Run this command:
```bash
make install
```
That's it! Radar is now permanently installed as a silent background service. You can visit `http://localhost:8000` at any time to see your dashboard.

If you ever want to completely remove it, just type:
```bash
make uninstall
```
