# Omnitrace Engine

Omnitrace Engine is a high-speed network tracing core written in C as a Python extension. It acts as the backend for modern traceroute and MTR alternatives.

Traditional traceroute tools frequently fail to map intermediate network hops because modern firewalls and routers are configured to drop standard ICMP echo or high-port UDP probes. Omnitrace solves this by executing an aggressive, multi-protocol escalation loop for silent hops, testing different header options and standard service ports to force responses from rate-limited or firewalled nodes.

## Key Features

* **Python C-API Extension:** Built natively using raw sockets. It releases the Python GIL during socket loops to ensure the main application UI thread is never blocked.
* **Smart Probing Escalation:** If a hop times out, the engine automatically cycles through standard ICMP, UDP, custom TOS/DSCP packages, and service ports (DNS on port 53, QUIC on port 443, NTP on port 123) to tease out a response.
* **OS Fingerprinting & Route Analysis:** Evaluates the TTL of incoming packets to estimate the responder's OS family (Cisco/Core, Linux/Juniper, or Windows/Host) and measures return-path distance to reveal asymmetric routing.
* **Concurrently Resolved ISPs:** Maps the IP address of each hop to its owning ISP/network provider (e.g., AT&T, Google, Comcast) concurrently using a thread pool for instant results.

---

## Step-by-Step Setup Guide

Follow these steps to compile and run the engine on your machine.

### Step 1: Install Prerequisites

Since this is a C-extension, you need a C compiler installed on your system.

* **Windows:**
  Download and install [Build Tools for Visual Studio](https://visualstudio.microsoft.com/downloads/#build-tools-for-visual-studio-2022). During installation, check the box for **Desktop development with C++** to install the MSVC compiler.
* **Linux (Ubuntu/Debian):**
  Run the following command to install compiler tools and Python headers:
  ```bash
  sudo apt update && sudo apt install build-essential python3-dev
  ```
* **macOS:**
  Install Xcode command line tools:
  ```bash
  xcode-select --install
  ```

### Step 2: Compile the Engine

Open your terminal/command prompt in the `omnitrace_engine` directory and compile the C code:

```bash
python setup.py build_ext --inplace --force
```
*This compiles the C file (`engine.c`) directly into a native binary (`.pyd` on Windows or `.so` on Unix) that Python can import.*

### Step 3: Run a Trace

Because the engine crafts raw network packets to bypass firewall filters, it **requires administrator/root privileges** to run.

* **Windows:**
  1. Search for **PowerShell** or **Command Prompt** in the Start Menu.
  2. Right-click and select **Run as Administrator**.
  3. Navigate to your project folder and run:
     ```powershell
     python verify.py 8.8.8.8
     ```
* **Linux / macOS:**
  Run the script using `sudo`:
  ```bash
  sudo python verify.py 8.8.8.8
  ```

---

## Troubleshooting Common Errors

### Error: `ImportError: No module named 'omnitrace_engine'`
This means the C extension has not been compiled yet. Run Step 2 to build it.

### Error: `PermissionError` or socket access forbidden
This occurs when the command is run without administrative privileges. Make sure your shell was opened using **Run as Administrator** (Windows) or that you prefix the command with `sudo` (Linux/macOS).

---

## Console Screenshot

![Console Output](Screenshot%20%282%29.png)
