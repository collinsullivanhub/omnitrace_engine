# Omnitrace Engine

Omnitrace Engine is a high-speed network tracing core written in C as a Python extension. It is designed to act as the backend for modern traceroute and MTR alternatives.

Traditional traceroute tools frequently fail to map intermediate network hops because modern firewalls and routers are configured to drop standard ICMP echo or high-port UDP probes. Omnitrace solves this by executing an aggressive, multi-protocol escalation loop for silent hops, testing different header options and standard service ports to force responses from rate-limited or firewalled nodes.

## Key Features

* **Python C Extension:** Built natively using the Python C-API and raw sockets. It releases the Python GIL during socket loops to ensure the main application UI thread is never blocked.
* **Smart Probing Escalation:** If a hop times out, the engine automatically escalates through a sequence of protocol tricks:
  * Standard ICMP Echo Requests
  * Standard UDP probes (port 33434+)
  * ICMP with TOS/DSCP set to Expedited Forwarding (`0xB8`) and 0-byte payloads to bypass size filters
  * ICMP with fragmentation enabled (`DF=0`)
  * UDP DNS queries (port 53) using a real, RFC-compliant DNS payload
  * UDP QUIC probes (port 443)
  * UDP NTP client queries (port 123)
* **Real-time Diagnostic Logs:** Prints progress lines to stdout indicating exactly which protocol is being tried next for a silent hop so you can see the escalation in real-time.
* **OS Fingerprinting & Route Analysis:** Evaluates the TTL of incoming packets to estimate the responder's OS family (Cisco/Core, Linux/Juniper, or Windows/Host) and measures return-path distance to reveal asymmetric routing paths.
* **Concurrently Resolved ISPs:** Maps the IP address of each hop to its owning ISP/network provider (e.g., AT&T, Google, Comcast) concurrently using a thread pool, meaning zero latency is added to the diagnostic output.

## Getting Started

### Prerequisites

* Windows (MSVC build tools installed) or Linux/macOS (GCC/Clang)
* Python 3.7+
* Administrator/Root privileges (required to create raw sockets)

### Build and Run

1. **Compile the extension:**
   ```bash
   python setup.py build_ext --inplace --force
   ```

2. **Run a trace:**
   ```bash
   python verify.py 8.8.8.8
   ```
