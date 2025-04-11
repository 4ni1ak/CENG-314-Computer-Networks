# CENG-314-Computer-Networks

## Overview

This script automates the process of network traffic analysis for common protocols. It performs the following actions:

1.  **Captures traffic:** Uses `tshark` to capture packets related to specific protocols.
2.  **Generates traffic:** Uses tools like `curl`, `ping`, and `arping` to generate relevant network activity.
3.  **Analyzes packets:** Processes captured `.pcap` files with `tshark` filters to extract details about TCP handshakes, DNS queries/responses, ICMP echo requests/replies, HTTP GET/POST requests, and ARP requests.
4.  **Generates Reports:** Creates detailed text files, Markdown summaries (`.md`), and potentially an aggregated HTML report for each analysis type within timestamped directories.
5.  **Web Server:** Starts a simple Python HTTP server to easily view the generated HTML report.

## Features

* **TCP Handshake Analysis:** Captures and analyzes the 3-way handshake, detailing SYN, SYN-ACK, and ACK packets.
* **DNS Query Analysis:** Captures DNS queries and responses for specified domains, showing resolved IPs and timings.
* **ICMP Ping Analysis:** Pings specified targets, captures ICMP echo requests/replies, and analyzes RTT, TTL, and packet loss.
* **HTTP Traffic Analysis:** Captures HTTP GET and POST requests/responses, detailing URIs, status codes, and headers.
* **ARP Request Analysis:** Generates and captures ARP requests for specified IPs, analyzing responses to determine MAC addresses.
* **Organized Output:** Saves results in clearly named, timestamped directories.
* **Report Generation:** Creates individual analysis files and consolidated reports in Markdown and HTML formats.
* **Docker Support:** Includes a `Dockerfile` for easy containerization and dependency management (using Arch Linux).

## Prerequisites

The script requires several standard Linux command-line utilities. Ensure the following are installed on your system:

* `bash`
* `tshark` (Command-line interface for Wireshark - often in `wireshark-cli` or similar package)
* `curl`
* `iproute2` (for `ip` command)
* `dnsutils` or `bind-utils` (for `dig`, `host`, `nslookup`)
* `bc` (For arbitrary precision calculations)
* `iputils-ping` / `iputils-arping` or `iputils` (for `ping`, `arping`)
* `nmap`
* `python3` (for the web server)
* `procps` or `procps-ng` (for `kill`, `ps`)
* `coreutils` (for `cat`, `chmod`, `mv`, `mkdir`, `rm`, `tail`, `date`, `grep`, `awk`, `sed`, `sort`, `uniq`, `wc`)
* `which` or `command -v` functionality

**For Docker Usage:**

* `docker`

## How to Use

1.  **Clone the repository:**
    ```bash
    git clone [https://github.com/4ni1ak/Bash-Network-Analyzer.git](https://github.com/KULLANICI_ADINIZ/Bash-Network-Analyzer.git)
    cd Bash-Network-Analyzer
    ```

2.  **Make the script executable:**
    ```bash
    chmod +x network_analyzer.sh
    ```

3.  **Run the script:**
    * You may need root privileges (`sudo`) for packet capture capabilities (`tshark`, `ping`, `arping`).
    ```bash
    sudo ./network_analyzer.sh
    ```
    * The script will:
        * Perform the network analyses one by one.
        * Create timestamped directories (e.g., `network_analysis_YYYYMMDD_HHMMSS`, `dns_analysis_...`, etc.) containing detailed logs, `.pcap` files, and reports.
        * Organize these into a final parent directory (e.g., `network_analysis-YYYYMMDD_HHMMSS`).
        * Generate a `General_Report.md` and `General_Report.html` in the final directory.
        * Start a Python web server on port 8000.

4.  **View the results:**
    * Check the terminal output for the location of the results directory (e.g., `network_analysis-YYYYMMDD_HHMMSS`).
    * Open your web browser and navigate to `http://localhost:8000` or `http://localhost:8000/General_Report.html` to view the HTML report.
    * Alternatively, explore the generated directories and view the individual `.txt` and `.md` files.

## Using Docker (Arch Linux Base)

A `Dockerfile` is provided to run the analysis in an Arch Linux container.

1.  **Build the Docker image:**
    ```bash
    docker build -t network-analyzer-arch .
    ```

2.  **Run the Docker container:**
    * `NET_ADMIN` and `NET_RAW` capabilities are required for network tools.
    * `-p 8000:8000` maps the container's port 8000 to your host's port 8000.
    * `--rm` automatically removes the container when it exits.
    * `-it` allows interactive access (though the script runs automatically).
    ```bash
    docker run --rm -it --cap-add=NET_ADMIN --cap-add=NET_RAW -p 8000:8000 network-analyzer-arch
    ```

3.  **View the results:**
    * Once the script finishes inside the container, it will start the Python web server.
    * Open `http://localhost:8000` in your browser on your host machine.
    * **Note:** Files generated inside the container are typically lost when the container is removed (`--rm`). To persist the results, use Docker volumes:
        ```bash
        # Create a directory on your host for results
        mkdir analysis_results
        # Run with volume mount
        docker run --rm -it --cap-add=NET_ADMIN --cap-add=NET_RAW -p 8000:8000 -v "$(pwd)/analysis_results:/app/network_analysis-*" network-analyzer-arch
        ```
        *(Adjust the volume path `/app/network_analysis-*` based on the actual output directory name pattern if needed)*

## Output Structure

The script generates a main results directory like `network_analysis-YYYYMMDD_HHMMSS` containing subdirectories for each analysis type:

* `analyze_tcp_handshake/`
* `analyze_dns_queries/`
* `analyze_icmp_ping/`
* `analyze_http_traffic/`
* `analyze_arp_requests/`

Each subdirectory contains:

* Raw packet capture files (`.pcap`)
* Detailed text output from `tshark` (`_detail.txt`)
* Filtered packet lists (`.txt`)
* Analysis summary files (`_analysis.txt`, `_analysis.md`, `_summary.txt`, `_summary.md`)
* Tool output (e.g., `ping_output.txt`, `arping_*.txt`)
* Screenshot instructions (`screenshot_instructions.txt`)
* A cleanup script (`cleanup.sh`)

The main results directory also contains:

* `General_Report.md`: An aggregated Markdown report.
* `General_Report.html`: An HTML version of the report.
* `index.html`: Redirects to `General_Report.html`.

## Student Information

This script appears to be part of a student project, identified by the student number `220201013` embedded within it for specific IP generation and potentially identification in reports.

## Contributing

Contributions are welcome! Please feel free to submit pull requests or open issues for bugs, improvements, or new features.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details (You would need to create a LICENSE file with the MIT license text).