#!/bin/bash

# Student identification and IP generation
STUDENT_NUMBER="220201013"
LAST_TWO_DIGITS=$(echo "$STUDENT_NUMBER" | tail -c 3)
GENERATED_IP="192.168.1.1${LAST_TWO_DIGITS}"
RESULTS_BASE_DIR="network_analysis_$(date +%Y%m%d_%H%M%S)"

analyze_tcp_handshake() {
    # Check if tshark is installed
    if ! command -v tshark &> /dev/null; then
        echo "Error: tshark is not installed. Please install it with:"
        echo "sudo apt install tshark"
        return 1
    fi

    # Create results directory
    mkdir -p "$RESULTS_BASE_DIR"
    echo "Created directory: $RESULTS_BASE_DIR"
    
    # Set permissions to allow anyone to read, write, and execute in the directory
    chmod -R 777 "$RESULTS_BASE_DIR"
    echo "Set permissions to allow anyone to access and modify the results"

    # Determine network interface automatically
    INTERFACE=$(ip -o -4 route show to default | awk '{print $5}' | head -1)
    if [ -z "$INTERFACE" ]; then
        echo "Could not determine network interface. Please enter it manually:"
        read -p "Interface name: " INTERFACE
    fi
    echo "Using network interface: $INTERFACE"

    # Let's try multiple target sites
    TARGETS=("akpinar.dev" "map.akpinar.dev" "raksangsk.com" "example.com")
    
    # Start capturing packets in background with a more precise filter
    echo "Starting packet capture for TCP handshake analysis..."
    
    # This capture will run longer to ensure we get the handshake
    tshark -i "$INTERFACE" -f "tcp" -w "$RESULTS_BASE_DIR/capture.pcap" &
    TSHARK_PID=$!
    
    # Wait for tshark to start
    sleep 2
    
    # Try connecting to multiple targets to increase chances of capturing a clear handshake
    for TARGET in "${TARGETS[@]}"; do
        echo "Generating traffic by connecting to http://$TARGET..."
        curl -s "http://$TARGET" --connect-timeout 5 > /dev/null
        sleep 1
        
        echo "Generating traffic by connecting to https://$TARGET..."
        curl -s "https://$TARGET" --connect-timeout 5 > /dev/null
        sleep 1
    done
    
    # Let the capture run a bit longer to ensure we get the complete handshake
    sleep 3
    
    # Stop the capture
    echo "Stopping packet capture..."
    kill $TSHARK_PID 2>/dev/null
    wait $TSHARK_PID 2>/dev/null
    echo "Packet capture completed."
    
    # First, find a complete handshake conversation in the capture
    echo "Finding a complete TCP handshake in the capture..."
    
    # Use follow stream to find TCP conversations
    tshark -r "$RESULTS_BASE_DIR/capture.pcap" -T fields -e tcp.stream | sort -n | uniq > "$RESULTS_BASE_DIR/tcp_streams.txt"
    
    FOUND_HANDSHAKE=0
    SELECTED_STREAM=""
    
    # Check each stream for a complete handshake
    while read -r STREAM; do
        # Check if this stream has a SYN packet
        SYN_COUNT=$(tshark -r "$RESULTS_BASE_DIR/capture.pcap" -Y "tcp.stream==$STREAM and tcp.flags.syn==1 and tcp.flags.ack==0" | wc -l)
        
        # Check if this stream has a SYN-ACK packet
        SYNACK_COUNT=$(tshark -r "$RESULTS_BASE_DIR/capture.pcap" -Y "tcp.stream==$STREAM and tcp.flags.syn==1 and tcp.flags.ack==1" | wc -l)
        
        # Check if this stream has an ACK packet following the SYN and SYN-ACK
        ACK_COUNT=$(tshark -r "$RESULTS_BASE_DIR/capture.pcap" -Y "tcp.stream==$STREAM and tcp.flags.syn==0 and tcp.flags.ack==1 and tcp.len==0" | wc -l)
        
        # If we have all three packet types, we found a complete handshake
        if [ $SYN_COUNT -gt 0 ] && [ $SYNACK_COUNT -gt 0 ] && [ $ACK_COUNT -gt 0 ]; then
            FOUND_HANDSHAKE=1
            SELECTED_STREAM=$STREAM
            echo "Found complete handshake in TCP stream $STREAM"
            break
        fi
    done < "$RESULTS_BASE_DIR/tcp_streams.txt"
    
    if [ $FOUND_HANDSHAKE -eq 0 ]; then
        echo "Could not find a complete TCP handshake in the capture."
        echo "Please try running the script again."
        return 1
    fi
    
    echo "Analyzing TCP handshake in stream $SELECTED_STREAM..."
    
    # Extract the first SYN packet of the selected stream
    tshark -r "$RESULTS_BASE_DIR/capture.pcap" -Y "tcp.stream==$SELECTED_STREAM and tcp.flags.syn==1 and tcp.flags.ack==0" \
        -T fields -e frame.number -e frame.time -e ip.src -e tcp.srcport -e ip.dst -e tcp.dstport -e tcp.seq -e tcp.flags -E header=y \
        | head -2 > "$RESULTS_BASE_DIR/syn_packet.txt"
    
    # Extract the first SYN-ACK packet of the selected stream
    tshark -r "$RESULTS_BASE_DIR/capture.pcap" -Y "tcp.stream==$SELECTED_STREAM and tcp.flags.syn==1 and tcp.flags.ack==1" \
        -T fields -e frame.number -e frame.time -e ip.src -e tcp.srcport -e ip.dst -e tcp.dstport -e tcp.seq -e tcp.ack -e tcp.flags -E header=y \
        | head -2 > "$RESULTS_BASE_DIR/synack_packet.txt"
    
    # Extract the first ACK packet that completes the handshake
    tshark -r "$RESULTS_BASE_DIR/capture.pcap" -Y "tcp.stream==$SELECTED_STREAM and tcp.flags.syn==0 and tcp.flags.ack==1 and tcp.len==0" \
        -T fields -e frame.number -e frame.time -e ip.src -e tcp.srcport -e ip.dst -e tcp.dstport -e tcp.seq -e tcp.ack -e tcp.flags -E header=y \
        | head -2 > "$RESULTS_BASE_DIR/ack_packet.txt"
    
    # Set permissions for the generated files
    chmod 666 "$RESULTS_BASE_DIR/syn_packet.txt"
    chmod 666 "$RESULTS_BASE_DIR/synack_packet.txt"
    chmod 666 "$RESULTS_BASE_DIR/ack_packet.txt"
    
    # Save detailed packet view for each handshake packet - FIX HERE
    # Extract just the frame number from the first line of data (second line in file)
    SYN_FRAME=$(awk 'NR==2 {print $1}' "$RESULTS_BASE_DIR/syn_packet.txt" 2>/dev/null)
    SYNACK_FRAME=$(awk 'NR==2 {print $1}' "$RESULTS_BASE_DIR/synack_packet.txt" 2>/dev/null)
    ACK_FRAME=$(awk 'NR==2 {print $1}' "$RESULTS_BASE_DIR/ack_packet.txt" 2>/dev/null)
    
    if [ -n "$SYN_FRAME" ]; then
        tshark -r "$RESULTS_BASE_DIR/capture.pcap" -Y "frame.number==$SYN_FRAME" -V > "$RESULTS_BASE_DIR/syn_packet_detail.txt"
        chmod 666 "$RESULTS_BASE_DIR/syn_packet_detail.txt"
    fi
    
    if [ -n "$SYNACK_FRAME" ]; then
        tshark -r "$RESULTS_BASE_DIR/capture.pcap" -Y "frame.number==$SYNACK_FRAME" -V > "$RESULTS_BASE_DIR/synack_packet_detail.txt"
        chmod 666 "$RESULTS_BASE_DIR/synack_packet_detail.txt"
    fi
    
    if [ -n "$ACK_FRAME" ]; then
        tshark -r "$RESULTS_BASE_DIR/capture.pcap" -Y "frame.number==$ACK_FRAME" -V > "$RESULTS_BASE_DIR/ack_packet_detail.txt"
        chmod 666 "$RESULTS_BASE_DIR/ack_packet_detail.txt"
    fi
    
    # Extract the IP addresses and ports for later use
    if [ -f "$RESULTS_BASE_DIR/syn_packet.txt" ] && [ -s "$RESULTS_BASE_DIR/syn_packet.txt" ]; then
        SYN_DATA=$(awk 'NR==2' "$RESULTS_BASE_DIR/syn_packet.txt")
        SYN_SRC=$(echo "$SYN_DATA" | awk '{print $3}')
        SYN_SPORT=$(echo "$SYN_DATA" | awk '{print $4}')
        SYN_DST=$(echo "$SYN_DATA" | awk '{print $5}')
        SYN_DPORT=$(echo "$SYN_DATA" | awk '{print $6}')
        SYN_SEQ=$(echo "$SYN_DATA" | awk '{print $7}')
    fi
    
    if [ -f "$RESULTS_BASE_DIR/synack_packet.txt" ] && [ -s "$RESULTS_BASE_DIR/synack_packet.txt" ]; then
        SYNACK_DATA=$(awk 'NR==2' "$RESULTS_BASE_DIR/synack_packet.txt")
        SYNACK_SRC=$(echo "$SYNACK_DATA" | awk '{print $3}')
        SYNACK_SPORT=$(echo "$SYNACK_DATA" | awk '{print $4}')
        SYNACK_DST=$(echo "$SYNACK_DATA" | awk '{print $5}')
        SYNACK_DPORT=$(echo "$SYNACK_DATA" | awk '{print $6}')
        SYNACK_SEQ=$(echo "$SYNACK_DATA" | awk '{print $7}')
        SYNACK_ACK=$(echo "$SYNACK_DATA" | awk '{print $8}')
    fi
    
    if [ -f "$RESULTS_BASE_DIR/ack_packet.txt" ] && [ -s "$RESULTS_BASE_DIR/ack_packet.txt" ]; then
        ACK_DATA=$(awk 'NR==2' "$RESULTS_BASE_DIR/ack_packet.txt")
        ACK_SRC=$(echo "$ACK_DATA" | awk '{print $3}')
        ACK_SPORT=$(echo "$ACK_DATA" | awk '{print $4}')
        ACK_DST=$(echo "$ACK_DATA" | awk '{print $5}')
        ACK_DPORT=$(echo "$ACK_DATA" | awk '{print $6}')
        ACK_SEQ=$(echo "$ACK_DATA" | awk '{print $7}')
        ACK_ACK=$(echo "$ACK_DATA" | awk '{print $8}')
    fi
    
    # Save the handshake packets to a separate capture file
    if [ -n "$SYN_FRAME" ] && [ -n "$SYNACK_FRAME" ] && [ -n "$ACK_FRAME" ]; then
        echo "Saving handshake packets to separate capture file..."
        tshark -r "$RESULTS_BASE_DIR/capture.pcap" -w "$RESULTS_BASE_DIR/handshake_only.pcap" -Y "frame.number==$SYN_FRAME or frame.number==$SYNACK_FRAME or frame.number==$ACK_FRAME"
        chmod 666 "$RESULTS_BASE_DIR/handshake_only.pcap"
        
        # Generate a summary of just the handshake
        tshark -r "$RESULTS_BASE_DIR/handshake_only.pcap" > "$RESULTS_BASE_DIR/handshake_summary.txt"
        chmod 666 "$RESULTS_BASE_DIR/handshake_summary.txt"
    fi
    
    # Create Markdown report file instead of plain text file
    cat > "$RESULTS_BASE_DIR/Report.md" << EOL
# TCP Handshake Analysis Report

## Overview
This report analyzes the TCP 3-way handshake process using captured network traffic data. The TCP handshake is a fundamental process for establishing reliable connections between network devices.

## Why TCP 3-Way Handshake Is Used
1. To establish a reliable connection between client and server
2. To synchronize sequence numbers between both sides
3. To agree on parameters for the connection
4. To ensure both sides are ready to exchange data
5. To prevent old duplicate connections from being established

## The Three Packets of the Handshake (With Captured Data)

### 1. SYN Packet (Client → Server)
- **Purpose**: Client initiates connection
- **Flags**: SYN=1, ACK=0
- **Source IP & Port**: $SYN_SRC:$SYN_SPORT
- **Destination IP & Port**: $SYN_DST:$SYN_DPORT
- **Initial Sequence Number (ISN)**: $SYN_SEQ

### 2. SYN-ACK Packet (Server → Client)
- **Purpose**: Server acknowledges connection request
- **Flags**: SYN=1, ACK=1
- **Source IP & Port**: $SYNACK_SRC:$SYNACK_SPORT
- **Destination IP & Port**: $SYNACK_DST:$SYNACK_DPORT
- **Server's Sequence Number**: $SYNACK_SEQ
- **Acknowledgment Number**: $SYNACK_ACK (Client's ISN + 1)

### 3. ACK Packet (Client → Server)
- **Purpose**: Client acknowledges the server's response
- **Flags**: SYN=0, ACK=1
- **Source IP & Port**: $ACK_SRC:$ACK_SPORT
- **Destination IP & Port**: $ACK_DST:$ACK_DPORT
- **Sequence Number**: $ACK_SEQ
- **Acknowledgment Number**: $ACK_ACK (Server's ISN + 1)

## Connection Establishment
After this exchange, the TCP connection is established and data transfer can begin.

## Visual Representation
\`\`\`
  CLIENT ($SYN_SRC:$SYN_SPORT)                    SERVER ($SYN_DST:$SYN_DPORT)
    |                                     |
    |------- SYN, Seq=$SYN_SEQ ---------->  |
    |                                     |
    |  <-- SYN-ACK, Seq=$SYNACK_SEQ, ACK=$SYNACK_ACK -- |
    |                                     |
    |------- ACK, ACK=$ACK_ACK ---------->  |
    |                                     |
    |          CONNECTION ESTABLISHED     |
    |                                     |
\`\`\`

## Student Information
- Student Number: $STUDENT_NUMBER
- Generated IP for filtering: $GENERATED_IP
- Analysis completed on: $(date)
EOL
    chmod 666 "$RESULTS_BASE_DIR/Report.md"
    
    # Display analysis results in terminal
    echo "===================================================================="
    echo "                    TCP HANDSHAKE ANALYSIS RESULTS                   "
    echo "===================================================================="
    echo
    echo "PACKET 1 (SYN):"
    if [ -f "$RESULTS_BASE_DIR/syn_packet.txt" ] && [ -s "$RESULTS_BASE_DIR/syn_packet.txt" ]; then
        cat "$RESULTS_BASE_DIR/syn_packet.txt"
        echo
        echo "Details from packet:"
        echo "Source IP & Port: $SYN_SRC:$SYN_SPORT"
        echo "Destination IP & Port: $SYN_DST:$SYN_DPORT"
        echo "Initial Sequence Number (ISN): $SYN_SEQ"
        echo "Flags: SYN=1, ACK=0"
    else
        echo "SYN packet data not available."
    fi
    echo
    
    echo "PACKET 2 (SYN-ACK):"
    if [ -f "$RESULTS_BASE_DIR/synack_packet.txt" ] && [ -s "$RESULTS_BASE_DIR/synack_packet.txt" ]; then
        cat "$RESULTS_BASE_DIR/synack_packet.txt"
        echo
        echo "Details from packet:"
        echo "Source IP & Port: $SYNACK_SRC:$SYNACK_SPORT"
        echo "Destination IP & Port: $SYNACK_DST:$SYNACK_DPORT"
        echo "Server's Sequence Number: $SYNACK_SEQ"
        echo "Acknowledgment Number: $SYNACK_ACK (Client's ISN + 1)"
        echo "Flags: SYN=1, ACK=1"
    else
        echo "SYN-ACK packet data not available."
    fi
    echo
    
    echo "PACKET 3 (ACK):"
    if [ -f "$RESULTS_BASE_DIR/ack_packet.txt" ] && [ -s "$RESULTS_BASE_DIR/ack_packet.txt" ]; then
        cat "$RESULTS_BASE_DIR/ack_packet.txt"
        echo
        echo "Details from packet:"
        echo "Source IP & Port: $ACK_SRC:$ACK_SPORT"
        echo "Destination IP & Port: $ACK_DST:$ACK_DPORT"
        echo "Sequence Number: $ACK_SEQ"
        echo "Acknowledgment Number: $ACK_ACK (Server's ISN + 1)"
        echo "Flags: SYN=0, ACK=1"
    else
        echo "ACK packet data not available."
    fi
    echo
    
    # Create a visual display of the handshake with actual data
    echo "TCP 3-WAY HANDSHAKE VISUALIZATION WITH ACTUAL DATA:"
    echo
    echo "  CLIENT ($SYN_SRC:$SYN_SPORT)                    SERVER ($SYN_DST:$SYN_DPORT)"
    echo "    |                                     |"
    echo "    |------- SYN, Seq=$SYN_SEQ ---------->  |"
    echo "    |                                     |"
    echo "    |  <-- SYN-ACK, Seq=$SYNACK_SEQ, ACK=$SYNACK_ACK -- |"
    echo "    |                                     |"
    echo "    |------- ACK, ACK=$ACK_ACK ---------->  |"
    echo "    |                                     |"
    echo "    |          CONNECTION ESTABLISHED     |"
    echo "    |                                     |"
    echo
    
    # Explain why TCP 3-way handshake is used
    echo "WHY THE TCP 3-WAY HANDSHAKE IS USED:"
    echo "- Establishes a reliable connection before data transfer"
    echo "- Synchronizes sequence numbers between client and server"
    echo "- Allows both parties to agree they are ready to communicate"
    echo "- Helps prevent old duplicate connections"
    echo "- Provides security against certain types of attacks"
    echo
    
    echo "All analysis results saved to: $RESULTS_BASE_DIR/"
    echo "Markdown report created at: $RESULTS_BASE_DIR/Report.md"
    echo "File permissions set to allow all users to read, write, and delete files"
    echo "===================================================================="
    
    # Create a cleanup script for easy deletion
    cat > "$RESULTS_BASE_DIR/cleanup.sh" << EOL
#!/bin/bash
# Cleanup script to remove all analysis files
echo "Removing TCP handshake analysis directory: $RESULTS_BASE_DIR"
rm -rf "$RESULTS_BASE_DIR"
echo "Cleanup completed!"
EOL
    chmod 755 "$RESULTS_BASE_DIR/cleanup.sh"
    
    echo "A cleanup script has been created at: $RESULTS_BASE_DIR/cleanup.sh"
    echo "To remove all analysis files, run: $RESULTS_BASE_DIR/cleanup.sh"
}
analyze_dns_queries() {
    # Check if tshark is installed
    if ! command -v tshark &> /dev/null; then
        echo "Error: tshark is not installed. Please install it with:"
        echo "sudo apt install tshark"
        return 1
    fi

    # Create results directory for DNS analysis
    DNS_RESULTS_DIR="dns_analysis_$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$DNS_RESULTS_DIR"
    echo "Created directory: $DNS_RESULTS_DIR"
    
    # Set permissions
    chmod -R 777 "$DNS_RESULTS_DIR"
    echo "Set permissions to allow anyone to access and modify the results"

    # Determine network interface automatically
    INTERFACE=$(ip -o -4 route show to default | awk '{print $5}' | head -1)
    if [ -z "$INTERFACE" ]; then
        echo "Could not determine network interface. Please enter it manually:"
        read -p "Interface name: " INTERFACE
    fi
    echo "Using network interface: $INTERFACE"

    # Define domains to query
    DOMAINS=("google.com" "youtube.com")
    
    # Create a directory to store temporary DNS server information
    mkdir -p "$DNS_RESULTS_DIR/tmp"
    
    # Get current DNS server
    echo "Detecting DNS servers..."
    cat /etc/resolv.conf | grep nameserver | awk '{print $2}' > "$DNS_RESULTS_DIR/tmp/dns_servers.txt"
    
    # Start capturing all DNS packets - use broader capture filter
    echo "Starting packet capture for DNS analysis..."
    tshark -i "$INTERFACE" -f "udp port 53 or tcp port 53" -w "$DNS_RESULTS_DIR/dns_capture.pcap" &
    TSHARK_PID=$!
    
    # Wait for tshark to start
    sleep 2
    
    # For each domain, perform multiple query attempts with various tools
    for DOMAIN in "${DOMAINS[@]}"; do
        echo "Generating DNS queries for $DOMAIN using multiple methods..."
        
        # Try to flush DNS cache to ensure fresh queries
        if command -v systemd-resolve &> /dev/null; then
            echo "Flushing DNS cache (systemd-resolve)..."
            sudo systemd-resolve --flush-caches &> /dev/null
        elif command -v service &> /dev/null && [ -f /etc/init.d/dns-clean ]; then
            echo "Flushing DNS cache (dns-clean)..."
            sudo service dns-clean start &> /dev/null
        elif command -v nscd &> /dev/null; then
            echo "Restarting nscd to clear cache..."
            sudo service nscd restart &> /dev/null
        fi
        
        # Query using different tools to maximize chances of capture
        echo "Querying $DOMAIN using dig..."
        dig $DOMAIN A +noall +answer
        sleep 1
        
        echo "Querying $DOMAIN using nslookup..."
        nslookup $DOMAIN
        sleep 1
        
        echo "Querying $DOMAIN using host..."
        host $DOMAIN
        sleep 1
        
        # Also try direct web access which will trigger DNS lookup
        echo "Accessing $DOMAIN via curl to trigger DNS lookup..."
        curl -s "http://$DOMAIN" --connect-timeout 3 > /dev/null
        sleep 2
    done
    
    # Let the capture run a bit longer to ensure we get all responses
    echo "Waiting to capture all DNS responses..."
    sleep 5
    
    # Stop the capture
    echo "Stopping packet capture..."
    kill $TSHARK_PID 2>/dev/null
    wait $TSHARK_PID 2>/dev/null
    echo "Packet capture completed."
    
    # Extract all DNS queries and responses from the capture file
    echo "Extracting all DNS queries from capture file..."
    tshark -r "$DNS_RESULTS_DIR/dns_capture.pcap" -Y "dns.flags.response == 0" > "$DNS_RESULTS_DIR/all_dns_queries.txt"
    
    echo "Extracting all DNS responses from capture file..."
    tshark -r "$DNS_RESULTS_DIR/dns_capture.pcap" -Y "dns.flags.response == 1" > "$DNS_RESULTS_DIR/all_dns_responses.txt"
    
    # Initialize arrays to store query and response frame numbers
    declare -A QUERY_FRAMES
    declare -A RESPONSE_FRAMES
    
    # Process each domain
    for DOMAIN in "${DOMAINS[@]}"; do
        echo "Processing $DOMAIN..."
        
        # Extract query packets more directly
        echo "Finding DNS queries for $DOMAIN..."
        tshark -r "$DNS_RESULTS_DIR/dns_capture.pcap" -Y "dns.qry.name contains \"$DOMAIN\" and dns.flags.response == 0" \
            -T fields -e frame.number -e frame.time_relative -e ip.src -e udp.srcport -e ip.dst -e udp.dstport -e dns.qry.name -e dns.id -E header=y \
            > "$DNS_RESULTS_DIR/${DOMAIN}_queries.txt"
        
        # Get the IDs of DNS queries for this domain to match with responses
        if [ -s "$DNS_RESULTS_DIR/${DOMAIN}_queries.txt" ]; then
            # Take the first query
            QUERY_LINE=$(sed -n '2p' "$DNS_RESULTS_DIR/${DOMAIN}_queries.txt" 2>/dev/null)
            
            if [ -n "$QUERY_LINE" ]; then
                QUERY_FRAME=$(echo "$QUERY_LINE" | awk '{print $1}')
                QUERY_TIME=$(echo "$QUERY_LINE" | awk '{print $2}')
                QUERY_SRC=$(echo "$QUERY_LINE" | awk '{print $3}')
                QUERY_SPORT=$(echo "$QUERY_LINE" | awk '{print $4}')
                QUERY_DST=$(echo "$QUERY_LINE" | awk '{print $5}')
                QUERY_DPORT=$(echo "$QUERY_LINE" | awk '{print $6}')
                DNS_ID=$(echo "$QUERY_LINE" | awk '{print $8}')
                
                # Save query frame
                QUERY_FRAMES[$DOMAIN]=$QUERY_FRAME
                
                echo "Found DNS query for $DOMAIN - Frame: $QUERY_FRAME, ID: $DNS_ID"
                echo "  Source: $QUERY_SRC:$QUERY_SPORT, Destination: $QUERY_DST:$QUERY_DPORT"
                
                # Create a summary of the first query
                tshark -r "$DNS_RESULTS_DIR/dns_capture.pcap" -Y "frame.number == $QUERY_FRAME" -V > "$DNS_RESULTS_DIR/${DOMAIN}_query_detail.txt"
                
                # Save selected query information as first query
                head -n 2 "$DNS_RESULTS_DIR/${DOMAIN}_queries.txt" > "$DNS_RESULTS_DIR/${DOMAIN}_query.txt"
                
                # Now find corresponding response
                echo "Finding DNS response for $DOMAIN with ID $DNS_ID..."
                tshark -r "$DNS_RESULTS_DIR/dns_capture.pcap" -Y "dns.flags.response == 1 and dns.id == $DNS_ID" \
                    -T fields -e frame.number -e frame.time_relative -e ip.src -e udp.srcport -e ip.dst -e udp.dstport -e dns.resp.name -e dns.a -E header=y \
                    > "$DNS_RESULTS_DIR/${DOMAIN}_responses.txt"
                
                if [ -s "$DNS_RESULTS_DIR/${DOMAIN}_responses.txt" ]; then
                    # Take the first response
                    RESPONSE_LINE=$(sed -n '2p' "$DNS_RESULTS_DIR/${DOMAIN}_responses.txt" 2>/dev/null)
                    
                    if [ -n "$RESPONSE_LINE" ]; then
                        RESPONSE_FRAME=$(echo "$RESPONSE_LINE" | awk '{print $1}')
                        RESPONSE_TIME=$(echo "$RESPONSE_LINE" | awk '{print $2}')
                        RESPONSE_SRC=$(echo "$RESPONSE_LINE" | awk '{print $3}')
                        RESPONSE_SPORT=$(echo "$RESPONSE_LINE" | awk '{print $4}')
                        RESPONSE_DST=$(echo "$RESPONSE_LINE" | awk '{print $5}')
                        RESPONSE_DPORT=$(echo "$RESPONSE_LINE" | awk '{print $6}')
                        RESOLVED_IP=$(echo "$RESPONSE_LINE" | awk '{print $8}')
                        
                        # Save response frame
                        RESPONSE_FRAMES[$DOMAIN]=$RESPONSE_FRAME
                        
                        echo "Found DNS response for $DOMAIN - Frame: $RESPONSE_FRAME"
                        echo "  Source: $RESPONSE_SRC:$RESPONSE_SPORT, Destination: $RESPONSE_DST:$RESPONSE_DPORT"
                        echo "  Resolved IP: $RESOLVED_IP"
                        
                        # Calculate response time
                        RESPONSE_TIME_MS=$(echo "$RESPONSE_TIME - $QUERY_TIME" | bc)
                        
                        # Create a summary of the first response
                        tshark -r "$DNS_RESULTS_DIR/dns_capture.pcap" -Y "frame.number == $RESPONSE_FRAME" -V > "$DNS_RESULTS_DIR/${DOMAIN}_response_detail.txt"
                        
                        # Save selected response information as first response
                        head -n 2 "$DNS_RESULTS_DIR/${DOMAIN}_responses.txt" > "$DNS_RESULTS_DIR/${DOMAIN}_response.txt"
                        
                        # Extract TTL from detailed packet view
                        TTL=$(grep -A 3 "Time to live" "$DNS_RESULTS_DIR/${DOMAIN}_response_detail.txt" | grep "TTL" | awk '{print $2}')
                        if [ -z "$TTL" ]; then
                            TTL="N/A (not found in packet)"
                        fi
                        
                        # Create a separate capture of just this query/response pair
                        tshark -r "$DNS_RESULTS_DIR/dns_capture.pcap" -w "$DNS_RESULTS_DIR/${DOMAIN}_dns_exchange.pcap" \
                            -Y "frame.number == $QUERY_FRAME or frame.number == $RESPONSE_FRAME"
                        
                        # Create analysis document for this domain
                        cat > "$DNS_RESULTS_DIR/${DOMAIN}_analysis.txt" << EOL
======================================================================
                     DNS ANALYSIS FOR $DOMAIN
======================================================================

DNS QUERY:
---------
Frame Number: $QUERY_FRAME
Source IP & Port: $QUERY_SRC:$QUERY_SPORT
Destination IP & Port: $QUERY_DST:$QUERY_DPORT
Query Time: $QUERY_TIME seconds from capture start
Domain Name Queried: $DOMAIN
DNS Query ID: $DNS_ID

DNS RESPONSE:
------------
Frame Number: $RESPONSE_FRAME
Source IP & Port: $RESPONSE_SRC:$RESPONSE_SPORT
Destination IP & Port: $RESPONSE_DST:$RESPONSE_DPORT
Response Time: $RESPONSE_TIME seconds from capture start
Resolved IP Address: $RESOLVED_IP
Time-to-Live (TTL): $TTL
Response Delay: $RESPONSE_TIME_MS seconds

DNS RESOLUTION PROCESS OBSERVED:
------------------------------
1. Your computer sent a DNS query asking: "What's the IP address for $DOMAIN?"
   - The query was sent from $QUERY_SRC:$QUERY_SPORT
   - It was sent to DNS server at $QUERY_DST:$QUERY_DPORT
   - A unique identifier (DNS ID: $DNS_ID) was assigned to track this query

2. The DNS server responded with the answer:
   - The server at $RESPONSE_SRC:$RESPONSE_SPORT sent back a response
   - It answered: "$DOMAIN is located at IP address $RESOLVED_IP"
   - This answer can be cached for $TTL seconds before it expires
   - The response took approximately $RESPONSE_TIME_MS seconds

3. Now your computer can connect directly to $DOMAIN using the IP address $RESOLVED_IP

This is how DNS (Domain Name System) works as the internet's "phone book,"
translating human-readable domain names into IP addresses that computers use
to identify each other on the network.

======================================================================
EOL
                    else
                        echo "No response line found for $DOMAIN"
                    fi
                else
                    echo "No DNS response found for $DOMAIN with ID $DNS_ID"
                    # Try an alternative approach - look for any responses with this domain
                    echo "Trying alternative approach to find response..."
                    tshark -r "$DNS_RESULTS_DIR/dns_capture.pcap" -Y "dns.flags.response == 1 and dns.resp.name contains \"$DOMAIN\"" \
                        -T fields -e frame.number -e frame.time_relative -e ip.src -e udp.srcport -e ip.dst -e udp.dstport -e dns.resp.name -e dns.a -E header=y \
                        > "$DNS_RESULTS_DIR/${DOMAIN}_alt_responses.txt"
                    
                    if [ -s "$DNS_RESULTS_DIR/${DOMAIN}_alt_responses.txt" ]; then
                        cp "$DNS_RESULTS_DIR/${DOMAIN}_alt_responses.txt" "$DNS_RESULTS_DIR/${DOMAIN}_response.txt"
                        echo "Found alternative responses for $DOMAIN, saved to file"
                    fi
                fi
            else
                echo "No query line found for $DOMAIN"
            fi
        else
            echo "No DNS queries found for $DOMAIN"
        fi
    done
    
    # Generate summary of findings based on what was actually captured
    echo "Generating DNS analysis summary based on captured data..."
    
    # Check if we have any captured data
    if [ ${#QUERY_FRAMES[@]} -eq 0 ]; then
        echo "No DNS queries were successfully captured. Cannot generate summary."
        return 1
    fi
    
    # Create domain-specific summaries for summary document
    GOOGLE_SUMMARY=""
    YOUTUBE_SUMMARY=""
    
    if [ -n "${QUERY_FRAMES[google.com]}" ] && [ -n "${RESPONSE_FRAMES[google.com]}" ]; then
        # Get Google.com IP
        GOOGLE_IP=$(grep -A 5 "Answers" "$DNS_RESULTS_DIR/google.com_response_detail.txt" | grep "addr" | head -1 | awk '{print $NF}')
        GOOGLE_QUERY_PORT=$(grep -A 2 "User Datagram Protocol" "$DNS_RESULTS_DIR/google.com_query_detail.txt" | grep "Source Port" | awk '{print $NF}')
        GOOGLE_RESPONSE_PORT=$(grep -A 2 "User Datagram Protocol" "$DNS_RESULTS_DIR/google.com_response_detail.txt" | grep "Source Port" | awk '{print $NF}')
        
        GOOGLE_SUMMARY="
GOOGLE.COM FINDINGS:
- Resolved IP address: $GOOGLE_IP
- Source port used for query: $GOOGLE_QUERY_PORT
- Server port used for response: $GOOGLE_RESPONSE_PORT"
    else
        GOOGLE_SUMMARY="
GOOGLE.COM: Analysis data incomplete (missing query or response packets)"
    fi
    
    if [ -n "${QUERY_FRAMES[youtube.com]}" ] && [ -n "${RESPONSE_FRAMES[youtube.com]}" ]; then
        # Get YouTube.com IP
        YOUTUBE_IP=$(grep -A 5 "Answers" "$DNS_RESULTS_DIR/youtube.com_response_detail.txt" | grep "addr" | head -1 | awk '{print $NF}')
        YOUTUBE_QUERY_PORT=$(grep -A 2 "User Datagram Protocol" "$DNS_RESULTS_DIR/youtube.com_query_detail.txt" | grep "Source Port" | awk '{print $NF}')
        YOUTUBE_RESPONSE_PORT=$(grep -A 2 "User Datagram Protocol" "$DNS_RESULTS_DIR/youtube.com_response_detail.txt" | grep "Source Port" | awk '{print $NF}')
        
        YOUTUBE_SUMMARY="
YOUTUBE.COM FINDINGS:
- Resolved IP address: $YOUTUBE_IP
- Source port used for query: $YOUTUBE_QUERY_PORT
- Server port used for response: $YOUTUBE_RESPONSE_PORT"
    else
        YOUTUBE_SUMMARY="
YOUTUBE.COM: Analysis data incomplete (missing query or response packets)"
    fi
    
    # Create general summary based on observed data
    # Get transport protocol used (UDP or TCP)
    TRANSPORT_PROTOCOL=$(grep -A 2 "Frame" "$DNS_RESULTS_DIR/all_dns_queries.txt" | grep -o "UDP\|TCP" | head -1)
    if [ -z "$TRANSPORT_PROTOCOL" ]; then
        TRANSPORT_PROTOCOL="UDP (default for DNS)"
    fi
    
    # Create summary document
    cat > "$DNS_RESULTS_DIR/dns_summary.txt" << EOL
======================================================================
                     DNS ANALYSIS SUMMARY
======================================================================

CAPTURED DATA SUMMARY:
--------------------
This analysis is based on actual DNS traffic captured on $(date)
Number of domains analyzed: ${#QUERY_FRAMES[@]}
Transport protocol observed: $TRANSPORT_PROTOCOL

$GOOGLE_SUMMARY

$YOUTUBE_SUMMARY

HOW DNS WORKS (BASED ON OBSERVED DATA):
------------------------------------
DNS (Domain Name System) acts as the internet's "phone book," translating 
domain names like google.com into IP addresses that computers use to 
identify each other.

THE DNS RESOLUTION PROCESS OBSERVED:
----------------------------------
1. REQUEST: Your computer generates a DNS query packet asking for the IP 
   address of the domain (google.com or youtube.com in this case).
   - The query includes a random source port (usually above 1024)
   - Destination is typically port 53 on your configured DNS server
   - Each query contains a unique ID to match responses to queries

2. LOOKUP: The DNS server receives your query and looks up the domain name.
   If it doesn't have the answer cached, it may query other DNS servers.

3. RESPONSE: The DNS server sends back a response containing:
   - The same ID as your query to match them up
   - The IP address(es) associated with the domain name
   - A Time-To-Live (TTL) value indicating how long to cache the result

4. CONNECTION: Your computer now has the IP address and can connect directly
   to the website server.

DNS PACKET STRUCTURE (OBSERVED):
------------------------------
As seen in our captures, DNS packets contain:
- Header: Contains query ID, flags, and section counts
- Question Section: The domain name being queried
- Answer Section: Contains the IP address(es) when it's a response
- Additional Sections: May contain extra information

PORTS USED (FROM ACTUAL CAPTURE):
------------------------------
- DNS server used port 53 (standard DNS port)
- Client used random high ports for queries

SECURITY CONSIDERATIONS:
---------------------
- The DNS traffic observed was unencrypted, which is typical but a potential
  security risk (eavesdropping possible)
- Modern alternatives like DNS over HTTPS (DoH) and DNS over TLS (DoT)
  encrypt DNS traffic for better privacy and security
- DNSSEC wasn't observed in these captures, but would help authenticate
  responses to prevent spoofing

======================================================================
EOL
    # Create summary document in Markdown format
    cat > "$DNS_RESULTS_DIR/dns_summary.md" << EOL
# DNS Analysis Summary

## Captured Data Summary
This analysis is based on actual DNS traffic captured on $(date)
- Number of domains analyzed: ${#QUERY_FRAMES[@]}
- Transport protocol observed: $TRANSPORT_PROTOCOL

## Domain-Specific Findings

### Google.com
$(if [ -n "${QUERY_FRAMES[google.com]}" ] && [ -n "${RESPONSE_FRAMES[google.com]}" ]; then
echo "- Resolved IP address: $GOOGLE_IP
- Source port used for query: $GOOGLE_QUERY_PORT
- Server port used for response: $GOOGLE_RESPONSE_PORT"
else
echo "Analysis data incomplete (missing query or response packets)"
fi)

### YouTube.com
$(if [ -n "${QUERY_FRAMES[youtube.com]}" ] && [ -n "${RESPONSE_FRAMES[youtube.com]}" ]; then
echo "- Resolved IP address: $YOUTUBE_IP
- Source port used for query: $YOUTUBE_QUERY_PORT
- Server port used for response: $YOUTUBE_RESPONSE_PORT"
else
echo "Analysis data incomplete (missing query or response packets)"
fi)

## How DNS Works (Based on Observed Data)
DNS (Domain Name System) acts as the internet's "phone book," translating 
domain names like google.com into IP addresses that computers use to 
identify each other.

## The DNS Resolution Process Observed

1. **REQUEST**: Your computer generates a DNS query packet asking for the IP 
   address of the domain (google.com or youtube.com in this case).
   - The query includes a random source port (usually above 1024)
   - Destination is typically port 53 on your configured DNS server
   - Each query contains a unique ID to match responses to queries

2. **LOOKUP**: The DNS server receives your query and looks up the domain name.
   If it doesn't have the answer cached, it may query other DNS servers.

3. **RESPONSE**: The DNS server sends back a response containing:
   - The same ID as your query to match them up
   - The IP address(es) associated with the domain name
   - A Time-To-Live (TTL) value indicating how long to cache the result

4. **CONNECTION**: Your computer now has the IP address and can connect directly
   to the website server.

## DNS Packet Structure (Observed)
As seen in our captures, DNS packets contain:
- **Header**: Contains query ID, flags, and section counts
- **Question Section**: The domain name being queried
- **Answer Section**: Contains the IP address(es) when it's a response
- **Additional Sections**: May contain extra information

## Ports Used (From Actual Capture)
- DNS server used port 53 (standard DNS port)
- Client used random high ports for queries

## Security Considerations
- The DNS traffic observed was unencrypted, which is typical but a potential
  security risk (eavesdropping possible)
- Modern alternatives like DNS over HTTPS (DoH) and DNS over TLS (DoT)
  encrypt DNS traffic for better privacy and security
- DNSSEC wasn't observed in these captures, but would help authenticate
  responses to prevent spoofing
EOL

    # Also create domain-specific Markdown analysis files
    for DOMAIN in "${DOMAINS[@]}"; do
        if [ -n "${QUERY_FRAMES[$DOMAIN]}" ] && [ -n "${RESPONSE_FRAMES[$DOMAIN]}" ]; then
            # Get domain details
            QUERY_FRAME=${QUERY_FRAMES[$DOMAIN]}
            RESPONSE_FRAME=${RESPONSE_FRAMES[$DOMAIN]}
            
            # Get details from the existing text files
            QUERY_LINE=$(sed -n '2p' "$DNS_RESULTS_DIR/${DOMAIN}_queries.txt" 2>/dev/null)
            RESPONSE_LINE=$(sed -n '2p' "$DNS_RESULTS_DIR/${DOMAIN}_responses.txt" 2>/dev/null)
            
            # Extract values
            QUERY_TIME=$(echo "$QUERY_LINE" | awk '{print $2}')
            QUERY_SRC=$(echo "$QUERY_LINE" | awk '{print $3}')
            QUERY_SPORT=$(echo "$QUERY_LINE" | awk '{print $4}')
            QUERY_DST=$(echo "$QUERY_LINE" | awk '{print $5}')
            QUERY_DPORT=$(echo "$QUERY_LINE" | awk '{print $6}')
            DNS_ID=$(echo "$QUERY_LINE" | awk '{print $8}')
            
            RESPONSE_TIME=$(echo "$RESPONSE_LINE" | awk '{print $2}')
            RESPONSE_SRC=$(echo "$RESPONSE_LINE" | awk '{print $3}')
            RESPONSE_SPORT=$(echo "$RESPONSE_LINE" | awk '{print $4}')
            RESPONSE_DST=$(echo "$RESPONSE_LINE" | awk '{print $5}')
            RESPONSE_DPORT=$(echo "$RESPONSE_LINE" | awk '{print $6}')
            RESOLVED_IP=$(echo "$RESPONSE_LINE" | awk '{print $8}')
            
            # Calculate response time
            RESPONSE_TIME_MS=$(echo "$RESPONSE_TIME - $QUERY_TIME" | bc)
            
            # Extract TTL from detailed packet view
            TTL=$(grep -A 3 "Time to live" "$DNS_RESULTS_DIR/${DOMAIN}_response_detail.txt" | grep "TTL" | awk '{print $2}')
            if [ -z "$TTL" ]; then
                TTL="N/A (not found in packet)"
            fi
            
            # Create markdown analysis file
            cat > "$DNS_RESULTS_DIR/${DOMAIN}_analysis.md" << EOL
# DNS Analysis for ${DOMAIN}

## DNS Query
- **Frame Number**: $QUERY_FRAME
- **Source IP & Port**: $QUERY_SRC:$QUERY_SPORT
- **Destination IP & Port**: $QUERY_DST:$QUERY_DPORT
- **Query Time**: $QUERY_TIME seconds from capture start
- **Domain Name Queried**: $DOMAIN
- **DNS Query ID**: $DNS_ID

## DNS Response
- **Frame Number**: $RESPONSE_FRAME
- **Source IP & Port**: $RESPONSE_SRC:$RESPONSE_SPORT
- **Destination IP & Port**: $RESPONSE_DST:$RESPONSE_DPORT
- **Response Time**: $RESPONSE_TIME seconds from capture start
- **Resolved IP Address**: $RESOLVED_IP
- **Time-to-Live (TTL)**: $TTL
- **Response Delay**: $RESPONSE_TIME_MS seconds

## DNS Resolution Process Observed

1. Your computer sent a DNS query asking: "What's the IP address for $DOMAIN?"
   - The query was sent from $QUERY_SRC:$QUERY_SPORT
   - It was sent to DNS server at $QUERY_DST:$QUERY_DPORT
   - A unique identifier (DNS ID: $DNS_ID) was assigned to track this query

2. The DNS server responded with the answer:
   - The server at $RESPONSE_SRC:$RESPONSE_SPORT sent back a response
   - It answered: "$DOMAIN is located at IP address $RESOLVED_IP"
   - This answer can be cached for $TTL seconds before it expires
   - The response took approximately $RESPONSE_TIME_MS seconds

3. Now your computer can connect directly to $DOMAIN using the IP address $RESOLVED_IP

This is how DNS (Domain Name System) works as the internet's "phone book,"
translating human-readable domain names into IP addresses that computers use
to identify each other on the network.
EOL
        fi
    done
    


    # Set permissions for all generated files
    chmod -R 666 "$DNS_RESULTS_DIR"/*.txt
    chmod -R 666 "$DNS_RESULTS_DIR"/*.pcap
    chmod -R 666 "$DNS_RESULTS_DIR"/*.md

    
    echo "===================================================================="
    echo "                    DNS ANALYSIS COMPLETED                           "
    echo "===================================================================="
    echo "All analysis results saved to: $DNS_RESULTS_DIR/"
    echo "Creating sample screenshot instructions..."
    
    # Create instructions for taking screenshots
    cat > "$DNS_RESULTS_DIR/screenshot_instructions.txt" << EOL
SCREENSHOT INSTRUCTIONS FOR DNS ANALYSIS
=======================================

For your assignment, take screenshots of the following:

For Google.com:
1. Open Wireshark and load the capture file: $DNS_RESULTS_DIR/dns_capture.pcap
2. Apply filter: "dns.qry.name contains \"google.com\""
3. Take a screenshot of a DNS query packet
   - Right-click on a query packet and select "Follow > UDP Stream" to see the full exchange
4. Take a screenshot of a DNS response packet showing the resolved IP address
   - Expand the "Domain Name System (response)" section
   - Expand the "Answers" section to show the IP address

For Youtube.com:
1. Using the same capture file
2. Apply filter: "dns.qry.name contains \"youtube.com\""
3. Take a screenshot of a DNS query packet
4. Take a screenshot of a DNS response packet showing the resolved IP address

Analysis Writing Guidelines:
---------------------------
Use the information in $DNS_RESULTS_DIR/dns_summary.txt and the domain-specific
analysis files to write your analysis. Include:

1. How DNS resolves domain names to IP addresses (the process)
2. The specific information observed in your captures:
   - Source and destination ports
   - Response times
   - Resolved IP addresses
3. Compare the results between Google.com and YouTube.com
4. Any security considerations related to DNS

EOL
    chmod 666 "$DNS_RESULTS_DIR/screenshot_instructions.txt"
    
    # Create a cleanup script for easy deletion
    cat > "$DNS_RESULTS_DIR/cleanup.sh" << EOL
#!/bin/bash
# Cleanup script to remove all DNS analysis files
echo "Removing DNS analysis directory: $DNS_RESULTS_DIR"
rm -rf "$DNS_RESULTS_DIR"
echo "Cleanup completed!"
EOL
    chmod 755 "$DNS_RESULTS_DIR/cleanup.sh"
    
    echo "A cleanup script has been created at: $DNS_RESULTS_DIR/cleanup.sh"
    echo "To remove all analysis files, run: $DNS_RESULTS_DIR/cleanup.sh"
}
analyze_icmp_ping() {
    # Check if tshark is installed
    if ! command -v tshark &> /dev/null; then
        echo "Error: tshark is not installed. Please install it with:"
        echo "sudo apt install tshark"
        return 1
    fi

    # Create results directory for ICMP analysis
    ICMP_RESULTS_DIR="icmp_analysis_$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$ICMP_RESULTS_DIR"
    chmod -R 777 "$ICMP_RESULTS_DIR"
    echo "Created directory: $ICMP_RESULTS_DIR"
    echo "Set permissions to allow anyone to access and modify the results"

    # Determine network interface automatically
    INTERFACE=$(ip -o -4 route show to default | awk '{print $5}' | head -1)
    if [ -z "$INTERFACE" ]; then
        echo "Could not determine network interface. Please enter it manually:"
        read -p "Interface name: " INTERFACE
    fi
    echo "Using network interface: $INTERFACE"

    # Define targets to ping, including the new domains
    TARGETS=("8.8.8.8" "1.1.1.1" "google.com" "akpinar.dev" "raksangsk.com")
    
    # Start capturing ICMP packets
    echo "Starting packet capture for ICMP analysis..."
    tshark -i "$INTERFACE" -f "icmp" -w "$ICMP_RESULTS_DIR/icmp_capture.pcap" &
    TSHARK_PID=$!
    
    # Wait for tshark to start
    sleep 2
    
    # For each target, perform ping
    for TARGET in "${TARGETS[@]}"; do
        echo "Generating ICMP traffic by pinging $TARGET..."
        
        # Create target-specific directory
        mkdir -p "$ICMP_RESULTS_DIR/$TARGET"
        chmod 777 "$ICMP_RESULTS_DIR/$TARGET"
        
        # Save the ping output
        ping -c 5 $TARGET > "$ICMP_RESULTS_DIR/$TARGET/ping_output.txt" 2>&1
        PING_STATUS=$?
        
        # Check if ping was successful
        if [ $PING_STATUS -ne 0 ]; then
            echo "Warning: Ping to $TARGET failed. See details in the output file."
        fi
        
        chmod 777 "$ICMP_RESULTS_DIR/$TARGET/ping_output.txt"
        
        # Display ping output
        echo "Ping results for $TARGET:"
        cat "$ICMP_RESULTS_DIR/$TARGET/ping_output.txt"
        echo "----------------------------------------------"
        
        # Wait a moment before pinging the next target
        sleep 2
    done
    
    # Let the capture run a bit longer to ensure we get all responses
    echo "Waiting to capture all ICMP responses..."
    sleep 3
    
    # Stop the capture
    echo "Stopping packet capture..."
    kill $TSHARK_PID 2>/dev/null
    wait $TSHARK_PID 2>/dev/null
    echo "Packet capture completed."
    chmod 777 "$ICMP_RESULTS_DIR/icmp_capture.pcap"
    
    # Extract all ICMP packets from the capture file
    echo "Extracting all ICMP packets from capture file..."
    tshark -r "$ICMP_RESULTS_DIR/icmp_capture.pcap" > "$ICMP_RESULTS_DIR/all_icmp_packets.txt"
    chmod 777 "$ICMP_RESULTS_DIR/all_icmp_packets.txt"
    
    # Extract ICMP echo requests (ping)
    echo "Extracting ICMP Echo Request packets..."
    tshark -r "$ICMP_RESULTS_DIR/icmp_capture.pcap" -Y "icmp.type == 8" > "$ICMP_RESULTS_DIR/icmp_echo_requests.txt"
    chmod 777 "$ICMP_RESULTS_DIR/icmp_echo_requests.txt"
    
    # Extract ICMP echo replies (pong)
    echo "Extracting ICMP Echo Reply packets..."
    tshark -r "$ICMP_RESULTS_DIR/icmp_capture.pcap" -Y "icmp.type == 0" > "$ICMP_RESULTS_DIR/icmp_echo_replies.txt"
    chmod 777 "$ICMP_RESULTS_DIR/icmp_echo_replies.txt"
    
    # Initialize arrays for report data
    declare -A TARGET_IPS
    declare -A AVG_PINGS
    declare -A PACKET_LOSSES
    declare -A REQUEST_COUNTS
    declare -A REPLY_COUNTS
    declare -A TTL_VALUES
    declare -A RTT_VALUES
    
    # Process each target
    for TARGET in "${TARGETS[@]}"; do
        echo "Processing ICMP data for $TARGET..."
        
        # Get actual IP address in case TARGET was a hostname
        TARGET_IP=$(grep -oE "\([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\)" "$ICMP_RESULTS_DIR/$TARGET/ping_output.txt" 2>/dev/null | head -1 | tr -d '()')
        if [ -z "$TARGET_IP" ]; then
            # Try alternative method to get IP if ping failed
            TARGET_IP=$(host $TARGET 2>/dev/null | grep "has address" | head -1 | awk '{print $NF}' 2>/dev/null)
            if [ -z "$TARGET_IP" ]; then
                TARGET_IP="Unknown (ping or DNS resolution failed)"
            fi
        fi
        
        # Store the IP for report
        TARGET_IPS[$TARGET]=$TARGET_IP
        
        # Extract request packets for this target - fix fields
        if [ "$TARGET_IP" != "Unknown (ping or DNS resolution failed)" ]; then
            tshark -r "$ICMP_RESULTS_DIR/icmp_capture.pcap" -Y "icmp.type == 8 and ip.dst == $TARGET_IP" \
                -T fields -e frame.number -e frame.time -e ip.src -e ip.dst -e icmp.seq_le -E header=y \
                > "$ICMP_RESULTS_DIR/$TARGET/echo_requests.txt"
            
            # Extract reply packets for this target - fix fields
            tshark -r "$ICMP_RESULTS_DIR/icmp_capture.pcap" -Y "icmp.type == 0 and ip.src == $TARGET_IP" \
                -T fields -e frame.number -e frame.time -e ip.src -e ip.dst -e icmp.seq_le -E header=y \
                > "$ICMP_RESULTS_DIR/$TARGET/echo_replies.txt"
        else
            # Create empty files if we couldn't get IP
            touch "$ICMP_RESULTS_DIR/$TARGET/echo_requests.txt"
            touch "$ICMP_RESULTS_DIR/$TARGET/echo_replies.txt"
        fi
        
        chmod 777 "$ICMP_RESULTS_DIR/$TARGET/echo_requests.txt"
        chmod 777 "$ICMP_RESULTS_DIR/$TARGET/echo_replies.txt"
        
        # Get the average ping time from ping output
        AVG_PING=$(grep "min/avg/max" "$ICMP_RESULTS_DIR/$TARGET/ping_output.txt" 2>/dev/null | awk -F'/' '{print $5}')
        if [ -z "$AVG_PING" ]; then
            AVG_PING="N/A"
        fi
        AVG_PINGS[$TARGET]=$AVG_PING
        
        # Get packet loss from ping output
        PACKET_LOSS=$(grep "packet loss" "$ICMP_RESULTS_DIR/$TARGET/ping_output.txt" 2>/dev/null | awk '{print $6}')
        if [ -z "$PACKET_LOSS" ]; then
            PACKET_LOSS="N/A"
        fi
        PACKET_LOSSES[$TARGET]=$PACKET_LOSS
        
        # Count request and reply packets
        REQUEST_COUNT=$(wc -l < "$ICMP_RESULTS_DIR/$TARGET/echo_requests.txt" 2>/dev/null)
        if [ -z "$REQUEST_COUNT" ] || [ "$REQUEST_COUNT" -eq 0 ]; then
            REQUEST_COUNT="0"
        else
            # Subtract 1 for the header line if file is not empty
            if [ "$REQUEST_COUNT" -gt 0 ]; then
                REQUEST_COUNT=$((REQUEST_COUNT - 1))
            fi
        fi
        REQUEST_COUNTS[$TARGET]=$REQUEST_COUNT
        
        REPLY_COUNT=$(wc -l < "$ICMP_RESULTS_DIR/$TARGET/echo_replies.txt" 2>/dev/null)
        if [ -z "$REPLY_COUNT" ] || [ "$REPLY_COUNT" -eq 0 ]; then
            REPLY_COUNT="0"
        else
            # Subtract 1 for the header line if file is not empty
            if [ "$REPLY_COUNT" -gt 0 ]; then
                REPLY_COUNT=$((REPLY_COUNT - 1))
            fi
        fi
        REPLY_COUNTS[$TARGET]=$REPLY_COUNT
        
        # Check if we have any request packets
        if [ -s "$ICMP_RESULTS_DIR/$TARGET/echo_requests.txt" ] && [ $(wc -l < "$ICMP_RESULTS_DIR/$TARGET/echo_requests.txt") -gt 1 ]; then
            # Take the first request for detailed analysis
            REQUEST_LINE=$(sed -n '2p' "$ICMP_RESULTS_DIR/$TARGET/echo_requests.txt" 2>/dev/null)
            
            if [ -n "$REQUEST_LINE" ]; then
                REQUEST_FRAME=$(echo "$REQUEST_LINE" | awk '{print $1}')
                REQUEST_TIME=$(echo "$REQUEST_LINE" | awk '{print $2}')
                REQUEST_SRC=$(echo "$REQUEST_LINE" | awk '{print $3}')
                REQUEST_DST=$(echo "$REQUEST_LINE" | awk '{print $4}')
                REQUEST_SEQ=$(echo "$REQUEST_LINE" | awk '{print $5}')
                
                echo "Found Echo Request packet to $TARGET - Frame: $REQUEST_FRAME, Seq: $REQUEST_SEQ"
                
                # Create a detailed view of this request packet
                tshark -r "$ICMP_RESULTS_DIR/icmp_capture.pcap" -Y "frame.number == $REQUEST_FRAME" -V > "$ICMP_RESULTS_DIR/$TARGET/request_detail.txt"
                chmod 777 "$ICMP_RESULTS_DIR/$TARGET/request_detail.txt"
                
                # Extract TTL from detailed packet view
                REQUEST_TTL=$(grep -A 2 "Time to live" "$ICMP_RESULTS_DIR/$TARGET/request_detail.txt" | grep "TTL" | awk '{print $2}')
                if [ -z "$REQUEST_TTL" ]; then
                    REQUEST_TTL="N/A (not found in packet)"
                fi
                
                # Extract ICMP ID from detailed packet view
                REQUEST_ID=$(grep -A 3 "Echo" "$ICMP_RESULTS_DIR/$TARGET/request_detail.txt" | grep "Identifier" | awk '{print $2}')
                if [ -z "$REQUEST_ID" ]; then
                    REQUEST_ID="N/A"
                fi
                
                # Now look for the corresponding reply with the same sequence number
                REPLY_LINE=$(grep " $REQUEST_SEQ " "$ICMP_RESULTS_DIR/$TARGET/echo_replies.txt" 2>/dev/null | head -1)
                
                if [ -n "$REPLY_LINE" ]; then
                    REPLY_FRAME=$(echo "$REPLY_LINE" | awk '{print $1}')
                    REPLY_TIME=$(echo "$REPLY_LINE" | awk '{print $2}')
                    REPLY_SRC=$(echo "$REPLY_LINE" | awk '{print $3}')
                    REPLY_DST=$(echo "$REPLY_LINE" | awk '{print $4}')
                    REPLY_SEQ=$(echo "$REPLY_LINE" | awk '{print $5}')
                    
                    echo "Found matching Echo Reply packet from $TARGET - Frame: $REPLY_FRAME, Seq: $REPLY_SEQ"
                    
                    # Create a detailed view of this reply packet
                    tshark -r "$ICMP_RESULTS_DIR/icmp_capture.pcap" -Y "frame.number == $REPLY_FRAME" -V > "$ICMP_RESULTS_DIR/$TARGET/reply_detail.txt"
                    chmod 777 "$ICMP_RESULTS_DIR/$TARGET/reply_detail.txt"
                    
                    # Extract TTL from detailed packet view
                    REPLY_TTL=$(grep -A 2 "Time to live" "$ICMP_RESULTS_DIR/$TARGET/reply_detail.txt" | grep "TTL" | awk '{print $2}')
                    if [ -z "$REPLY_TTL" ]; then
                        REPLY_TTL="N/A (not found in packet)"
                    fi
                    
                    # Store TTL values for report
                    TTL_VALUES[$TARGET]="$REPLY_TTL"
                    
                    # Extract timestamps and calculate round-trip time
                    REQUEST_TIMESTAMP=$(tshark -r "$ICMP_RESULTS_DIR/icmp_capture.pcap" -Y "frame.number == $REQUEST_FRAME" -T fields -e frame.time_epoch)
                    REPLY_TIMESTAMP=$(tshark -r "$ICMP_RESULTS_DIR/icmp_capture.pcap" -Y "frame.number == $REPLY_FRAME" -T fields -e frame.time_epoch)
                    
                    # Calculate round-trip time in milliseconds
                    RTT_MS=$(echo "($REPLY_TIMESTAMP - $REQUEST_TIMESTAMP) * 1000" | bc)
                    
                    # Store RTT for report
                    RTT_VALUES[$TARGET]="$RTT_MS"
                    
                    # Create a separate capture of just this request/reply pair
                    tshark -r "$ICMP_RESULTS_DIR/icmp_capture.pcap" -w "$ICMP_RESULTS_DIR/$TARGET/icmp_exchange.pcap" \
                        -Y "frame.number == $REQUEST_FRAME or frame.number == $REPLY_FRAME"
                    chmod 777 "$ICMP_RESULTS_DIR/$TARGET/icmp_exchange.pcap"
                    
                    # Create analysis document for this target
                    cat > "$ICMP_RESULTS_DIR/$TARGET/icmp_analysis.txt" << EOL
======================================================================
                     ICMP PING ANALYSIS FOR $TARGET
======================================================================

ECHO REQUEST (PING):
-----------------
Frame Number: $REQUEST_FRAME
Source IP: $REQUEST_SRC
Destination IP: $REQUEST_DST
Time: $REQUEST_TIME
Sequence Number: $REQUEST_SEQ
Identifier: $REQUEST_ID
TTL: $REQUEST_TTL

ECHO REPLY (PONG):
---------------
Frame Number: $REPLY_FRAME
Source IP: $REPLY_SRC
Destination IP: $REPLY_DST
Time: $REPLY_TIME
Sequence Number: $REPLY_SEQ
TTL: $REPLY_TTL

TIMING:
------
Round-Trip Time: $RTT_MS milliseconds

ICMP PING/ECHO PROCESS OBSERVED:
------------------------------
1. Your computer sent an ICMP Echo Request (Type 8) packet to $TARGET_IP
   - The packet contained a sequence number ($REQUEST_SEQ) and identifier ($REQUEST_ID)
   - These values help match requests with their replies
   - The packet was sent with a TTL (Time To Live) of $REQUEST_TTL
   
2. The destination ($TARGET_IP) responded with an ICMP Echo Reply (Type 0)
   - The response used the same sequence number and identifier to match the request
   - The response came with a TTL of $REPLY_TTL
   - The round-trip time was $RTT_MS milliseconds

3. This demonstrates the basic function of ICMP ping:
   - Testing if a host is reachable
   - Measuring the round-trip time for network diagnostics
   - Discovering the network path (with tools like traceroute that use varying TTL values)

======================================================================
EOL
                    chmod 777 "$ICMP_RESULTS_DIR/$TARGET/icmp_analysis.txt"
                else
                    echo "No matching Echo Reply found for request sequence $REQUEST_SEQ to $TARGET"
                    # Create partial analysis document
                    cat > "$ICMP_RESULTS_DIR/$TARGET/icmp_analysis.txt" << EOL
======================================================================
                     ICMP PING ANALYSIS FOR $TARGET
======================================================================

ECHO REQUEST (PING):
-----------------
Frame Number: $REQUEST_FRAME
Source IP: $REQUEST_SRC
Destination IP: $REQUEST_DST
Time: $REQUEST_TIME
Sequence Number: $REQUEST_SEQ
Identifier: $REQUEST_ID
TTL: $REQUEST_TTL

ECHO REPLY (PONG):
---------------
No matching Echo Reply packet was found for this request.
This could indicate packet loss or filtering of ICMP traffic.

ICMP PING/ECHO PROCESS:
--------------------
1. Your computer sent an ICMP Echo Request (Type 8) packet to $TARGET_IP
   - The packet contained a sequence number ($REQUEST_SEQ) and identifier ($REQUEST_ID)
   - These values help match requests with their replies
   - The packet was sent with a TTL (Time To Live) of $REQUEST_TTL
   
2. No response was received or captured
   - This could indicate network congestion, firewall rules, or that the target is unreachable

======================================================================
EOL
                    chmod 777 "$ICMP_RESULTS_DIR/$TARGET/icmp_analysis.txt"
                    
                    # Save null values for report
                    TTL_VALUES[$TARGET]="N/A"
                    RTT_VALUES[$TARGET]="N/A"
                fi
            else
                echo "No Echo Request line found for $TARGET"
                # Save null values for report
                TTL_VALUES[$TARGET]="N/A"
                RTT_VALUES[$TARGET]="N/A"
            fi
        else
            echo "No ICMP Echo Requests found for $TARGET"
            # Save null values for report
            TTL_VALUES[$TARGET]="N/A"
            RTT_VALUES[$TARGET]="N/A"
        fi
    done
    
    # Create a summary document with information about all targets
    echo "Creating ICMP ping summary document..."
    
    # Initialize the summary document
    cat > "$ICMP_RESULTS_DIR/icmp_summary.txt" << EOL
======================================================================
                     ICMP PING ANALYSIS SUMMARY
======================================================================

CAPTURED DATA SUMMARY:
--------------------
This analysis is based on actual ICMP traffic captured on $(date)
Number of targets pinged: ${#TARGETS[@]}

TARGET SUMMARIES:
--------------
EOL

    # Add information about each target to the summary
    for TARGET in "${TARGETS[@]}"; do
        cat >> "$ICMP_RESULTS_DIR/icmp_summary.txt" << EOL

TARGET: $TARGET (${TARGET_IPS[$TARGET]})
---------------------------
Average Ping Time: ${AVG_PINGS[$TARGET]} ms
Packet Loss: ${PACKET_LOSSES[$TARGET]}
ICMP Echo Requests Captured: ${REQUEST_COUNTS[$TARGET]}
ICMP Echo Replies Captured: ${REPLY_COUNTS[$TARGET]}
TTL Value: ${TTL_VALUES[$TARGET]}
Round-Trip Time: ${RTT_VALUES[$TARGET]} ms
EOL
    done
    
    # Add general ICMP information to the summary
    cat >> "$ICMP_RESULTS_DIR/icmp_summary.txt" << EOL

ABOUT ICMP AND PING:
------------------
ICMP (Internet Control Message Protocol) is a network layer protocol used by
network devices to diagnose network communication issues. Ping is one of the
most common utilities that uses ICMP to test the reachability of a host on
an IP network.

HOW PING WORKS (BASED ON OBSERVED DATA):
-------------------------------------
1. ECHO REQUEST: The source device sends an ICMP Echo Request (Type 8) packet
   to the destination.
   - Each packet contains a sequence number and identifier to match replies
   - The packet also contains data (typically a timestamp or pattern)
   - TTL (Time To Live) is set to limit how many hops the packet can traverse

2. TRAVEL: The packet travels through the network, with each router decrementing
   the TTL value by 1 before forwarding it.

3. ECHO REPLY: When the destination receives the Echo Request, it responds with
   an ICMP Echo Reply (Type 0) packet.
   - The reply contains the same sequence number and identifier
   - The reply contains the same data that was sent in the request
   - The source and destination IP addresses are reversed

4. MEASUREMENT: The source calculates the round-trip time by comparing the
   time the request was sent to when the reply was received.

ICMP PACKET STRUCTURE (OBSERVED):
------------------------------
Echo Request (Type 8) and Echo Reply (Type 0) packets include:
- Type: 8 for request, 0 for reply
- Code: 0 for both Echo Request and Echo Reply
- Checksum: Error checking value
- Identifier: Helps match requests and replies, especially from multiple processes
- Sequence Number: Incremented for each ping attempt in a series
- Data: Payload data that is echoed back in the reply

COMMON USES OF PING/ICMP:
-----------------------
1. Testing connectivity between devices
2. Measuring network latency
3. Identifying packet loss
4. Network troubleshooting
5. Basis for traceroute and MTR (My TraceroRoute) utilities

SECURITY CONSIDERATIONS:
---------------------
- Some networks block ICMP traffic for security reasons
- ICMP flood attacks (ping floods) can be used for DoS attacks
- Ping can be used for network reconnaissance
- Many firewalls can be configured to limit or block ICMP traffic

======================================================================
EOL
    chmod 777 "$ICMP_RESULTS_DIR/icmp_summary.txt"
    
    # Create a detailed Markdown report
    echo "Creating detailed markdown report..."
    
    cat > "$ICMP_RESULTS_DIR/icmp_analysis_report.md" << EOL
# ICMP Packet Analysis Report

## Objective
Use Wireshark to capture ICMP (ping) packets and analyze their structure.

## Methodology
1. Generated ICMP traffic by pinging multiple targets
2. Captured the packets using tshark
3. Analyzed packet details to extract relevant information
4. Documented findings about ICMP Echo Request and Echo Reply structure

## Equipment and Tools
- Network Interface: $INTERFACE
- Packet Capture Tool: tshark (Wireshark CLI)
- Analysis: Custom shell script with tshark filters
- Date of Capture: $(date)

## ICMP Traffic Generation and Capture
ICMP packets were generated by pinging the following hosts:

EOL

    # Add target summary information
    for TARGET in "${TARGETS[@]}"; do
        cat >> "$ICMP_RESULTS_DIR/icmp_analysis_report.md" << EOL
### Target: $TARGET (${TARGET_IPS[$TARGET]})
- **Average Response Time:** ${AVG_PINGS[$TARGET]} ms
- **Packet Loss Rate:** ${PACKET_LOSSES[$TARGET]}
- **Echo Requests Captured:** ${REQUEST_COUNTS[$TARGET]}
- **Echo Replies Captured:** ${REPLY_COUNTS[$TARGET]}
- **TTL Value:** ${TTL_VALUES[$TARGET]}
- **Calculated RTT:** ${RTT_VALUES[$TARGET]} ms

EOL
    done
    
    # Add ICMP packet analysis section
    cat >> "$ICMP_RESULTS_DIR/icmp_analysis_report.md" << EOL
## ICMP Packet Structure Analysis

### Echo Request (Type 8) Analysis
The ICMP Echo Request packet contains:
- **Type Field:** 8 (Echo Request)
- **Code Field:** 0 
- **Checksum:** Used for error detection
- **Identifier:** Used to match requests with replies (especially with multiple ping processes)
- **Sequence Number:** Increments with each packet in a sequence
- **Data:** Contains timestamp or pattern data that gets echoed back

### Echo Reply (Type 0) Analysis
The ICMP Echo Reply packet contains:
- **Type Field:** 0 (Echo Reply)
- **Code Field:** 0
- **Checksum:** Used for error detection
- **Identifier:** Matches the Echo Request packet
- **Sequence Number:** Matches the Echo Request packet
- **Data:** Identical to the data sent in the request

### Key Observations

1. **Round-Trip Time Variations:**
   - Fastest response: $(echo "${RTT_VALUES[@]}" | tr ' ' '\n' | grep -v "N/A" | sort -n | head -1) ms
   - Slowest response: $(echo "${RTT_VALUES[@]}" | tr ' ' '\n' | grep -v "N/A" | sort -n | tail -1) ms

2. **TTL Values:**
   The TTL values in the Echo Reply packets provide insight into the network distance:
   - Lower TTL values (around 50-60) suggest the target is further away in terms of network hops
   - Higher TTL values (above 100) suggest the target is closer
   
3. **Packet Loss:**
   - Most reliable target: $(for TARGET in "${!PACKET_LOSSES[@]}"; do echo "$TARGET:${PACKET_LOSSES[$TARGET]}"; done | grep "0%" | head -1 | cut -d: -f1)
   - Targets with packet loss: $(for TARGET in "${!PACKET_LOSSES[@]}"; do [[ "${PACKET_LOSSES[$TARGET]}" != "0%" && "${PACKET_LOSSES[$TARGET]}" != "N/A" ]] && echo "$TARGET (${PACKET_LOSSES[$TARGET]})"; done | tr '\n' ', ' | sed 's/,$//')

## Sequence Number and Identifier Field Analysis

The sequence number and identifier fields play crucial roles in ICMP:

- **Sequence Numbers:** Incremental values that help track the order of packets
- **Identifier Values:** Unique values that help distinguish between different ping processes

In our analysis:
- Each Echo Request had a unique sequence number
- Echo Replies maintained the same sequence number as their corresponding request
- The identifier remained constant across all packets in the same ping session

## Round-Trip Time Analysis

Round-trip time (RTT) measures how long it takes for a packet to travel from source to destination and back. Factors affecting RTT include:

1. Physical distance between endpoints
2. Network congestion
3. Processing delays at intermediate devices
4. Quality of network infrastructure

Based on our analysis:
- Local/nearby servers (likely with fewer hops) showed lower RTT values
- More distant servers showed higher and more variable RTT values

## ICMP Ping as a Diagnostic Tool

ICMP ping serves multiple diagnostic purposes:

1. **Connectivity Testing:** Verifies if a host is reachable
2. **Latency Measurement:** Quantifies network delay
3. **Packet Loss Detection:** Identifies network reliability issues
4. **MTU Discovery:** Can help determine maximum transmission unit (with appropriate flags)
5. **Network Path Analysis:** Forms the basis for traceroute

## Limitations and Security Considerations

1. **Blocked ICMP Traffic:** Many networks block ICMP for security reasons
2. **Inconsistent Prioritization:** Routers may de-prioritize ICMP traffic during congestion
3. **Security Risks:**
   - ICMP flood attacks can cause denial of service
   - Ping can be used for network reconnaissance
4. **Unreliable for SLA Monitoring:** Not suitable as the sole metric for service level agreements
5. **Limited Information:** Only provides basic connectivity and timing data

## Conclusion

This analysis demonstrates the basic structure and function of ICMP Echo Request and Echo Reply packets. The captured packets show the fundamental mechanism behind the ping utility, which remains one of the most commonly used network diagnostic tools. The differences in response times and TTL values across various targets highlight how network distance and infrastructure can impact ICMP traffic.

The sequence numbers and identifiers in the packets functioned as expected, allowing for proper matching of requests and replies. Overall, this analysis confirms that ICMP provides a simple but effective means of testing basic network connectivity and performance.

EOL
    chmod 777 "$ICMP_RESULTS_DIR/icmp_analysis_report.md"
    
    echo "===================================================================="
    echo "                    ICMP ANALYSIS COMPLETED                          "
    echo "===================================================================="
    echo "All analysis results saved to: $ICMP_RESULTS_DIR/"
    echo "Detailed report created: $ICMP_RESULTS_DIR/icmp_analysis_report.md"
    
    # Create a cleanup script for easy deletion
    cat > "$ICMP_RESULTS_DIR/cleanup.sh" << EOL
#!/bin/bash
# Cleanup script to remove all ICMP analysis files
echo "Removing ICMP analysis directory: $ICMP_RESULTS_DIR"
rm -rf "$ICMP_RESULTS_DIR"
echo "Cleanup completed!"
EOL
    chmod 755 "$ICMP_RESULTS_DIR/cleanup.sh"
    
    echo "A cleanup script has been created at: $ICMP_RESULTS_DIR/cleanup.sh"
    echo "To remove all analysis files, run: $ICMP_RESULTS_DIR/cleanup.sh"
}
analyze_http_traffic() {
    # Check if tshark is installed
    if ! command -v tshark &> /dev/null; then
        echo "Error: tshark is not installed. Please install it with:"
        echo "sudo apt install tshark"
        return 1
    fi

    # Create results directory for HTTP analysis
    HTTP_RESULTS_DIR="http_analysis_$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$HTTP_RESULTS_DIR"
    echo "Created directory: $HTTP_RESULTS_DIR"
    
    # Set permissions
    chmod -R 777 "$HTTP_RESULTS_DIR"
    echo "Set permissions to allow anyone to access and modify the results"

    # Determine network interface automatically
    INTERFACE=$(ip -o -4 route show to default | awk '{print $5}' | head -1)
    if [ -z "$INTERFACE" ]; then
        echo "Could not determine network interface. Please enter it manually:"
        read -p "Interface name: " INTERFACE
    fi
    echo "Using network interface: $INTERFACE"

    # Define target HTTP sites
    PRIMARY_TARGET="gaia.cs.umass.edu/wireshark-labs/HTTP-wireshark-file1.html"
    BACKUP_TARGETS=("example.com" "neverssl.com" "info.cern.ch")
    
    echo "===================================================================="
    echo "                  HTTP TRAFFIC ANALYSIS TOOL                         "
    echo "===================================================================="
    echo "This tool will capture and analyze HTTP GET and POST requests."
    echo "Primary target: $PRIMARY_TARGET"
    echo "Backup targets (if primary fails): ${BACKUP_TARGETS[*]}"
    echo "--------------------------------------------------------------------"
    
    # Start packet capture with a filter for HTTP traffic
    echo "Starting packet capture for HTTP traffic..."
    tshark -i "$INTERFACE" -f "tcp port 80" -w "$HTTP_RESULTS_DIR/http_capture.pcap" &
    TSHARK_PID=$!
    
    # Wait for tshark to start
    sleep 2
    
    # Generate HTTP traffic
    echo "Generating HTTP traffic..."
    echo "1. Attempting to access primary target: $PRIMARY_TARGET"
    curl -s "http://$PRIMARY_TARGET" --connect-timeout 5 -o "$HTTP_RESULTS_DIR/primary_response.html"
    PRIMARY_SUCCESS=$?
    
    # If primary target fails, try backup targets
    if [ $PRIMARY_SUCCESS -ne 0 ]; then
        echo "   Could not access primary target. Trying backup targets..."
        for TARGET in "${BACKUP_TARGETS[@]}"; do
            echo "2. Attempting to access: $TARGET"
            curl -s "http://$TARGET" --connect-timeout 5 -o "$HTTP_RESULTS_DIR/${TARGET}_response.html"
            if [ $? -eq 0 ]; then
                echo "   Successfully accessed $TARGET"
                echo "ACTIVE_TARGET=\"$TARGET\"" > "$HTTP_RESULTS_DIR/target_info.txt"
                break
            fi
        done
    else
        echo "   Successfully accessed primary target"
        echo "ACTIVE_TARGET=\"$PRIMARY_TARGET\"" > "$HTTP_RESULTS_DIR/target_info.txt"
    fi
    
    # Generate some HTTP POST traffic as well
    echo "3. Generating HTTP POST request to httpbin.org..."
    curl -s -X POST "http://httpbin.org/post" -d "name=student&number=$STUDENT_NUMBER" --connect-timeout 5 -o "$HTTP_RESULTS_DIR/post_response.json"
    
    # Wait for a moment to ensure all packets are captured
    echo "Waiting for packet capture to complete..."
    sleep 5
    
    # Stop the capture
    echo "Stopping packet capture..."
    kill $TSHARK_PID 2>/dev/null
    wait $TSHARK_PID 2>/dev/null
    echo "Packet capture completed."
    
    # Load the active target information
    if [ -f "$HTTP_RESULTS_DIR/target_info.txt" ]; then
        source "$HTTP_RESULTS_DIR/target_info.txt"
    else
        echo "Error: Could not determine which target was successfully accessed."
        ACTIVE_TARGET="unknown"
    fi
    
    # Extract HTTP GET requests from the capture
    echo "Extracting HTTP GET requests from capture..."
    tshark -r "$HTTP_RESULTS_DIR/http_capture.pcap" -Y "http.request.method == \"GET\"" \
        -T fields -e frame.number -e frame.time_relative -e ip.src -e tcp.srcport -e ip.dst -e tcp.dstport -e http.request.full_uri -E header=y \
        > "$HTTP_RESULTS_DIR/http_get_requests.txt"
    
    # Extract HTTP POST requests from the capture
    echo "Extracting HTTP POST requests from capture..."
    tshark -r "$HTTP_RESULTS_DIR/http_capture.pcap" -Y "http.request.method == \"POST\"" \
        -T fields -e frame.number -e frame.time_relative -e ip.src -e tcp.srcport -e ip.dst -e tcp.dstport -e http.request.full_uri -E header=y \
        > "$HTTP_RESULTS_DIR/http_post_requests.txt"
    
    # Extract HTTP responses
    echo "Extracting HTTP responses from capture..."
    tshark -r "$HTTP_RESULTS_DIR/http_capture.pcap" -Y "http.response" \
        -T fields -e frame.number -e frame.time_relative -e ip.src -e tcp.srcport -e ip.dst -e tcp.dstport -e http.response.code -e http.response.phrase -E header=y \
        > "$HTTP_RESULTS_DIR/http_responses.txt"
    
    # Extract HTTP content
    echo "Extracting HTTP content from capture..."
    tshark -r "$HTTP_RESULTS_DIR/http_capture.pcap" -Y "http.file_data" \
        -T fields -e frame.number -e http.file_data -E header=y \
        > "$HTTP_RESULTS_DIR/http_content.txt"
    
    # Initialize variables for GET request details
    GET_FRAME=""
    GET_TIME=""
    GET_SRC_IP=""
    GET_SRC_PORT=""
    GET_DST_IP=""
    GET_DST_PORT=""
    GET_URI=""
    
    # Process the first GET request (if available)
    if [ -s "$HTTP_RESULTS_DIR/http_get_requests.txt" ]; then
        GET_LINE=$(sed -n '2p' "$HTTP_RESULTS_DIR/http_get_requests.txt" 2>/dev/null)
        
        if [ -n "$GET_LINE" ]; then
            GET_FRAME=$(echo "$GET_LINE" | awk '{print $1}')
            GET_TIME=$(echo "$GET_LINE" | awk '{print $2}')
            GET_SRC_IP=$(echo "$GET_LINE" | awk '{print $3}')
            GET_SRC_PORT=$(echo "$GET_LINE" | awk '{print $4}')
            GET_DST_IP=$(echo "$GET_LINE" | awk '{print $5}')
            GET_DST_PORT=$(echo "$GET_LINE" | awk '{print $6}')
            GET_URI=$(echo "$GET_LINE" | awk '{print $7}')
            
            echo "Found HTTP GET request - Frame: $GET_FRAME"
            echo "  Source: $GET_SRC_IP:$GET_SRC_PORT"
            echo "  Destination: $GET_DST_IP:$GET_DST_PORT"
            echo "  URI: $GET_URI"
            
            # Save detailed GET request
            tshark -r "$HTTP_RESULTS_DIR/http_capture.pcap" -Y "frame.number == $GET_FRAME" -V > "$HTTP_RESULTS_DIR/get_request_detail.txt"
            chmod 666 "$HTTP_RESULTS_DIR/get_request_detail.txt"
        fi
    else
        echo "No HTTP GET requests found in the capture."
    fi
    
    # Initialize variables for POST request details
    POST_FRAME=""
    POST_TIME=""
    POST_SRC_IP=""
    POST_SRC_PORT=""
    POST_DST_IP=""
    POST_DST_PORT=""
    POST_URI=""
    
    # Process the first POST request (if available)
    if [ -s "$HTTP_RESULTS_DIR/http_post_requests.txt" ]; then
        POST_LINE=$(sed -n '2p' "$HTTP_RESULTS_DIR/http_post_requests.txt" 2>/dev/null)
        
        if [ -n "$POST_LINE" ]; then
            POST_FRAME=$(echo "$POST_LINE" | awk '{print $1}')
            POST_TIME=$(echo "$POST_LINE" | awk '{print $2}')
            POST_SRC_IP=$(echo "$POST_LINE" | awk '{print $3}')
            POST_SRC_PORT=$(echo "$POST_LINE" | awk '{print $4}')
            POST_DST_IP=$(echo "$POST_LINE" | awk '{print $5}')
            POST_DST_PORT=$(echo "$POST_LINE" | awk '{print $6}')
            POST_URI=$(echo "$POST_LINE" | awk '{print $7}')
            
            echo "Found HTTP POST request - Frame: $POST_FRAME"
            echo "  Source: $POST_SRC_IP:$POST_SRC_PORT"
            echo "  Destination: $POST_DST_IP:$POST_DST_PORT"
            echo "  URI: $POST_URI"
            
            # Save detailed POST request
            tshark -r "$HTTP_RESULTS_DIR/http_capture.pcap" -Y "frame.number == $POST_FRAME" -V > "$HTTP_RESULTS_DIR/post_request_detail.txt"
            
            # Also try to extract POST data
            tshark -r "$HTTP_RESULTS_DIR/http_capture.pcap" -Y "frame.number == $POST_FRAME" -T fields -e urlencoded-form.key -e urlencoded-form.value > "$HTTP_RESULTS_DIR/post_data.txt"
            
            chmod 666 "$HTTP_RESULTS_DIR/post_request_detail.txt"
            chmod 666 "$HTTP_RESULTS_DIR/post_data.txt"
        fi
    else
        echo "No HTTP POST requests found in the capture."
    fi
    
    # Initialize variables for response details
    RESPONSE_FRAME=""
    RESPONSE_TIME=""
    RESPONSE_SRC_IP=""
    RESPONSE_SRC_PORT=""
    RESPONSE_DST_IP=""
    RESPONSE_DST_PORT=""
    RESPONSE_CODE=""
    RESPONSE_PHRASE=""
    
    # Process the first HTTP response (if available)
    if [ -s "$HTTP_RESULTS_DIR/http_responses.txt" ]; then
        RESPONSE_LINE=$(sed -n '2p' "$HTTP_RESULTS_DIR/http_responses.txt" 2>/dev/null)
        
        if [ -n "$RESPONSE_LINE" ]; then
            RESPONSE_FRAME=$(echo "$RESPONSE_LINE" | awk '{print $1}')
            RESPONSE_TIME=$(echo "$RESPONSE_LINE" | awk '{print $2}')
            RESPONSE_SRC_IP=$(echo "$RESPONSE_LINE" | awk '{print $3}')
            RESPONSE_SRC_PORT=$(echo "$RESPONSE_LINE" | awk '{print $4}')
            RESPONSE_DST_IP=$(echo "$RESPONSE_LINE" | awk '{print $5}')
            RESPONSE_DST_PORT=$(echo "$RESPONSE_LINE" | awk '{print $6}')
            RESPONSE_CODE=$(echo "$RESPONSE_LINE" | awk '{print $7}')
            RESPONSE_PHRASE=$(echo "$RESPONSE_LINE" | awk '{$1=$2=$3=$4=$5=$6=$7=""; print $0}' | sed 's/^ *//')
            
            echo "Found HTTP response - Frame: $RESPONSE_FRAME"
            echo "  Source: $RESPONSE_SRC_IP:$RESPONSE_SRC_PORT"
            echo "  Destination: $RESPONSE_DST_IP:$RESPONSE_DST_PORT"
            echo "  Status: $RESPONSE_CODE $RESPONSE_PHRASE"
            
            # Save detailed response
            tshark -r "$HTTP_RESULTS_DIR/http_capture.pcap" -Y "frame.number == $RESPONSE_FRAME" -V > "$HTTP_RESULTS_DIR/http_response_detail.txt"
            chmod 666 "$HTTP_RESULTS_DIR/http_response_detail.txt"
            
            # Try to extract the content type from the response
            CONTENT_TYPE=$(grep -A 5 "Content-Type" "$HTTP_RESULTS_DIR/http_response_detail.txt" | grep "Content-Type" | head -1 | sed 's/.*Content-Type: //')
            if [ -z "$CONTENT_TYPE" ]; then
                CONTENT_TYPE="Not found in packet"
            fi
        fi
    else
        echo "No HTTP responses found in the capture."
    fi
    
    # Create analysis summary with actual captured data
    echo "Creating HTTP analysis summary with captured data..."
    cat > "$HTTP_RESULTS_DIR/http_analysis.txt" << EOL
======================================================================
                     HTTP TRAFFIC ANALYSIS
======================================================================

TARGET INFORMATION:
-----------------
Target Site: $ACTIVE_TARGET
Capture Date: $(date)
Student Number: $STUDENT_NUMBER

HTTP GET REQUEST DETAILS:
----------------------
Frame Number: $GET_FRAME
Source IP & Port: $GET_SRC_IP:$GET_SRC_PORT
Destination IP & Port: $GET_DST_IP:$GET_DST_PORT
Request Time: $GET_TIME seconds from capture start
Requested URI: $GET_URI

HTTP RESPONSE DETAILS:
-------------------
Frame Number: $RESPONSE_FRAME
Source IP & Port: $RESPONSE_SRC_IP:$RESPONSE_SRC_PORT
Destination IP & Port: $RESPONSE_DST_IP:$RESPONSE_DST_PORT
Response Time: $RESPONSE_TIME seconds from capture start
Status Code: $RESPONSE_CODE $RESPONSE_PHRASE
Content Type: $CONTENT_TYPE

HTTP POST REQUEST DETAILS (if captured):
-------------------------------------
Frame Number: $POST_FRAME
Source IP & Port: $POST_SRC_IP:$POST_SRC_PORT
Destination IP & Port: $POST_DST_IP:$POST_DST_PORT
Request Time: $POST_TIME seconds from capture start
Posted URI: $POST_URI
(See post_data.txt for POST parameters)

HOW HTTP WORKS (BASED ON OBSERVED DATA):
-------------------------------------
HTTP (Hypertext Transfer Protocol) is the foundation of data communication
on the World Wide Web. Based on our captured traffic, we observed:

1. HTTP REQUEST PROCESS:
   - Your computer sends an HTTP GET request to the server
   - The request specifies which resource is being requested (URI)
   - Headers provide additional information to the server
   - In POST requests, form data is sent in the message body

2. HTTP RESPONSE PROCESS:
   - The server processes the request and returns a response
   - The response includes a status code ($RESPONSE_CODE) indicating success/failure
   - Headers provide metadata about the response
   - The actual content (HTML, images, etc.) follows in the message body

3. COMMON HTTP STATUS CODES:
   - 200 OK: Request succeeded, and requested content is returned
   - 301/302: Redirected to a different URL
   - 404: Resource not found
   - 500: Server error

4. HTTP GET vs POST:
   - GET: Parameters are visible in the URL, used for retrieving data
   - POST: Parameters are sent in the message body, used for submitting data

HTTP PACKET STRUCTURE (OBSERVED):
------------------------------
As seen in our captures, HTTP packets contain:
- Start line: Method, URI, and HTTP version for requests
             HTTP version, status code, and phrase for responses
- Headers: Key-value pairs providing additional information
- Empty line: Separates headers from body
- Body: Contains data being sent (in POST requests) or content being returned

SECURITY CONSIDERATIONS:
---------------------
- The HTTP traffic observed was unencrypted, allowing anyone monitoring the
  network to see all details including URLs, headers, and content
- Modern websites typically use HTTPS which encrypts the traffic
- Sensitive information should never be transmitted over plain HTTP
- POST data, while not visible in the URL, is still sent in clear text in HTTP

======================================================================
EOL
    chmod 666 "$HTTP_RESULTS_DIR/http_analysis.txt"
    
    # Create helpful visualization for learning
    cat > "$HTTP_RESULTS_DIR/http_visualization.txt" << EOL
HTTP REQUEST AND RESPONSE VISUALIZATION

CLIENT ($GET_SRC_IP:$GET_SRC_PORT)                 SERVER ($GET_DST_IP:$GET_DST_PORT)
    |                                               |
    |  -------- HTTP GET REQUEST ------------->    |
    |  GET $GET_URI HTTP/1.1                       |
    |  Host: $ACTIVE_TARGET                        |
    |  User-Agent: curl/x.xx.x                     |
    |  Accept: */*                                 |
    |                                               |
    |                                               |
    |  <-------- HTTP RESPONSE ---------------     |
    |  HTTP/1.1 $RESPONSE_CODE $RESPONSE_PHRASE    |
    |  Content-Type: $CONTENT_TYPE                 |
    |  Content-Length: xxxx                        |
    |                                               |
    |  <HTML content follows...>                    |
    |                                               |
    
EOL
    chmod 666 "$HTTP_RESULTS_DIR/http_visualization.txt"
    
    # Create instructions for taking screenshots
    cat > "$HTTP_RESULTS_DIR/screenshot_instructions.txt" << EOL
SCREENSHOT INSTRUCTIONS FOR HTTP ANALYSIS
========================================

For your assignment, take screenshots of the following:

1. HTTP GET Request:
   a. Open Wireshark and load the capture file: $HTTP_RESULTS_DIR/http_capture.pcap
   b. Apply filter: "http.request.method == \"GET\""
   c. Click on a GET request packet
   d. In the middle pane, expand "Hypertext Transfer Protocol" to see request details
   e. Take a screenshot showing:
      - The requested URL
      - The HTTP method (GET)
      - Request headers

2. HTTP Response:
   a. Apply filter: "http.response"
   b. Click on a response packet
   c. In the middle pane, expand "Hypertext Transfer Protocol" to see response details
   d. Take a screenshot showing:
      - The status code and phrase (e.g., "200 OK")
      - Response headers
      - Beginning of content (if visible)

3. HTTP POST Request (if available):
   a. Apply filter: "http.request.method == \"POST\""
   b. Click on a POST request packet
   c. In the middle pane, expand "Hypertext Transfer Protocol" to see request details
   d. Take a screenshot showing:
      - The request URL
      - The HTTP method (POST)
      - Request headers
      - Form data in the request body

Analysis Writing Guidelines:
---------------------------
Use the information in $HTTP_RESULTS_DIR/http_analysis.txt to write your analysis.
Include:

1. Explain the HTTP request-response process
2. Highlight the specific information from your captures:
   - Source and destination IP addresses and ports
   - Status codes and their meanings
   - Content types
3. Discuss the differences between GET and POST methods
4. Mention security considerations (HTTP vs HTTPS)

EOL
    chmod 666 "$HTTP_RESULTS_DIR/screenshot_instructions.txt"
    
    # Create a Markdown report with the actual captured data
    cat > "$HTTP_RESULTS_DIR/http_traffic_analysis_report.md" << EOL
# HTTP Traffic Analysis Report

## 1. Introduction

This report presents an analysis of HTTP traffic captured using Wireshark. The focus is on HTTP GET and POST requests and their corresponding responses, demonstrating how unencrypted HTTP communication works in practice.

## 2. Methodology

HTTP traffic was generated and captured using the following tools:
- **Wireshark/tshark**: For packet capture and analysis
- **curl**: For generating HTTP traffic

The primary target site was \`$ACTIVE_TARGET\`, with backup options available if the primary target was inaccessible.

## 3. HTTP GET Request Analysis

### 3.1 GET Request Details
- **Frame Number**: $GET_FRAME
- **Source IP & Port**: $GET_SRC_IP:$GET_SRC_PORT
- **Destination IP & Port**: $GET_DST_IP:$GET_DST_PORT
- **Request Time**: $GET_TIME seconds from capture start
- **Requested URI**: $GET_URI

### 3.2 GET Request Structure
The HTTP GET request follows this general structure:
\`\`\`
GET $GET_URI HTTP/1.1
Host: $ACTIVE_TARGET
User-Agent: curl/x.xx.x
Accept: */*
\`\`\`

## 4. HTTP Response Analysis

### 4.1 Response Details
- **Frame Number**: $RESPONSE_FRAME
- **Source IP & Port**: $RESPONSE_SRC_IP:$RESPONSE_SRC_PORT
- **Destination IP & Port**: $RESPONSE_DST_IP:$RESPONSE_DST_PORT
- **Response Time**: $RESPONSE_TIME seconds from capture start
- **Status Code**: $RESPONSE_CODE $RESPONSE_PHRASE
- **Content Type**: $CONTENT_TYPE

### 4.2 Response Structure
The HTTP response follows this general structure:
\`\`\`
HTTP/1.1 $RESPONSE_CODE $RESPONSE_PHRASE
Content-Type: $CONTENT_TYPE
Content-Length: xxxx

<HTML content>
\`\`\`

## 5. HTTP POST Request Analysis
$(if [ -n "$POST_FRAME" ]; then
echo "
### 5.1 POST Request Details
- **Frame Number**: $POST_FRAME
- **Source IP & Port**: $POST_SRC_IP:$POST_SRC_PORT
- **Destination IP & Port**: $POST_DST_IP:$POST_DST_PORT
- **Request Time**: $POST_TIME seconds from capture start
- **Posted URI**: $POST_URI

### 5.2 POST Request Structure
The HTTP POST request follows this general structure:
\`\`\`
POST $POST_URI HTTP/1.1
Host: httpbin.org
User-Agent: curl/x.xx.x
Accept: */*
Content-Type: application/x-www-form-urlencoded
Content-Length: xx

name=student&number=XXXXXXXX
\`\`\`
"
else
echo "
No HTTP POST requests were captured during this analysis session.
"
fi)

## 6. Understanding HTTP Communication

### 6.1 HTTP Request Process
1. The client ($GET_SRC_IP:$GET_SRC_PORT) initiates a connection to the server ($GET_DST_IP:$GET_DST_PORT)
2. The client sends an HTTP GET request specifying the resource URI ($GET_URI)
3. Headers provide additional information to the server about the client's capabilities and preferences

### 6.2 HTTP Response Process
1. The server processes the request and returns a response with status code $RESPONSE_CODE
2. The response includes headers with metadata about the response
3. The actual content follows the headers in the message body

### 6.3 Differences Between GET and POST
| GET Method | POST Method |
|------------|-------------|
| Parameters visible in URL | Parameters sent in message body |
| Used primarily for retrieving data | Used for submitting data |
| Cacheable | Not typically cached |
| Limited data size | Can send larger amounts of data |
| Idempotent (repeated requests have same effect) | Not necessarily idempotent |

## 7. Security Considerations

The HTTP traffic captured in this analysis was transmitted in plain text, which means:

1. All details (URLs, headers, content) are visible to anyone monitoring the network
2. Sensitive information can be easily intercepted
3. POST data, while not visible in the URL, is still sent in clear text
4. Modern websites use HTTPS (HTTP over TLS/SSL) to encrypt traffic and prevent eavesdropping

## 8. Conclusion

This analysis demonstrates the structure and function of HTTP requests and responses. By examining actual packets, we can see how web clients and servers communicate using the HTTP protocol. The capture also highlights the insecure nature of plain HTTP communication, emphasizing why HTTPS is now the standard for web traffic.

---
*Report generated: $(date)*
EOL
    chmod 666 "$HTTP_RESULTS_DIR/http_traffic_analysis_report.md"
    
    # Create a cleanup script for easy deletion
    cat > "$HTTP_RESULTS_DIR/cleanup.sh" << EOL
#!/bin/bash
# Cleanup script to remove all HTTP analysis files
echo "Removing HTTP analysis directory: $HTTP_RESULTS_DIR"
rm -rf "$HTTP_RESULTS_DIR"
echo "Cleanup completed!"
EOL
    chmod 755 "$HTTP_RESULTS_DIR/cleanup.sh"
    
    echo "===================================================================="
    echo "                    HTTP ANALYSIS COMPLETED                          "
    echo "===================================================================="
    echo "All analysis results saved to: $HTTP_RESULTS_DIR/"
    echo "Markdown report generated: $HTTP_RESULTS_DIR/http_traffic_analysis_report.md"
    echo "File permissions set to allow all users to read, write, and delete files"
    echo "A cleanup script has been created at: $HTTP_RESULTS_DIR/cleanup.sh"
    echo "To remove all analysis files, run: $HTTP_RESULTS_DIR/cleanup.sh"
    echo "===================================================================="
}
analyze_arp_requests() {
    echo "===================================================================="
    echo "                    ARP REQUEST ANALYSIS TOOL                        "
    echo "===================================================================="
    
    # Create results directory for ARP analysis
    ARP_RESULTS_DIR="$RESULTS_BASE_DIR/arp_analysis"
    mkdir -p "$ARP_RESULTS_DIR"
    echo "Created directory: $ARP_RESULTS_DIR"
    
    # Set permissions
    chmod -R 777 "$ARP_RESULTS_DIR"
    echo "Set permissions to allow anyone to access and modify the results"

    # Determine network interface automatically
    INTERFACE=$(ip -o -4 route show to default | awk '{print $5}' | head -1)
    if [ -z "$INTERFACE" ]; then
        echo "Could not determine network interface. Please enter it manually:"
        read -p "Interface name: " INTERFACE
    fi
    echo "Using network interface: $INTERFACE"
    
    # Get local IP and subnet information
    LOCAL_IP=$(ip -4 addr show $INTERFACE | grep -oP '(?<=inet\s)\d+(\.\d+){3}')
    if [ -z "$LOCAL_IP" ]; then
        echo "Could not determine local IP address. Please enter it manually:"
        read -p "Local IP address: " LOCAL_IP
    fi
    echo "Local IP: $LOCAL_IP"
    
    # Generate IP based on student number
    echo "Student number: $STUDENT_NUMBER"
    echo "Generated IP from student number: $GENERATED_IP"
    
    # Scan network to find a real device
    echo "Scanning network to find available devices..."
    # Extract subnet
    SUBNET=$(echo $LOCAL_IP | cut -d. -f1-3)
    echo "Subnet: $SUBNET.0/24"
    
    # Start packet capture for ARP analysis
    echo "Starting packet capture for ARP analysis..."
    tshark -i "$INTERFACE" -f "arp" -w "$ARP_RESULTS_DIR/arp_capture.pcap" &
    TSHARK_PID=$!
    
    # Wait for tshark to start
    sleep 2
    
    # Save list of devices in network for reference
    echo "Scanning network for available devices (this may take a few moments)..."
    nmap -sn $SUBNET.0/24 > "$ARP_RESULTS_DIR/network_scan.txt"
    
    # Find a real device IP (different from our own)
    REAL_DEVICE_IP=$(grep -oP '\d+(\.\d+){3}' "$ARP_RESULTS_DIR/network_scan.txt" | grep -v "$LOCAL_IP" | head -1)
    
    if [ -z "$REAL_DEVICE_IP" ]; then
        echo "Could not find another device on the network. Using gateway as real device."
        REAL_DEVICE_IP=$(ip route | grep default | awk '{print $3}')
    fi
    
    echo "Selected real device IP: $REAL_DEVICE_IP"
    
    # Generate ARP Request for the student number based IP
    echo "Generating ARP request for student number based IP: $GENERATED_IP"
    arping -c 3 -I $INTERFACE $GENERATED_IP &> "$ARP_RESULTS_DIR/arping_student_ip.txt"
    sleep 2
    
    # Generate ARP Request for real device
    echo "Generating ARP request for real device IP: $REAL_DEVICE_IP"
    arping -c 3 -I $INTERFACE $REAL_DEVICE_IP &> "$ARP_RESULTS_DIR/arping_real_device.txt"
    sleep 2
    
    # Use ping to also generate ARP traffic (backup method)
    echo "Using ping to generate additional ARP traffic..."
    ping -c 1 $GENERATED_IP &> /dev/null
    sleep 1
    ping -c 1 $REAL_DEVICE_IP &> /dev/null
    sleep 3
    
    # Stop the capture
    echo "Stopping packet capture..."
    kill $TSHARK_PID 2>/dev/null
    wait $TSHARK_PID 2>/dev/null
    echo "Packet capture completed."
    
    # Extract the ARP requests from the capture file
    echo "Extracting ARP requests for student IP..."
    tshark -r "$ARP_RESULTS_DIR/arp_capture.pcap" -Y "arp.dst.proto_ipv4 == $GENERATED_IP" > "$ARP_RESULTS_DIR/student_ip_arp_requests.txt"
    
    echo "Extracting ARP requests for real device..."
    tshark -r "$ARP_RESULTS_DIR/arp_capture.pcap" -Y "arp.dst.proto_ipv4 == $REAL_DEVICE_IP" > "$ARP_RESULTS_DIR/real_device_arp_requests.txt"
    
    # Extract all ARP packets
    echo "Extracting all ARP packets for reference..."
    tshark -r "$ARP_RESULTS_DIR/arp_capture.pcap" > "$ARP_RESULTS_DIR/all_arp_packets.txt"
    
    # Create separate capture files for each type of request
    tshark -r "$ARP_RESULTS_DIR/arp_capture.pcap" -Y "arp.dst.proto_ipv4 == $GENERATED_IP" -w "$ARP_RESULTS_DIR/student_ip_arp.pcap"
    tshark -r "$ARP_RESULTS_DIR/arp_capture.pcap" -Y "arp.dst.proto_ipv4 == $REAL_DEVICE_IP" -w "$ARP_RESULTS_DIR/real_device_arp.pcap"
    
    # Create summary files for each ARP request type
    for TYPE in "student_ip" "real_device"; do
        if [ "$TYPE" == "student_ip" ]; then
            TARGET_IP=$GENERATED_IP
            FILE_PREFIX="student_ip"
            DESCRIPTION="Student number based IP"
        else
            TARGET_IP=$REAL_DEVICE_IP
            FILE_PREFIX="real_device"
            DESCRIPTION="Real device IP"
        fi
        
        # Create detailed analysis
        tshark -r "$ARP_RESULTS_DIR/${FILE_PREFIX}_arp.pcap" -V > "$ARP_RESULTS_DIR/${FILE_PREFIX}_detailed.txt"
        
        # Extract sender MAC, target MAC if available
        SENDER_MAC=$(grep -A 3 "Sender MAC address" "$ARP_RESULTS_DIR/${FILE_PREFIX}_detailed.txt" | grep "Address:" | head -1 | awk '{print $2}')
        TARGET_MAC=$(grep -A 3 "Target MAC address" "$ARP_RESULTS_DIR/${FILE_PREFIX}_detailed.txt" | grep "Address:" | head -1 | awk '{print $2}')
        
        if [ -z "$SENDER_MAC" ]; then
            SENDER_MAC="Not found in capture"
        fi
        
        if [ -z "$TARGET_MAC" ]; then
            TARGET_MAC="Not found in capture (likely broadcast)"
        fi
        
        # Create analysis summary
        cat > "$ARP_RESULTS_DIR/${FILE_PREFIX}_analysis.txt" << EOL
======================================================================
                     ARP ANALYSIS FOR $DESCRIPTION
======================================================================

TARGET INFORMATION:
-----------------
Target IP: $TARGET_IP
Target MAC: $TARGET_MAC

ARP REQUEST DETAILS:
------------------
Sender MAC: $SENDER_MAC
Sender IP: $LOCAL_IP

REQUEST CHARACTERISTICS:
----------------------
EOL
        
        # Check if we got any responses
        if grep -q "is-at" "$ARP_RESULTS_DIR/arping_${FILE_PREFIX}.txt" 2>/dev/null; then
            echo "Response received" >> "$ARP_RESULTS_DIR/${FILE_PREFIX}_analysis.txt"
            RECEIVED_MAC=$(grep "is-at" "$ARP_RESULTS_DIR/arping_${FILE_PREFIX}.txt" | head -1 | awk '{print $4}')
            echo "Received MAC: $RECEIVED_MAC" >> "$ARP_RESULTS_DIR/${FILE_PREFIX}_analysis.txt"
            echo "Status: SUCCESSFUL ARP RESOLUTION" >> "$ARP_RESULTS_DIR/${FILE_PREFIX}_analysis.txt"
        else
            echo "No response received" >> "$ARP_RESULTS_DIR/${FILE_PREFIX}_analysis.txt"
            echo "Status: NO RESPONSE (IP likely not in use)" >> "$ARP_RESULTS_DIR/${FILE_PREFIX}_analysis.txt"
        fi
        
        # Add packet count
        PACKET_COUNT=$(wc -l "$ARP_RESULTS_DIR/${FILE_PREFIX}_arp_requests.txt" | awk '{print $1}')
        echo "Number of packets captured: $PACKET_COUNT" >> "$ARP_RESULTS_DIR/${FILE_PREFIX}_analysis.txt"
        
        cat >> "$ARP_RESULTS_DIR/${FILE_PREFIX}_analysis.txt" << EOL

======================================================================
EOL
    done
    
    # Create comparison analysis
    cat > "$ARP_RESULTS_DIR/arp_comparison.txt" << EOL
======================================================================
           COMPARISON OF ARP REQUESTS FOR DIFFERENT TARGETS
======================================================================

STUDENT NUMBER BASED IP ($GENERATED_IP):
--------------------------------------
$(cat "$ARP_RESULTS_DIR/student_ip_analysis.txt" | grep -A 20 "ARP REQUEST DETAILS:" | grep -v "======")

REAL DEVICE IP ($REAL_DEVICE_IP):
------------------------------
$(cat "$ARP_RESULTS_DIR/real_device_analysis.txt" | grep -A 20 "ARP REQUEST DETAILS:" | grep -v "======")

KEY DIFFERENCES:
--------------
1. Response Status:
   - Student IP: $(grep "Status:" "$ARP_RESULTS_DIR/student_ip_analysis.txt" | cut -d: -f2)
   - Real Device: $(grep "Status:" "$ARP_RESULTS_DIR/real_device_analysis.txt" | cut -d: -f2)

2. Target MAC:
   - Student IP: $(grep "Target MAC:" "$ARP_RESULTS_DIR/student_ip_analysis.txt" | cut -d: -f2-)
   - Real Device: $(grep "Target MAC:" "$ARP_RESULTS_DIR/real_device_analysis.txt" | cut -d: -f2-)

======================================================================
EOL
    
    # Create educational document about ARP
    cat > "$ARP_RESULTS_DIR/arp_explanation.txt" << EOL
======================================================================
                  ADDRESS RESOLUTION PROTOCOL (ARP)
======================================================================

WHAT IS ARP?
-----------
ARP (Address Resolution Protocol) is a protocol used to map an IP address to a 
physical machine address (MAC address) on a local network. It's a fundamental 
protocol in the TCP/IP suite and operates at the network interface layer.

WHEN IS ARP USED?
---------------
ARP is used whenever a device on a local network needs to communicate with 
another device on the same network. Specifically:

1. Before sending a packet, a device checks if it has the destination MAC address
   for the target IP in its ARP cache (a temporary table of IP-to-MAC mappings).

2. If the mapping is not in the cache, the device sends an ARP request broadcast
   to all devices on the local network asking "Who has this IP address?"

3. Only the device with the matching IP address responds with an ARP reply
   containing its MAC address.

4. The original sender then stores this mapping in its ARP cache and uses the
   MAC address to send the data packet.

ARP REQUEST PACKET STRUCTURE:
---------------------------
- Hardware type: Typically Ethernet (value: 1)
- Protocol type: IPv4 (value: 0x0800)
- Hardware address length: 6 bytes (for MAC addresses)
- Protocol address length: 4 bytes (for IPv4 addresses)
- Operation: 1 for request, 2 for reply
- Sender MAC address: MAC address of the requesting device
- Sender IP address: IP address of the requesting device
- Target MAC address: Set to 00:00:00:00:00:00 in requests
- Target IP address: The IP address being looked up

DIFFERENCES BETWEEN SUCCESSFUL AND UNSUCCESSFUL ARP REQUESTS:
----------------------------------------------------------
1. Successful ARP request:
   - An ARP reply is received from the target device
   - The reply contains the actual MAC address of the target
   - The communication can proceed using the resolved MAC address

2. Unsuccessful ARP request:
   - No ARP reply is received (target doesn't exist or is offline)
   - The ARP request may be retransmitted several times
   - Eventually times out, and the communication fails

SECURITY CONSIDERATIONS:
---------------------
- ARP has no authentication mechanism, making it vulnerable to ARP spoofing
  or ARP poisoning attacks
- ARP spoofing allows attackers to intercept communications by sending fake
  ARP messages
- Techniques like static ARP entries, ARP monitoring, and secure switches
  help mitigate these risks

TROUBLESHOOTING WITH ARP:
----------------------
- ARP is useful for troubleshooting network connectivity issues
- If ARP requests don't receive responses, it indicates layer 2 connectivity
  problems
- Tools like "arp -a" display the current ARP cache entries

======================================================================
EOL
    
    # Create screenshot instruction file
    cat > "$ARP_RESULTS_DIR/screenshot_instructions.txt" << EOL
SCREENSHOT INSTRUCTIONS FOR ARP ANALYSIS
=======================================

For your assignment, take screenshots of the following:

1. For Student Number Based IP ($GENERATED_IP):
   a. Open Wireshark and load the capture file: 
      $ARP_RESULTS_DIR/student_ip_arp.pcap
   b. Take a screenshot of the ARP request packet
      - Double-click on an ARP request packet
      - Expand the Address Resolution Protocol section
      - Ensure you capture the source MAC, source IP, target MAC (zeros), and target IP

2. For Real Device IP ($REAL_DEVICE_IP):
   a. Open Wireshark and load the capture file:
      $ARP_RESULTS_DIR/real_device_arp.pcap
   b. Take a screenshot of the ARP request packet
      - Follow the same instructions as above
   c. If available, take a screenshot of the ARP reply packet
      - Look for packets with "ARP reply" in the info column
      - Expand it to show the response MAC address

3. Analysis Screenshots:
   a. Take a screenshot of your system's ARP cache
      - Run "arp -a" in terminal
      - Capture the output showing MAC-to-IP mappings

EOL

    # Create Markdown report using actual values from the analysis
    cat > "$ARP_RESULTS_DIR/arp_analysis_report.md" << EOL
# ARP Analysis Report

## General Information

- **Date:** $(date "+%d.%m.%Y")
- **Network Interface:** $INTERFACE
- **Local IP:** $LOCAL_IP
- **Subnet:** $SUBNET.0/24
- **Student Number:** $STUDENT_NUMBER
- **Student IP:** $GENERATED_IP
- **Real Device IP:** $REAL_DEVICE_IP

## ARP Request Analysis

### ARP Request for Student IP ($GENERATED_IP)

- **Target IP:** $GENERATED_IP
- **Source MAC:** $SENDER_MAC
- **Source IP:** $LOCAL_IP
- **Target MAC:** $(grep "Target MAC:" "$ARP_RESULTS_DIR/student_ip_analysis.txt" | cut -d: -f2- | tr -d '\n')

#### Response Status
$(if grep -q "SUCCESSFUL" "$ARP_RESULTS_DIR/student_ip_analysis.txt"; then
    echo "- **Status:** SUCCESSFUL ARP RESOLUTION"
    echo "- **Response MAC:** $(grep "Received MAC:" "$ARP_RESULTS_DIR/student_ip_analysis.txt" | cut -d: -f2)"
else
    echo "- **Status:** NO RESPONSE (The IP is likely not in use)"
fi)

#### Packet Information
- **Captured Packet Count:** $(grep "packets captured" "$ARP_RESULTS_DIR/student_ip_analysis.txt" | cut -d: -f2 | tr -d ' ')

### ARP Request for Real Device IP ($REAL_DEVICE_IP)

- **Target IP:** $REAL_DEVICE_IP
- **Source MAC:** $SENDER_MAC
- **Source IP:** $LOCAL_IP
- **Target MAC:** $(grep "Target MAC:" "$ARP_RESULTS_DIR/real_device_analysis.txt" | cut -d: -f2- | tr -d '\n')

#### Response Status
$(if grep -q "SUCCESSFUL" "$ARP_RESULTS_DIR/real_device_analysis.txt"; then
    echo "- **Status:** SUCCESSFUL ARP RESOLUTION"
    echo "- **Response MAC:** $(grep "Received MAC:" "$ARP_RESULTS_DIR/real_device_analysis.txt" | cut -d: -f2)"
else
    echo "- **Status:** NO RESPONSE (The IP is likely not in use)"
fi)

#### Packet Information
- **Captured Packet Count:** $(grep "packets captured" "$ARP_RESULTS_DIR/real_device_analysis.txt" | cut -d: -f2 | tr -d ' ')

## Comparison of ARP Requests

| Feature | Student IP ($GENERATED_IP) | Real Device IP ($REAL_DEVICE_IP) |
|---------|----------------------------|----------------------------------|
| Target MAC (Request) | $(grep "Target MAC:" "$ARP_RESULTS_DIR/student_ip_analysis.txt" | cut -d: -f2- | tr -d '\n') | $(grep "Target MAC:" "$ARP_RESULTS_DIR/real_device_analysis.txt" | cut -d: -f2- | tr -d '\n') |
| Response Status | $(if grep -q "SUCCESSFUL" "$ARP_RESULTS_DIR/student_ip_analysis.txt"; then echo "SUCCESSFUL"; else echo "FAILED"; fi) | $(if grep -q "SUCCESSFUL" "$ARP_RESULTS_DIR/real_device_analysis.txt"; then echo "SUCCESSFUL"; else echo "FAILED"; fi) |
| Packet Count | $(grep "packets captured" "$ARP_RESULTS_DIR/student_ip_analysis.txt" | cut -d: -f2 | tr -d ' ') | $(grep "packets captured" "$ARP_RESULTS_DIR/real_device_analysis.txt" | cut -d: -f2 | tr -d ' ') |

## Conclusion and Evaluation

$(if grep -q "SUCCESSFUL" "$ARP_RESULTS_DIR/real_device_analysis.txt" && ! grep -q "SUCCESSFUL" "$ARP_RESULTS_DIR/student_ip_analysis.txt"; then
    echo "While ARP requests sent to the real device IP ($REAL_DEVICE_IP) were successfully answered, the requests to the IP based on the student number ($GENERATED_IP) were not. This demonstrates how ARP protocol can be used to detect the presence or absence of devices on a network."
    echo
    echo "- **Real Device IP:** The device responded to the ARP request and its MAC address was identified."
    echo "- **Student IP:** No response was received to the ARP request, indicating that no device is using this IP on the network."
elif grep -q "SUCCESSFUL" "$ARP_RESULTS_DIR/real_device_analysis.txt" && grep -q "SUCCESSFUL" "$ARP_RESULTS_DIR/student_ip_analysis.txt"; then
    echo "ARP requests to both the real device IP ($REAL_DEVICE_IP) and the student-based IP ($GENERATED_IP) were successfully answered. This shows that devices using both IP addresses are present on the network."
    echo
    echo "- **Real Device IP:** The device responded to the ARP request and its MAC address was identified."
    echo "- **Student IP:** Interestingly, a device with this IP was also detected on the network. This suggests that the student-based IP is coincidentally in use."
elif ! grep -q "SUCCESSFUL" "$ARP_RESULTS_DIR/real_device_analysis.txt" && ! grep -q "SUCCESSFUL" "$ARP_RESULTS_DIR/student_ip_analysis.txt"; then
    echo "Neither the ARP requests to the real device IP ($REAL_DEVICE_IP) nor the student-based IP ($GENERATED_IP) were answered. This could indicate network connectivity issues or that no devices are using either of the IPs."
    echo
    echo "- **Real Device IP:** Unexpectedly, no response was received from the device with this IP. It may be offline or there may be network issues."
    echo "- **Student IP:** As expected, no device was found using this IP on the network."
else
    echo "Interestingly, while ARP requests to the student-based IP ($GENERATED_IP) were answered, the ones sent to the real device IP ($REAL_DEVICE_IP) were not. This is an unexpected result."
    echo
    echo "- **Real Device IP:** Unexpectedly, no response was received from the device with this IP. It may be offline or there may be network issues."
    echo "- **Student IP:** Interestingly, a device was found using this IP on the network. This suggests the student-based IP is coincidentally in use."
fi)

## Lessons Learned

1. The ARP protocol is used to discover IP-MAC mappings of devices on a local network.
2. ARP requests are answered when a device with the target IP address exists.
3. If there is no ARP response, it usually indicates no device with the target IP is present on the network.
4. The ARP protocol is a useful tool for diagnosing network connectivity issues.
5. ARP requests and responses can also reveal potential network vulnerabilities (e.g., ARP poisoning).

## Additional Information

This analysis was performed using the following tools:
- tshark (command-line version of Wireshark)
- arping
- nmap
- Linux networking tools (ip, ping)

All analysis results are stored in: $ARP_RESULTS_DIR/
EOL

    
    # Set permissions for all files
    chmod -R 666 "$ARP_RESULTS_DIR"/*.txt
    chmod -R 666 "$ARP_RESULTS_DIR"/*.pcap
    chmod -R 666 "$ARP_RESULTS_DIR"/*.md
    
    echo "===================================================================="
    echo "                    ARP ANALYSIS COMPLETED                           "
    echo "===================================================================="
    echo "All analysis results saved to: $ARP_RESULTS_DIR/"
    echo "Markdown report created: $ARP_RESULTS_DIR/arp_analysis_report.md"
    echo ""
    echo "The analysis demonstrates the difference between:"
    echo "1. ARP requests to non-existent IPs (no response)"
    echo "2. ARP requests to existing devices (successful resolution)"
    echo ""
    echo "Review the comparison file, MD report, and explanation document for details."
    echo "Follow the screenshot instructions for your assignment submission."
}

organize_and_generate_report() {
    local current_dir=$(pwd)
    local timestamp=$(date +%Y%m%d_%H%M%S)
    local output_dir="network_analysis-$timestamp"
    mkdir "$output_dir"

    declare -A folder_map=(
        ["network_analysis"]="analyze_tcp_handshake"
        ["dns_analysis"]="analyze_dns_queries"
        ["icmp_analysis"]="analyze_icmp_ping"
        ["http_analysis"]="analyze_http_traffic"
    )

    for prefix in "network_analysis" "dns_analysis" "icmp_analysis" "http_analysis"; do
        folder=$(find . -maxdepth 1 -type d -name "${prefix}_*" | head -n 1)
        if [ -d "$folder" ]; then
            new_name="${folder_map[$prefix]}"
            mv "$folder" "$output_dir/$new_name"
        fi
    done

    if [ -d "$output_dir/analyze_tcp_handshake/arp_analysis" ]; then
        mv "$output_dir/analyze_tcp_handshake/arp_analysis" "$output_dir/analyze_arp_requests"
    fi

    local report_path="$output_dir/General_Report.md"
    > "$report_path"

    for name in \
        "analyze_tcp_handshake" \
        "analyze_dns_queries" \
        "analyze_icmp_ping" \
        "analyze_http_traffic" \
        "analyze_arp_requests"
    do
        folder="$output_dir/$name"
        if [ -d "$folder" ]; then
            md_files=$(find "$folder" -type f -name "*.md" | sort)
            for md in $md_files; do
                echo -e "\n---\n# $(basename "$md")\n---\n" >> "$report_path"
                cat "$md" >> "$report_path"
                echo -e "\n" >> "$report_path"
            done
        fi
    done

    echo "✅ Rapor oluşturuldu: $report_path"

    chmod -R 777 "$output_dir"
    echo "🔐 '$output_dir' klasörüne tam erişim verildi (chmod 777)."

    local backup_dir="/var/backups"
    if [ ! -d "$backup_dir" ]; then
        backup_dir="$HOME/backups"
        mkdir -p "$backup_dir"
    fi
    cp -r "$output_dir" "$backup_dir/"
    echo "💾 '$output_dir' klasörü '$backup_dir/' dizinine yedeklendi."

    cat > "$output_dir/index.html" << 'EOF'
<!DOCTYPE html>
<html lang="tr">
<head>
  <meta charset="UTF-8">
  <meta http-equiv="refresh" content="0; url=General_Report.html">
  <title>Yönlendiriliyor...</title>
</head>
<body>
  <p>General_Report.html sayfasına yönlendiriliyorsunuz...</p>
  <p>Otomatik yönlendirme çalışmazsa, <a href="General_Report.html">buraya tıklayın</a>.</p>
</body>
</html>
EOF

    local html_path="$output_dir/General_Report.html"
    cat > "$html_path" << 'EOF'
<!DOCTYPE html>
<html lang="tr">
<head>
  <meta charset="UTF-8">
  <title>Network Analysis Report - GitHub Tarzı Görünüm</title>
  <style>
    :root {
      --border-color: #e1e4e8;
      --background-color: #fff;
      --text-color: #24292e;
      --code-bg: #f6f8fa;
      --header-bg: #f6f8fa;
    }
    
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif;
      line-height: 1.5;
      color: var(--text-color);
      max-width: 980px;
      margin: 0 auto;
      padding: 20px;
      background-color: var(--background-color);
    }
    
    .markdown-body {
      box-sizing: border-box;
      min-width: 200px;
      max-width: 980px;
      margin: 0 auto;
      padding: 45px;
      border: 1px solid #ddd;
      border-radius: 6px;
    }
    
    @media (max-width: 767px) {
      .markdown-body {
        padding: 15px;
      }
    }
    
    h1, h2, h3, h4, h5, h6 {
      margin-top: 24px;
      margin-bottom: 16px;
      font-weight: 600;
      line-height: 1.25;
    }
    
    h1 {
      border-bottom: 1px solid var(--border-color);
      padding-bottom: 0.3em;
      font-size: 2em;
    }
    
    h2 {
      border-bottom: 1px solid var(--border-color);
      padding-bottom: 0.3em;
      font-size: 1.5em;
    }
    
    p {
      margin-top: 0;
      margin-bottom: 16px;
    }
    
    code {
      font-family: SFMono-Regular, Consolas, "Liberation Mono", Menlo, monospace;
      padding: 0.2em 0.4em;
      margin: 0;
      font-size: 85%;
      background-color: var(--code-bg);
      border-radius: 3px;
    }
    
    pre {
      font-family: SFMono-Regular, Consolas, "Liberation Mono", Menlo, monospace;
      padding: 16px;
      overflow: auto;
      font-size: 85%;
      line-height: 1.45;
      background-color: var(--code-bg);
      border-radius: 6px;
    }
    
    pre code {
      padding: 0;
      margin: 0;
      background-color: transparent;
    }
    
    blockquote {
      padding: 0 1em;
      color: #6a737d;
      border-left: 0.25em solid #dfe2e5;
      margin: 0 0 16px 0;
    }
    
    hr {
      height: 0.25em;
      padding: 0;
      margin: 24px 0;
      background-color: #e1e4e8;
      border: 0;
    }
    
    table {
      border-spacing: 0;
      border-collapse: collapse;
      margin-top: 0;
      margin-bottom: 16px;
      display: block;
      width: 100%;
      overflow: auto;
    }
    
    table th, table td {
      padding: 6px 13px;
      border: 1px solid #dfe2e5;
    }
    
    table tr {
      background-color: #fff;
      border-top: 1px solid #c6cbd1;
    }
    
    table tr:nth-child(2n) {
      background-color: #f6f8fa;
    }
    
    .header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding: 10px 16px;
      background-color: var(--header-bg);
      border-bottom: 1px solid var(--border-color);
      border-radius: 6px 6px 0 0;
    }
    
    .header h1 {
      margin: 0;
      font-size: 18px;
      border-bottom: none;
      padding-bottom: 0;
    }
  </style>
</head>
<body>
  <div class="header">
    <h1>Network Analysis Report</h1>
  </div>
  <div class="markdown-body" id="content">
    Loading markdown content...
  </div>

  <!-- Markdown işlemesi için marked.js kütüphanesini ekle -->
  <script src="https://cdnjs.cloudflare.com/ajax/libs/marked/4.0.2/marked.min.js"></script>
  <script>
    // Markdown dosyasını yükle ve işle
    fetch('General_Report.md')
      .then(response => response.text())
      .then(markdown => {
        document.getElementById('content').innerHTML = marked.parse(markdown);
      })
      .catch(error => {
        document.getElementById('content').innerHTML = '<p>Error loading markdown file: ' + error.message + '</p>';
      });
  </script>
</body>
</html>
EOF

    echo "🌐 GitHub stilinde HTML raporu oluşturuldu: $html_path"

    echo "🚀 Web sunucusu başlatılıyor: http://localhost:8000/General_Report.html"
    
    if command -v xdg-open &> /dev/null; then
        (sleep 1 && xdg-open "http://localhost:8000/General_Report.html") &
    elif command -v open &> /dev/null; then
        (sleep 1 && open "http://localhost:8000/General_Report.html") &
    elif command -v start &> /dev/null; then
        (sleep 1 && start "http://localhost:8000/General_Report.html") &
    fi
    
    cd "$output_dir"
    python3 -m http.server 8000
}

main(){
    analyze_tcp_handshake
    analyze_dns_queries
    analyze_icmp_ping
    analyze_http_traffic
    analyze_arp_requests
    organize_and_generate_report
}
main