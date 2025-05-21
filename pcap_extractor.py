from scapy.all import rdpcap, TCP, Raw, sniff
from scapy.layers.http import HTTP, HTTPRequest, HTTPResponse
import re
import os
import zlib
import argparse # Import the argparse module

# --- Helper Functions ---

def dechunk_http_body(chunked_body):
    """
    De-chunks an HTTP message body.
    Handles lines ending with CRLF and removes chunk size headers.
    """
    if not chunked_body:
        return b''

    dechunked_data = b''
    offset = 0
    while offset < len(chunked_body):
        # Find the end of the chunk size line (CRLF)
        crlf_pos = chunked_body.find(b'\r\n', offset)
        if crlf_pos == -1:
            break # Malformed chunk

        chunk_size_hex = chunked_body[offset:crlf_pos].strip()
        try:
            chunk_size = int(chunk_size_hex, 16)
        except ValueError:
            # Not a valid hex chunk size, might be end-of-chunks (0\r\n\r\n)
            # or malformed data.
            # If the next bytes are b'0\r\n\r\n', it's the end of the chunked message.
            if chunk_size_hex == b'0':
                if crlf_pos + 4 <= len(chunked_body) and chunked_body[crlf_pos + 2:crlf_pos + 4] == b'\r\n':
                    return dechunked_data # End of chunked transfer
            print(f"Warning: Could not parse chunk size from '{chunk_size_hex}'")
            break # Stop parsing, assume malformed

        # Move past the chunk size line to the actual data
        data_start = crlf_pos + 2
        data_end = data_start + chunk_size

        if data_end > len(chunked_body):
            print(f"Warning: Chunk size {chunk_size} exceeds remaining data length.")
            break # Not enough data for the declared chunk size

        dechunked_data += chunked_body[data_start:data_end]

        # Move past the data and its trailing CRLF
        offset = data_end + 2 # +2 for the CRLF after the data

        # Check for the final chunk (0\r\n\r\n)
        if chunk_size == 0:
            if offset + 2 <= len(chunked_body) and chunked_body[offset:offset+2] == b'\r\n':
                return dechunked_data # End of chunked transfer
            else:
                # Malformed final chunk.
                print("Warning: Malformed final chunk terminator.")
                break
    return dechunked_data


def get_file_extension(content_type):
    """Guesses file extension based on Content-Type header."""
    if not content_type:
        return '.bin'
    content_type = content_type.lower()
    if 'image/jpeg' in content_type or 'image/jpg' in content_type:
        return '.jpg'
    elif 'image/png' in content_type:
        return '.png'
    elif 'image/gif' in content_type:
        return '.gif'
    elif 'text/plain' in content_type:
        return '.txt'
    elif 'application/json' in content_type:
        return '.json'
    elif 'application/xml' in content_type or 'text/xml' in content_type:
        return '.xml'
    elif 'text/html' in content_type:
        return '.html'
    elif 'video/mp4' in content_type:
        return '.mp4'
    elif 'video/webm' in content_type:
        return '.webm'
    elif 'application/pdf' in content_type:
        return '.pdf'
    # Add more as needed
    return '.bin' # Default to binary if unknown

# --- Main Logic ---

def extract_multipart_mixed_replace(pcap_file, output_dir, http_port):
    print(f"Loading PCAP file: {pcap_file}")
    try:
        packets = rdpcap(pcap_file)
    except Exception as e:
        print(f"Error loading PCAP: {e}")
        return

    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
        print(f"Created output directory: {output_dir}")

    tcp_streams = {} # Dictionary to store TCP stream data: { (src_ip, src_port, dst_ip, dst_port): [list_of_raw_payloads] }

    print("Reassembling TCP streams...")
    for pkt in packets:
        # Check if the packet has the TCP layer and if either source or destination port matches http_port
        if pkt.haslayer(TCP) and (pkt[TCP].sport == http_port or pkt[TCP].dport == http_port):
            # Identify the unique tuple for the stream.
            # We normalize the tuple to represent the stream regardless of direction
            # The client_ip and client_port should always be the first two elements
            # The server_ip and server_port should always be the last two elements
            if pkt[TCP].dport == http_port: # This is a client request to the server
                stream_key = (pkt.src, pkt[TCP].sport, pkt.dst, pkt[TCP].dport)
            else: # This is a server response or other traffic from the server
                stream_key = (pkt.dst, pkt[TCP].dport, pkt.src, pkt[TCP].sport)

            if Raw in pkt:
                payload = bytes(pkt[Raw].load)
                if stream_key not in tcp_streams:
                    tcp_streams[stream_key] = b''
                tcp_streams[stream_key] += payload

    extracted_count = 0
    for stream_key, stream_data in tcp_streams.items():
        # Look for HTTP responses in the stream data
        # We need to find the start of an HTTP response, typically 'HTTP/1.1 200 OK'
        # The raw data might contain multiple requests/responses or partial data.

        # Regex to find HTTP/1.1 200 OK followed by headers and then body.
        # This is a simplification; a full HTTP parser would be more robust.
        # We look for a response line followed by headers, then two CRLFs, then the body.
        match = re.search(rb'HTTP/1\.1 200 OK\r\n(.*?)\r\n\r\n(.*)', stream_data, re.DOTALL)
        if not match:
            continue

        headers_raw = match.group(1)
        body_raw = match.group(2)

        # Parse headers
        headers = {}
        for line in headers_raw.split(b'\r\n'):
            if b':' in line:
                key, value = line.split(b':', 1)
                headers[key.strip().lower()] = value.strip()

        content_type = headers.get(b'content-type', b'').decode('latin-1') # Use latin-1 for headers
        transfer_encoding = headers.get(b'transfer-encoding', b'').decode('latin-1')

        if 'transfer-encoding' in headers and b'chunked' in headers[b'transfer-encoding']:
            print(f"[{stream_key}] De-chunking HTTP body...")
            body = dechunk_http_body(body_raw)
        else:
            body = body_raw

        # --- Check for multipart/x-mixed-replace ---
        if 'multipart/x-mixed-replace' in content_type:
            boundary_match = re.search(r'boundary=(.+)', content_type)
            if not boundary_match:
                print(f"[{stream_key}] Warning: multipart/x-mixed-replace found but no boundary string.")
                continue
            
            boundary_str = boundary_match.group(1).strip()
            # The boundary in the actual data starts with two hyphens
            # The final boundary also ends with two hyphens
            boundary_bytes = (b'--' + boundary_str.encode('latin-1')).strip() # Encode boundary string

            print(f"[{stream_key}] Found multipart/x-mixed-replace with boundary: '{boundary_str}'")

            # Split the body by the boundary
            parts = body.split(boundary_bytes)

            # The first part is usually empty or prelude, the last is often the terminator or postlude.
            # Iterate through the parts, skipping the first and last (which might be the final --)
            for i, part in enumerate(parts):
                if not part.strip(): # Skip empty parts (like the one before the first boundary)
                    continue

                # The last part might be the final boundary (--BoundaryString--)
                if part.strip() == b'--':
                    continue

                # Each part starts with its own headers, followed by CRLF and then its data
                part_headers_end = part.find(b'\r\n\r\n')
                if part_headers_end == -1:
                    print(f"[{stream_key}] Warning: Malformed part {i} - no double CRLF after headers.")
                    continue

                part_headers_raw = part[:part_headers_end]
                part_data = part[part_headers_end + 4:] # +4 for the \r\n\r\n

                part_headers = {}
                for line in part_headers_raw.split(b'\r\n'):
                    if b':' in line:
                        key, value = line.split(b':', 1)
                        part_headers[key.strip().lower()] = value.strip()

                part_content_type = part_headers.get(b'content-type', b'').decode('latin-1')
                file_ext = get_file_extension(part_content_type)
                
                # Generate a unique filename
                # Use server IP and port for the stream identifier in the filename
                # Example: stream_192.168.1.100_80_part_1.jpg
                filename = os.path.join(output_dir, f"stream_{stream_key[2]}_{stream_key[3]}_part_{extracted_count + 1}{file_ext}")
                
                try:
                    with open(filename, 'wb') as f:
                        f.write(part_data)
                    print(f"Extracted: {filename} (Content-Type: {part_content_type})")
                    extracted_count += 1
                except IOError as e:
                    print(f"Error writing file {filename}: {e}")

    print(f"\nExtraction complete. Total files extracted: {extracted_count}")
    if extracted_count == 0:
        print("No multipart/x-mixed-replace content found or extracted.")

# --- Run the Script ---
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Extract files from multipart/x-mixed-replace HTTP streams in a PCAP.")
    parser.add_argument('--pcap', type=str, required=True,
                        help="Path to the input PCAP file.")
    parser.add_argument('--output', type=str, default='extracted_files',
                        help="Directory to save extracted files. (default: 'extracted_files')")
    parser.add_argument('--port', type=int, default=80,
                        help="HTTP port to listen on. (default: 80)")

    args = parser.parse_args()

    # Now pass the arguments to your main function
    extract_multipart_mixed_replace(args.pcap, args.output, args.port)
