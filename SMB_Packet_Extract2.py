import os
import json
from scapy.all import rdpcap, TCP

def extract_smb_packets(pcap_file):
    packets = rdpcap(pcap_file)
    smb_packets = []
    
    for packet in packets:
        if TCP in packet and (packet[TCP].dport == 445 or packet[TCP].sport == 445):
            smb_packets.append(packet)
    
    return smb_packets

def parse_smb2_packets(smb_packets):
    read_requests = []
    write_requests = []
    read_responses = []
    write_responses = []
    
    for packet in smb_packets:
        if b'\xfeSMB' in bytes(packet[TCP].payload):
            smb2_header = bytes(packet[TCP].payload)[4:36]  # Extract SMB2 header
            command = smb2_header[12:14]  # Command field
            if command == b'\x08\x00':  # SMB2 READ
                if b'\x09\x00' in bytes(packet[TCP].payload):  # READ Response
                    read_responses.append(packet)
                else:
                    read_requests.append(packet)
            elif command == b'\x09\x00':  # SMB2 WRITE
                if b'\x08\x00' in bytes(packet[TCP].payload):  # WRITE Response
                    write_responses.append(packet)
                else:
                    write_requests.append(packet)
    
    return read_requests, write_requests, read_responses, write_responses

def extract_metadata(packet):
    ip_layer = packet.getlayer('IP')
    tcp_layer = packet.getlayer('TCP')
    metadata = {
        'source_ip': ip_layer.src,
        'destination_ip': ip_layer.dst,
        'source_port': tcp_layer.sport,
        'destination_port': tcp_layer.dport
    }
    return metadata

def extract_file_data(packet):
    tcp_payload = bytes(packet[TCP].payload)
    smb2_header = tcp_payload[4:36]
    smb2_payload = tcp_payload[36:]
    
    if smb2_header[12:14] == b'\x08\x00':  # READ Response
        data_offset = int.from_bytes(smb2_payload[48:52], byteorder='little')
        data_length = int.from_bytes(smb2_payload[56:60], byteorder='little')
        file_data = smb2_payload[data_offset:data_offset + data_length]
        return file_data
    elif smb2_header[12:14] == b'\x09\x00':  # WRITE Request
        data_offset = int.from_bytes(smb2_payload[48:52], byteorder='little')
        data_length = int.from_bytes(smb2_payload[56:60], byteorder='little')
        file_data = smb2_payload[data_offset:data_offset + data_length]
        return file_data
    return None

def save_extracted_file(file_data, file_path):
    with open(file_path, 'wb') as f:
        f.write(file_data)

def save_metadata(metadata, output_file):
    with open(output_file, 'w') as f:
        json.dump(metadata, f, indent=4)

def main():
    pcap_file = r'smb.pcap'  # Set your pcap file path here
    output_dir = 'extracted_files'
    metadata_file = 'metadata.json'
    
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    
    smb_packets = extract_smb_packets(pcap_file)
    read_requests, write_requests, read_responses, write_responses = parse_smb2_packets(smb_packets)
    metadata = []

    for i, packet in enumerate(read_requests + write_requests + read_responses + write_responses):
        packet_metadata = extract_metadata(packet)
        file_data = extract_file_data(packet)
        
        if file_data:
            file_name = f"file_{i}.data"
            file_path = os.path.join(output_dir, file_name)
            save_extracted_file(file_data, file_path)
            packet_metadata['file_name'] = file_name
            packet_metadata['file_size'] = len(file_data)
        
        metadata.append(packet_metadata)
    
    save_metadata(metadata, metadata_file)
    print(f'Metadata saved to {metadata_file}')

if __name__ == '__main__':
    main()