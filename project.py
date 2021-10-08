import socket
import struct
import pcapy


# Convert to readable ethernet address
def ethernet_address(raw_addr):
    addr = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (raw_addr[0], raw_addr[1], raw_addr[2], raw_addr[3], raw_addr[4], raw_addr[5])
    return addr


def clean_print(ip_src, ip_dest, tcp_src_port, tcp_dest_port, data, num):
    # Separate substrings by \r\n to get request/header lines
    sliced_data = data.split("\\r\\n")

    # Build the HTTP_line string from sliced data
    HTTP_line = str(num) + " " + \
                  str(ip_src) + ":" + \
                  str(tcp_src_port) + " " + \
                  str(ip_dest) + ":" + \
                  str(tcp_dest_port) + " HTTP "

    # Check if data is a HTTP Response or HTTP Request
    if "GET" in sliced_data[0]:
        HTTP_line += "Request"
    else:
        HTTP_line += "Response"
    print(HTTP_line)

    # Iterate through sliced data and print out header lines
    line = 0
    while sliced_data[line]:
        print(sliced_data[line])
        line += 1

    # Print newline
    print()


# Helper function to break down data inside the packet and convert it to readable form
def packet_helper(packet, packet_num):
# VARS =================================================================================================================
    # Ethernet
    eth_hdr_len = 14

    # IP
    ip_hdr_len = 20
    ip_src = ""
    ip_dest = ""

    # TCP
    tcp_hdr_len = -1
    tcp_src_port = ""
    tcp_dest_port = ""

    # Data Payload
    data_payload_len = -1
    data_payload = ""
# ======================================================================================================================
# PARSE ETHERNET HEADER ================================================================================================
    # Unpack Ethernet header data using struct.unpack
    eth_hdr = packet[:eth_hdr_len]
    eth = struct.unpack('!6s6sH', eth_hdr)
    eth_dest_mac = ethernet_address(packet[0:6])
    eth_src_mac = ethernet_address(packet[6:12])

    # Grab ethernet protocol using socket library
    eth_proto = socket.ntohs(eth[2])
# ======================================================================================================================
    if eth_proto == 8:
# PARSE IP HEADER ======================================================================================================
        # Unpack IP Header data using struct.unpack
        ip_hdr = packet[eth_hdr_len:ip_hdr_len + eth_hdr_len]
        ip = struct.unpack('!BBHHHBBH4s4s', ip_hdr)

        # Grab IP Protocol to check later if TCP
        ip_proto = ip[6]

        # Grab source/destination IP addresses using socket library
        ip_src = socket.inet_ntoa(ip[8])
        ip_dest = socket.inet_ntoa(ip[9])
# ======================================================================================================================
        if ip_proto == 6:
# PARSE TCP HEADER =====================================================================================================
            # Unpack TCP Header using struct.unpack
            tcp_hdr_offset = eth_hdr_len + ip_hdr_len
            tcp_hdr = packet[tcp_hdr_offset:tcp_hdr_offset + 20]
            tcp = struct.unpack('!HHLLBBHHH', tcp_hdr)

            # Get TCP Header length using bit shift
            tcp_hdr_len = tcp[4] >> 4

            # Grab source/destination TCP ports
            tcp_src_port = tcp[0]
            tcp_dest_port = tcp[1]
# ======================================================================================================================
# PARSE DATA PAYLOAD ===================================================================================================
            # Calculate full header length
            header_len = eth_hdr_len + ip_hdr_len + tcp_hdr_len * 4

            # Extract packet data
            data_payload = packet[header_len:]
# ======================================================================================================================
# EXTRACT HTTP REQUESTS ================================================================================================
    # Ignore bit annotation to the string after conversion
    data = str(data_payload)[2:-1]

    # Check if data is a HTTP response of request
    if data and ("HTTP" or "GET") in data:
        clean_print(ip_src, ip_dest, tcp_src_port, tcp_dest_port, data, packet_num)

        # If an HTTP response/request that sucessfully prints, increment by 1
        return 1 + packet_num
    # Else, don't increment by 1
    return 0 + packet_num
# ======================================================================================================================


if __name__ == "__main__":
# DEVICE SELECTION =====================================================================================================
    # Find all available devices
    devList = pcapy.findalldevs()

    # Construct prompt string
    input_string = "Enter the # for the device (Press Enter for 0 as default): \n"
    for number, option in enumerate(devList):
        input_string += "Device [" + str(number) + "]: " + option + "\n"

    # Prompt user for input
    deviceNum = int(input(input_string) or "0")
    device = devList[deviceNum]
    print("You have selected: " + str(deviceNum) + "\n")
    print("Press CTRL+C to exit the program at any time.")
    print("Currently sniffing network traffic on [" + device.upper() + "]...")

    # Open device
    #   Arg 1: Device
    #   Arg 2: Snaplen - max # of bytes to capture per packet
    #   Arg 3: Promiscious Mode - Set to True
    #   Arg 4: Timeout - In milliseconds
    capture = pcapy.open_live(device, 65536, True, 0)
# ======================================================================================================================
# PACKET SNIFFING ======================================================================================================
    # Set filter to reduce unwanted traffic
    capture.setfilter("tcp port 80")

    # Start packet sniffing
    packet_num = 1
    while True:
        # Capture the next packet header and packet data
        header, packet = capture.next()

        # Call the packet_helper function to get/print required data
        packet_num = packet_helper(packet, packet_num)
# ======================================================================================================================