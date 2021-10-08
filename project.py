import socket
import struct
import pcapy

if __name__ == "__main__":

    # DEVICE SELECTION =================================================================================================
    # Find all available devices
    devList = pcapy.findalldevs()

    # Construct prompt string
    input_string = "Enter the # for the device (Press Enter for 0 as default): \n"
    for number, option in enumerate(devList):
        input_string += "Device [" + str(number) + "]: " + option + "\n"

    # Prompt user for input
    deviceNum = int(input(input_string) or "0")
    print("You have selected: " + str(deviceNum))
    device = devList[deviceNum]

    # Open device
    #   Arg 1: Device
    #   Arg 2: Snaplen - max # of bytes to capture per packet
    #   Arg 3: Promiscious Mode - Set to True
    #   Arg 4: Timeout - In milliseconds
    capture = pcapy.open_live(device, 65536, True, 0)
    # ==================================================================================================================

    # START PACKET SNIFFING ============================================================================================

