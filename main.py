import pcapy


def callback():
    return


if __name__ == "__main__":
    # Find devices
    devsList = pcapy.findalldevs()
    print(devsList)

    # Construct prompt string
    input_string = "Enter the # for the device: \n"
    for number, option in enumerate(devsList):
        input_string += "Device [" + str(number) + "]: " + option + "\n"

    # Prompt user for input
    deviceNum = int(input(input_string) or "0")
    print("You have selected: " + str(deviceNum))
    device = devsList[deviceNum]

    # Capture packets
    handle = pcapy.open_live(device, 65535, True, 0)

    try:
        while True:
            # Set filter
            handle.setfilter('tcp port 80')

            # Collect next packet

            # Print response
            network = handle.getnet()
            link = handle.datalink()
            dis = handle.dispatch()

    except KeyboardInterrupt:
        print("User manually ended loop.")
        pass
