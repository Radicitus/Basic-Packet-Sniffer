import pcapy


def callback(h):
    network = h.getnet()
    mask = h.getmask()
    link = h.datalink()
    fd = h.getfd()
    stats = h.stats()
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

            # Callback loop
            handle.loop(10, callback(handle))

            # Collect next packet

    except KeyboardInterrupt:
        print("User manually ended loop.")
        pass
