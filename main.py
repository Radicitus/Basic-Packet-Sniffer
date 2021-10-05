import pcapy

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



