# 0x7359 Deauther
<img src="https://github.com/user-attachments/assets/3e4997c1-8edc-400d-b5cb-8219a26b9074" alt='5G Deauther' width='500' />

### Original Project
[Original project repo](https://github.com/tesa-klebeband/RTL8720dn-Deauther)

[Divine Zeal's repo](https://github.com/dkyazzentwatwa/cypher-5G-deauther)

## Main Changes
In this new version, I have updated and refined the code. I've tweaked the UI by adding a signal strength indicator and battery level display, and the main feature is that I've also integrated the functionality to sniff deauthed networks, capturing both management and EAPOL frames. The captured frames are automatically compiled into a .pcap file that can be downloaded via browser and processed with hcxpcapngtool to generate a .hc22000 hash file compatible with hashcat.

Please note, this is not a final release—there are many improvements planned, and I may eventually focus on a dual BW16 version instead of this one.

## How to Upload Firmware / Usage

1) Go to RTL8720DN_SSD1306_FIX folder. You need to first backup any files that will be replaced, and then add this into your Arduino/libraries folder.
    - This fixes bugs that make Adafruit SSD1306 library incompatible with BW16 board.
2) Upload the firmware using the .ino file via Arduino IDE.
3) Turn it on and select/attack!
4) Credentials to connect to the network to download the .pcap file
    wifi=0x7359
    pw=0123456789


## Requirements

- SSD1306
- 3 Buttons
- BW16 Board (DO NOT USE BW16E, 5GHZ DOESN'T WORK PROPERLY WITH IT)

## PICTURES
<img src="https://github.com/user-attachments/assets/e6b0c5cf-70d0-43fa-b013-4c666d8061ef" width='400' />
<img src="https://github.com/user-attachments/assets/743730e5-2dff-4091-b4fa-2c1dd8a95930" width='400' />
<img src="https://github.com/user-attachments/assets/eb828eda-369e-4712-8ea6-f3e9b49f3c3d" width='400' />
<img src="img/device4.JPG" width='400' />

## Connections

### Buttons
- **Up Button**: PA27  
- **Down Button**: PA12  
- **Select Button**: PA13  

### SSD1306 128x64 .96inch Display
- **SDA**: PA26  
- **SCL**: PA25  

## TODO
- [x] signal strength indicator
- [x] web server to serve the captured .pcap files
- [x] battery level display
- [ ] add module to save .pcap file to SD card
- [ ] manage more than one .pcap file per session
- [x] fix display bug after finishing sniffing
- [ ] attack all  + sniff all
- [ ] dual frequency attack on selecting network
- [ ] improve UX/UI
- [ ] refactor the code
- [ ] add evil twin functionality
- [ ] add evil portal functionality
