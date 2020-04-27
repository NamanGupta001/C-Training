/***********************************************************************************************************************************************
display file will be responsible for printing pcap file stats into console and returning the formatted values to the caller function.
***********************************************************************************************************************************************/

#ifndef DISPLAY_H
#define DISPLAY_H

class display
{
    public:
    std::string displayMacAddr(unsigned char macAddress []);
    std::string printIpv6Address(unsigned char ipAddress[]);
    std::string printIpv4Address(unsigned char ipv4Address[]);
    void printPortNumber(unsigned short int port);
    
};

#endif