#include<cstdio>
#include<iostream>
#include <arpa/inet.h>
#include<string>

struct display
{
    std::string displayMacAddr(unsigned char macAddress []);
    std::string printIpv6Address(unsigned char ipAddress[]);
    std::string printIpv4Address(unsigned char ipv4Address[]);
    void printPortNumber(unsigned short int port);
    
};

std::string display::displayMacAddr(unsigned char macAddress [])
{
    char  macAddr[18];  //Will be used to write values into csv file

    printf("%x:%x:%x:%x:%x:%x", macAddress[0], macAddress[1], macAddress[2], macAddress[3], macAddress[4], macAddress[5]);
    snprintf(macAddr,18,"%x:%x:%x:%x:%x:%x", macAddress[0], macAddress[1], macAddress[2], macAddress[3], macAddress[4], macAddress[5]);
    std::cout<<"\n";

    return macAddr;

}

std::string display::printIpv6Address(unsigned char ipAddress[])
{
    std::string totalIpAddr="";

    for (int index=0;index < 15;index+=2)
    {
        // if (ipAddress[index] == 0 && ipAddress[index+1] == 0)
        // {
        //     continue;
        // }
        // else if (ipAddress[index] == 0 && ipAddress[index+1] != 0)
        // {
        //     printf("%x",ipAddress[index+1]);
        // }
        // else if (ipAddress[index] !=0 && ipAddress[index+1] == 0)
        // {
        //     std::cout<<"::";
        //     printf("%x",ipAddress[index]);
        // }
        // else
        // {
        //      printf("%x%x%s",ipAddress[index],ipAddress[index+1],":");
        // }    
        char temp[6];
        if (index != 14) 
        {
            printf("%x%x%s",ipAddress[index],ipAddress[index+1],":");
            snprintf(temp,6,"%x%x%s",ipAddress[index],ipAddress[index+1],":");
            totalIpAddr += temp;
        }
        else
        {   
            printf("%x%x",ipAddress[index],ipAddress[index+1]);
            snprintf(temp,6,"%x%x",ipAddress[index],ipAddress[index+1]);
            totalIpAddr += temp;
            
        }
        
       
    }
    std::cout<<"\n";
    return totalIpAddr;
}
std::string display::printIpv4Address(unsigned char ipv4Address[])
{
    
    char ipv4Addr[17];
    // bytes[0] = ipv4Address & 0xFF;
    // bytes[1] = (ipv4Address >> 8) & 0xFF;
    // bytes[2] = (ipv4Address >> 16) & 0xFF;
    // bytes[3] = (ipv4Address >> 24) & 0xFF;
    printf("%d.%d.%d.%d", ipv4Address[0],ipv4Address[1], ipv4Address[2], ipv4Address[3]);
    snprintf(ipv4Addr,17,"%d.%d.%d.%d", ipv4Address[0],ipv4Address[1], ipv4Address[2], ipv4Address[3]);
    return ipv4Addr;
}
void display::printPortNumber(unsigned short int port)
{   
    
    std::cout<<ntohs(port);
}