#include<cstdio>
#include<iostream>
#include<string>

#include <arpa/inet.h>

#include "display.h"

 std::string display::displayMacAddr(unsigned char macAddress [])
{
    char  macAddr[18];  //Will be used to write values into csv file

    printf("%x:%x:%x:%x:%x:%x", macAddress[0], macAddress[1], macAddress[2], macAddress[3], macAddress[4], macAddress[5]);
    snprintf(macAddr,18,"%x:%x:%x:%x:%x:%x", macAddress[0], macAddress[1], macAddress[2], macAddress[3], macAddress[4], macAddress[5]);

    return macAddr;

}

 std::string display::printIpv6Address(unsigned char ipAddress[])
{
    std::string totalIpAddr="";

    for (int index=0;index < 15;index+=2)
    {
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
    
    printf("%d.%d.%d.%d", ipv4Address[0],ipv4Address[1], ipv4Address[2], ipv4Address[3]);
    snprintf(ipv4Addr,17,"%d.%d.%d.%d", ipv4Address[0],ipv4Address[1], ipv4Address[2], ipv4Address[3]);
    return ipv4Addr;
}
 void display::printPortNumber(unsigned short int port)
{   
    
    std::cout<<ntohs(port);
}

