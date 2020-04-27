#include "Global.h"
#include "Packet.h"
#include "Ethernet.h"
#include "ipUnion.h"
#include "Tcp.h"
#include "Udp.h"
#include "Display.h"
#include "packetCount.h"
#include "writeToCsv.h"
#include "extractFiles.h"
#include<iostream>
#include<fstream>
#include<vector>

using namespace std;

class PcapParser
{
   public:
   void pcapParser(string filePath);
   string getFileName(string filePath);
   
};
string PcapParser::getFileName(string filePath)
{
   const size_t last_slash_idx = filePath.find_last_of("\\/");
   if (std::string::npos != last_slash_idx)
   {
    filePath.erase(0, last_slash_idx + 1);
   }

   // Remove extension if present.
   const size_t period_idx = filePath.rfind('.');
   if (std::string::npos != period_idx)
   {
    filePath.erase(period_idx);
   }

   return filePath;
}
void PcapParser::pcapParser(string filePath)
{
  
   //For BIG-ENDIAN MACHINE
   const int  ETHER_TYPE_IPV6 = 56710; //0x dd 86
   const int  ETHER_TYPE_IPV4 = 8; //0x 00 08
   const char PROTOCOL_TCP    = 6; //HEX VALUE IS 06
   const char PROTOCOL_UDP    = 17;//HEX VALUE IS 11
   long long int readerPointer= 24;

   string fileName = getFileName(filePath);
   string packetStatsFilePath ="F:/Packet Content csv/" + fileName + ".csv";  
   string packetCountFilePath ="F:/Packet Count csv/" + fileName + ".csv";

   global_header   gh_obj;
   ethernet_header eh_obj;
   packet_header   ph_obj;
   ifstream        fread_obj;
   ofstream        fwrite_obj;
   IpAddress       ip_obj;
   tcp_header      tcph_obj;
   udp_header      udph_obj;
   PacketCount     packetCnt_obj;
   display         show_obj; 
   writeToCsv      csvObj;

   //Telegram_VoiceCall_Sender_5Iterations_0.pcap
   fread_obj.open(filePath,ios::binary);

   //Checking if file exists or not
   if (fread_obj)
   {

      fread_obj.read((char*) &gh_obj.uint32_magic, 4);
      fread_obj.seekg(16,ios::cur); 
      fread_obj.read((char*) &gh_obj.uint32_network,4);

   /*         GLOBAL HEADER ENDS HERE     */
    
    //Condition for checking ethernet packet
    if (gh_obj.uint32_network == 1)
    {
       //Valid pcap file
       //Writing Pcap file column names
       
       csvObj.writeColumnNames(fwrite_obj, packetStatsFilePath);
       
     // int k=5500;
       while (fread_obj)
       {
         //Boolean Variables
         bool isIpv6Packet=false;
         bool isIpv4Packet=false;
         bool isTcpPacket=false;
         bool isUdpPacket=false;
         
         string srcIpv4Addr="";
         string destnIpv4Addr="";
         string srcIpv6Addr="";
         string destnIpv6Addr="";
         
         //Read only packet capture length
         fread_obj.seekg(8,ios::cur);
         fread_obj.read((char*) &ph_obj.cap_len, 4);
         fread_obj.seekg(4,ios::cur);
         
         //Pcap packet header ends
         
         cout<<"Captured length of packet is\n";
         cout<<ph_obj.cap_len<<"\n";
         
         fread_obj.read((char*) &eh_obj.ether_dhost, 6);
         fread_obj.read((char*) &eh_obj.ether_shost,6);
         
         cout<<"Destination Mac Address\n";
         string destnMac=show_obj.displayMacAddr(eh_obj.ether_dhost);
         cout<<"\n";
        
        
         cout<<"Source mac Address\n";
         string sourceMac=show_obj.displayMacAddr(eh_obj.ether_shost);
         
         cout<<"Ethernet type\n";
         fread_obj.read((char*) &eh_obj.ether_type,2);
         
         cout<<eh_obj.ether_type;
         cout<<endl;

         //Condition for IPV6 packet
         if (eh_obj.ether_type == ETHER_TYPE_IPV6 )
         {  
            isIpv6Packet = true;

            fread_obj.seekg(6,ios::cur);
            
            //Reading next header(protocol) field
            fread_obj.read((char*) &ip_obj.ipv6obj.nextHeader ,1);
            
            //Skipping Hop Limit field
            fread_obj.seekg(1,ios::cur);

            //Reading IP Address of Source and Destination
            fread_obj.read((char*) &ip_obj. ipv6obj.ipv6_source,16);
            fread_obj.read((char*) &ip_obj. ipv6obj.ipv6_destn,16);
            
            cout<<"Source IP Address\n";
            srcIpv6Addr=show_obj.printIpv6Address(ip_obj. ipv6obj.ipv6_source);
            
            cout<<"Destination IP Address\n";
            destnIpv6Addr=show_obj.printIpv6Address(ip_obj. ipv6obj.ipv6_destn);

                // IPV6 HEADER ENDS

            //Checking for TCP and UDP packets
            if (ip_obj.ipv6obj.nextHeader == PROTOCOL_TCP)
            {
               //if TCP packet (size = 20 bytes)
               isTcpPacket = true;
               fread_obj.read((char*) &tcph_obj.tcpSrcPort ,2);
               fread_obj.read((char*) &tcph_obj.tcpDestnPort ,2);
               fread_obj.seekg(16,ios::cur);
               
               // IPV6 TCP Packet ends here
            }
            else if (ip_obj.ipv6obj.nextHeader == PROTOCOL_UDP)
            {
               //if UDP packet (size = 8 bytes)
               isUdpPacket = true;

               fread_obj.read((char*) &udph_obj.srcPort ,2);
               fread_obj.read((char*) &udph_obj.destnPort ,2);
               fread_obj.seekg(4,ios::cur);
               
               // IPV6 UDP Packet ends here
            }
            
            //Packet other than TCP or UDP
            else
            {             
               ; //do nothing
            }
            
           
         }
         
         //Condition for IPV4 packet
         else if (eh_obj.ether_type == ETHER_TYPE_IPV4)
         {
           isIpv4Packet=true;
           
           //Skipping first 9 bytes of IPV4 header to reach protocol field
           fread_obj.seekg(9,ios::cur);
           fread_obj.read((char*) &ip_obj.ipv4obj.protocol, 1);
           
           //skip two bytes of header checksum
           fread_obj.seekg(2,ios::cur);

           //Reading source IP Address
           fread_obj.read((char*) &ip_obj.ipv4obj.source, 4);
           
           cout<<"IPV4 Source Address\n";
           srcIpv4Addr=show_obj.printIpv4Address(ip_obj.ipv4obj.source);
           cout<<"\n";
           
           //Reading destination IP Address
           fread_obj.read((char*) &ip_obj.ipv4obj.destn, 4);
           
           cout<<"IPV4 Destn Address\n";
           destnIpv4Addr=show_obj.printIpv4Address(ip_obj.ipv4obj.destn);
           cout<<"\n";
           //If protocol is TCP,header size is (20 bytes)
           if (ip_obj.ipv4obj.protocol == PROTOCOL_TCP)
           {
            isTcpPacket=true;
            
            //Reading Source Port
            fread_obj.read((char*) &tcph_obj.tcpSrcPort, 2);

            //Reading Destination Port
            fread_obj.read((char*) &tcph_obj.tcpDestnPort, 2);

            //Printing source and destn port
            cout<<"TCP Protocol Source Port\n";
            show_obj.printPortNumber(tcph_obj.tcpSrcPort);
            cout<<"\n";
            
            cout<<"TCP Protocol Destn Port\n";
            show_obj.printPortNumber(tcph_obj.tcpDestnPort);
            cout<<"\n";

            //Skipping rest of the fields
            fread_obj.seekg(16,ios::cur);
            
            //END OF IPV4 TCP PACKET

           }
           else if (ip_obj.ipv4obj.protocol == PROTOCOL_UDP)
           {
            isUdpPacket=true;
            //Reading Source Port
            fread_obj.read((char*) &udph_obj.srcPort, 2);

            //Reading Destination Port
            fread_obj.read((char*) &udph_obj.destnPort, 2);

            cout<<"UDP Protocol Source Port\n";
            show_obj.printPortNumber(udph_obj.srcPort);
            cout<<"\n";
            cout<<"UDP Protocol Destn Port\n";
            show_obj.printPortNumber(udph_obj.destnPort);
            cout<<"\n";
            //Skipping rest of the fields
            fread_obj.seekg(4,ios::cur);
            
            //END OF IPV4 UDP PACKET

           }

           //If IPV4 packet is neither TCP nor UDP
           else { 
            
           ; /*do nothing */}

        
         }
         
         //Condition if packet is not of ethernet type
         else{ ;/* do nothing */}
         
        
         //Writing packet contents to csv file
         if (isIpv6Packet)
         {
            packetCnt_obj.ipv6AddrCount += 1;

            if (isTcpPacket)
            {
              packetCnt_obj.ipv6TcpCount +=1 ;
              fwrite_obj<<destnMac<<","<<sourceMac<<","<<srcIpv6Addr<<","<<destnIpv6Addr<<","
              <<ntohs(tcph_obj.tcpSrcPort)<<","<<ntohs(tcph_obj.tcpDestnPort)<<"\n";
            }
            else if (isUdpPacket)
            {
              packetCnt_obj.ipv6UdpCount += 1;
              fwrite_obj<<destnMac<<","<<sourceMac<<","<<srcIpv4Addr<<","<<destnIpv4Addr<<","
              <<ntohs(udph_obj.srcPort)<<","<<ntohs(udph_obj.destnPort)<<"\n";
            }
            
         }
         else if(isIpv4Packet)
         {
            packetCnt_obj.ipv4AddrCount += 1;
            
            if (isTcpPacket)
            {
              packetCnt_obj.ipv4TcpCount +=1 ;
              fwrite_obj<<destnMac<<","<<sourceMac<<","<<srcIpv4Addr<<","<<destnIpv4Addr<<","
              <<ntohs(tcph_obj.tcpSrcPort)<<","<<ntohs(tcph_obj.tcpDestnPort)<<"\n";
            }
            else if (isUdpPacket)
            {
              packetCnt_obj.ipv4UdpCount += 1;
              fwrite_obj<<destnMac<<","<<sourceMac<<","<<srcIpv4Addr<<","<<destnIpv4Addr<<","
              <<ntohs(udph_obj.srcPort)<<","<<ntohs(udph_obj.destnPort)<<"\n";
            }
            else{}
         }
        
         //UPdating reader pointer so it may reach to the next packet header
         
         readerPointer += ph_obj.cap_len + 16;
        
         fread_obj.seekg(readerPointer,ios::beg);
        // k--;
         cout<<"packet ended\n";
   
   }
}
 else{//do nothing
         }

cout<<"Total ipv4 addresses\n";
cout<<packetCnt_obj.ipv4AddrCount<<"\n";
cout<<"Total tcp packets count\n";
cout<<packetCnt_obj.ipv4TcpCount<<"\n";
cout<<"Total udp packet count\n";
cout<<packetCnt_obj.ipv4UdpCount<<"\n";

cout<<"Total ipv6 addresses\n";
cout<<packetCnt_obj.ipv6AddrCount<<"\n";
cout<<"Total tcp packets count\n";
cout<<packetCnt_obj.ipv6TcpCount<<"\n";
cout<<"Total udp packet count\n";
cout<<packetCnt_obj.ipv6UdpCount<<"\n";

unsigned int packetCount[6]={packetCnt_obj.ipv4AddrCount,packetCnt_obj.ipv4TcpCount,
                             packetCnt_obj.ipv4UdpCount,packetCnt_obj.ipv6AddrCount,
                             packetCnt_obj.ipv6TcpCount,packetCnt_obj.ipv6UdpCount
                            };
unsigned short int arrSize=6;                            
csvObj.writePacketCounts(packetCount,arrSize,packetCountFilePath);

fwrite_obj.close();
fread_obj.close();
}
else
{
   ;//Pcap file not exists
}
}

int main()
{  
  PcapParser parserObj;
  string dir="/home/ubuntu/shared/C++ Training/"; 
  cout<<"Extracting pcap files from directory\n";
  FileExtractor fileExtractorObj;
  vector<string> pcapFiles;
  vector<string> filePathsContainer = fileExtractorObj.listFiles(dir,true,pcapFiles);
  
  ofstream ob;
  
  //Parsing pcap files one by one
  for (int index=0;index < filePathsContainer.size();index++)
  { 
    parserObj.pcapParser(filePathsContainer[index]);
   //  cout<<"Pcap file name\n";
   //  cout<<filePathsContainer[index]<<endl;
     
  }
   //parserObj.pcapParser(dir);

}