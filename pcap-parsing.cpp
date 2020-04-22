//# pragma once

#include "watch.h"
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
#include "fileHandling.h"
#include "uniqueIPCount.h"
#include "pairIPds.h"

#include <iostream>
#include <fstream>
#include <vector>
#include <arpa/inet.h>
#include <pthread.h>
#include <cstdio>
#include <cstring>
#include <unordered_map>
#include <iterator>
#include <string>

using namespace std;

class PcapParser
{
   const string PACKET_CONTENT_FOLDER_PATH = "/home/ubuntu/Downloads/content/";
   const string PACKET_COUNT_FOLDER_PATH   = "/home/ubuntu/Downloads/count/";
   const string IP_PAIR_STATS_FOLDER_PATH  = "/home/ubuntu/Downloads/ip pair stats/";
   
   public:
   
   void pcapParser(string filePath);
   string getFileName(string filePath);
   static void* startWatch(void* filePath);
   string getPacketContentFolderPath(); 
   string getPacketCountFolderPath();
   string getIPPairStatsFolderPath();

};
string FileHandling::removeExtension(string filePath)
{
   const size_t period_idx = filePath.rfind('.');
   if (std::string::npos != period_idx)
   {
    filePath.erase(period_idx);
   }
   
   return filePath;
}

void FileHandling::removeFile(string pcapFileName)
{
  
  PcapParser ob;
  string fileName = removeExtension(pcapFileName);
  string contentFilePath = ob.getPacketContentFolderPath() + fileName +".csv";
  string countFilePath = ob.getPacketCountFolderPath() + fileName +".csv";                                  
  
  const char *fileContentPath = contentFilePath.c_str();
  cout<<"file to be deleted path -"<<contentFilePath<<"\n";

  int contentStatus = remove(fileContentPath); 
  if (contentStatus == 0) cout<<"Content File deleted successfully\n";
  else cout<<"Error deleting content file\n";
  
  const char *fileCountPath = countFilePath.c_str();

  int countStatus = remove(fileCountPath);
  if (countStatus == 0) cout<<"Count File deleted successfully\n";
  else cout<<"Error deleting count file\n";
}

void DsUniqueIPAddr::displayUniqueIP()
{
   
   cout<<"Displaying hashmap values\n";
   cout<<"size of map\n"<<singleIPMap.size()<<"\n";
   unordered_map<string,int>::iterator traverse;
   traverse = singleIPMap.begin();
   
   for (traverse;traverse != singleIPMap.end();traverse++)
   {
      cout<<"IpAddress "<<traverse->first<<"\t\t\t\t\t\t";
      cout<<"Count of IP "<<traverse->second<<"\n";
      
   }
}

void DsUniqueIPAddr::populateSingleIPMap(string sourceIP)
{
   unordered_map<string,int>::iterator traverseMap;
   traverseMap=singleIPMap.find(sourceIP);
   if (traverseMap != singleIPMap.end())
   {
      singleIPMap.at(sourceIP) += 1;
   }
   else
   {
      int count=1;
      singleIPMap.insert(make_pair(sourceIP,count));
   }
   
}

string PcapParser::getPacketCountFolderPath()
{
  return PACKET_COUNT_FOLDER_PATH ;
}

string PcapParser::getPacketContentFolderPath()
{
  return PACKET_CONTENT_FOLDER_PATH ;
}

string PcapParser::getIPPairStatsFolderPath()
{
  return IP_PAIR_STATS_FOLDER_PATH;
}

void* PcapParser::startWatch(void* filePath)
{
   printf("Starting point:-%s\n","Mein aa gya");
    char *path;
    path=( char*) filePath;

    char pathArr[50];
    
    snprintf(pathArr,50, "%s",path);  
   
    printf("Path is %s \n",path);
    std::string watchDirPath = pathArr;
    std::cout<<watchDirPath<<"\n";

  int length, i = 0, wd;
  int fd;
  char buffer[BUF_LEN];
  
  /* Initialize Inotify*/
  fd = inotify_init();
  if ( fd < 0 ) {
    perror( "Couldn't initialize inotify");
  }
 
  /* add watch to starting directory */
  wd = inotify_add_watch(fd, path, IN_CREATE | IN_MODIFY | IN_DELETE | IN_MOVED_FROM | IN_MOVED_TO); 
 
  if (wd == -1)
    {
      printf("Couldn't add watch to %s\n",path);
    }
  else
    {
      printf("Watching:: %s\n",path);
    }
 
  /* do it forever*/
  while(1)
    {
      i = 0;
      length = read( fd, buffer, BUF_LEN );  
 
      if ( length < 0 ) {
        perror( "read" );
      }  
 
      while ( i < length ) {
        struct inotify_event *event = ( struct inotify_event * ) &buffer[ i ];
        std::string eventPath = watchDirPath  ;

        if ( event->len ) {
          if ( event->mask & IN_CREATE) {
            if (event->mask & IN_ISDIR)
              printf( "The directory %s was Created.\n", event->name );       
            else
              printf( "The file %s was Created with WD %d\n", event->name, event->wd );  
              snprintf(pathArr,50,"%s",event->name);
              eventPath +=  pathArr;
              
              std::cout<<"Inside create func.\n";
              std::cout<<eventPath<<"\n";

              //Sending file to parse 
              PcapParser parserOb;
              parserOb.pcapParser(eventPath);  
                         

          }
           
          if ( event->mask & IN_MODIFY) {
            if (event->mask & IN_ISDIR)
              printf( "The directory %s was modified.\n", event->name );       
            else
              printf( "The file %s was modified with WD %d\n", event->name, event->wd );       
          }
           
          if ( event->mask & IN_DELETE) {
            if (event->mask & IN_ISDIR)
              printf( "The directory %s was deleted.\n", event->name );       
            else
              printf( "The file %s was deleted with WD %d\n", event->name, event->wd );
              snprintf(pathArr,50,"%s",event->name);
              eventPath += pathArr;
              std::cout<<eventPath<<"\n";       
          }  
 
          if (event->mask & IN_MOVED_FROM){
            if (event->mask & IN_ISDIR)
                ;//kuch karna hai
            else
                printf("The file %s is moved out of watch\n",event->name);
          }    
           if (event->mask & IN_MOVED_TO){
            if (event->mask & IN_ISDIR)
                ;//kuch karna hai
            else
                printf("The file is added to watch %s\n",event->name);
          }     
                
          i += EVENT_SIZE + event->len;
        }
      }
    }
 
  /* Clean up*/
  inotify_rm_watch( fd, wd );
  close( fd );
}
 
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
   //For BIG-ENDIAN MACHINE                                     //Hex values
   const unsigned short int  ETHER_TYPE_IPV6 = 56710;           //0x dd 86
   const unsigned short int  ETHER_TYPE_IPV4 = 8;               //0x 00 08
   const unsigned int        MAGIC_NUMBER    = 2712847316;      //a1b2c3d4
   const char                PROTOCOL_TCP    = 6;               //HEX VALUE IS 06
   const char                PROTOCOL_UDP    = 17;              //HEX VALUE IS 11
   long long int             readerPointer   = 24;              //Starts after global header is read
   
   //Extracting filename from filepath
   string fileName = getFileName(filePath);
   
   //Defining the path where csv's of count and stats of pcap file will be stored
   string packetStatsFilePath = getPacketContentFolderPath()+ fileName + ".csv";  
   string packetCountFilePath = getPacketCountFolderPath() + fileName + ".csv";
   string ipPairStatsFilePath = getIPPairStatsFolderPath() + fileName + ".csv";

   //Defining the objects of headers
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
   DsUniqueIPAddr  uniqueIPObj;
   PairIP          pairIPObj;

   //Opening the file
   fread_obj.open(filePath,ios::binary);

   //Checking if file exists or not
   if (fread_obj)
   {
      //Reading the global header
      fread_obj.read((char*) &gh_obj.uint32_magic, 4);
      fread_obj.seekg(16,ios::cur); 
      fread_obj.read((char*) &gh_obj.uint32_network,4);

   /*         GLOBAL HEADER ENDS HERE     */
    
    //Check for valid magic number
    if (gh_obj.uint32_magic == MAGIC_NUMBER)
    {
    //Condition for checking ethernet packet
      if (gh_obj.uint32_network == 1)
      {
        //Pointer to packet header structure
        struct packet_header *pktheader;
        pktheader=&ph_obj;
        //Writing Pcap file stats column names       
        csvObj.writeColumnNames(fwrite_obj, packetStatsFilePath);
        //int k=2;
        //Read file until packet header is readable
        while (fread_obj.read((char*)pktheader,16))        
        {
          //Boolean Variables
          bool isIpv6Packet=false;
          bool isIpv4Packet=false;
          bool isTcpPacket=false;
          bool isUdpPacket=false;
          cout<<ph_obj.tsSec;exit(0);
          string srcIpv4Addr="";
          string destnIpv4Addr="";
          string srcIpv6Addr="";
          string destnIpv6Addr="";

          cout<<"Captured length of packet is\n";
          cout<<ph_obj.cap_len<<"\n";
          
          //Reading MAC Addresses
          fread_obj.read((char*) &eh_obj.ether_dhost, 6);
          fread_obj.read((char*) &eh_obj.ether_shost,6);
          
          cout<<"Destination Mac Address\n";
          string destnMac=show_obj.displayMacAddr(eh_obj.ether_dhost);
                   
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
                
                //Reading port numbers 
                fread_obj.read((char*) &tcph_obj.tcpSrcPort ,2);
                fread_obj.read((char*) &tcph_obj.tcpDestnPort ,2);
                fread_obj.seekg(16,ios::cur);
                
                // IPV6 TCP Packet ends here
              }
              else if (ip_obj.ipv6obj.nextHeader == PROTOCOL_UDP)
              {
                //if UDP packet (size = 8 bytes)
                isUdpPacket = true;

                //Reading port numbers
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
              //populating map of unique ip address and its packet count 
              uniqueIPObj.populateSingleIPMap(srcIpv6Addr);
              
              //populating pair ip map with packet transer attributes
              pairIPObj.populatePairMap(srcIpv6Addr,destnIpv6Addr,ph_obj.tsSec);

              //Updating the count of ipv6 packet
              packetCnt_obj.ipv6AddrCount += 1;

              if (isTcpPacket)
              {
                //Updating the count of ipv6 tcp packet
                packetCnt_obj.ipv6TcpCount +=1 ;
                
                //Writing stats of pcap into csv file
                fwrite_obj<<destnMac<<","<<sourceMac<<","<<srcIpv6Addr<<","<<destnIpv6Addr<<","
                <<ntohs(tcph_obj.tcpSrcPort)<<","<<ntohs(tcph_obj.tcpDestnPort)<<"\n";
              }
              else if (isUdpPacket)
              {
                //Updating the count of ipv6 udp packet
                packetCnt_obj.ipv6UdpCount += 1;
                
                //Writing stats of pcap into csv file
                fwrite_obj<<destnMac<<","<<sourceMac<<","<<srcIpv4Addr<<","<<destnIpv4Addr<<","
                <<ntohs(udph_obj.srcPort)<<","<<ntohs(udph_obj.destnPort)<<"\n";
              }
              
          }
          else if(isIpv4Packet)
          {   
              //populating map of unique ip address and its packet count
              uniqueIPObj.populateSingleIPMap(srcIpv4Addr);
              
              //populating pair ip map with packet transer attributes
              pairIPObj.populatePairMap(srcIpv4Addr,destnIpv4Addr,ph_obj.tsSec);

              //Updating the count of ipv4 packet
              packetCnt_obj.ipv4AddrCount += 1;
              
              if (isTcpPacket)
              {
                //Updating the count of ipv4 tcp packet
                packetCnt_obj.ipv4TcpCount +=1 ;
                
                //Writing stats of pcap into csv file
                
                fwrite_obj<<destnMac<<","<<sourceMac<<","<<srcIpv4Addr<<","<<destnIpv4Addr<<","
                <<ntohs(tcph_obj.tcpSrcPort)<<","<<ntohs(tcph_obj.tcpDestnPort)<<"\n";
              }
              else if (isUdpPacket)
              {
                //Updating the count of ipv4 udp packet
                packetCnt_obj.ipv4UdpCount += 1;
                
                //Writing stats of pcap into csv file
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
    
    //Displaying unique ips with their count
    uniqueIPObj.displayUniqueIP();
    
    //Displaying pair ip's with packet transer stats
    pairIPObj.displayPairMap();
    
    //Call to func. to write in packet transfer stats in csv file
   // csvObj.writeIPPairStats(pairIPObj,ipPairStatsFilePath);
}
else{}

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
   ;//Invalid magic number
}
   }
else{
  ;//Error opening file
  }
}


void* watchtest(void* dirPath)
{
   printf("Starting point:-%s\n","Mein aa gya");
    char *path;
    path=( char*) dirPath;

    char pathArr[50];
    PcapParser parserOb;
    FileExtractor extractorOb;
    FileHandling fHandleOb;
    snprintf(pathArr,50, "%s",path);  
   
    printf("Path is %s \n",path);
    std::string watchDirPath = pathArr;
    std::cout<<watchDirPath<<"\n";

  int length, i = 0, wd;
  int fd;
  char buffer[BUF_LEN];
  
  /* Initialize Inotify*/
  fd = inotify_init();
  if ( fd < 0 ) {
    perror( "Couldn't initialize inotify");
  }
 
  /* add watch to starting directory */
  wd = inotify_add_watch(fd, path, IN_CREATE | IN_MODIFY | IN_DELETE | IN_MOVED_FROM | IN_MOVED_TO); 
 
  if (wd == -1)
    {
      printf("Couldn't add watch to %s\n",path);
    }
  else
    {
      printf("Watching:: %s\n",path);
    }
 
  /* do it forever*/
  while(1)
    {
      i = 0;
      length = read( fd, buffer, BUF_LEN );  
 
      if ( length < 0 ) {
        perror( "read" );
      }  
 
      while ( i < length ) {
        struct inotify_event *event = ( struct inotify_event * ) &buffer[ i ];
        std::string eventPath = watchDirPath  ;

        if ( event->len ) {
          
          if ( event->mask & IN_CREATE) {
            if (event->mask & IN_ISDIR)
              printf( "The directory %s was Created.\n", event->name );       
            else
              printf( "The file %s was Created with WD %d\n", event->name, event->wd );  
              snprintf(pathArr,50,"%s",event->name);
              eventPath +=  pathArr;
              
              std::cout<<"Inside create func.\n";
              std::cout<<eventPath<<"\n";
              
              //Sending file to parse 
              
              bool isPcapFile = extractorOb.hasEnding(event->name,".pcap");
              
              if (isPcapFile)
               parserOb.pcapParser(eventPath);  
              else {;}           

          }
           
          if ( event->mask & IN_MODIFY) {
            if (event->mask & IN_ISDIR)
              printf( "The directory %s was modified.\n", event->name );       
            else
              printf( "The file %s was modified with WD %d\n", event->name, event->wd );

          }
           
          if ( event->mask & IN_DELETE) {
            if (event->mask & IN_ISDIR)
              printf( "The directory %s was deleted.\n", event->name );       
            else
              printf( "The file %s was deleted with WD %d\n", event->name, event->wd );
              snprintf(pathArr,50,"%s",event->name);
              eventPath += pathArr;
              std::cout<<eventPath<<"\n";
              
              bool isPcapFile = extractorOb.hasEnding(event->name,".pcap");
              
              if (isPcapFile)
               fHandleOb.removeFile(pathArr);  
              else ;
              


          }  
 
          if (event->mask & IN_MOVED_FROM){
            if (event->mask & IN_ISDIR)
                ;//kuch karna hai
            else
                printf("The file %s is moved out of watch\n",event->name);
                 bool isPcapFile = extractorOb.hasEnding(event->name,".pcap");
              
               if (isPcapFile)
                fHandleOb.removeFile(pathArr);  
               else ;
          }    
           if (event->mask & IN_MOVED_TO){
            if (event->mask & IN_ISDIR)
                ;//kuch karna hai
            else
                printf("The file %s is added to watch\n",event->name);
                bool isPcapFile = extractorOb.hasEnding(event->name,".pcap");
              
               if (isPcapFile){
                eventPath += event->name;
                parserOb.pcapParser(eventPath);  
               }else ;
          }     
                
          i += EVENT_SIZE + event->len;
        }
      }
    }

  /* Clean up*/
  inotify_rm_watch( fd, wd );
  close( fd );
}

int main()
{  
  PcapParser parserObj;
  pthread_t watcher;
    //directory to get pcap files
   const char *watchDir="/home/ubuntu/Downloads/";
   //watch directory

   int id=pthread_create(&watcher,NULL,watchtest,(void *)watchDir);

   if (id == 0) cout<<"Thread creation successful\n";
   else cout<<"Error,couldnt create thread\n";
  
 // parserObj.createThread();

  string pcapDir="/home/ubuntu/shared/C++ Training/"; 
  cout<<"Extracting pcap files from directory\n";
  FileExtractor fileExtractorObj;
  vector<string> pcapFiles;

  vector<string> filePathsContainer = fileExtractorObj.listFiles(pcapDir,true,pcapFiles);
  
  //Parsing pcap files one by one
  for (int index=0;index < filePathsContainer.size();index++)
  { 
    parserObj.pcapParser(filePathsContainer[index]);
   //  cout<<"Pcap file name\n";
   // cout<<filePathsContainer[index]<<endl;
     
  }

   cout<<"press q to terminate program\n";
   char choice;
   cin>>choice;
   if (choice == 'q') exit(0);
}