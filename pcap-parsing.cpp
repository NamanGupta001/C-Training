/************************************************************************************************************************************************
*************Main driver file in which pcap file parsing for 64bit machine along with watch service is implemented******************************* 
*************************************************************************************************************************************************/
#include <sys/stat.h>                                                                                                                        

#include <iostream>
#include <fstream>
#include <vector>
#include <cstdio>
#include <cstring>
#include <string>
#include <chrono>

#include "watch.h"
#include "Global.h"
#include "Packet.h"
#include "Ethernet.h"
#include "ipUnion.h"
#include "Tcp.h"
#include "Udp.h"
#include "display.h"
#include "packetCount.h"
#include "writeToCsv.h"
#include "extractFiles.h"
#include "uniqueIPCount.h"
#include "pairIPds.h"

#include <arpa/inet.h>
#include <pthread.h>

using namespace std;

class PcapParser
{
   
  public:
  
  //Function parses pcap file by taking filepath as parameter 
  void pcapParser(string filePath);
  
  //Returns filename from given filepath
  string getFileName(string filePath);
  
  //getter functions
  string getPacketContentFolderPath(); 
  string getPacketCountFolderPath();
  string getIPPairStatsFolderPath();

  //Function to create folders for storing csv files
  void createFolders();
  
  //Foler creation status
  void folderStatus(int status);

  //removes the csv's of pcap files who no longer exists
  void removeFile(string fileName);
  
  //Removes extension of a file by taking filepath as parameter
  string removeExtension(string path);

  //Func. indicate when watch service will stop
  bool getSignal();
  
  //Setting the signal variable value(setter) func.
  void setSignal(bool keepRunning);

  private:
  
  string PACKET_CONTENT_FOLDER_PATH = "/home/ubuntu/Downloads/content/";
  string PACKET_COUNT_FOLDER_PATH   = "/home/ubuntu/Downloads/count/";
  string IP_PAIR_STATS_FOLDER_PATH  = "/home/ubuntu/Downloads/ip pair stats/";
  
  //variable for starting/stopping watch service
  bool signal=true;
};


void PcapParser::pcapParser(string filePath)
{  
   //For BIG-ENDIAN MACHINE                                     //Hex values
   const unsigned short int  ETHER_TYPE_IPV6 = 56710;           //0x dd 86
   const unsigned short int  ETHER_TYPE_IPV4 = 8;               //0x 00 08
   const unsigned int        MAGIC_NUMBER    = 2712847316;      //a1b2c3d4
   const char                PROTOCOL_TCP    = 6;               //HEX VALUE IS 06
   const char                PROTOCOL_UDP    = 17;              //HEX VALUE IS 11
   long long int             readerPointer   = 24;              //Starts after global header is read
   
   //Defining the objects of headers
   ifstream        fread_obj;
   global_header   gh_obj;
   
   //Opening the file
   fread_obj.open(filePath,ios::binary);

   //Checking if file exists or not
   if (fread_obj)
    {
      //Reading the global header
      fread_obj.read((char*) &gh_obj.magic_number, 4);
      fread_obj.seekg(16,ios::cur); 
      fread_obj.read((char*) &gh_obj.uint32_network,4);

   /*         GLOBAL HEADER ENDS HERE     */
    
    //Check for valid magic number
    if (gh_obj.magic_number == MAGIC_NUMBER)
    {
    //Condition for checking ethernet packet
      if (gh_obj.uint32_network == 1)
      {
        //Extracting filename from filepath
        string fileName = getFileName(filePath);   
   
        //Defining the path where csv's of count and stats of pcap file will be stored
        string packetStatsFilePath = getPacketContentFolderPath()+ fileName + ".csv";  
        string packetCountFilePath = getPacketCountFolderPath() +  fileName + ".csv";
        string ipPairStatsFilePath = getIPPairStatsFolderPath() +  fileName + ".csv";
        
        //Defining objects of header file included
        ethernet_header eh_obj;
        packet_header   ph_obj;
        ofstream        fwrite_obj;
        IpAddress       ip_obj;
        tcp_header      tcph_obj;
        udp_header      udph_obj;
        PacketCount     packetCnt_obj;
        display         show_obj; 
        writeToCsv      csv_obj;
        DsUniqueIPAddr  uniqueIP_obj;
        PairIP          pairIP_obj;

        //Creaing folders in which csv files will be stored
        createFolders();
        
        //Pointer to packet header structure
        struct packet_header *pktheader;
        pktheader=&ph_obj;

        //Writing Pcap file stats column names       
        csv_obj.writeColumnNames(packetStatsFilePath);
        
        //Read file until packet header is readable
        while (fread_obj.read((char*)pktheader,16))        
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

          cout<<"Captured length of packet is\n";
          cout<<ph_obj.cap_len<<"\n";
          
          //Reading MAC Addresses
          fread_obj.read((char*) &eh_obj.ether_dhost, 6);
          fread_obj.read((char*) &eh_obj.ether_shost,6);
          
          cout<<"Destination Mac Address\n";
          string destnMac=show_obj.displayMacAddr(eh_obj.ether_dhost);
           cout<<'\n';        
          cout<<"Source mac Address\n";
          string sourceMac=show_obj.displayMacAddr(eh_obj.ether_shost);
          cout<<'\n';
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
              fread_obj.read((char*) &ip_obj.ipv6obj.next_header ,1);
              
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
              if (ip_obj.ipv6obj.next_header == PROTOCOL_TCP)
              {
                //if TCP packet (size = 20 bytes)
                isTcpPacket = true;
                
                //Reading port numbers 
                fread_obj.read((char*) &tcph_obj.tcpSrcPort ,2);
                fread_obj.read((char*) &tcph_obj.tcpDestnPort ,2);
                fread_obj.seekg(16,ios::cur);
                
                // IPV6 TCP Packet ends here
              }
              else if (ip_obj.ipv6obj.next_header == PROTOCOL_UDP)
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
              uniqueIP_obj.populateSingleIPMap(srcIpv6Addr);
              
              //populating pair ip map with packet transer attributes
              pairIP_obj.populatePairMap(srcIpv6Addr,destnIpv6Addr,ph_obj.tsuSec);

              //Updating the count of ipv6 packet
              packetCnt_obj.ipv6AddrCount += 1;

              if (isTcpPacket)
              {
                //Updating the count of ipv6 tcp packet
                packetCnt_obj.ipv6TcpCount +=1 ;
                
                //Writing stats of pcap into csv file
                string pcapStats[6]= {destnMac,sourceMac,srcIpv6Addr,destnIpv6Addr,to_string(ntohs(tcph_obj.tcpSrcPort))
                                    ,to_string(ntohs(tcph_obj.tcpDestnPort))};
                csv_obj.writePacketStats(pcapStats,6);          
                
              }
              else if (isUdpPacket)
              {
                //Updating the count of ipv6 udp packet
                packetCnt_obj.ipv6UdpCount += 1;
                
                //Writing stats of pcap into csv file
                string pcapStats[6]= {destnMac,sourceMac,srcIpv6Addr,destnIpv6Addr,to_string(ntohs(udph_obj.srcPort))
                                    ,to_string(ntohs(udph_obj.destnPort))};
                csv_obj.writePacketStats(pcapStats,6);
                
              }
              
          }
          else if(isIpv4Packet)
          {   
              //populating map of unique ip address and its packet count
              uniqueIP_obj.populateSingleIPMap(srcIpv4Addr);
              
              //populating pair ip map with packet transer attributes
              pairIP_obj.populatePairMap(srcIpv4Addr,destnIpv4Addr,ph_obj.tsSec);

              //Updating the count of ipv4 packet
              packetCnt_obj.ipv4AddrCount += 1;
              
              if (isTcpPacket)
              {
                //Updating the count of ipv4 tcp packet
                packetCnt_obj.ipv4TcpCount +=1 ;
                
                //Writing stats of pcap into csv file
                
                string pcapStats[6]= {destnMac,sourceMac,srcIpv4Addr,destnIpv4Addr,to_string(ntohs(tcph_obj.tcpSrcPort))
                                    ,to_string(ntohs(tcph_obj.tcpDestnPort))};
                csv_obj.writePacketStats(pcapStats,6); 
                
              }
              else if (isUdpPacket)
              {
                //Updating the count of ipv4 udp packet
                packetCnt_obj.ipv4UdpCount += 1;
                
                //Writing stats of pcap into csv file
                string pcapStats[6]= {destnMac,sourceMac,srcIpv4Addr,destnIpv4Addr,to_string(ntohs(udph_obj.srcPort))
                                    ,to_string(ntohs(udph_obj.destnPort))};
                csv_obj.writePacketStats(pcapStats,6);
                
              }
              else{}
          }
          
          //UPdating reader pointer so it may reach to the next packet header
          
          readerPointer += ph_obj.cap_len + 16;
          
          fread_obj.seekg(readerPointer,ios::beg);
          
          cout<<"packet ended\n";         
        }
    
  //Displaying unique ips with their count
  uniqueIP_obj.displayUniqueIP();
    
  //Displaying pair ip's with packet transer stats
  // pairIP_obj.displayPairMap();
    
  //This func. writes pair ip stats in csv file
  csv_obj.writeIPPairStats(pairIP_obj,ipPairStatsFilePath);

  //Populating packet count stats in array 
  unsigned int packetCount[6]={packetCnt_obj.ipv4AddrCount,packetCnt_obj.ipv4TcpCount,
                              packetCnt_obj.ipv4UdpCount,packetCnt_obj.ipv6AddrCount,
                              packetCnt_obj.ipv6TcpCount,packetCnt_obj.ipv6UdpCount
                              };
  unsigned short int arrSize=6; 

  //This func. writes packet count stats into csv file
  csv_obj.writePacketCounts(packetCount,arrSize,packetCountFilePath);

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

  fwrite_obj.close();
  fread_obj.close();
}
else{}
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

inline string PcapParser::getFileName(string filePath)
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

inline string PcapParser::getPacketContentFolderPath()
{
  return PACKET_CONTENT_FOLDER_PATH ;
}

inline string PcapParser::getPacketCountFolderPath()
{
  return PACKET_COUNT_FOLDER_PATH ;
}

inline string PcapParser::getIPPairStatsFolderPath()
{
  return IP_PAIR_STATS_FOLDER_PATH;
}

void PcapParser::createFolders()
{
  
  int contentStatus = mkdir(getPacketContentFolderPath().c_str(),S_IRWXU | S_IRWXG | S_IRWXO);
  int countStatus   = mkdir(getPacketCountFolderPath().c_str()  ,S_IRWXU | S_IRWXG | S_IRWXO);
  int pairIPStatus  = mkdir(getIPPairStatsFolderPath().c_str()  ,S_IRWXU | S_IRWXG | S_IRWXO);

  //Checking mkdir function status for all folders
  folderStatus(contentStatus);
  folderStatus(countStatus);
  folderStatus(pairIPStatus);
    
 
}

void PcapParser::folderStatus(int status)
{
      if (status == 0)            cout<<"folder successfully created\n";
      else if (errno == EEXIST)   cout<<"folder exists\n";
      else                        cout<<"folder couln't be created ,with error no. -"<<errno;
}

void PcapParser::removeFile(string pcapFileName)
{
 
  string fileName  = removeExtension(pcapFileName);
 
  //Converting string into const char* as to be compatible with remove func. parameter
  string contentFilePath = getPacketContentFolderPath() + fileName + ".csv";
  string countFilePath   = getPacketCountFolderPath()   + fileName + ".csv";                                  
  string ipPairFilePath  = getIPPairStatsFolderPath()   + fileName + ".csv";

  cout<<"file to be deleted path -"<<contentFilePath<<"\n";
  
  int contentStatus = remove(contentFilePath.c_str()); 
  if (contentStatus == 0) cout<<"Content File deleted successfully\n";
  else                    cout<<"Error deleting content file\n";

  int countStatus = remove(countFilePath.c_str());
  if (countStatus == 0) cout<<"Count File deleted successfully\n";
  else                  cout<<"Error deleting count file\n";

  int ipPairStatus = remove(ipPairFilePath.c_str());
  if (countStatus == 0) cout<<"IP pair File deleted successfully\n";
  else                  cout<<"Error deleting ip pair file\n";
}

string PcapParser::removeExtension(string filePath)
{
   cout<<"inside remove extension\n"<<filePath<<'\n';
  const size_t lastPeriodIndex = filePath.rfind('.');
   if (std::string::npos != lastPeriodIndex)
   {
    filePath.erase(lastPeriodIndex);
   }
  return filePath;
  
}

void* watchtest(void* dirPath)
{
  char *path = 0;
  path=( char*) dirPath;
  printf("Path is %s \n",path);

  int length, loopindex = 0, wd;
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

  PcapParser parserOb;
  FileExtractor extractorOb;


  
  /* do it forever*/
  while(parserOb.getSignal())
    { 
      std::string eventPath ="";
      std::string eventName ="";
      loopindex = 0;
      length = read( fd, buffer, BUF_LEN );  
 
      if ( length < 0 ) 
      {
        perror( "read" );
      }  
      
      eventPath = path ;
      
      while ( loopindex < length ) 
      {
        struct inotify_event *event = ( struct inotify_event * ) &buffer[ loopindex ];

        if ( event->len ) 
        {         
          if ( event->mask & IN_CREATE) 
          {
            if (event->mask & IN_ISDIR)
              printf( "The directory %s was Created.\n", event->name );       
            else
              printf( "The file %s was Created with WD %d\n", event->name, event->wd );  
              
              //Path of file created
              eventPath +=  event->name;
              
              std::cout<<eventPath<<"\n";
              eventName = event->name;
              //Sending file to parse 
              
              bool isPcapFile = extractorOb.hasEnding(eventName,".pcap");
              
              if (isPcapFile)
               parserOb.pcapParser(eventPath);  
              else {;}           

          }
           
          if ( event->mask & IN_MODIFY) 
          {
            if (event->mask & IN_ISDIR)
              printf( "The directory %s was modified.\n", event->name );       
            else
              printf( "The file %s was modified with WD %d\n", event->name, event->wd );

          }
           
          if ( event->mask & IN_DELETE) 
          {
            if (event->mask & IN_ISDIR)
              printf( "The directory %s was deleted.\n", event->name );       
            else
              printf( "The file %s was deleted with WD %d\n", event->name, event->wd );
              
              eventPath += event->name;
              std::cout<<eventPath<<"\n";
              eventName = event->name;

              bool isPcapFile = extractorOb.hasEnding(eventName,".pcap");
              bool isFileExists = extractorOb.isExists(eventPath);
              
              //Remove only when file is pcap and its csv file exists
              if (isPcapFile && isFileExists)
                parserOb.removeFile(eventName);  
              else ;
           
          }  
 
          if (event->mask & IN_MOVED_FROM)
          {
            if (event->mask & IN_ISDIR)
                ;
            else
                printf("The file %s is moved out of watch\n",event->name);
                eventName = event->name;
                bool isPcapFile   = extractorOb.hasEnding(eventName,".pcap");
                bool isFileExists = extractorOb.isExists(eventPath);
                cout<<"in watcher func.(in moved from)"<<eventName<<'\n';
                if (isPcapFile && isFileExists)
                  parserOb.removeFile(eventName);  
                else ;
          }    
           if (event->mask & IN_MOVED_TO)
           {
            if (event->mask & IN_ISDIR)
                ;
            else
                printf("The file %s is added to watch\n",event->name);
                eventName = event->name;
                bool isPcapFile = extractorOb.hasEnding(eventName,".pcap");

               //Parse only when it's a pcap file
               if (isPcapFile)
               {
                eventPath += event->name;
                parserOb.pcapParser(eventPath);  
               }
               else ;
          }     
                
          loopindex += EVENT_SIZE + event->len;
        }
      }
    
    }
  
  /* Clean up*/
  inotify_rm_watch( fd, wd );
  close( fd );
  pthread_exit(NULL);
}

bool PcapParser::getSignal()
{
  return signal;
}

void PcapParser::setSignal(bool keepRunning)
{
  signal = keepRunning;
}

int main()
{  
  
  //directory to get pcap files
  string pcapDir ="";

  //where folders containing csv files will be created
  string invalidInput="/home/ubuntu/Downloads/";
  FileExtractor fileExtractorObj;
  
  //program will continue only after valid dir is entered
  while(true)
  {
    cout<<"Enter directory(with trailing slash) to get its pcap files parsed\n";
    getline(cin,pcapDir);
    
    //Checks for a valid directory
    bool isValidDir = fileExtractorObj.isDir(pcapDir);
    if (isValidDir)   
    {
      if (! pcapDir.compare(invalidInput))
        cout<<"You can't use this dir..please enter another one\n";
      else  
        break;
    }
    
    else  cout<<"Invalid dir.Try again\n";
  }
  auto start = chrono::high_resolution_clock::now();
  
  //Declaring thread instance
  pthread_t watcher;
  
  //watch servide dir path
  const char *watchDir = pcapDir.c_str();
  
  //Thread creation for starting watch service
  int id=pthread_create(&watcher,NULL,watchtest,(void *)watchDir);
  
  if (id == 0) cout<<"Thread creation successful\n";
  else         cout<<"Error,couldn't create thread\n";

  //string pcapDir="/home/ubuntu/shared/C++ Training/"; 
  cout<<"Extracting pcap files from directory\n";
  
  //Vector will be populated with pcap file paths
  vector<string> pcapFiles{""};
  
  /*function call returns a vector containing filepath of pcap files present at that location,
    second parameter indicates whether to search in sub-directories or not */

  vector<string> filePathsContainer{""}; 
  filePathsContainer= fileExtractorObj.listFiles(pcapDir,true,pcapFiles);
  PcapParser parserObj;
  
  //Parsing pcap files one by one
  for (int index=0;index < filePathsContainer.size();index++)
  { 
    parserObj.pcapParser(filePathsContainer[index]);
     
  }
  
  auto end = chrono::high_resolution_clock::now();
  double time = chrono::duration_cast<chrono::seconds>(end - start).count() ;
  cout<<"time taken "<<time<<"sec."<<'\n';
  
  cout<<"press any key to terminate program\n";
  char choice;
  if (cin>>choice)
  {
    //Stopping the watch service
    parserObj.setSignal(false) ;
    
    return 0;
    
  }
  
    
}