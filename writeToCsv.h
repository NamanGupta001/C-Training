#include<fstream>
#include<iostream>
#include<string>

using namespace std;

struct writeToCsv
{   
    ofstream countWriterObj;
    void writeColumnNames(std::ofstream &csvObj,std::string pcapStatsCsv);
    void writePacketCounts(unsigned int packetCount[],unsigned short int arrSize,std::string filePath);
   // void writeIPPairStats(PairIP obj,string targetPath);
};

void writeToCsv::writeColumnNames(std::ofstream &csvObj,std::string pcapStatsCsv)
{   
    csvObj.open(pcapStatsCsv);

    if (csvObj)
        csvObj<<"DestinationMacAddr,SourceMacAddr,SourceIPAddr,DestinationIPAddr,SourcePort,DestinationPort\n";
    else
    {
        cout<<"Error opening content csv file\n";
    }
    
}

void writeToCsv::writePacketCounts(unsigned int packetCount[],unsigned short int arrSize,std::string filePath)
{
    
    countWriterObj.open(filePath);
    if (countWriterObj)
    {   
        countWriterObj<<"Total ipv4 addresses,Total ipv4 tcp packets count,Total ipv4 udp packet count \
                        ,Total ipv6 addresses,Total ipv6 tcp packets count,Total ipv6 udp packet count\n";
        
        for (int index=0;index < arrSize;index++)
        {
            if (index != arrSize-1) countWriterObj<<packetCount[index]<<",";
            else                    countWriterObj<<packetCount[index]<<"\n";            
                
        }
    }    
    else
    {
        cout<<"Error opening count csv file\n";
    }
    countWriterObj.close();
}

// void writeToCsv::writeIPPairStats(PairIP obj,string targetPath)
// {
//    // countWriterObj.open();
// }