/***********************************************************************************************************************************************
****************This header file will write pcap file stats,packet count info and packet transfer stats. into csv files*************************
***********************************************************************************************************************************************/
#ifndef WRITE_CSV_H
#define WRITE_CSV_H

#include<fstream>
#include "pairIPds.h"

class writeToCsv
{   
    public:
    std::ofstream writeToCsvObj;

    //Writes pcap stats attribute names in csv file
    void writeColumnNames(std::string pcapStatsCsv);
    
    //Writes values of pcap file stats
    void writePacketStats(std::string pcapStatsArr[],unsigned short int arrSize);
    
    //Writes counts of tcp,udp,ipv4,ipv6 packets resp.
    void writePacketCounts(unsigned int packetCount[],unsigned short int arrSize,std::string filePath);
    
    //Writes pair ip stats in csv file
    void writeIPPairStats(PairIP pairIPObj,std::string targetPath);
};

#endif // !WRITE_CSV_H
