#include<iostream>
#include<string>

#include "writeToCsv.h"

void writeToCsv::writeColumnNames(std::string pcapStatsCsv)
{   
    writeToCsvObj.open(pcapStatsCsv);

    if (writeToCsvObj)
        writeToCsvObj<<"DestinationMacAddr,SourceMacAddr,SourceIPAddr,DestinationIPAddr,SourcePort,DestinationPort\n";
    else
        std::cout<<"Error opening content csv file\n";
        
}

void writeToCsv::writePacketStats(std::string pcapStatsArr[],unsigned short int arrSize)
{   
    //Writes data in csv file
    for (int index=0;index < arrSize;index++)
    {
        if (index != arrSize-1)
            writeToCsvObj<<pcapStatsArr[index]<<",";
        else
            writeToCsvObj<<pcapStatsArr[index]<<"\n";
            
    }  
        
}

void writeToCsv::writePacketCounts(unsigned int packetCount[],unsigned short int arrSize,std::string filePath)
{
    
    std::ofstream countWriterObj;
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
        std::cout<<"Error opening count csv file\n";
    }
    countWriterObj.close();
}

void writeToCsv::writeIPPairStats(PairIP pairIPObj,std::string targetPath)
{
   std::ofstream writeIpPairCsvObj;
   writeIpPairCsvObj.open(targetPath);

   //If csv file is created successfully 
   if (writeIpPairCsvObj)
   {   
       //Writing column names 
       writeIpPairCsvObj<<"Source IP Address"<<","<<"Destination IP Address"<<","<<"Packets(a->b)"<<","
                        <<"Packets(b->a)"<<","<<"Session time(micro sec.)"<<"\n";
       
       //Writing pair ip packet transfer stats
       for (auto const &entry: pairIPObj.getPairIpMap())
	    {
            auto key_pair = entry.first;
            writeIpPairCsvObj<< key_pair.first << "," << key_pair.second << ","
                            << entry.second.src_to_destn <<","<< entry.second.destn_to_src<<","
                            <<entry.second.end_ts - entry.second.begin_ts<<'\n';
	    }                 
        writeIpPairCsvObj.close();
   }
   else
   {
       std::cout<<"error creating pair ip stats file\n";
   }
   
}
