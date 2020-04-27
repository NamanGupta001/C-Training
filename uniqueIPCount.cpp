#include <iostream>
#include <iterator>
#include <iomanip>

#include "uniqueIPCount.h"

void DsUniqueIPAddr::populateSingleIPMap(std::string sourceIP)
{
   std::unordered_map<std::string,int>::iterator traverseMap;
   traverseMap=singleIPMap.find(sourceIP);
   
   //Increment count if ip address found
   if (traverseMap != singleIPMap.end())
   {
      singleIPMap.at(sourceIP) += 1;
   }
   else
   {  
      //Insert the ipaddress in map
      int count=1;
      singleIPMap.insert(make_pair(sourceIP,count));
   }
   
}

void DsUniqueIPAddr::displayUniqueIP()
{
   
   std::cout<<"Displaying hashmap values\n";
   std::cout<<"size of map\n"<<singleIPMap.size()<<"\n";
   std::unordered_map<std::string,int>::iterator traverse;
   traverse = singleIPMap.begin();
   
   std::cout<<std::setw(36)<<"IP Address"<<std::setw(15)<<"Count";
   for (traverse;traverse != singleIPMap.end();traverse++)
   {
     std::cout<<std::setw(36)<<traverse->first<<std::setw(15)<<traverse->second<<"\n";
      
      
   }
}
