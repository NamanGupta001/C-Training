/**********************************************************************************************************************************************
******************This header file will be responsible for filling and displaying unique ip addresses with their respective counts*************
***********************************************************************************************************************************************/

#include <unordered_map>
#ifndef UNIQUE_IP_COUNT_H
#define UNIQUE_IP_COUNT_H

class DsUniqueIPAddr
{
    
    public:
    //Below map stores ipaddress as keys and their 
    //resp. counts as values   
    std::unordered_map<std::string,int> singleIPMap;
    
    //Fills the values in unordered map
    void populateSingleIPMap(std::string sourceIP) ;
    
    //Displays the key value pairs of map
    void displayUniqueIP();
};

#endif // !UNIQUE_IP_COUNT_H