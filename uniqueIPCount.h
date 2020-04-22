#include <iostream>
#include <unordered_map>
#include <iterator>

class DsUniqueIPAddr
{
    
    public:   
    std::unordered_map<std::string,int> singleIPMap;
    void populateSingleIPMap(std::string sourceIP) ;
    void displayUniqueIP();
};