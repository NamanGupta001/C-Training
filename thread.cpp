#include<cstdio>
#include <string>
#include <iostream>

using namespace std;

string removeExtension(string filePath)
{
   const size_t period_idx = filePath.rfind('.');
   if (std::string::npos != period_idx)
   {
    filePath.erase(period_idx);
   }
    return filePath;
}
int main()
{
    string test="one.pcap";
    cout<<removeExtension(test);
    //cout<<test;
}