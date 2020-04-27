/***********************************************************************************************************************************************
*******This header file is responsoble for extracting all pcap files from a directory and return a vector containing paths of al files**********
***********************************************************************************************************************************************/

#ifndef FILE_EXTRACTOR_H
#define FILE_EXTRACTOR_H

class FileExtractor
{
    public:
    //Returns a vector containing filepaths of pcap files
    std::vector<std::string> listFiles(std::string baseDir, bool recursive,std::vector<std::string> &paths);
    
    //Returns true if passed string parameter ends with ending string parameter
    bool hasEnding (std::string const fullString, std::string const ending);
    
    //Return true if passed parameter value refers to a directory 
    bool isDir(std::string dir);

    //Returns true if file exists
    bool isExists(std::string filepath);
    
    
};
#endif 
