#include <dirent.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <fstream>
#include <iostream>
#include <string>
#include <vector>

#include "extractFiles.h"

std::vector<std::string> FileExtractor::listFiles(std::string baseDir, bool recursive,std::vector<std::string> &paths)
{
    //directory stream object
    DIR *dp;
    struct dirent *dirp;
    
    if ((dp = opendir(baseDir.c_str())) == NULL) 
    {
       std:: cout << "[ERROR: " << errno << " ] Couldn't open " << baseDir << "." << '\n';        
    } 
    else 
    {
        while ((dirp = readdir(dp)) != NULL) 
        {   
            //Ignoring the "." and ".." entries
            if (dirp->d_name != std::string(".") && dirp->d_name != std::string("..")) 
            {
                if (isDir(baseDir + dirp->d_name) == true && recursive == true) 
                {
                    std::cout << "[DIR]\t" << baseDir << dirp->d_name << "/" << std::endl;
                    listFiles(baseDir + dirp->d_name + "/", true,paths);
                } 
                else 
                {
                    if (hasEnding(dirp->d_name,".pcap"))
                      {
                        std::cout << "[FILE]\t" << baseDir<< dirp->d_name << '\n';
                        paths.push_back(baseDir+dirp->d_name);
                      }
                }
            }
        }
        closedir(dp);
    }

return paths;
}

bool FileExtractor::isDir(std::string dir)
{
    struct stat fileInfo;
    stat(dir.c_str(), &fileInfo);
    if (S_ISDIR(fileInfo.st_mode)) {
        return true;
    } else {
        return false;
    }
}

bool FileExtractor::hasEnding (std::string const fullString, std::string const ending) {
    if (fullString.length() >= ending.length()) {
        return (0 == fullString.compare (fullString.length() - ending.length(), ending.length(), ending));
    } else {
        return false;
    }
}

bool FileExtractor::isExists(std::string filepath)
{
    std::ifstream ifile(filepath);
    if (ifile)  return true;
    else        return false;
}


