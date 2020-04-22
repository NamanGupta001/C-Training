#include <fstream>
#include <iostream>
#include <string>
#include <vector>
#include <dirent.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>

using namespace std;

struct FileExtractor
{
    bool hasEnding (std::string const &fullString, std::string const &ending);
    bool isDir(string dir);
    vector<string> listFiles(string baseDir, bool recursive,vector<string> &paths);
};
bool FileExtractor::hasEnding (std::string const &fullString, std::string const &ending) {
    if (fullString.length() >= ending.length()) {
        return (0 == fullString.compare (fullString.length() - ending.length(), ending.length(), ending));
    } else {
        return false;
    }
}
bool FileExtractor::isDir(string dir)
{
    struct stat fileInfo;
    stat(dir.c_str(), &fileInfo);
    if (S_ISDIR(fileInfo.st_mode)) {
        return true;
    } else {
        return false;
    }
}
vector<string> FileExtractor::listFiles(string baseDir, bool recursive,vector<string> &paths)
{
    DIR *dp;
    struct dirent *dirp;
    
    if ((dp = opendir(baseDir.c_str())) == NULL) {
        cout << "[ERROR: " << errno << " ] Couldn't open " << baseDir << "." << endl;
        //reutn ;
    } else {
        while ((dirp = readdir(dp)) != NULL) {
            if (dirp->d_name != string(".") && dirp->d_name != string("..")) {
                if (isDir(baseDir + dirp->d_name) == true && recursive == true) {
                    cout << "[DIR]\t" << baseDir << dirp->d_name << "/" << endl;
                    listFiles(baseDir + dirp->d_name + "/", true,paths);
                } else {
                    if (hasEnding(dirp->d_name,".pcap"))
                      {
                      cout << "[FILE]\t" << baseDir<< dirp->d_name << endl;
                      paths.push_back(baseDir+dirp->d_name);
                      }
                }
            }
        }
        closedir(dp);
    }

return paths;
}

