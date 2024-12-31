//this is the header of the 3 files version 
#ifndef LOG_PROCESSOR_H
#define LOG_PROCESSOR_H

#include <string>
#include <vector>

struct LogEntry {
    std::string timestamp;
    std::string ip;
    std::string event_type;
    std::string host_name;
    std::string client_id;
    std::string arch_name;
    std::string user_name;
    std::string user_id;
    std::string machine_id;
    std::string tool_name;
    std::string status;
    std::string status_msg;
    std::string authentication;
    std::string validation;
};

std::vector<LogEntry> parseLogFile(const std::string& filePath);
void writeCSV(const std::string& outputPath, const std::vector<LogEntry>& entries);
std::string extractDateFromFilename(const std::string& filename);

#endif
