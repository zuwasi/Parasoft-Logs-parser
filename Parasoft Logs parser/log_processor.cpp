
//this is the seconed file of teh 3 files version
#include "log_processor.h"
#include <iostream>
#include <fstream>
#include <regex>
#include <filesystem>

namespace fs = std::filesystem;

std::vector<LogEntry> parseLogFile(const std::string& filePath) {
    std::vector<LogEntry> entries;
    std::ifstream file(filePath);
    std::string line;

    std::regex entryRegex(
        R"(<time>(.*?)</time>.*?<ip>(.*?)</ip>.*?<type>(.*?)</type>(?:<request>.*?<hostName>(.*?)</hostName>.*?<clientID>(.*?)</clientID>.*?<archName>(.*?)</archName>.*?<userName>(.*?)</userName>.*?<userID>(.*?)</userID>.*?<machineID>(.*?)</machineID>.*?<toolName>(.*?)</toolName>.*?</request>)?.*?<status>(.*?)</status>.*?<statusmsg>(.*?)</statusmsg>.*?(<authentication>(.*?)</authentication>)?.*?(<validation>(.*?)</validation>)?)");

    size_t lineCount = 0;

    while (std::getline(file, line)) {
        lineCount++;
        std::smatch match;
        if (std::regex_search(line, match, entryRegex)) {
            LogEntry entry = {
                match[1].str(),
                match[2].str(),
                match[3].str(),
                match[4].matched ? match[4].str() : "",
                match[5].matched ? match[5].str() : "",
                match[6].matched ? match[6].str() : "",
                match[7].matched ? match[7].str() : "",
                match[8].matched ? match[8].str() : "",
                match[9].matched ? match[9].str() : "",
                match[10].matched ? match[10].str() : "",
                match[11].str(),
                match[12].str(),
                match[14].matched ? match[14].str() : "",
                match[16].matched ? match[16].str() : ""
            };
            entries.push_back(entry);
        }
    }

    return entries;
}

void writeCSV(const std::string& outputPath, const std::vector<LogEntry>& entries) {
    std::ofstream outFile(outputPath);
    outFile << "Timestamp,IP Address,Event Type,Host Name,Client ID,Architecture Name,User Name,User ID,Machine ID,Tool Name,Status,Status Message,Authentication,Validation\n";

    for (const auto& entry : entries) {
        outFile << entry.timestamp << ','
            << entry.ip << ','
            << entry.event_type << ','
            << entry.host_name << ','
            << entry.client_id << ','
            << entry.arch_name << ','
            << entry.user_name << ','
            << entry.user_id << ','
            << entry.machine_id << ','
            << entry.tool_name << ','
            << entry.status << ','
            << entry.status_msg << ','
            << entry.authentication << ','
            << entry.validation << '\n';
    }
}

std::string extractDateFromFilename(const std::string& filename) {
    std::regex dateRegex(R"(ls_access\.log\.(\d{4}-\d{2}-\d{2}))");
    std::smatch match;
    if (std::regex_search(filename, match, dateRegex)) {
        return match[1].str();
    }
    return "unknown_date";
}
