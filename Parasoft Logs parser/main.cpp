#include <iostream>
#include <filesystem>
#include <fstream>
#include <vector>
#include <string>
#include <regex>

namespace fs = std::filesystem;

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

std::vector<LogEntry> parseLogFile(const std::string& filePath) {
    std::vector<LogEntry> entries;
    std::ifstream file(filePath);
    std::string line;

    // Refined regex to match log entries with optional request fields
    std::regex entryRegex(
        R"(<time>(.*?)</time>.*?<ip>(.*?)</ip>.*?<type>(.*?)</type>(?:<request>.*?<hostName>(.*?)</hostName>.*?<clientID>(.*?)</clientID>.*?<archName>(.*?)</archName>.*?<userName>(.*?)</userName>.*?<userID>(.*?)</userID>.*?<machineID>(.*?)</machineID>.*?<toolName>(.*?)</toolName>.*?</request>)?.*?<status>(.*?)</status>.*?<statusmsg>(.*?)</statusmsg>.*?(<authentication>(.*?)</authentication>)?.*?(<validation>(.*?)</validation>)?)");

    size_t lineCount = 0;
    size_t matchedCount = 0;

    while (std::getline(file, line)) {
        lineCount++;
        std::smatch match;
        if (std::regex_search(line, match, entryRegex)) {
            matchedCount++;
            LogEntry entry = {
                match[1].str(),
                match[2].str(),
                match[3].str(),
                match[4].matched ? match[4].str() : "",  // host_name
                match[5].matched ? match[5].str() : "",  // client_id
                match[6].matched ? match[6].str() : "",  // arch_name
                match[7].matched ? match[7].str() : "",  // user_name
                match[8].matched ? match[8].str() : "",  // user_id
                match[9].matched ? match[9].str() : "",  // machine_id
                match[10].matched ? match[10].str() : "", // tool_name
                match[11].str(), // status
                match[12].str(), // status_msg
                match[14].matched ? match[14].str() : "", // authentication
                match[16].matched ? match[16].str() : ""  // validation
            };
            entries.push_back(entry);

            // Debugging output for each parsed entry
            std::cout << "Parsed Entry " << matchedCount << ":\n"
                << "  Timestamp: " << entry.timestamp << "\n"
                << "  IP: " << entry.ip << "\n"
                << "  Event Type: " << entry.event_type << "\n"
                << "  Host Name: " << entry.host_name << "\n"
                << "  Client ID: " << entry.client_id << "\n"
                << "  Architecture: " << entry.arch_name << "\n"
                << "  User Name: " << entry.user_name << "\n"
                << "  User ID: " << entry.user_id << "\n"
                << "  Machine ID: " << entry.machine_id << "\n"
                << "  Tool Name: " << entry.tool_name << "\n"
                << "  Status: " << entry.status << "\n"
                << "  Status Message: " << entry.status_msg << "\n"
                << "  Authentication: " << entry.authentication << "\n"
                << "  Validation: " << entry.validation << "\n";
        }
        else {
            std::cerr << "Warning: Could not parse line " << lineCount << ": " << line << std::endl;
        }
    }

    std::cout << "Total lines processed: " << lineCount << std::endl;
    std::cout << "Total entries matched: " << matchedCount << std::endl;

    if (entries.empty()) {
        std::cerr << "No entries were parsed from the file: " << filePath << std::endl;
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

    std::cout << "CSV file written successfully with " << entries.size() << " entries." << std::endl;
}

std::string extractDateFromFilename(const std::string& filename) {
    std::regex dateRegex(R"(ls_access\.log\.(\d{4}-\d{2}-\d{2}))");
    std::smatch match;
    if (std::regex_search(filename, match, dateRegex)) {
        return match[1].str();
    }
    return "unknown_date";
}

int main() {
    const std::string sourceDir = "C:\\ProgramData\\Parasoft\\DTP\\logs";
    const std::string destinationDir = "C:\\usage_logs_parasoft-analyzed";

    // Check if source directory exists
    if (!fs::exists(sourceDir)) {
        std::cerr << "Source directory does not exist: " << sourceDir << std::endl;
        return 1;
    }

    // Create destination directory if it doesn't exist
    if (!fs::exists(destinationDir)) {
        fs::create_directories(destinationDir);
    }

    bool continueAnalyzing = true;

    while (continueAnalyzing) {
        // Enumerate files
        std::vector<std::string> logFiles;
        for (const auto& entry : fs::directory_iterator(sourceDir)) {
            if (entry.is_regular_file() && entry.path().filename().string().find("ls_access.log") == 0) {
                logFiles.push_back(entry.path().string());
            }
        }

        if (logFiles.empty()) {
            std::cout << "No log files found starting with 'ls_access.log' in directory." << std::endl;
            return 0;
        }

        // List files
        std::cout << "Found log files:" << std::endl;
        for (size_t i = 0; i < logFiles.size(); ++i) {
            std::cout << i + 1 << ". " << logFiles[i] << std::endl;
        }

        // Choose a file
        size_t choice=0;
        std::cout << "Enter the number of the file to process: ";
        std::cin >> choice;

        if (choice < 1 || choice > logFiles.size()) {
            std::cerr << "Invalid choice." << std::endl;
            return 1;
        }

        const std::string selectedFile = logFiles[choice - 1];
        const std::string destinationFile = destinationDir + "\\" + fs::path(selectedFile).filename().string();

        // Copy file
        fs::copy(selectedFile, destinationFile, fs::copy_options::overwrite_existing);

        // Parse log file
        std::vector<LogEntry> entries = parseLogFile(selectedFile);

        // Extract date for unique CSV filename
        std::string date = extractDateFromFilename(fs::path(selectedFile).filename().string());
        std::string csvFilePath = destinationDir + "\\parsed_log_" + date + ".csv";
           

        // Write to CSV
        writeCSV(csvFilePath, entries);

        std::cout << "Log file copied and converted to CSV: " << csvFilePath << std::endl;

        // Ask user if they want to analyze another file
        char userChoice;
        std::cout << "Would you like to analyze another file? (y/n): ";
        std::cin >> userChoice;

        if (userChoice == 'n' || userChoice == 'N') {
            continueAnalyzing = false;
        }
    }

    return 0;
}
