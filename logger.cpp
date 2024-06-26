#include "Logger.h"
#include <iostream>
#include <fstream>
#include <ctime>

// Function to initialize the log file
void Logger::initLog() {
    std::ofstream logFile("log.txt", std::ios::out | std::ios::app);

    // Check if the log file is not open
    if (!logFile.is_open()) {
        // Try to create the log file
        logFile.open("log.txt", std::ios::out | std::ios::app);

        // If it still cannot be opened, print an error and handle it
        if (!logFile.is_open()) {
            std::cerr << "Error: Unable to create or open log file." << std::endl;
        }
    }
}

void Logger::appendLog(const std::string& info) {
    std::ofstream logFile("log.txt", std::ios::out | std::ios::app);

    if (logFile.is_open()) {
        // Get the current timestamp
        std::time_t currentTime = std::time(nullptr);
        struct tm timeInfo;
        localtime_s(&timeInfo, &currentTime);

        char timestamp[100];
        std::strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", &timeInfo);

        logFile << timestamp << "\n";
        logFile << info << "\n";
        logFile.close();
    }
    else {
        std::cerr << "Error appending to file" << std::endl;
    }
}

void Logger::newLog() {
    std::ofstream logFile("log.txt", std::ios::out | std::ios::app);

    if (logFile.is_open()) {
        logFile << "\n";
        logFile.close();
    }
    else {
        std::cerr << "Error appending to file" << std::endl;
    }
}