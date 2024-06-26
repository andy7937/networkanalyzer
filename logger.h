#ifndef LOGGER_H
#define LOGGER_H

#include <string>


class Logger {
public:
    // Function to initialize the log file
    void initLog();
    void appendLog(const std::string& info);
    void newLog();
};

#endif // LOGGER_H