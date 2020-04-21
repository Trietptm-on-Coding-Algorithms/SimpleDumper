#include "utils.h"

void printfColor (const char * format, DWORD color, HANDLE stdoutHandle, ...)
{
    CONSOLE_SCREEN_BUFFER_INFO consoleInfo;
    WORD savedAttributes;
    GetConsoleScreenBufferInfo(stdoutHandle, &consoleInfo);
    savedAttributes = consoleInfo.wAttributes;
    SetConsoleTextAttribute(stdoutHandle, color);
    va_list args;
    va_start(args, stdoutHandle);
    vprintf (format,args); // vprintf when we do not know how many arguments we gonna pass
    va_end (args);
    SetConsoleTextAttribute(stdoutHandle, savedAttributes);
}
void log (const char * messageFormatted, logType type, HANDLE stdoutHandle, ...)
{   
    CONSOLE_SCREEN_BUFFER_INFO consoleInfo;
    WORD savedAttributes;
    GetConsoleScreenBufferInfo(stdoutHandle, &consoleInfo);
    savedAttributes = consoleInfo.wAttributes;

    SetConsoleTextAttribute(stdoutHandle, type);
    switch (type)
    {
        case logType::WARNING:
        {
            printf ("[!] ");
            break;
        }
        case logType::INFO:
        {
            printf ("[*] ");
            break;
        }
        case logType::ERR:
        {
            printf ("[!] ");
            break;
        }
    }    
    SetConsoleTextAttribute(stdoutHandle, savedAttributes);
    va_list args;
    va_start(args, stdoutHandle);
    vprintf (messageFormatted,args); // vprintf when we do not know how many arguments we gonna pass
    va_end (args);
}
void* parseStringToAddress (std::string toConvert)
{
    void * address;
    sscanf (toConvert.c_str(),"%x", &address);
    return address;
}
int parseStringToNumber (std::string toConvert, int base = 10)
{
    int number;
    if (base == 10)
    {
        sscanf (toConvert.c_str(), "%i", &number);
    }
    else if (base == 16)
    {
        sscanf (toConvert.c_str(), "%x", &number);
    }
    return number;
}