#pragma once

#include <windows.h>
#include <stdio.h>
#include <string>
#include <vector>
#include <regex>

enum logType
{
    WARNING = 5,
    ERR = 12,
    INFO = 15,
};

void printfColor (const char *, DWORD, HANDLE, ... );
void log (const char *, logType, HANDLE,  ...);
void * parseStringToAddress (std::string);
int parseStringToNumber (std::string, int);
