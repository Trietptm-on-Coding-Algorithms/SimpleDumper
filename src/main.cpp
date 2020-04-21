#include <stdio.h>
#include "utils.h"

int main (int argc, char ** argv)
{
	HANDLE stdoutHandle = GetStdHandle(STD_OUTPUT_HANDLE);
	if (argc < 2)
    {
        log("Usage: simpledumper <exe> [OEP, e.g 0x401000]\n", logType::ERR, stdoutHandle);
        return 1;
    }
    return 0;
}