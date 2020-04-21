#include <stdio.h>
#include "utils.h"
#include "dumper.h"

int main (int argc, char ** argv)
{
	HANDLE stdoutHandle = GetStdHandle(STD_OUTPUT_HANDLE);

	if (argc < 3)
    {
        log("Usage: simpledumper <exe> <output exe> [OEP, e.g 0x401000]\n", logType::ERR, stdoutHandle);
        return 1;
    }

    std::string exeName (argv[1]);
    std::string outputExeName (argv[2]);
    void * OEPAddress = nullptr;
    if (argc == 4)
    {
    	OEPAddress = parseStringToAddress (std::string(argv[3]));
    } 
    try 
    {
    	dumper d (exeName, OEPAddress);
    	d.saveAsFile (outputExeName);
	}
	catch (std::exception e)
	{
		return 1;
	}
    return 0;
}