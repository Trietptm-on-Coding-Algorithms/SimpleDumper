#pragma once
#include <string>
#include <windows.h>
#include "utils.h"
#include "peParser.h"

class dumper 
{
	private:
		HANDLE stdoutHandle;
		STARTUPINFO si;
    	PROCESS_INFORMATION pi;
    	void dbgLoop ();
    	void suggestOEP (uint64_t);
    	PEparser <IMAGE_NT_HEADERS64> * packedPE;
	public:
		dumper (std::string, void *);
		void saveAsFile (std::string);
};