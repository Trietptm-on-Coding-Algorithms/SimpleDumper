#pragma once
#include <string>
#include "utils.h"
#include <windows.h>
#include "memory.h"
#include "peHelper.h"

class dumper 
{
	private:
		HANDLE stdoutHandle;
		STARTUPINFO si;
    	PROCESS_INFORMATION pi;
	public:
		dumper (std::string, void *);
		void saveAsFile (std::string);
		void * getPeb (HANDLE);
};