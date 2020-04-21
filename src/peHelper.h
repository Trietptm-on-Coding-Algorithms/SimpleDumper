#include <map>
#include "utils.h"
#include <windows.h>

template <class NT_HEADERS>
class PEhelper 
{
	private:
	void * baseAddress;
	HANDLE stdoutHandle;
	HANDLE processHandle;
	NT_HEADERS ntHeaders;
	bool x64;
	void * getPEstructure ();
	public:
	PEhelper (HANDLE, void *);
	std::map <void *, std::string> getSections ();	
};