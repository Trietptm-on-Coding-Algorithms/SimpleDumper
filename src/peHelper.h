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
	void * PEheaderAddr;
	public:
	PEhelper (HANDLE, void *);
	IMAGE_SECTION_HEADER * getSections ();
};