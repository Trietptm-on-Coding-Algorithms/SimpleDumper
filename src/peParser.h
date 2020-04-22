#pragma once

#include <windows.h>
#include "utils.h"
#include "peb.h"
#include "memory.h";
#include <set>

typedef struct _PROCESS_BASIC_INFORMATION 
{
    PVOID Reserved1;
    PVOID PebBaseAddress;
    PVOID Reserved2[2];
    ULONG_PTR UniqueProcessId;
    PVOID Reserved3;
} PROCESS_BASIC_INFORMATION;

template <class NT_HEADERS>
class PEparser 
{
	private:
	void * baseAddress;
	void * entryPoint;

	HANDLE stdoutHandle;
	HANDLE processHandle;

	NT_HEADERS ntHeaders;
	IMAGE_SECTION_HEADER * sections;
	std::set <IMAGE_SECTION_HEADER *> trappedSections;
	memoryMap * memMap;

	int wow64 = false;
	int nSections;

	void * getPEstructure ();
	void * PEheaderAddr;
	void * getPEBaddr ();
	void * getEntryPoint ();
	IMAGE_SECTION_HEADER * getSections ();
	void * getImageBase ();
	void readPEheader ();
	void checkWOW64 ();
	bool isAddrInSection (uint64_t, IMAGE_SECTION_HEADER *);
	IMAGE_SECTION_HEADER * getEntryPointSection ();
	
	public:
	PEparser (HANDLE);
	~PEparser ();
	void showSections ();
	void removeXrightOthers ();
	bool isAddressInTrappedSections (uint64_t);

};