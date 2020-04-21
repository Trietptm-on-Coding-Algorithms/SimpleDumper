#include "peHelper.h"

// _IMAGE_SECTION_HEADER
template <class NT_HEADERS>
PEhelper<NT_HEADERS>::PEhelper (HANDLE processHandle, void * baseAddress)
{
	stdoutHandle = GetStdHandle(STD_OUTPUT_HANDLE);
	this->baseAddress = baseAddress;
	this->processHandle = processHandle;
	this->x64 = x64;
	void * PEheader = getPEstructure ();
	if (!ReadProcessMemory (processHandle, (LPCVOID) PEheader, &ntHeaders, sizeof (ntHeaders), NULL))
	{
		log ("Cannot get Image NT headers \n", logType::ERR, stdoutHandle);
		throw std::exception ();
	}
}
std::map <void *, std::string> getSections ()
{
	std::map <void *, std::string> toRet;
	WORD numberOfSections;
}
template <class NT_HEADERS>
void * PEhelper<NT_HEADERS>::getPEstructure ()
{
	IMAGE_DOS_HEADER * dosHeader = new IMAGE_DOS_HEADER;
	if (!ReadProcessMemory (processHandle, (LPCVOID) baseAddress, (uint8_t *) dosHeader, sizeof (IMAGE_DOS_HEADER), NULL))
	{
		log ("Cannot get DOS header of this executable\n", logType::ERR, stdoutHandle);
		throw std::exception ();
	}
	void * PEaddr = (void *)((uint64_t )baseAddress + (uint64_t) dosHeader->e_lfanew);
	delete dosHeader;
	return PEaddr;
}

template class PEhelper <IMAGE_NT_HEADERS32>; // ????????????
template class PEhelper <IMAGE_NT_HEADERS64>;
