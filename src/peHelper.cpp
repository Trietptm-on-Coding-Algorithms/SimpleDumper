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
	PEheaderAddr = PEheader;
	if (!ReadProcessMemory (processHandle, (LPCVOID) PEheader, &ntHeaders, sizeof (ntHeaders), NULL))
	{
		log ("Cannot read Image NT headers \n", logType::ERR, stdoutHandle);
		throw std::exception ();
	}
}
template <class NT_HEADERS>
IMAGE_SECTION_HEADER * PEhelper<NT_HEADERS>::getSections ()
{
	WORD numberOfSections = ntHeaders.FileHeader.NumberOfSections;
	uint64_t sectionsStartAddr =  (uint64_t) PEheaderAddr + sizeof (ntHeaders);

	IMAGE_SECTION_HEADER * sections = new IMAGE_SECTION_HEADER [numberOfSections];
	for (int i = 0 ; i < numberOfSections; i++)
	{
		if (!ReadProcessMemory (processHandle, (LPCVOID) sectionsStartAddr + (sizeof(IMAGE_SECTION_HEADER) * i), &sections[i], sizeof (IMAGE_SECTION_HEADER), NULL))
		{
			log ("Cannot read section from PE file\n", logType::ERR, stdoutHandle);
			throw std::exception ();
		}
	}
	return sections;
}
template <class NT_HEADERS>
void * PEhelper<NT_HEADERS>::getPEstructure ()
{
	IMAGE_DOS_HEADER * dosHeader = new IMAGE_DOS_HEADER;
	if (!ReadProcessMemory (processHandle, (LPCVOID) baseAddress, (uint8_t *) dosHeader, sizeof (IMAGE_DOS_HEADER), NULL))
	{
		log ("Cannot read DOS header of this executable\n", logType::ERR, stdoutHandle);
		throw std::exception ();
	}
	void * PEaddr = (void *)((uint64_t )baseAddress + (uint64_t) dosHeader->e_lfanew);
	delete dosHeader;
	return PEaddr;
}

template class PEhelper <IMAGE_NT_HEADERS32>; // ????????????
template class PEhelper <IMAGE_NT_HEADERS64>;
