#include "peParser.h"

typedef NTSTATUS (*pNtQueryInformationProcess) (HANDLE, DWORD, PVOID, ULONG, PULONG);

pNtQueryInformationProcess NtQueryInformationProcess()
{
    static pNtQueryInformationProcess fNtQueryInformationProcess = NULL;
    if (!fNtQueryInformationProcess)
    {
        HMODULE hNtdll = GetModuleHandle("ntdll.dll"); // loaded in every process not needed to load library
        fNtQueryInformationProcess = (pNtQueryInformationProcess) GetProcAddress(hNtdll, "NtQueryInformationProcess");
    }
    return fNtQueryInformationProcess;
}

template <class NT_HEADERS>
PEparser<NT_HEADERS>::PEparser (HANDLE processHandle)
{
	stdoutHandle = GetStdHandle(STD_OUTPUT_HANDLE);
	this->processHandle = processHandle;
	memMap = new memoryMap (processHandle);
	memMap->updateMemoryMap ();
	memMap->showMemoryMap ();

	checkWOW64 ();
	baseAddress = getImageBase (); // using PEB
	PEheaderAddr = getPEstructure ();
	readPEheader ();
	entryPoint = getEntryPoint ();
	sections = getSections ();
}
template <class NT_HEADERS>
PEparser<NT_HEADERS>::~PEparser()
{
	delete memMap;
	delete sections;
}
template <class NT_HEADERS>
void  PEparser<NT_HEADERS>::readPEheader ()
{
	if (!ReadProcessMemory (processHandle, (LPCVOID) PEheaderAddr, &ntHeaders, sizeof (ntHeaders), NULL))
	{
		log ("Cannot read Image NT headers \n", logType::ERR, stdoutHandle);
		throw std::exception ();
	}
}
template <class NT_HEADERS>
void  PEparser<NT_HEADERS>::checkWOW64 ()
{
	if (!IsWow64Process (processHandle, &wow64))
	{
		log ("Cannot determine is process running under WOW64 subsystem by IsWow64Process() %s \n", logType::ERR, stdoutHandle);
		throw std::exception ();
	}
}
template <class NT_HEADERS>
IMAGE_SECTION_HEADER * PEparser<NT_HEADERS>::getSections ()
{
	WORD numberOfSections = ntHeaders.FileHeader.NumberOfSections;
	uint64_t sectionsStartAddr =  (uint64_t) PEheaderAddr + sizeof (ntHeaders);

	IMAGE_SECTION_HEADER * sections = new IMAGE_SECTION_HEADER [numberOfSections];
	nSections = numberOfSections;
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
void * PEparser<NT_HEADERS>::getPEstructure ()
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
template <class NT_HEADERS>
void * PEparser<NT_HEADERS>::getPEBaddr ()
{
	PROCESS_BASIC_INFORMATION processInfo;
	NtQueryInformationProcess () (processHandle, 0, &processInfo, sizeof (processInfo), nullptr); // 0 - ProcessBasicInformation
	return (void *) processInfo.PebBaseAddress;
}
template <class NT_HEADERS>
bool PEparser <NT_HEADERS>::isAddrInSection (uint64_t addr, IMAGE_SECTION_HEADER * section)
{
	if (addr >= section->VirtualAddress + (uint64_t) baseAddress && addr < section->VirtualAddress + section->Misc.VirtualSize + (uint64_t) baseAddress)
	{
		return true;
	}
	return false;
}
template <class NT_HEADERS>
IMAGE_SECTION_HEADER * PEparser <NT_HEADERS>::getEntryPointSection ()
{
	for (int i = 0; i < nSections; i++)
	{
		if (isAddrInSection((uint64_t) entryPoint, &sections[i]))
		{
			return &sections[i];
		}
	}
	log ("Cannot get section within entrypoint, something very nasty \n", logType::ERR, stdoutHandle);
	throw std::exception ();
}
template <class NT_HEADERS>
void PEparser <NT_HEADERS>::removeXrightOthers ()
{
	IMAGE_SECTION_HEADER * entryPointSection = getEntryPointSection ();
	for (int i = 0; i < nSections; i++)
	{
		if (sections[i].VirtualAddress == entryPointSection->VirtualAddress)
		{
			continue;
		}
		uint64_t currentSectionAddr = sections[i].VirtualAddress + (uint64_t) baseAddress;
		uint64_t currentSectionSize = sections[i].Misc.VirtualSize;
		memoryProtection prot = memMap->protectionForAddr (currentSectionAddr);
		if (prot.execute)
		{
			trappedSections.insert(&sections[i]);
			log ("Found other section than entrypoint one with execution privileges, removing X protection\n", logType::INFO, stdoutHandle);
			prot.execute = 0;
			memMap->setProtection (currentSectionAddr, currentSectionSize, prot);
		}
	}
}
template <class NT_HEADERS>
bool PEparser <NT_HEADERS>::isAddressInTrappedSections (uint64_t addr)
{
	for (const auto & i : trappedSections)
	{
		if (isAddrInSection(addr,i))
		{
			return true;
		}
	}
	return false;
}
template <class NT_HEADERS>
void * PEparser<NT_HEADERS>::getImageBase ()
{
	void * PEB = getPEBaddr ();
	if (wow64)
	{
		PEB32 peb;
		if (!ReadProcessMemory (processHandle, (LPVOID) PEB, &peb, sizeof (PEB32), NULL))
		{
			log ("Cannot read PEB32 of process \n", logType::ERR, stdoutHandle);
			throw std::exception ();
		}
		return (void *) peb.ImageBaseAddress;
	}
	else
	{
		PEB64 peb;
		if (!ReadProcessMemory (processHandle, (LPVOID) PEB, &peb, sizeof (PEB64), NULL))
		{
			log ("Cannot read PEB64 of process \n", logType::ERR, stdoutHandle);
			throw std::exception ();
		}
		return (void *) peb.ImageBaseAddress;
	}
}
template <class NT_HEADERS>
void * PEparser<NT_HEADERS>::getEntryPoint ()
{
	return (void *) (ntHeaders.OptionalHeader.AddressOfEntryPoint + (uint64_t) baseAddress);
}
template <class NT_HEADERS>
void PEparser<NT_HEADERS>::showSections ()
{
	for (int i = 0 ; i < nSections; i++)
	{
		printf ("%s --> %.16llx VIRT[%.16llx] RAW[%.16llx]\n", sections[i].Name, sections[i].VirtualAddress, sections[i].Misc.VirtualSize, sections[i].SizeOfRawData);
	}
}

template class PEparser <IMAGE_NT_HEADERS32>; // ????????????
template class PEparser <IMAGE_NT_HEADERS64>;
