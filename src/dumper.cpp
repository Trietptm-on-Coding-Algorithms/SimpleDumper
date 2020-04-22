#include "dumper.h"

typedef NTSTATUS (*pNtQueryInformationProcess) (HANDLE, DWORD, PVOID, ULONG, PULONG);

typedef struct _PROCESS_BASIC_INFORMATION 
{
    PVOID Reserved1;
    PVOID PebBaseAddress;
    PVOID Reserved2[2];
    ULONG_PTR UniqueProcessId;
    PVOID Reserved3;
} PROCESS_BASIC_INFORMATION;

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

void * dumper::getPEBaddr ()
{
	PROCESS_BASIC_INFORMATION processInfo;
	NtQueryInformationProcess () (pi.hProcess, 0, &processInfo, sizeof (processInfo), nullptr); // 0 - ProcessBasicInformation
	return (void *) processInfo.PebBaseAddress;
}
void * dumper::getImageBase ()
{
	void * PEB = getPEBaddr ();
	if (wow64)
	{
		PEB32 peb;
		if (!ReadProcessMemory (pi.hProcess, (LPVOID) PEB, &peb, sizeof (PEB32), NULL))
		{
			log ("Cannot read PEB32 of process \n", logType::ERR, stdoutHandle);
			throw std::exception ();
		}
		return (void *) peb.ImageBaseAddress;
	}
	else
	{
		PEB64 peb;
		if (!ReadProcessMemory (pi.hProcess, (LPVOID) PEB, &peb, sizeof (PEB64), NULL))
		{
			log ("Cannot read PEB64 of process \n", logType::ERR, stdoutHandle);
			throw std::exception ();
		}
		return (void *) peb.ImageBaseAddress;
	}
}
dumper::dumper (std::string fileName, void * OEP)
{
	stdoutHandle = GetStdHandle(STD_OUTPUT_HANDLE);

    ZeroMemory( &si, sizeof(si) );
    si.cb = sizeof(si);
    ZeroMemory( &pi, sizeof(pi) );

	if (!CreateProcess (fileName.c_str(), nullptr, nullptr, nullptr, FALSE, CREATE_SUSPENDED | CREATE_SUSPENDED, nullptr, nullptr, &si, &pi))
	{
		log ("Cannot create new process %s \n", logType::ERR, stdoutHandle ,fileName.c_str());
		throw std::exception ();
	}
	void * imageBase = getImageBase ();
	printf ("%.16llx \n",imageBase);
	/*
	memoryMap * memMap = new memoryMap ();
	memMap->updateMemoryMap (pi.hProcess);
	memMap->showMemoryMap ();
	*/
	if (!IsWow64Process (pi.hProcess, &wow64))
	{
		log ("Cannot determine is process running under WOW64 subsystem by IsWow64Process() %s \n", logType::ERR, stdoutHandle);
		throw std::exception ();
	}

	PEhelper <IMAGE_NT_HEADERS64> packedPE (pi.hProcess, (void *) imageBase);

	int nSections;
	IMAGE_SECTION_HEADER * sections = packedPE.getSections (&nSections);
	for (int i = 0 ; i < nSections; i++)
	{
		printf ("%s --> %.16llx [%.16llx] \n", sections[i].Name, sections[i].VirtualAddress, sections[i].Misc.VirtualSize);
	}
	//delete packedPE;
	//delete memMap;
	/*
	asm (".byte 0xeb");
	asm (".byte 0xfe");
	*/
}
void dumper::saveAsFile (std::string fileName)
{

}