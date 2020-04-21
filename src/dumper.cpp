#include "dumper.h"

dumper::dumper (std::string fileName, void * OEP)
{
	stdoutHandle = GetStdHandle(STD_OUTPUT_HANDLE);

    ZeroMemory( &si, sizeof(si) );
    si.cb = sizeof(si);
    ZeroMemory( &pi, sizeof(pi) );

	if (!CreateProcess (fileName.c_str(), NULL, NULL, NULL, FALSE, CREATE_SUSPENDED | CREATE_SUSPENDED, NULL, NULL, &si, &pi))
	{
		log ("Cannot create new process %s \n", logType::ERR, stdoutHandle ,fileName.c_str());
		throw std::exception ();
	}

	memoryMap * memMap = new memoryMap ();
	memMap->updateMemoryMap (pi.hProcess);
	memMap->showMemoryMap ();

	PEhelper <IMAGE_NT_HEADERS64> packedPE (pi.hProcess, (void *) 0x400000);
	//PEhelper <IMAGE_NT_HEADERS64> * packedPE = new PEhelper <IMAGE_NT_HEADERS64> (pi.hProcess, (void *)0x400000);
	//delete packedPE;
	delete memMap;
	/*
	asm (".byte 0xeb");
	asm (".byte 0xfe");
	*/
}
void dumper::saveAsFile (std::string fileName)
{

}