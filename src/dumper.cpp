#include "dumper.h"

dumper::dumper (std::string fileName, void * OEP)
{
	stdoutHandle = GetStdHandle(STD_OUTPUT_HANDLE);

    ZeroMemory( &si, sizeof(si) );
    si.cb = sizeof(si);
    ZeroMemory( &pi, sizeof(pi) );

	if (!CreateProcess (fileName.c_str(), nullptr, nullptr, nullptr, FALSE, DEBUG_ONLY_THIS_PROCESS | CREATE_SUSPENDED, nullptr, nullptr, &si, &pi))
	{
		log ("Cannot create new process %s \n", logType::ERR, stdoutHandle ,fileName.c_str());
		throw std::exception ();
	}

	packedPE = new PEparser <IMAGE_NT_HEADERS64>  (pi.hProcess);
	packedPE->showSections ();
	packedPE->removeXrightOthers ();

	ResumeThread (pi.hThread);
	dbgLoop ();
}
void dumper::suggestOEP (uint64_t addr)
{
	log ("SimpleDumper suggest OEP to be at %.16llx \n",logType::ERR, stdoutHandle, addr);
}
void dumper::dbgLoop ()
{
	bool debugging = true;
	while (debugging)
	{
		DEBUG_EVENT debugEvent;
		if (!WaitForDebugEvent (&debugEvent,INFINITE))
	    {
	        log ("WaitForDebugEvent returned nonzero value\n",logType::ERR, stdoutHandle);
	        throw std::exception ();
	    }
	    if (debugEvent.dwDebugEventCode == EXCEPTION_DEBUG_EVENT)
	    {
	    	EXCEPTION_DEBUG_INFO exception = debugEvent.u.Exception;
	    	uint64_t exceptionAddr = (uint64_t) exception.ExceptionRecord.ExceptionAddress;
	    	switch (exception.ExceptionRecord.ExceptionCode)
	    	{
	    	    case EXCEPTION_ACCESS_VIOLATION:
	    	    {
	    	    	if (packedPE->isAddressInTrappedSections (exceptionAddr) && exception.dwFirstChance)
	    	    	{
						suggestOEP (exceptionAddr);
	    	    	}
	    	    	break;
	    	    }
	    	    /*
	    	    case EXCEPTION_BREAKPOINT:
	    	    {
	    	    	log ("Breakpoint ??? \n",logType::ERR, stdoutHandle);
	    	    	break;
	    	    }
	    	    case EXCEPTION_SINGLE_STEP:
	    	    {
	    	    	log ("Single step ???\n",logType::ERR, stdoutHandle);
	    	    	break;
	    	    }
	    	    */
	    	}
	    }
	    else if (debugEvent.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT)
        {
            EXIT_PROCESS_DEBUG_INFO infoProc = debugEvent.u.ExitProcess;
            log ("Process %u exited with code 0x%.08x\n", logType::ERR, stdoutHandle, debugEvent.dwProcessId, infoProc.dwExitCode);
            debugging = false;
        }
	    ContinueDebugEvent (debugEvent.dwProcessId,debugEvent.dwThreadId, DBG_EXCEPTION_NOT_HANDLED);
	}
}
void dumper::saveAsFile (std::string fileName)
{

}