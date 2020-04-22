#pragma once

#include <windows.h>
#include <inttypes.h>
#include <vector>
#include "utils.h"

struct memoryProtection
{
	bool read = 0;
	bool write = 0;
	bool execute = 0;
	bool copy = 0;
	bool guard = 0;
	std::string toString ();
};

struct memoryRegion
{
	std::string name = "";
	uint64_t start;
	uint64_t size;
	memoryProtection protection; // when type is reserved protection is undefined
	std::string state;
	std::string type;
	// access rights
};

struct baseRegion // e.g. all memory regions that belongs to specific module
{
	std::string name = "";
	uint64_t base;
	std::vector <memoryRegion> memRegions;
};

class memoryMap
{
	private:
		HANDLE processHandle;
		HANDLE stdoutHandle;
		std::vector <baseRegion> baseRegions;
		void setProtectStateType (MEMORY_BASIC_INFORMATION mbi, memoryRegion *);
		DWORD memoryProtectionToDWORD (memoryProtection);
	public:
		memoryMap (HANDLE);
		void updateMemoryMap ();
		void showMemoryMap ();
		memoryProtection protectionForAddr (uint64_t addr);
		void setProtection (uint64_t, uint64_t, memoryProtection);

};