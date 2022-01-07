#include <stdio.h>
#include <stdlib.h>
#include <Windows.h>
#include <intrin.h>

typedef void* PRTL_USER_PROCESS_PARAMETERS;
typedef void* PPS_POST_PROCESS_INIT_ROUTINE;

typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _PEB_LDR_DATA //, 7 elements, 0x28 bytes
{
	DWORD dwLength;
	DWORD dwInitialized;
	LPVOID lpSsHandle;
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
	LPVOID lpEntryInProgress;
} PEB_LDR_DATA, * PPEB_LDR_DATA;

typedef struct _PEB {
	BYTE Reserved1[2];
	BYTE BeingDebugged;
	BYTE Reserved2[1];
	PVOID Reserved3[2];
	PPEB_LDR_DATA Ldr;
	PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
	PVOID Reserved4[3];
	PVOID AtlThunkSListPtr;
	PVOID Reserved5;
	ULONG Reserved6;
	PVOID Reserved7;
	ULONG Reserved8;
	ULONG AtlThunkSListPtr32;
	PVOID Reserved9[45];
	BYTE Reserved10[96];
	PPS_POST_PROCESS_INIT_ROUTINE PostProcessInitRoutine;
	BYTE Reserved11[128];
	PVOID Reserved12[1];
	ULONG SessionId;
} PEB, * PPEB;

typedef struct /*_LDR_DATA_TABLE_ENTRY*/
{
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags;
	SHORT LoadCount;
	SHORT TlsIndex;
	LIST_ENTRY HashTableEntry;
	ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

typedef struct _OBJECT_ATTRIBUTES
{
	ULONG Length;
	HANDLE RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG Attributes;
	PVOID SecurityDescriptor;        // Points to type SECURITY_DESCRIPTOR
	PVOID SecurityQualityOfService;  // Points to type SECURITY_QUALITY_OF_SERVICE

} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;

typedef struct _IO_STATUS_BLOCK
{
	union
	{
		NTSTATUS Status;
		PVOID Pointer;
	};
	ULONG_PTR Information;
} IO_STATUS_BLOCK, * PIO_STATUS_BLOCK;

typedef NTSYSAPI NTSTATUS(NTAPI* FUNC_NTOPENFILE)(
	OUT PHANDLE FileHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	IN ULONG ShareAccess,
	IN ULONG OpenOptions
	);

typedef NTSTATUS(NTAPI* FUNC_NTCREATESECTION)
(_Out_ PHANDLE SectionHandle, _In_ ACCESS_MASK DesiredAccess,
	_In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
	_In_opt_ PLARGE_INTEGER MaximumSize, _In_ ULONG SectionPageProtection,
	_In_ ULONG AllocationAttributes, _In_opt_ HANDLE FileHandle);

typedef NTSTATUS(NTAPI* FUNC_NTMAPVIEWOFSECTION)
(_In_ HANDLE SectionHandle, _In_ HANDLE ProcessHandle,
	_Inout_ PVOID* BaseAddress, _In_ ULONG_PTR ZeroBits, _In_ SIZE_T CommitSize,
	_Inout_opt_ PLARGE_INTEGER SectionOffset, _Inout_ PSIZE_T ViewSize,
	_In_ DWORD InheritDisposition, _In_ ULONG AllocationType,
	_In_ ULONG Win32Protect);

typedef VOID(NTAPI* FUNC_RTLINITUNICODESTRING)(
	IN OUT PUNICODE_STRING 	DestinationString,
	IN PCWSTR 	SourceString
	);

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)
#endif

#ifndef InitializeObjectAttributes
#define InitializeObjectAttributes( p, n, a, r, s ) {   \
    (p)->Length = sizeof( OBJECT_ATTRIBUTES );          \
    (p)->RootDirectory = r;                             \
    (p)->Attributes = a;                                \
    (p)->ObjectName = n;                                \
    (p)->SecurityDescriptor = s;                        \
    (p)->SecurityQualityOfService = NULL;               \
    }
#endif

#define OBJ_CASE_INSENSITIVE	0x40
#define STATUS_IMAGE_NOT_AT_BASE	0x40000003

#define MAX_EXPORT_NAME_LENGTH	64
#define MAX_SYSCALL_STUB_SIZE	64
#define MAX_NUMBER_OF_SYSCALLS	1024

/*
0:001> u ntdll!LdrpThunkSignature
ntdll!LdrpThunkSignature:
00007ff9`2e1860d0 4c8bd1          mov     r10,rcx
00007ff9`2e1860d3 b833000000      mov     eax,33h
00007ff9`2e1860d8 f604250803fe7f01 test    byte ptr [SharedUserData+0x308 (00000000`7ffe0308)],1
00007ff9`2e1860e0 4c8bd1          mov     r10,rcx
00007ff9`2e1860e3 b84a000000      mov     eax,4Ah
00007ff9`2e1860e8 f604250803fe7f01 test    byte ptr [SharedUserData+0x308 (00000000`7ffe0308)],1
00007ff9`2e1860f0 4c8bd1          mov     r10,rcx
00007ff9`2e1860f3 b83d000000      mov     eax,3Dh
0:001> db ntdll!LdrpThunkSignature
00007ff9`2e1860d0  4c 8b d1 b8 33 00 00 00-f6 04 25 08 03 fe 7f 01  L...3.....%.....
00007ff9`2e1860e0  4c 8b d1 b8 4a 00 00 00-f6 04 25 08 03 fe 7f 01  L...J.....%.....
00007ff9`2e1860f0  4c 8b d1 b8 3d 00 00 00-f6 04 25 08 03 fe 7f 01  L...=.....%.....
00007ff9`2e186100  4c 8b d1 b8 37 00 00 00-f6 04 25 08 03 fe 7f 01  L...7.....%.....
00007ff9`2e186110  4c 8b d1 b8 28 00 00 00-f6 04 25 08 03 fe 7f 01  L...(.....%.....
*/



FUNC_NTOPENFILE NtOpenFile = NULL;
FUNC_NTCREATESECTION NtCreateSection = NULL;
FUNC_NTMAPVIEWOFSECTION NtMapViewOfSection = NULL;

FUNC_RTLINITUNICODESTRING RtlInitUnicodeString = (FUNC_RTLINITUNICODESTRING)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "RtlInitUnicodeString");

ULONG_PTR BuildSyscallStub(ULONG_PTR StubRegion, DWORD dwSyscallNo)
{
	BYTE SyscallStub[] =
	{
		0x4c, 0x8b, 0xd1,				// mov     r10,rcx
		0xb8, 0x00, 0x00, 0x00, 0x00,	// mov     eax,xxx
		0x0f, 0x05,						// syscall
		0xc3							// ret
	};

	memcpy((PBYTE)StubRegion, SyscallStub, sizeof(SyscallStub));
	*(DWORD*)(StubRegion + 4) = dwSyscallNo;
	
	return StubRegion;
}

BOOL InitSyscallsFromLdrpThunkSignature()
{
	PPEB Peb = (PPEB)__readgsqword(0x60);
	PPEB_LDR_DATA Ldr = Peb->Ldr;
	PLDR_DATA_TABLE_ENTRY NtdllLdrEntry = NULL;

	for (PLDR_DATA_TABLE_ENTRY LdrEntry = (PLDR_DATA_TABLE_ENTRY)Ldr->InLoadOrderModuleList.Flink;
		LdrEntry->DllBase != NULL;
		LdrEntry = (PLDR_DATA_TABLE_ENTRY)LdrEntry->InLoadOrderLinks.Flink)
	{
		if (_wcsnicmp(LdrEntry->BaseDllName.Buffer, L"ntdll.dll", 9) == 0)
		{
			// got ntdll
			NtdllLdrEntry = LdrEntry;
			break;
		}
	}

	if (NtdllLdrEntry == NULL)
	{
		return FALSE;
	}
	
	PIMAGE_NT_HEADERS ImageNtHeaders = (PIMAGE_NT_HEADERS)((ULONG_PTR)NtdllLdrEntry->DllBase + ((PIMAGE_DOS_HEADER)NtdllLdrEntry->DllBase)->e_lfanew);
	PIMAGE_SECTION_HEADER SectionHeader = (PIMAGE_SECTION_HEADER)((ULONG_PTR)&ImageNtHeaders->OptionalHeader + ImageNtHeaders->FileHeader.SizeOfOptionalHeader);
	
	ULONG_PTR DataSectionAddress = NULL;
	DWORD DataSectionSize;

	for (WORD i = 0; i < ImageNtHeaders->FileHeader.NumberOfSections; i++)
	{
		if (!strcmp((char*)SectionHeader[i].Name, ".data"))
		{
			DataSectionAddress = (ULONG_PTR)NtdllLdrEntry->DllBase + SectionHeader[i].VirtualAddress;
			DataSectionSize = SectionHeader[i].Misc.VirtualSize;
			break;
		}
	}

	DWORD dwSyscallNo_NtOpenFile = 0, dwSyscallNo_NtCreateSection = 0, dwSyscallNo_NtMapViewOfSection = 0;

	if (!DataSectionAddress || DataSectionSize < 16 * 5)
	{
		return FALSE;
	}

	for (UINT uiOffset = 0; uiOffset < DataSectionSize - (16 * 5); uiOffset++)
	{
		if (*(DWORD*)(DataSectionAddress + uiOffset) == 0xb8d18b4c &&
			*(DWORD*)(DataSectionAddress + uiOffset + 16) == 0xb8d18b4c &&
			*(DWORD*)(DataSectionAddress + uiOffset + 32) == 0xb8d18b4c &&
			*(DWORD*)(DataSectionAddress + uiOffset + 48) == 0xb8d18b4c &&
			*(DWORD*)(DataSectionAddress + uiOffset + 64) == 0xb8d18b4c)
		{
			dwSyscallNo_NtOpenFile = *(DWORD*)(DataSectionAddress + uiOffset + 4);
			dwSyscallNo_NtCreateSection = *(DWORD*)(DataSectionAddress + uiOffset + 16 + 4);
			dwSyscallNo_NtMapViewOfSection = *(DWORD*)(DataSectionAddress + uiOffset + 64 + 4);
			break;
		}
	}

	if (!dwSyscallNo_NtOpenFile)
	{
		return FALSE;
	}

	ULONG_PTR SyscallRegion = (ULONG_PTR)VirtualAlloc(NULL, 3 * MAX_SYSCALL_STUB_SIZE, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	if (!SyscallRegion)
	{
		return FALSE;
	}

	NtOpenFile = (FUNC_NTOPENFILE)BuildSyscallStub(SyscallRegion, dwSyscallNo_NtOpenFile);
	NtCreateSection = (FUNC_NTCREATESECTION)BuildSyscallStub(SyscallRegion + MAX_SYSCALL_STUB_SIZE, dwSyscallNo_NtCreateSection);
	NtMapViewOfSection = (FUNC_NTMAPVIEWOFSECTION)BuildSyscallStub(SyscallRegion + (2* MAX_SYSCALL_STUB_SIZE), dwSyscallNo_NtMapViewOfSection);

	return TRUE;
}

ULONG_PTR LoadNtdllIntoSection()
{
	NTSTATUS ntStatus;
	HANDLE hFile = NULL;
	OBJECT_ATTRIBUTES ObjectAttributes = { 0 };
	UNICODE_STRING ObjectPath = { 0 };
	IO_STATUS_BLOCK IoStatusBlock = { 0 };
	HANDLE hSection = NULL;
	LARGE_INTEGER maxSize = { 0 };
	LPVOID lpvSection = NULL;
	SIZE_T viewSize = 0;

	RtlInitUnicodeString(&ObjectPath, L"\\??\\C:\\Windows\\System32\\ntdll.dll");

	InitializeObjectAttributes(
		&ObjectAttributes,
		&ObjectPath,
		OBJ_CASE_INSENSITIVE,
		0,
		NULL
	);

	ntStatus = NtOpenFile(
		&hFile,
		FILE_READ_DATA,
		&ObjectAttributes,
		&IoStatusBlock,
		FILE_SHARE_READ,
		0
	);

	if (!NT_SUCCESS(ntStatus))
	{
		goto Cleanup;
	}

	ntStatus = NtCreateSection(
		&hSection,
		SECTION_ALL_ACCESS,
		NULL,
		NULL,
		PAGE_READONLY,
		SEC_COMMIT,
		hFile
	);

	if (!NT_SUCCESS(ntStatus))
	{
		goto Cleanup;
	}

	ntStatus = NtMapViewOfSection(hSection, GetCurrentProcess(), &lpvSection, NULL, NULL, NULL, &viewSize, 1, 0, PAGE_READONLY);

	if (!NT_SUCCESS(ntStatus))
	{
		return NULL;
	}

Cleanup:
	if (hSection) CloseHandle(hSection);
	if (hFile) CloseHandle(hFile);
	return (ULONG_PTR)lpvSection;
}

ULONG_PTR RVAToFileOffsetPointer(ULONG_PTR pModule, DWORD dwRVA)
{
	PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)pModule;
	PIMAGE_NT_HEADERS ImageNtHeaders = (PIMAGE_NT_HEADERS)(pModule + ((PIMAGE_DOS_HEADER)pModule)->e_lfanew);
	PIMAGE_SECTION_HEADER SectionHeader = (PIMAGE_SECTION_HEADER)((ULONG_PTR)&ImageNtHeaders->OptionalHeader + ImageNtHeaders->FileHeader.SizeOfOptionalHeader);

	for (WORD i = 0; i < ImageNtHeaders->FileHeader.NumberOfSections; i++)
	{
		if (SectionHeader[i].VirtualAddress <= dwRVA && SectionHeader[i].VirtualAddress + SectionHeader[i].Misc.VirtualSize > dwRVA)
		{
			dwRVA -= SectionHeader[i].VirtualAddress;
			dwRVA += SectionHeader[i].PointerToRawData;
			
			return pModule + dwRVA;
		}
	}

	return NULL;
}

ULONG_PTR FindBytes(ULONG_PTR Source, DWORD SourceLength, ULONG_PTR Search, DWORD SearchLength)
{
	while (SearchLength <= SourceLength)
	{
		if (!memcmp((PBYTE)Source, (PBYTE)Search, SearchLength))
		{
			return Source;
		}

		Source++;
		SourceLength--;
	}

	return NULL;
}

UINT ExtractSyscalls(ULONG_PTR pNtdll, CHAR rgszNames[MAX_NUMBER_OF_SYSCALLS][MAX_EXPORT_NAME_LENGTH], ULONG_PTR rgpStubs[MAX_NUMBER_OF_SYSCALLS])
{
	PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)pNtdll;
	PIMAGE_NT_HEADERS ImageNtHeaders = (PIMAGE_NT_HEADERS)(pNtdll + ((PIMAGE_DOS_HEADER)pNtdll)->e_lfanew);
	PIMAGE_SECTION_HEADER SectionHeader = (PIMAGE_SECTION_HEADER)((ULONG_PTR)&ImageNtHeaders->OptionalHeader + ImageNtHeaders->FileHeader.SizeOfOptionalHeader);

	PIMAGE_DATA_DIRECTORY DataDirectory = (PIMAGE_DATA_DIRECTORY)ImageNtHeaders->OptionalHeader.DataDirectory;
	DWORD VirtualAddress = DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	PIMAGE_EXPORT_DIRECTORY ExportDirectory = (PIMAGE_EXPORT_DIRECTORY)RVAToFileOffsetPointer(pNtdll, VirtualAddress);

	DWORD NumberOfNames = ExportDirectory->NumberOfNames;

	NumberOfNames = ExportDirectory->NumberOfNames;

	PDWORD Functions = (PDWORD)RVAToFileOffsetPointer(pNtdll, ExportDirectory->AddressOfFunctions);
	PDWORD Names = (PDWORD)RVAToFileOffsetPointer(pNtdll, ExportDirectory->AddressOfNames);
	PWORD Ordinals = (PWORD)RVAToFileOffsetPointer(pNtdll, ExportDirectory->AddressOfNameOrdinals);

	UINT uiCount = 0;

	ULONG_PTR pStubs = (ULONG_PTR)VirtualAlloc(NULL, MAX_NUMBER_OF_SYSCALLS * MAX_SYSCALL_STUB_SIZE, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	
	if (!pStubs)
	{
		return 0;
	}

	for (DWORD i = 0; i < NumberOfNames && uiCount < MAX_NUMBER_OF_SYSCALLS; i++)
	{
		PCHAR FunctionName = (PCHAR)RVAToFileOffsetPointer(pNtdll, Names[i]);

		if (*(USHORT*)FunctionName == 'wZ')
		{
			ULONG_PTR FunctionPtr = RVAToFileOffsetPointer(pNtdll, Functions[Ordinals[i]]);
			ULONG_PTR FunctionEnd = FindBytes(FunctionPtr, MAX_SYSCALL_STUB_SIZE, (ULONG_PTR)"\x0f\x05\xc3", 3) + 3;

			if (FunctionEnd)
			{
				strcpy_s(rgszNames[uiCount], MAX_EXPORT_NAME_LENGTH, FunctionName);
				*(WORD*)(rgszNames[uiCount]) = 'tN';

				memcpy((PBYTE)pStubs + (uiCount * MAX_SYSCALL_STUB_SIZE), (PBYTE)FunctionPtr, FunctionEnd - FunctionPtr);
				rgpStubs[uiCount] = pStubs + (uiCount * MAX_SYSCALL_STUB_SIZE);
				uiCount++;
			}
		}
	}

	return uiCount;
}

ULONG_PTR GetSyscall(CHAR rgszNames[MAX_NUMBER_OF_SYSCALLS][MAX_EXPORT_NAME_LENGTH], ULONG_PTR rgpStubs[MAX_NUMBER_OF_SYSCALLS], UINT uiCount, PCHAR pzSyscallName)
{
	for (UINT i = 0; i < uiCount; i++)
	{
		if (!strcmp(rgszNames[i], pzSyscallName))
		{
			return rgpStubs[i];
		}
	}

	return NULL;
}

typedef NTSTATUS(NTAPI* FUNC_NTCREATETHREADEX)(
	OUT PHANDLE hThread,
	IN ACCESS_MASK DesiredAccess,
	IN PVOID ObjectAttributes,
	IN HANDLE ProcessHandle,
	IN PVOID lpStartAddress,
	IN PVOID lpParameter,
	IN ULONG Flags,
	IN SIZE_T StackZeroBits,
	IN SIZE_T SizeOfStackCommit,
	IN SIZE_T SizeOfStackReserve,
	OUT PVOID lpBytesBuffer);

int main(void)
{
	InitSyscallsFromLdrpThunkSignature();
	ULONG_PTR pNtdll = LoadNtdllIntoSection();
	
	CHAR rgszNames[MAX_NUMBER_OF_SYSCALLS][MAX_EXPORT_NAME_LENGTH] = { 0 };
	ULONG_PTR rgpStubs[MAX_NUMBER_OF_SYSCALLS] = { 0 };
	
	UINT uiCount = ExtractSyscalls(pNtdll, rgszNames, rgpStubs);

	FUNC_NTCREATETHREADEX NtCreateThreadEx = (FUNC_NTCREATETHREADEX)GetSyscall(rgszNames, rgpStubs, uiCount, (PCHAR)"NtCreateThreadEx");

	NTSTATUS ntStatus;
	HANDLE hThread = NULL;

	ntStatus = NtCreateThreadEx(&hThread, GENERIC_ALL, NULL, GetCurrentProcess(), (LPTHREAD_START_ROUTINE)0x41414141, NULL, 0, 0, 0, 0, NULL);

	if (!NT_SUCCESS(ntStatus))
	{
		return FALSE;
	}

	Sleep(INFINITE);

	return 0;
}
