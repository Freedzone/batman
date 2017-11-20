#include <ntddk.h>
#include <ntifs.h>
#include <wdm.h>


PVOID NTEXAPI GetSystemInformation (
	SYSTEM_INFORMATION_CLASS InfoClass
	)
{
	NTSTATUS Status;
	PVOID Buffer;
	ULONG Size = PAGE_SIZE * 4;

	PAGED_CODE();

	do
	{
		ULONG t;

		Buffer = ExAllocatePool (PagedPool, Size);

		if (!Buffer)
		{
			KdPrint(("!!!NOT ENOUGH MEMORY!!! PoolSize %lx\n", Size));
			return NULL;
		}

		Status = ZwQuerySystemInformation ( InfoClass,
			Buffer,
			Size,
			&t );

		if (!NT_SUCCESS(Status))
			ExFreePool (Buffer);

		Size = Size + PAGE_SIZE*4;
	}
	while (Status == STATUS_INFO_LENGTH_MISMATCH);

	if (!NT_SUCCESS(Status))
	{
		return NULL;
	}

	return Buffer;
}

PVOID
	NTEXAPI
	GetProcedureAddressEx(
	IN PVOID Base,
	IN PCHAR FunctionName OPTIONAL,
	IN PVOID FunctionEntry OPTIONAL
	)
{
	PIMAGE_DOS_HEADER mz;
	PIMAGE_FILE_HEADER pfh;
	PIMAGE_OPTIONAL_HEADER poh;
	PIMAGE_EXPORT_DIRECTORY pexd;
	PULONG AddressOfFunctions;
	PULONG AddressOfNames;
	PUSHORT AddressOfNameOrdinals;
	ULONG i;

	// Get headers
	*(PUCHAR*)&mz = (PUCHAR)Base;
	*(PUCHAR*)&pfh = (PUCHAR)Base + mz->e_lfanew + sizeof(IMAGE_NT_SIGNATURE);
	*(PIMAGE_FILE_HEADER*)&poh = pfh + 1;

	// Get export
	*(PUCHAR*)&pexd = (PUCHAR)Base + poh->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	*(PUCHAR*)&AddressOfFunctions = (PUCHAR)Base + pexd->AddressOfFunctions;
	*(PUCHAR*)&AddressOfNames = (PUCHAR)Base + pexd->AddressOfNames;
	*(PUCHAR*)&AddressOfNameOrdinals = (PUCHAR)Base + pexd->AddressOfNameOrdinals;

	// Find function
	for( i=0; i<pexd->NumberOfNames; i++ ) 
	{
		PCHAR name = ((char*)Base + AddressOfNames[i]);
		PVOID addr = (PVOID*)((ULONG)Base + AddressOfFunctions[AddressOfNameOrdinals[i]]);

		if (ARGUMENT_PRESENT (FunctionName))
		{
			if( !strcmp( name, FunctionName ) ) 
			{
				return addr;
			}
		}
		else if (ARGUMENT_PRESENT (FunctionEntry))
		{
			if (FunctionEntry == addr)
				return name;
		}
		else
		{
			ASSERTMSG ("SHOULD NOT REACH HERE", ARGUMENT_PRESENT(FunctionName) || ARGUMENT_PRESENT(FunctionEntry));
		}
	}

	return NULL;
}

PEPROCESS
	NTEXAPI
	GetProcessByNameAndSessionId(
	PWCHAR wszProcessName,
	PULONG RequiredSessionId OPTIONAL,
	PULONG SessionIdReturned OPTIONAL
	)
{
	PSYSTEM_PROCESSES_INFORMATION Processes;
	NTSTATUS Status = STATUS_NOT_FOUND;
	PEPROCESS Process;

	PAGED_CODE();

	Processes = (PSYSTEM_PROCESSES_INFORMATION) GetSystemInformation (SystemProcessesAndThreadsInformation);

	if (Processes)
	{
		PSYSTEM_PROCESSES_INFORMATION Proc;

		for (Proc=Processes; ; *(ULONG*)&Proc += Proc->NextEntryDelta)
		{
			BOOLEAN sessionIdOk = true;

			if (ARGUMENT_PRESENT(RequiredSessionId))
			{
				sessionIdOk = (Proc->SessionId == *RequiredSessionId);
			}

			if (Proc->ProcessName.Buffer && 
				!_wcsicmp (Proc->ProcessName.Buffer, wszProcessName) &&
				sessionIdOk)
			{
				Status = PsLookupProcessByProcessId ((PVOID) Proc->ProcessId, &Process);

				if(NT_SUCCESS(Status))
				{
					if (ARGUMENT_PRESENT(SessionIdReturned))
						*SessionIdReturned = Proc->SessionId;
					ExFreePool (Processes);
					return Process;
				}

				break;
			}

			if (!Proc->NextEntryDelta) break;
		}

		ExFreePool (Processes);

		return NULL;
	}

	return NULL;
}

// thnx to Twister
PPEB NTEXAPI GetProcessPeb(HANDLE hProcess)
	/**
	Get PEB of current process
	*/
{    
	PROCESS_BASIC_INFORMATION    pbi;
	NTSTATUS                    status;
	PPEB                        result = NULL;

	PAGED_CODE();

	status = ZwQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(PROCESS_BASIC_INFORMATION), NULL);
	if (NT_SUCCESS(status)) 
	{
		result = pbi.PebBaseAddress;
	}

	return result;
}

// thnx to Twister
PVOID NTEXAPI UserFindModule (PWSTR ModuleName)
	/**
	Find user module (kernel-mode version for GetModuleHandle)
	*/
{
	PLIST_ENTRY             Next;
	PPEB                    Peb;
	PLDR_DATA_TABLE_ENTRY   Entry;
	UNICODE_STRING          us;

	PAGED_CODE();

	Peb = GetProcessPeb (NtCurrentProcess());
	if (Peb) 
	{
		RtlInitUnicodeString(&us, ModuleName);

		Next = Peb->Ldr->InMemoryOrderModuleList.Flink;
		while (Next != &Peb->Ldr->InMemoryOrderModuleList) 
		{
			Entry = CONTAINING_RECORD(Next, LDR_DATA_TABLE_ENTRY, MemoryOrder);

			if(!RtlCompareUnicodeString(&Entry->ModuleName, &us, TRUE)) 
			{
				return Entry->ModuleBaseAddress;
			}

			Next = Next->Flink;
		}
	}

	return NULL;
}