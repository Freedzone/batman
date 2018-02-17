#include <ntddk.h>
#include <ntifs.h>
#include <ntstatus.h>
#include <wdm.h>

#include "CORE_STRUCTS.h"
#include "IoCtl.h"

#define RVATOVA(base, offset)((PVOID)((ULONG_PTR)base + (ULONG)offset))
#define TABLE_LEVEL_MASK 3 

#define PID 5504

typedef unsigned int UINT, *PUINT;

int ObjectTableOffset = 0x200;
int g_PIDOFFSET   = 0x180;
int g_FLINKOFFSET = 0x188; 

PEPROCESS      Process;
HANDLE         g_hProc;
PDEVICE_OBJECT g_pDevice;
UNICODE_STRING g_DeviceName;
UNICODE_STRING g_SymLinkName;

NTSTATUS Driver_IoControl(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp);
NTSTATUS DispatchAny(DEVICE_OBJECT *pDevice, IRP *pIrp);
NTSTATUS CreateDriverDevice(IN PDRIVER_OBJECT pDriverObject);
NTSTATUS DriverEntry(IN PDRIVER_OBJECT DriverObject, IN PUNICODE_STRING RegistryPath);
VOID UnloadRoutine(IN PDRIVER_OBJECT DriverObject);

// https://vxlab.info/wasm/article.php-article=lockfileswork.htm
PHANDLE_TABLE_ENTRY ExLookupHandleTableEntry( IN PHANDLE_TABLE HandleTable, IN EXHANDLE Handle )
{
	ULONG i, j, k;
	PHANDLE_TABLE_ENTRY Entry = NULL;
	ULONG_PTR TableCode = HandleTable->TableCode & ~TABLE_LEVEL_MASK;

	//DbgPrint("OUTPUT DATA: %d  %d", HandleTable->TableCode, Handle.Index);

	i = (Handle.Index >> 17) & 0x1FF;
	j = (Handle.Index >> 9)  & 0x1FF;
	k = (Handle.Index)       & 0x1FF;

	switch (HandleTable->TableCode & TABLE_LEVEL_MASK)
	{
	case 0 :
		Entry = &((PHANDLE_TABLE_ENTRY)TableCode)[k];
		break;

	case 1 :
		if (((PVOID *)TableCode)[j]) 
		{
			Entry = &((PHANDLE_TABLE_ENTRY *)TableCode)[j][k];			
		}
		break;

	case 2 :
		if (((PVOID *)TableCode)[i])
			if (((PVOID **)TableCode)[i][j])
			{
				Entry = &((PHANDLE_TABLE_ENTRY **)TableCode)[i][j][k];				  		 
			}
			break;
	}
	return Entry;
}

ULONG_PTR FindProcessEPROC (int nProcessID)   
{   
	int   current_PID = 0;   
	int   start_PID   = 0;    
	int   i_count     = 0;   
	ULONG_PTR eproc       = 0x0000000000000000;    
	PLIST_ENTRY plist_active_procs;   

	if (nProcessID == 0)   
		return nProcessID;   

	eproc = (ULONG_PTR) PsGetCurrentProcess();   
	start_PID = *((ULONG_PTR*)(eproc + g_PIDOFFSET));   
	current_PID = start_PID;   

	
	while(1)   
	{   
		if(nProcessID == current_PID)   
			return eproc;  

		else if( (i_count >= 1) && (start_PID == current_PID) )   
		{   
			return 0x0000000000000000;   
		}   

		else 
		{   
			plist_active_procs = (LIST_ENTRY *) (eproc+g_FLINKOFFSET);   
			eproc = (ULONG_PTR) plist_active_procs->Flink;   
			eproc = eproc - g_FLINKOFFSET;   
			current_PID = *((int *)(eproc+g_PIDOFFSET));   
			i_count++;   
		}   
	}   
}   

NTSTATUS SetHandleAccess( IN HANDLE Handle, IN ACCESS_MASK GrantedAccess )
{
	PHANDLE_TABLE       ObjectTable = NULL;
	PHANDLE_TABLE_ENTRY  Entry       = NULL;
	EXHANDLE            ExHandle;
	ULONG_PTR ProcAdr;

	try
	{
		ExHandle.GenericHandleOverlay = Handle;
		ProcAdr = (ULONG_PTR)PsGetCurrentProcess();
		ObjectTable = *((PHANDLE_TABLE *) (ProcAdr + ObjectTableOffset));

		Entry = ExLookupHandleTableEntry(ObjectTable, ExHandle);

		if (Entry)
		{
			Entry->GrantedAccess = GrantedAccess;
			return STATUS_SUCCESS;
		}
	}
	_except (SYSTEM_SERVICE_EXCEPTION)
	{
		//DbgPrint("System Service Exception called");
	}
	return STATUS_UNSUCCESSFUL;
}

NTSTATUS Driver_IoControl(IN PDEVICE_OBJECT pDeviceObj, IN PIRP pIrp)
{
	PIO_STACK_LOCATION      pStack;
	NTSTATUS                nts;
	PHANDLE_CONTAINER       inBUF;
	HANDLE                  hProcess;

	//DbgPrint("Driver control called");
	pStack = IoGetCurrentIrpStackLocation(pIrp);

	switch(pStack->Parameters.DeviceIoControl.IoControlCode)
	{
	case IOCTL_PASS_HANDLE:

		if (pStack->Parameters.DeviceIoControl.InputBufferLength  != sizeof(HANDLE_CONTAINER)  )
		{
			nts = STATUS_INVALID_BUFFER_SIZE;
			pIrp->IoStatus.Information = 0;
			//DbgPrint("%d %d", sizeof(ULONG), sizeof(HANDLE_CONTAINER));
			break;
		}

		ASSERT(pIrp->AssociatedIrp.SystemBuffer != NULL);
		
		inBUF  = (PHANDLE_CONTAINER)pIrp->AssociatedIrp.SystemBuffer;
		hProcess = (HANDLE)inBUF->Handle_Value;

		if( SetHandleAccess(hProcess, AC_GENERIC_ALL | AC_STANDARD_RIGHTS_ALL | SPECIFIC_RIGHTS_ALL) != STATUS_SUCCESS ) {
			nts = STATUS_DATA_ERROR
			//DbgPrint("Set handle access - UnSuccessFul");
		}
		else {
			nts = STATUS_SUCCESS;
			pIrp->IoStatus.Information = sizeof(HANDLE_CONTAINER);
		}		

		break;

	default:
		nts = STATUS_INVALID_DEVICE_REQUEST;
		pIrp->IoStatus.Information = 0;
	}
	pIrp->IoStatus.Status = nts;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);

	return nts;
}

NTSTATUS DispatchAny(DEVICE_OBJECT *pDevice, IRP *pIrp)
{
	pIrp->IoStatus.Status      = STATUS_SUCCESS;
	pIrp->IoStatus.Information = 0;

	IoCompleteRequest(pIrp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}

NTSTATUS CreateDriverDevice(IN PDRIVER_OBJECT pDriverObject)
{
	PDEVICE_OBJECT pDeviceObj;
	NTSTATUS stat;

	RtlInitUnicodeString(&g_DeviceName,  L"\\Device\\Batman");
	RtlInitUnicodeString(&g_SymLinkName, L"\\DosDevices\\Batman");

	stat = IoCreateDevice( pDriverObject, 0, &g_DeviceName, 
		                   FILE_DEVICE_UNKNOWN, 
		                   FILE_DEVICE_SECURE_OPEN, 
						   FALSE, 
						   &g_pDevice);

	if( stat == STATUS_SUCCESS)
	{
		stat = IoCreateSymbolicLink(&g_SymLinkName, &g_DeviceName);
		if(stat == STATUS_SUCCESS)
		{
			pDriverObject->MajorFunction[IRP_MJ_CREATE]  = 
			pDriverObject->MajorFunction[IRP_MJ_CLEANUP] = 
			pDriverObject->MajorFunction[IRP_MJ_CLOSE]   = DispatchAny;
			pDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = Driver_IoControl;
				
			return stat;
		}
	}
	return stat;
}

NTSTATUS DriverEntry(IN PDRIVER_OBJECT pDriverObject, IN PUNICODE_STRING RegistryPath)
{
	NTSTATUS status;
	KAPC_STATE APC_state;

	if( STATUS_SUCCESS != CreateDriverDevice(pDriverObject) )
	{
		//DbgPrint("Can't create Device link");
	}

	if ( STATUS_SUCCESS != PsLookupProcessByProcessId(PID, &Process) )
	{
		DbgPrint("Fak");
	}

	pDriverObject->DriverUnload = UnloadRoutine;
	return STATUS_SUCCESS;
}

VOID UnloadRoutine(IN PDRIVER_OBJECT DriverObject)
{
	IoDeleteDevice(g_pDevice);
	IoDeleteSymbolicLink(&g_SymLinkName);
	ZwClose(g_hProc);
}
