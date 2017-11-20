#pragma once

#define IOCTL_PASS_HANDLE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_IN_DIRECT, FILE_ANY_ACCESS) 

#define AC_GENERIC_READ        0x120089
#define AC_GENERIC_WRITE       0x120196
#define AC_DELETE              0x110080
#define AC_READ_CONTROL        0x120080
#define AC_WRITE_DAC           0x140080
#define AC_WRITE_OWNER         0x180080
#define AC_GENERIC_ALL         0x1f01ff
#define AC_STANDARD_RIGHTS_ALL 0x1f0080

#define SPECIFIC_RIGHTS_ALL              (0x0000FFFFL)
#define SYNCHRONIZE                      (0x00100000L)

typedef struct _HANDLE_CONTAINER
{
	ULONG       Handle_Value;
	ACCESS_MASK DesiredAccess;
} HANDLE_CONTAINER, *PHANDLE_CONTAINER;

typedef struct _EXHANDLE 
{
	union 
	{
		struct 
		{
			ULONG TagBits : 02;
			ULONG Index   : 30;
		};
		HANDLE GenericHandleOverlay;
	};
} EXHANDLE, *PEXHANDLE;