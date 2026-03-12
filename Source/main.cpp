#include <ntifs.h>
#include <ntddk.h>

// Exact match for your provided driver.h
#define CODE_RW                  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x47536, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define CODE_BA                  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x36236, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define CODE_GET_GUARDED_REGION  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x13437, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define CODE_SECURITY            0x457c1d6

typedef struct _RW {
    INT32 security;
    INT32 process_id;
    ULONGLONG address;
    ULONGLONG buffer;
    ULONGLONG size;
    BOOLEAN write;
} RW, * PRW;

typedef struct _BA {
    INT32 security;
    INT32 process_id;
    ULONGLONG* address;
} BA, * PBA;

typedef struct _GA {
    INT32 security;
    ULONGLONG* address;
} GA, * PGA;

extern "C" {
    NTSTATUS NTAPI MmCopyVirtualMemory(PEPROCESS SourceProcess, PVOID SourceAddress, PEPROCESS TargetProcess, PVOID TargetAddress, SIZE_T BufferSize, KPROCESSOR_MODE PreviousMode, PSIZE_T ReturnSize);
    PVOID NTAPI PsGetProcessSectionBaseAddress(PEPROCESS Process);
}

// Logic to handle Guarded Region (Required for Fortnite UWorld)
ULONGLONG GetGuardedRegion() {
    UNICODE_STRING name;
    RtlInitUnicodeString(&name, L"MmGuardedPoolEnd"); // Common pointer for guarded region base
    PVOID addr = MmGetSystemRoutineAddress(&name);
    if (addr) return *(ULONGLONG*)addr;
    return 0;
}

NTSTATUS IoControl(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    UNREFERENCED_PARAMETER(DeviceObject);
    PIO_STACK_LOCATION Stack = IoGetCurrentIrpStackLocation(Irp);
    PVOID Buffer = Irp->AssociatedIrp.SystemBuffer;
    ULONG ControlCode = Stack->Parameters.DeviceIoControl.IoControlCode;
    ULONG InputSize = Stack->Parameters.DeviceIoControl.InputBufferLength;
    NTSTATUS Status = STATUS_SUCCESS;
    ULONG BytesIO = 0;

    if (ControlCode == CODE_RW && InputSize == sizeof(RW)) {
        PRW req = (PRW)Buffer;
        if (req->security == CODE_SECURITY) {
            PEPROCESS Process = NULL;
            if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)req->process_id, &Process))) {
                SIZE_T Bytes = 0;
                if (req->write)
                    MmCopyVirtualMemory(PsGetCurrentProcess(), (PVOID)req->buffer, Process, (PVOID)req->address, req->size, KernelMode, &Bytes);
                else
                    MmCopyVirtualMemory(Process, (PVOID)req->address, PsGetCurrentProcess(), (PVOID)req->buffer, req->size, KernelMode, &Bytes);
                ObDereferenceObject(Process);
            }
        }
        BytesIO = sizeof(RW);
    }
    else if (ControlCode == CODE_BA && InputSize == sizeof(BA)) {
        PBA req = (PBA)Buffer;
        if (req->security == CODE_SECURITY) {
            PEPROCESS Process = NULL;
            if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)req->process_id, &Process))) {
                *req->address = (ULONGLONG)PsGetProcessSectionBaseAddress(Process);
                ObDereferenceObject(Process);
            }
        }
        BytesIO = sizeof(BA);
    }
    else if (ControlCode == CODE_GET_GUARDED_REGION && InputSize == sizeof(GA)) {
        PGA req = (PGA)Buffer;
        if (req->security == CODE_SECURITY) {
            *req->address = GetGuardedRegion();
        }
        BytesIO = sizeof(GA);
    }

    Irp->IoStatus.Status = Status;
    Irp->IoStatus.Information = BytesIO;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return Status;
}

NTSTATUS CreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    UNREFERENCED_PARAMETER(DeviceObject);
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

// Entry point designed for manual mapping (No RegistryPath usage)
extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    UNREFERENCED_PARAMETER(RegistryPath);

    UNICODE_STRING DevName, SymName;
    RtlInitUnicodeString(&DevName, L"\\Device\\ChudWareDrv");
    RtlInitUnicodeString(&SymName, L"\\DosDevices\\ChudWareDrv");

    PDEVICE_OBJECT DeviceObject = NULL;
    NTSTATUS Status = IoCreateDevice(DriverObject, 0, &DevName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &DeviceObject);
    if (!NT_SUCCESS(Status)) return Status;

    Status = IoCreateSymbolicLink(&SymName, &DevName);
    if (!NT_SUCCESS(Status)) {
        IoDeleteDevice(DeviceObject);
        return Status;
    }

    DriverObject->MajorFunction[IRP_MJ_CREATE] = CreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = CreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = IoControl;

    DeviceObject->Flags |= DO_BUFFERED_IO;
    DeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

    return STATUS_SUCCESS;
}