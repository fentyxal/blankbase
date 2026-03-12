#pragma once
#include <Windows.h>
#include <TlHelp32.h>
#include <cstdint>
#include <winioctl.h>
#include <iostream>

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

class DRIVER_CLASS {
public:
    HANDLE DriverHandle = INVALID_HANDLE_VALUE;
    INT32 ProcessID = 0;

    bool Init() {
        DriverHandle = CreateFileA("\\\\.\\ChudWareDrv", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
        return (DriverHandle != INVALID_HANDLE_VALUE);
    }

    INT32 FindProcess(const char* name) {
        PROCESSENTRY32 entry;
        entry.dwSize = sizeof(PROCESSENTRY32);
        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
        if (Process32First(snapshot, &entry)) {
            while (Process32Next(snapshot, &entry)) {
                if (strcmp(entry.szExeFile, name) == 0) {
                    ProcessID = entry.th32ProcessID;
                    CloseHandle(snapshot);
                    return ProcessID;
                }
            }
        }
        CloseHandle(snapshot);
        return 0;
    }

    ULONGLONG GetBaseAddress() {
        ULONGLONG base = 0;
        BA args = { CODE_SECURITY, ProcessID, &base };
        DWORD returned;
        DeviceIoControl(DriverHandle, CODE_BA, &args, sizeof(args), &args, sizeof(args), &returned, NULL);
        return base;
    }

    ULONGLONG GetGuardedRegion() {
        ULONGLONG guarded = 0;
        GA args = { CODE_SECURITY, &guarded };
        DWORD returned;
        DeviceIoControl(DriverHandle, CODE_GET_GUARDED_REGION, &args, sizeof(args), &args, sizeof(args), &returned, NULL);
        return guarded;
    }

    void ReadPhysicalMemory(PVOID address, PVOID buffer, DWORD size) {
        RW args = { CODE_SECURITY, ProcessID, (ULONGLONG)address, (ULONGLONG)buffer, size, FALSE };
        DWORD returned;
        DeviceIoControl(DriverHandle, CODE_RW, &args, sizeof(args), &args, sizeof(args), &returned, NULL);
    }

    void WritePhysicalMemory(PVOID address, PVOID buffer, DWORD size) {
        RW args = { CODE_SECURITY, ProcessID, (ULONGLONG)address, (ULONGLONG)buffer, size, TRUE };
        DWORD returned;
        DeviceIoControl(DriverHandle, CODE_RW, &args, sizeof(args), &args, sizeof(args), &returned, NULL);
    }
};

inline DRIVER_CLASS driver;

class MEMORY_CLASS {
public:
    ULONGLONG BaseAddress;

    template <typename T>
    T read(uint64_t addr) {
        T buf{};
        driver.ReadPhysicalMemory((PVOID)addr, &buf, sizeof(T));
        return buf;
    }

    template <typename T>
    void write(uint64_t addr, T val) {
        driver.WritePhysicalMemory((PVOID)addr, &val, sizeof(T));
    }
};

inline MEMORY_CLASS memory;