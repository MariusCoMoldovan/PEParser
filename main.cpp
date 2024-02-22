#include <stdio.h>
#include <Windows.h>


LPVOID lpFileBase;
WORD SECTION_COUNT;
PIMAGE_SECTION_HEADER SECTION_HEADERS;

void printTitle(const char* title) {
    printf("\n\n--%s--\n\n", title);
}

int findSection(DWORD virtualAddress) {
    for (int i = 0; i < SECTION_COUNT; i++) {
        if (virtualAddress > SECTION_HEADERS[i].VirtualAddress &&
            virtualAddress < SECTION_HEADERS[i].VirtualAddress + SECTION_HEADERS[i].Misc.VirtualSize)
            return i;
    }
    fprintf(stderr, "Could not resolve virtualAddress %lu\n", virtualAddress);
    return -1;
}

DWORD findOffset(DWORD virtualAddress) {
    int index = findSection(virtualAddress);
    if (index == -1)
        exit(1);
    return (virtualAddress - SECTION_HEADERS[index].VirtualAddress) + SECTION_HEADERS[index].PointerToRawData;
}


void parseDosHeader(PIMAGE_DOS_HEADER dosHeader) {
    printTitle("DOS HEADER");
    printf("Magic 0x%X\n", dosHeader->e_magic);
    printf("MinAlloc 0x%X\n", dosHeader->e_minalloc);
    printf("MaxAlloc 0x%X\n", dosHeader->e_maxalloc);
    printf("e_lfanew 0x%X\n", dosHeader->e_lfanew);
}

void parseImageFileHeader(PIMAGE_NT_HEADERS header) {
    printTitle("IMAGE FILE HEADER");
    printf("Machine: 0x%X\n", header->FileHeader.Machine);
    printf("Sections: 0x%X\n", header->FileHeader.NumberOfSections);
    printf("Pointer to Symbol Table: %lu\n", header->FileHeader.PointerToSymbolTable);
    printf("No. of symbols: %lu\n", header->FileHeader.NumberOfSymbols);
    printf("Size of Optional Header: 0x%X\n", header->FileHeader.SizeOfOptionalHeader);
}

void printSectionHeaderInfo(IMAGE_SECTION_HEADER sectionHeader) {
    printf("    * %.8s:\n", sectionHeader.Name);
    printf("        VirtualAddress: 0x%X\n", sectionHeader.VirtualAddress);
    printf("        VirtualSize: 0x%X\n", sectionHeader.Misc.VirtualSize);
    printf("        PointerToRawData: 0x%X\n", sectionHeader.PointerToRawData);
    printf("        SizeOfRawData: 0x%X\n", sectionHeader.SizeOfRawData);
    printf("        Characteristics: 0x%X\n\n", sectionHeader.Characteristics);
}

void parseSectionHeaders() {
    printTitle("SECTION HEADERS");
    for (int i = 0; i < SECTION_COUNT; i++) {
        printSectionHeaderInfo(SECTION_HEADERS[i]);
    }
}

void parseOptionalHeader(IMAGE_OPTIONAL_HEADER optionalHeader) {
    printTitle("OPTIONAL HEADER");

    printf("Magic: 0x%X\n", optionalHeader.Magic);
    printf("Size of code: %lu\n", optionalHeader.SizeOfCode);
    printf("Size of initialised data: %lu\n", optionalHeader.SizeOfInitializedData);
    printf("Address of entry point: %lu\n", optionalHeader.AddressOfEntryPoint);
    printf("Base of code: %lu\n", optionalHeader.BaseOfCode);
    printf("Base of data: %lu\n", optionalHeader.BaseOfData);
    printf("Section alignment: %lu\n", optionalHeader.SectionAlignment);
    printf("File alignment: %lu\n", optionalHeader.FileAlignment);
    printf("Win32 version value: %lu\n", optionalHeader.Win32VersionValue);
    printf("Sizeof image: %lu\n", optionalHeader.SizeOfImage);
    printf("Sizeof headers: %lu\n", optionalHeader.SizeOfHeaders);
    printf("Checksum: %lu\n", optionalHeader.CheckSum);
    printf("Dll Characteristics 0x%X\n", optionalHeader.DllCharacteristics);
    printf("Sizeof stack reserve: %lu\n", optionalHeader.SizeOfStackReserve);
    printf("Sizeof stack commit: %lu\n", optionalHeader.SizeOfStackCommit);
    printf("Sizeof heap reserve: %lu\n", optionalHeader.SizeOfHeapReserve);
    printf("Sizeof heap commit: %lu\n", optionalHeader.SizeOfHeapCommit);
    printf("Loader flags: %lu\n", optionalHeader.LoaderFlags);
    printf("Number of RVA and Sizes: %lu\n", optionalHeader.NumberOfRvaAndSizes);
}

void printImageDescriptorInfo(IMAGE_IMPORT_DESCRIPTOR imageDescriptor) {
    char* name;
    int nameOffset = findOffset(imageDescriptor.Name);
    name = (char*)lpFileBase + nameOffset;
    printf("%s\n", name);

    printf("       ILT RVA: 0x%X\n", imageDescriptor.OriginalFirstThunk);
    printf("       IAT RVA: 0x%X\n", imageDescriptor.FirstThunk);

    if (imageDescriptor.TimeDateStamp == 0) {
        printf("       Bound: FALSE\n");
    }
    else if (imageDescriptor.TimeDateStamp == -1) {
        printf("       Bound: TRUE\n");
    }

    printf("\n");
    int iltOffset = findOffset(imageDescriptor.OriginalFirstThunk);
    PIMAGE_THUNK_DATA data = (PIMAGE_THUNK_DATA)((u_char*)lpFileBase + iltOffset);
    int i = 0;
    for (i = 0; data[i].u1.AddressOfData != 0; i++) {
        if ((data[i].u1.Ordinal & 0x80000000) != 0)
            printf("            Ordinal: 0x%X", data[i].u1.Ordinal);
        else {
            //int nameOffset = findOffset(data[i].u1.AddressOfData);
            PIMAGE_IMPORT_BY_NAME nameImport = (PIMAGE_IMPORT_BY_NAME)((u_char*)lpFileBase + findOffset(data[i].u1.AddressOfData));
            printf("            Name: %s\n", nameImport->Name);
        }
    }

}

void parseImports(IMAGE_DATA_DIRECTORY imports) {
    printTitle("IMPORTS");
    PIMAGE_IMPORT_DESCRIPTOR imageDescriptor;
    imageDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)((u_char*)lpFileBase + findOffset(imports.VirtualAddress));
    for (int i = 0; ; i++) {
        if (imageDescriptor[i].Name == 0 && imageDescriptor[i].Characteristics == 0)
            break;
         printImageDescriptorInfo(imageDescriptor[i]);
    }
}

void parseExports(IMAGE_DATA_DIRECTORY exports) {
    printTitle("EXPORT DIRECTORY");
    printf("    Virtual Address: 0x%X", exports.VirtualAddress);
    if (exports.VirtualAddress == 0)
        return;
    int exportsOffset = findOffset(exports.VirtualAddress);
    PIMAGE_EXPORT_DIRECTORY exportDirectory = (PIMAGE_EXPORT_DIRECTORY)((u_char*)lpFileBase + exportsOffset);
    printf("    Characteristics: 0x%X\n", exportDirectory->Characteristics);
    printf("    Major Version: 0x%X\n", exportDirectory->MajorVersion);

    int nameOrdinalsOffset = findOffset(exportDirectory->AddressOfNameOrdinals);
    WORD* nameOrdinals = (WORD*)((u_char*)lpFileBase + nameOrdinalsOffset);

    int namesOffset = findOffset(exportDirectory->AddressOfNames);
    DWORD* names = (DWORD*)((u_char*)lpFileBase + namesOffset);
    for (int i = 0; i < exportDirectory->NumberOfNames; i++) {
        printf("        Name ordinal %d: 0x%X\n", i, nameOrdinals[i]);
        int helpOffset = findOffset(names[i]);
        char* help = (char*)lpFileBase + helpOffset;
        printf("        Name: %s\n", help);
    }

    int functionsOffset = findOffset(exportDirectory->AddressOfFunctions);
    DWORD* functions = (DWORD*)((u_char*)lpFileBase + functionsOffset);
    for (int i = 0; i < exportDirectory->NumberOfFunctions; i++) {
        printf("        Function Adress: 0x%X\n", functions[i]);
    }


}

void parseDataDirectory(PIMAGE_DATA_DIRECTORY dataDirectory) {
    printTitle("DATA DIRECTORY");
    parseImports(dataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]);
    parseExports(dataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]);

}


int main(int argc, char* argv[]) {
    
    HANDLE hFile;   // File Handle
    HANDLE hMapping;    //File Mapping Handle
    PIMAGE_NT_HEADERS ntHeader;
    
    if (argc < 2) {
        fprintf(stderr, "Error, usage: %s <exe_path>\n", argv[0]);
        return 1;
    }

    hFile = CreateFile(argv[1], GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "Could not open file\n");
        return 1;
    }

    hMapping = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    if (hMapping == NULL) {
        fprintf(stderr, "Could not create file mapping\n");
        return 1;
    }

    lpFileBase = MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
    if (!lpFileBase) {
        fprintf(stderr, "Could not Map View of File\n");
        return 1;
    }

    //DO STUFF
    
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)lpFileBase;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        fprintf(stderr, "NOT A PE FILE, DUMBASS\n");
        return 1;
    }

    parseDosHeader(dosHeader);
    ntHeader = (PIMAGE_NT_HEADERS)((u_char*)dosHeader + dosHeader->e_lfanew);
    if (ntHeader->Signature != IMAGE_NT_SIGNATURE) {
        fprintf(stderr, "NT SIGNATURE NOT MATCHED!\n");
        return 1;
    }

    printf("Signature: %lu\n", ntHeader->Signature);
    parseImageFileHeader(ntHeader);
    SECTION_COUNT = ntHeader->FileHeader.NumberOfSections;
    SECTION_HEADERS = (PIMAGE_SECTION_HEADER)((u_char*)lpFileBase + dosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS));
    parseSectionHeaders();

    parseOptionalHeader(ntHeader->OptionalHeader);
    parseDataDirectory(ntHeader->OptionalHeader.DataDirectory);

    //END DO STUFF

    UnmapViewOfFile(lpFileBase);
    CloseHandle(hMapping);
    CloseHandle(hFile);




}