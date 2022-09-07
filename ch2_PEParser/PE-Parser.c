#include<windows.h>
#include<stdio.h>
#include<stdlib.h>
#include<time.h>

unsigned long readFileToBuf(char* filename, char** buf);
unsigned long getFileSize(FILE* fh);
void parsePE(char* buf, unsigned long size);
const char* MachineIdentify(WORD machine);
char* unixTimeToStr(time_t unixTime);
unsigned short FileCharactisticsIdentify(WORD charatistics, const char* buf[]);
unsigned short SectionCharactisticsIdentify(DWORD charatistics, const char* buf[]);

int main(int argc, char** argv)
{
    if(argc != 2)
    {
        printf("Usage: PE-Parser.exe <PE file>");
        exit(1);
    }

    char* PEFilename = argv[1];
    char* PEBuf = NULL;
    unsigned long fileSize = readFileToBuf(PEFilename, &PEBuf);

    printf("filename: %s\n", PEFilename);
    printf("filesize: %d bytes\n", fileSize);
    printf("\n---\n\n");
    parsePE(PEBuf, fileSize);

    free(PEBuf);
    return 0;
}

unsigned long readFileToBuf(char* filename, char** buf)
{
    FILE* fh = fopen(filename, "rb");
    if(fh == NULL)
    {
        printf("File %s not exist.", filename);
        exit(1);
    }

    unsigned long fileSize = getFileSize(fh);
    *buf = (char *) malloc(fileSize * sizeof(char));
    fread(*buf, sizeof(char), fileSize, fh);

    return fileSize;
}
unsigned long getFileSize(FILE* fh)
{
    // Credit: https://stackoverflow.com/questions/238603/how-can-i-get-a-files-size-in-c
    unsigned long size;
    fseek(fh, 0, SEEK_END); // seek to end of file
    size = ftell(fh); // get current file pointer
    fseek(fh, 0, SEEK_SET); // seek back to beginning of file
    return size;
}
void parsePE(char* buf, unsigned long size)
{
    const char* ERROR_MSG = "Invalid PE file";

    IMAGE_DOS_HEADER* DOSHeader = (IMAGE_DOS_HEADER*) (buf + 0);
    printf("DOS header start: 0x%x\n", 0x0);
    printf("Signature: %c%c\n", DOSHeader->e_magic, DOSHeader->e_magic/0x100);
    if(DOSHeader->e_magic != IMAGE_DOS_SIGNATURE)
    {
        printf("%s\n", ERROR_MSG);
        return;
    }
    printf("\n");

    IMAGE_NT_HEADERS* NTHeader = (IMAGE_NT_HEADERS*)(buf + DOSHeader->e_lfanew);
    printf("NT header start: 0x%x\n", DOSHeader->e_lfanew);
    printf("Signature: %c%c\n", NTHeader->Signature, NTHeader->Signature/0x100);
    if(NTHeader->Signature != IMAGE_NT_SIGNATURE)
    {
        printf("%s\n", ERROR_MSG);
        return;
    }
    printf("\n");

    IMAGE_FILE_HEADER* fileHeader = &(NTHeader->FileHeader);
    printf("File header start: 0x%x\n", DOSHeader->e_lfanew + 0x4);
    printf("\tMachine: %s\n", MachineIdentify(fileHeader->Machine));
    printf("\tNum of Sections: %u\n", fileHeader->NumberOfSections);
    char* timeBuf = unixTimeToStr(fileHeader->TimeDateStamp);
    printf("\tCompiled time: %s\n", timeBuf);
    free(timeBuf);
    printf("\tSymbol table addr: 0x%x\n", fileHeader->PointerToSymbolTable);
    printf("\tNum of Symbols: %u (0x%x)\n", fileHeader->NumberOfSymbols, fileHeader->NumberOfSymbols);
    printf("\tSize of Option header: %u (0x%x)\n", fileHeader->SizeOfOptionalHeader, fileHeader->SizeOfOptionalHeader);
    printf("\tCharactistics: \n");
    const char* charactisticsArray[16];
    unsigned short arraysize = FileCharactisticsIdentify(fileHeader->Characteristics, charactisticsArray);
    for(short i=0; i<arraysize; i++)
    {
        printf("\t\t%s\n", charactisticsArray[i]);
    }
    printf("\n");

    IMAGE_OPTIONAL_HEADER* optHeader = &(NTHeader->OptionalHeader);
    printf("Option header start: 0x%x\n", DOSHeader->e_lfanew + 0x4 + IMAGE_SIZEOF_FILE_HEADER);
    printf("\tImage base: 0x%x\n", optHeader->ImageBase);
    printf("\tSize of image: %u (0x%x)\n", optHeader->SizeOfImage, optHeader->SizeOfImage);
    printf("\tSize of headers: %u (0x%x)\n", optHeader->SizeOfHeaders, optHeader->SizeOfHeaders);
    printf("\tEntrypoint: 0x%x\n", optHeader->ImageBase + optHeader->AddressOfEntryPoint);
    printf("\tStatic alignment: %u (0x%x)\n", optHeader->FileAlignment, optHeader->FileAlignment);
    printf("\tRuntime alignment: %u (0x%x)\n", optHeader->SectionAlignment, optHeader->SectionAlignment);
    printf("\tData Directory: \n");
    const char* dataDirectory[16] = {
        "Export directory",
        "Import directory",
        "Resource directory",
        "Exception directory",
        "Security directory",
        "Base relocation table",
        "Debug directory",
        "x86 architecture specific data (deprecated)",
        "Global pointer directory index (deprecated)",
        "Thread local storage (TLS)",
        "Load configure directory",
        "Bound import directory in headers",
        "Import address table (IAT)",
        "Delay load import descriptors",
        "COM runtime descriptor",
        "Reserved"
    };
    for(short i=0; i<16; i++)
    {
        IMAGE_DATA_DIRECTORY* dd = &(optHeader->DataDirectory[i]);
        printf("\t\t%-45s 0x%08x ~ 0x%08x  (0x%08x)\n", 
            dataDirectory[i], 
            dd->VirtualAddress, 
            dd->VirtualAddress+dd->Size, 
            dd->Size
        );
    }
    printf("\n");

    IMAGE_SECTION_HEADER* sectionHeader = (IMAGE_SECTION_HEADER*)(buf + DOSHeader->e_lfanew + 0x4 + IMAGE_SIZEOF_FILE_HEADER + fileHeader->SizeOfOptionalHeader);
    printf("Section header start: 0x%x\n", DOSHeader->e_lfanew + 0x4 + IMAGE_SIZEOF_FILE_HEADER + fileHeader->SizeOfOptionalHeader);
    for(short i=0; i<fileHeader->NumberOfSections; i++)
    {
        const char* charactisticsArray[6];
        unsigned short arraysize = SectionCharactisticsIdentify(sectionHeader[i].Characteristics, charactisticsArray);
        printf("\t%-10s\tStatic: 0x%08x ~ 0x%08x (0x%08x) \t Dynamic: 0x%08x ~ 0x%08x (0x%08x)\t",
            sectionHeader[i].Name,
            sectionHeader[i].PointerToRawData,
            sectionHeader[i].PointerToRawData + sectionHeader[i].SizeOfRawData,
            sectionHeader[i].SizeOfRawData,
            sectionHeader[i].VirtualAddress,
            sectionHeader[i].VirtualAddress + sectionHeader[i].Misc.VirtualSize,
            sectionHeader[i].Misc.VirtualSize
        );
        for(short j = 0; j < arraysize; j++)
        {
            printf(" %s", charactisticsArray[j]);
        }
        printf("\n");
    }
    printf("\n");
}
const char* MachineIdentify(WORD machine)
{
    switch (machine)
    {
    case IMAGE_FILE_MACHINE_UNKNOWN:
        return "Unknown";
    case IMAGE_FILE_MACHINE_ALPHA64:
        return "ALPHA 64";
    case IMAGE_FILE_MACHINE_ALPHA:
        return "ALPHA (AXP 64)";
    case IMAGE_FILE_MACHINE_AM33:
        return "AM33";
    case IMAGE_FILE_MACHINE_AMD64:
        return "AMD 64 (x64)";
    case IMAGE_FILE_MACHINE_ARM64:
        return "ARM 64";
    case IMAGE_FILE_MACHINE_ARM:
        return "ARM";
    case IMAGE_FILE_MACHINE_ARMNT:
        return "ARM Thumb-2 (V7)";
    case IMAGE_FILE_MACHINE_CEE:
        return "CEE";
    case IMAGE_FILE_MACHINE_CEF:
        return "CEF";
    case IMAGE_FILE_MACHINE_EBC:
        return "EFI (EBC)";
    case IMAGE_FILE_MACHINE_I386:
        return "i386 (x86)";
    case IMAGE_FILE_MACHINE_IA64:
        return "IA64";
    case IMAGE_FILE_MACHINE_M32R:
        return "Mitsubishi M32R";
    case IMAGE_FILE_MACHINE_MIPS16:
        return "MIPS 16";
    case IMAGE_FILE_MACHINE_MIPSFPU16:
        return "MIPS with FPU 64";
    case IMAGE_FILE_MACHINE_MIPSFPU:
        return "MIPS with FPU";
    case IMAGE_FILE_MACHINE_POWERPC:
        return "POWER PC";
    case IMAGE_FILE_MACHINE_POWERPCFP:
        return "POWER PC with FP";
    case IMAGE_FILE_MACHINE_R10000:
        return "R10000";
    case IMAGE_FILE_MACHINE_R3000:
        return "R3000";
    case IMAGE_FILE_MACHINE_R4000:
        return "R4000";
    case IMAGE_FILE_MACHINE_SH3:
        return "Hitachi SH3";
    case IMAGE_FILE_MACHINE_SH3DSP:
        return "Hitachi SH3 DSP";
    case IMAGE_FILE_MACHINE_SH3E:
        return "Hitachi SH3 E";
    case IMAGE_FILE_MACHINE_SH4:
        return "Hitachi SH4";
    case IMAGE_FILE_MACHINE_SH5:
        return "Hitachi SH5";
    case IMAGE_FILE_MACHINE_THUMB:
        return "Thumb";
    case IMAGE_FILE_MACHINE_TRICORE:
        return "TRICORE";
    case IMAGE_FILE_MACHINE_WCEMIPSV2:
        return "WCE MIPS v2";
    default:
        return "Unknown";
    }
}
char* unixTimeToStr(time_t unixTime)
{
    // Credit: https://www.epochconverter.com/programming/c
    const int BUF_SIZE = 50;

    char* buf = malloc(BUF_SIZE * sizeof(char));
    struct tm ts = *localtime(&unixTime);
    strftime(buf, BUF_SIZE, "%Y-%m-%d %H:%M:%S %Z", &ts);
    return buf;
}
unsigned short FileCharactisticsIdentify(WORD charatistics, const char* buf[])
{
    const char* charactisticsName[] = {
        "No base relocation",
        "Executable",
        "Line numbers removed (deprecated)",
        "Symbol table entries removed (deprecated)",
        "Aggressively trim working set (deprecated)",
        "2GB+ addresses handleable",
        "(reserved)",
        "(deprecated)",
        "Machine 32-bit architecture",
        "No debugging info",
        "Run on swap (removable media)",
        "Run on swap (network media)",
        "System file",
        "DLL",
        "Uniprocessor only",
        "(deprecated)"
    };

    unsigned short bufsize = 0;
    for(short i=0; i<16; i++)
    {
        if((charatistics >> i) & 1)
        {
            buf[bufsize] = charactisticsName[i];
            bufsize += 1;
        }
    }

    return bufsize;
}
unsigned short SectionCharactisticsIdentify(DWORD charatistics, const char* buf[])
{
    const char* permession[] = {
        "---",
        "--X",
        "R--",
        "R-X",
        "-W-",
        "-WX",
        "RW-",
        "RWX"
    };
    const char* charactisticsName[] = 
    {
        "shared",
        "non_paged",
        "non_cached",
        "discardable",
        "extend_relocation"
    };

    charatistics = charatistics >> 24;
    buf[0] = permession[charatistics >> 5];

    unsigned short bufsize = 1;
    for(short i=0; i<5; i++)
    {
        if((charatistics >> (4-i)) & 1)
        {
            buf[bufsize] = charactisticsName[i];
            bufsize += 1;
        }
    }

    return bufsize;
}
