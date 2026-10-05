// EIP native core - pe_structs.h
// Raw on-disk PE32/PE32+ structure layouts, defined from scratch so this
// header has zero dependency on <windows.h>. That is what lets pe.cpp build
// and run as a normal native binary on Linux (used for file-based parsing:
// `eip inspect`, persistent patch output, and this project's own tests) as
// well as being cross-compiled into the Windows-only eip_core.dll.
//
// Field names and offsets follow the Microsoft PE/COFF specification.
#pragma once
#include <cstdint>

namespace eip::pe_raw {

#pragma pack(push, 1)

constexpr std::uint16_t DOS_MAGIC = 0x5A4D;      // "MZ"
constexpr std::uint32_t NT_SIGNATURE = 0x00004550; // "PE\0\0"
constexpr std::uint16_t OPT_MAGIC_PE32 = 0x10B;
constexpr std::uint16_t OPT_MAGIC_PE32PLUS = 0x20B;

constexpr std::uint16_t MACHINE_I386 = 0x014C;
constexpr std::uint16_t MACHINE_AMD64 = 0x8664;

struct DosHeader {
    std::uint16_t e_magic;
    std::uint16_t e_cblp;
    std::uint16_t e_cp;
    std::uint16_t e_crlc;
    std::uint16_t e_cparhdr;
    std::uint16_t e_minalloc;
    std::uint16_t e_maxalloc;
    std::uint16_t e_ss;
    std::uint16_t e_sp;
    std::uint16_t e_csum;
    std::uint16_t e_ip;
    std::uint16_t e_cs;
    std::uint16_t e_lfarlc;
    std::uint16_t e_ovno;
    std::uint16_t e_res[4];
    std::uint16_t e_oemid;
    std::uint16_t e_oeminfo;
    std::uint16_t e_res2[10];
    std::int32_t  e_lfanew;      // file offset of NT headers
};
static_assert(sizeof(DosHeader) == 64, "DosHeader must be 64 bytes");

struct FileHeader {
    std::uint16_t Machine;
    std::uint16_t NumberOfSections;
    std::uint32_t TimeDateStamp;
    std::uint32_t PointerToSymbolTable;
    std::uint32_t NumberOfSymbols;
    std::uint16_t SizeOfOptionalHeader;
    std::uint16_t Characteristics;
};
static_assert(sizeof(FileHeader) == 20, "FileHeader must be 20 bytes");

struct DataDirectory {
    std::uint32_t VirtualAddress;
    std::uint32_t Size;
};

enum DataDirectoryIndex : int {
    DIR_EXPORT = 0,
    DIR_IMPORT = 1,
    DIR_RESOURCE = 2,
    DIR_EXCEPTION = 3,
    DIR_SECURITY = 4,
    DIR_BASERELOC = 5,
    DIR_DEBUG = 6,
    DIR_ARCHITECTURE = 7,
    DIR_GLOBALPTR = 8,
    DIR_TLS = 9,
    DIR_LOAD_CONFIG = 10,
    DIR_BOUND_IMPORT = 11,
    DIR_IAT = 12,
    DIR_DELAY_IMPORT = 13,
    DIR_COM_DESCRIPTOR = 14,
    DIR_RESERVED = 15,
    DIR_COUNT = 16,
};

struct OptionalHeader32 {
    std::uint16_t Magic;
    std::uint8_t  MajorLinkerVersion;
    std::uint8_t  MinorLinkerVersion;
    std::uint32_t SizeOfCode;
    std::uint32_t SizeOfInitializedData;
    std::uint32_t SizeOfUninitializedData;
    std::uint32_t AddressOfEntryPoint;
    std::uint32_t BaseOfCode;
    std::uint32_t BaseOfData;
    std::uint32_t ImageBase;
    std::uint32_t SectionAlignment;
    std::uint32_t FileAlignment;
    std::uint16_t MajorOperatingSystemVersion;
    std::uint16_t MinorOperatingSystemVersion;
    std::uint16_t MajorImageVersion;
    std::uint16_t MinorImageVersion;
    std::uint16_t MajorSubsystemVersion;
    std::uint16_t MinorSubsystemVersion;
    std::uint32_t Win32VersionValue;
    std::uint32_t SizeOfImage;
    std::uint32_t SizeOfHeaders;
    std::uint32_t CheckSum;
    std::uint16_t Subsystem;
    std::uint16_t DllCharacteristics;
    std::uint32_t SizeOfStackReserve;
    std::uint32_t SizeOfStackCommit;
    std::uint32_t SizeOfHeapReserve;
    std::uint32_t SizeOfHeapCommit;
    std::uint32_t LoaderFlags;
    std::uint32_t NumberOfRvaAndSizes;
    DataDirectory DataDirectories[16];
};

struct OptionalHeader64 {
    std::uint16_t Magic;
    std::uint8_t  MajorLinkerVersion;
    std::uint8_t  MinorLinkerVersion;
    std::uint32_t SizeOfCode;
    std::uint32_t SizeOfInitializedData;
    std::uint32_t SizeOfUninitializedData;
    std::uint32_t AddressOfEntryPoint;
    std::uint32_t BaseOfCode;
    std::uint64_t ImageBase;
    std::uint32_t SectionAlignment;
    std::uint32_t FileAlignment;
    std::uint16_t MajorOperatingSystemVersion;
    std::uint16_t MinorOperatingSystemVersion;
    std::uint16_t MajorImageVersion;
    std::uint16_t MinorImageVersion;
    std::uint16_t MajorSubsystemVersion;
    std::uint16_t MinorSubsystemVersion;
    std::uint32_t Win32VersionValue;
    std::uint32_t SizeOfImage;
    std::uint32_t SizeOfHeaders;
    std::uint32_t CheckSum;
    std::uint16_t Subsystem;
    std::uint16_t DllCharacteristics;
    std::uint64_t SizeOfStackReserve;
    std::uint64_t SizeOfStackCommit;
    std::uint64_t SizeOfHeapReserve;
    std::uint64_t SizeOfHeapCommit;
    std::uint32_t LoaderFlags;
    std::uint32_t NumberOfRvaAndSizes;
    DataDirectory DataDirectories[16];
};

struct SectionHeader {
    char          Name[8];       // not NUL-terminated if exactly 8 chars
    std::uint32_t VirtualSize;
    std::uint32_t VirtualAddress;
    std::uint32_t SizeOfRawData;
    std::uint32_t PointerToRawData;
    std::uint32_t PointerToRelocations;
    std::uint32_t PointerToLinenumbers;
    std::uint16_t NumberOfRelocations;
    std::uint16_t NumberOfLinenumbers;
    std::uint32_t Characteristics;
};
static_assert(sizeof(SectionHeader) == 40, "SectionHeader must be 40 bytes");

// Section characteristics bits we actually use.
constexpr std::uint32_t SCN_CNT_CODE = 0x00000020;
constexpr std::uint32_t SCN_CNT_INITIALIZED_DATA = 0x00000040;
constexpr std::uint32_t SCN_MEM_EXECUTE = 0x20000000;
constexpr std::uint32_t SCN_MEM_READ = 0x40000000;
constexpr std::uint32_t SCN_MEM_WRITE = 0x80000000;

struct ExportDirectory {
    std::uint32_t Characteristics;
    std::uint32_t TimeDateStamp;
    std::uint16_t MajorVersion;
    std::uint16_t MinorVersion;
    std::uint32_t Name;              // RVA to DLL name string
    std::uint32_t Base;              // starting ordinal number
    std::uint32_t NumberOfFunctions;
    std::uint32_t NumberOfNames;
    std::uint32_t AddressOfFunctions;    // RVA -> array of RVA (export table)
    std::uint32_t AddressOfNames;        // RVA -> array of RVA (name strings)
    std::uint32_t AddressOfNameOrdinals; // RVA -> array of u16 ordinals
};

struct ImportDescriptor {
    std::uint32_t OriginalFirstThunk; // RVA to INT (names/ordinals), 0 if none
    std::uint32_t TimeDateStamp;
    std::uint32_t ForwarderChain;
    std::uint32_t Name;                // RVA to DLL name string
    std::uint32_t FirstThunk;          // RVA to IAT
};
static_assert(sizeof(ImportDescriptor) == 20, "ImportDescriptor must be 20 bytes");

struct BaseRelocationBlockHeader {
    std::uint32_t PageRVA;
    std::uint32_t BlockSize; // includes this 8-byte header
};

struct TlsDirectory32 {
    std::uint32_t StartAddressOfRawData;
    std::uint32_t EndAddressOfRawData;
    std::uint32_t AddressOfIndex;
    std::uint32_t AddressOfCallBacks;
    std::uint32_t SizeOfZeroFill;
    std::uint32_t Characteristics;
};

struct TlsDirectory64 {
    std::uint64_t StartAddressOfRawData;
    std::uint64_t EndAddressOfRawData;
    std::uint64_t AddressOfIndex;
    std::uint64_t AddressOfCallBacks;
    std::uint32_t SizeOfZeroFill;
    std::uint32_t Characteristics;
};

struct DebugDirectoryEntry {
    std::uint32_t Characteristics;
    std::uint32_t TimeDateStamp;
    std::uint16_t MajorVersion;
    std::uint16_t MinorVersion;
    std::uint32_t Type;
    std::uint32_t SizeOfData;
    std::uint32_t AddressOfRawData;
    std::uint32_t PointerToRawData;
};

// x64 exception directory entries (.pdata), fixed-size function table entries.
struct RuntimeFunction64 {
    std::uint32_t BeginAddress;
    std::uint32_t EndAddress;
    std::uint32_t UnwindInfoAddress;
};

struct ResourceDirectory {
    std::uint32_t Characteristics;
    std::uint32_t TimeDateStamp;
    std::uint16_t MajorVersion;
    std::uint16_t MinorVersion;
    std::uint16_t NumberOfNamedEntries;
    std::uint16_t NumberOfIdEntries;
};

struct ResourceDirectoryEntry {
    std::uint32_t NameOrId;   // high bit set => offset into string table (name)
    std::uint32_t OffsetToData; // high bit set => offset to another ResourceDirectory (subdirectory)
};

struct ResourceDataEntry {
    std::uint32_t OffsetToData; // RVA of the raw resource data
    std::uint32_t Size;
    std::uint32_t CodePage;
    std::uint32_t Reserved;
};

#pragma pack(pop)

} // namespace eip::pe_raw
