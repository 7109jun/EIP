// EIP native core - pe.h
// Portable PE32/PE32+ parser and writer. No Windows API dependency: this
// file builds and runs on any platform (used directly on Linux for
// `eip inspect`, tests, and persistent-patch output generation), and is
// also linked into the Windows-only eip_core runtime where the same
// PEImage is additionally built directly from a live process's mapped
// memory (see process.h / Module::pe()).
#pragma once

#include "eip/common.h"
#include "eip/pe_structs.h"
#include <vector>
#include <string>
#include <map>
#include <optional>
#include <functional>

namespace eip {

// A reader abstraction so PEImage can be built either from a flat on-disk
// byte buffer (file offsets) or from a live process's memory (RVA offsets
// from a module base, via whatever cross-process read primitive the caller
// has). PEImage itself never knows which one it's talking to.
struct ByteSource {
    virtual ~ByteSource() = default;
    // Read `size` bytes starting at `pos` (file offset, or RVA for a loaded
    // image) into `out`. Returns false if any part of the range is unreadable.
    virtual bool read(std::uint64_t pos, void* out, std::size_t size) const = 0;
    virtual std::uint64_t size() const = 0; // total addressable span, best-effort
};

class FileByteSource final : public ByteSource {
public:
    explicit FileByteSource(std::vector<u8> bytes) : bytes_(std::move(bytes)) {}
    bool read(std::uint64_t pos, void* out, std::size_t size) const override;
    std::uint64_t size() const override { return bytes_.size(); }
    const std::vector<u8>& raw() const { return bytes_; }
private:
    std::vector<u8> bytes_;
};

// Wraps an arbitrary callback, used by the Windows runtime to source bytes
// directly from ReadProcessMemory against a loaded module.
class CallbackByteSource final : public ByteSource {
public:
    using ReadFn = std::function<bool(std::uint64_t, void*, std::size_t)>;
    explicit CallbackByteSource(ReadFn fn, std::uint64_t span)
        : fn_(std::move(fn)), span_(span) {}
    bool read(std::uint64_t pos, void* out, std::size_t size) const override {
        return fn_(pos, out, size);
    }
    std::uint64_t size() const override { return span_; }
private:
    ReadFn fn_;
    std::uint64_t span_;
};

struct ExportEntry {
    std::string name;   // empty if exported by ordinal only
    u32 ordinal;
    RVA rva;
    bool is_forwarder;
    std::string forwarder_target; // "OtherDll.Func" when is_forwarder
};

struct ImportedFunction {
    std::string name;   // empty if imported by ordinal
    u16 ordinal;
    RVA iat_rva;         // RVA of the IAT slot that holds the resolved address
};

struct ImportedModule {
    std::string dll_name;
    std::vector<ImportedFunction> functions;
};

struct SectionInfo {
    std::string name;
    RVA virtual_address;
    u32 virtual_size;
    u32 raw_size;
    u32 raw_offset;
    u32 characteristics;
    bool executable() const { return (characteristics & pe_raw::SCN_MEM_EXECUTE) != 0; }
    bool writable() const { return (characteristics & pe_raw::SCN_MEM_WRITE) != 0; }
    bool readable() const { return (characteristics & pe_raw::SCN_MEM_READ) != 0; }
};

struct RelocationEntry {
    RVA rva;
    u16 type; // IMAGE_REL_BASED_* (0=absolute/padding, 3=HIGHLOW, 10=DIR64, ...)
};

struct TlsInfo {
    Address start_address_of_raw_data;
    Address end_address_of_raw_data;
    Address address_of_index;
    Address address_of_callbacks;
    u32 size_of_zero_fill;
    u32 characteristics;
    std::vector<Address> callbacks; // resolved callback addresses (0-terminated array in the image)
};

struct DebugInfoEntry {
    u32 type;
    u32 size_of_data;
    RVA address_of_raw_data;
    u32 pointer_to_raw_data;
};

struct ExceptionFunctionEntry { // x64 .pdata
    RVA begin_address;
    RVA end_address;
    RVA unwind_info_address;
};

// Whether a PEImage was built from the on-disk file layout (section data at
// PointerToRawData, aligned to FileAlignment) or from a loaded-in-memory
// layout (section data at VirtualAddress, aligned to SectionAlignment).
// rva_to_offset() behaves differently depending on this.
enum class PELayout { OnDisk, Loaded };

class PEImage {
public:
    // Parses `path` from disk. Throws EipError(PEParseFailed/UnsupportedPE) on failure.
    static PEImage parse_file(const std::string& path);

    // Parses an already-loaded buffer (e.g. a whole file already read into
    // memory by the caller) as an on-disk layout.
    static PEImage parse_bytes(std::vector<u8> bytes);

    // Parses a module mapped into a live process: `reader` returns bytes at
    // a given RVA from `base`, `image_size` bounds how far we'll read.
    static PEImage parse_loaded(CallbackByteSource::ReadFn reader, Address base, u64 image_size);

    bool is_pe32plus() const { return magic_ == pe_raw::OPT_MAGIC_PE32PLUS; }
    Arch arch() const { return arch_; }
    Address image_base() const { return image_base_; }
    u32 size_of_image() const { return size_of_image_; }
    u32 entry_point_rva() const { return entry_point_rva_; }
    u32 size_of_headers() const { return size_of_headers_; }
    u32 section_alignment() const { return section_alignment_; }
    u32 file_alignment() const { return file_alignment_; }
    u16 subsystem() const { return subsystem_; }
    u16 characteristics() const { return file_characteristics_; }
    PELayout layout() const { return layout_; }

    const std::vector<SectionInfo>& sections() const { return sections_; }
    const std::vector<ExportEntry>& exports() const { return exports_; }
    const std::vector<ImportedModule>& imports() const { return imports_; }
    const std::vector<RelocationEntry>& relocations() const { return relocations_; }
    const std::optional<TlsInfo>& tls() const { return tls_; }
    const std::vector<DebugInfoEntry>& debug_entries() const { return debug_entries_; }
    const std::vector<ExceptionFunctionEntry>& exception_table() const { return exception_table_; }
    bool has_resources() const { return resource_dir_rva_ != 0; }

    // Finds the first section containing `rva`, or nullptr.
    const SectionInfo* section_for_rva(RVA rva) const;

    // Converts between RVA and an addressable position in this image's own
    // ByteSource (file offset for OnDisk layout, identical value for Loaded).
    std::optional<u64> rva_to_offset(RVA rva) const;

    // Reads `size` raw bytes at `rva`. Throws AddressInvalid on failure.
    std::vector<u8> read_rva(RVA rva, std::size_t size) const;
    bool try_read_rva(RVA rva, void* out, std::size_t size) const;

    // Export lookup by name (case-sensitive, matches PE export name table).
    std::optional<RVA> find_export(const std::string& name) const;

    // --- Mutation (used by the persistent Patch engine, section 5/7) ------
    // Overwrites `size` bytes at `rva` in this in-memory image. Only valid
    // for images built from parse_file/parse_bytes (OnDisk layout); the
    // bytes are later flushed to disk by save(). Does not touch a live
    // process - that goes through Memory::write() in the Windows core.
    void patch_bytes(RVA rva, const void* data, std::size_t size);

    // Appends a brand new section (e.g. ".eip" holding injected code for a
    // Feature's new functions) and returns its assigned RVA. Recomputes
    // SizeOfImage. The section is appended both to the header table and to
    // the backing byte buffer so save() writes it out.
    RVA add_section(const std::string& name, const std::vector<u8>& data, u32 characteristics);

    // Serializes the current (possibly patched / extended) image back out
    // to `path` as a valid PE file. Only valid for OnDisk-layout images.
    void save(const std::string& path) const;

    // PE checksum algorithm per the Microsoft spec (used by save()).
    static u32 compute_checksum(const std::vector<u8>& file_bytes, std::size_t checksum_field_offset);

private:
    PEImage() = default;
    void parse_common(const ByteSource& src);

    std::vector<u8> buffer_;      // only populated for OnDisk layout (owns the bytes we can mutate/save)
    PELayout layout_ = PELayout::OnDisk;
    CallbackByteSource::ReadFn loaded_reader_; // only for Loaded layout

    u16 magic_ = 0;
    Arch arch_ = Arch::Unknown;
    Address image_base_ = 0;
    u32 size_of_image_ = 0;
    u32 entry_point_rva_ = 0;
    u32 size_of_headers_ = 0;
    u32 section_alignment_ = 0x1000;
    u32 file_alignment_ = 0x200;
    u16 subsystem_ = 0;
    u16 file_characteristics_ = 0;
    u32 dos_lfanew_ = 0;

    // File offsets of key structures, recorded during parse so save()/
    // add_section()/patch mutation can write fields back in place.
    // Meaningless (0) for Loaded-layout images, which are never saved.
    u64 off_file_header_ = 0;
    u64 off_optional_header_ = 0;
    u64 off_checksum_field_ = 0;   // absolute offset of OptionalHeader.CheckSum
    u64 off_size_of_image_field_ = 0;
    u64 off_section_table_ = 0;

    pe_raw::DataDirectory data_dirs_[pe_raw::DIR_COUNT]{};

    std::vector<SectionInfo> sections_;
    std::vector<ExportEntry> exports_;
    std::vector<ImportedModule> imports_;
    std::vector<RelocationEntry> relocations_;
    std::optional<TlsInfo> tls_;
    std::vector<DebugInfoEntry> debug_entries_;
    std::vector<ExceptionFunctionEntry> exception_table_;
    RVA resource_dir_rva_ = 0;
};

} // namespace eip
