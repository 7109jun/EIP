#include "eip/pe.h"
#include <fstream>
#include <cstring>
#include <algorithm>

namespace eip {

using namespace eip::pe_raw;

namespace {
u64 align_up(u64 value, u64 alignment) {
    if (alignment == 0) return value;
    return (value + alignment - 1) / alignment * alignment;
}
} // namespace

// ---------------------------------------------------------------------------
// FileByteSource
// ---------------------------------------------------------------------------
bool FileByteSource::read(std::uint64_t pos, void* out, std::size_t size) const {
    if (pos + size > bytes_.size() || pos + size < pos) return false;
    std::memcpy(out, bytes_.data() + pos, size);
    return true;
}

// ---------------------------------------------------------------------------
// parse_file / parse_bytes / parse_loaded
// ---------------------------------------------------------------------------
PEImage PEImage::parse_file(const std::string& path) {
    std::ifstream f(path, std::ios::binary | std::ios::ate);
    if (!f) throw EipError(ErrorCode::IoError, "cannot open '" + path + "'");
    std::streamsize len = f.tellg();
    if (len <= 0) throw EipError(ErrorCode::IoError, "empty file '" + path + "'");
    f.seekg(0);
    std::vector<u8> bytes(static_cast<std::size_t>(len));
    if (!f.read(reinterpret_cast<char*>(bytes.data()), len)) {
        throw EipError(ErrorCode::IoError, "failed reading '" + path + "'");
    }
    return parse_bytes(std::move(bytes));
}

PEImage PEImage::parse_bytes(std::vector<u8> bytes) {
    PEImage img;
    img.layout_ = PELayout::OnDisk;
    img.buffer_ = std::move(bytes);
    FileByteSource src(img.buffer_); // transient copy for the read interface; parse_common only reads
    img.parse_common(src);
    return img;
}

PEImage PEImage::parse_loaded(CallbackByteSource::ReadFn reader, Address base, u64 image_size) {
    PEImage img;
    img.layout_ = PELayout::Loaded;
    img.loaded_reader_ = reader;
    img.image_base_ = base;
    CallbackByteSource src(reader, image_size);
    img.parse_common(src);
    return img;
}

// ---------------------------------------------------------------------------
// Core header/section/export/import/reloc/TLS/debug/exception parsing.
// Shared verbatim between OnDisk and Loaded layouts: the only difference is
// what `src.read(pos, ...)` means (file offset vs RVA-from-base), which is
// exactly what rva_to_offset() + this function abstract away via `src`.
// ---------------------------------------------------------------------------
void PEImage::parse_common(const ByteSource& src) {
    DosHeader dos{};
    if (!src.read(0, &dos, sizeof(dos)) || dos.e_magic != DOS_MAGIC) {
        throw EipError(ErrorCode::PEParseFailed, "missing MZ signature");
    }
    if (dos.e_lfanew < 0) {
        throw EipError(ErrorCode::PEParseFailed, "negative e_lfanew");
    }
    dos_lfanew_ = static_cast<u32>(dos.e_lfanew);

    u32 nt_sig = 0;
    if (!src.read(dos_lfanew_, &nt_sig, sizeof(nt_sig)) || nt_sig != NT_SIGNATURE) {
        throw EipError(ErrorCode::PEParseFailed, "missing PE\\0\\0 signature");
    }

    off_file_header_ = dos_lfanew_ + sizeof(u32);
    FileHeader fh{};
    if (!src.read(off_file_header_, &fh, sizeof(fh))) {
        throw EipError(ErrorCode::PEParseFailed, "truncated file header");
    }
    if (fh.Machine != MACHINE_I386 && fh.Machine != MACHINE_AMD64) {
        throw EipError(ErrorCode::ArchitectureMismatch, "unsupported machine type");
    }
    arch_ = (fh.Machine == MACHINE_AMD64) ? Arch::X64 : Arch::X86;
    file_characteristics_ = fh.Characteristics;

    off_optional_header_ = off_file_header_ + sizeof(FileHeader);
    if (!src.read(off_optional_header_, &magic_, sizeof(magic_))) {
        throw EipError(ErrorCode::PEParseFailed, "truncated optional header");
    }

    if (magic_ == OPT_MAGIC_PE32) {
        OptionalHeader32 oh{};
        if (!src.read(off_optional_header_, &oh, sizeof(oh))) {
            throw EipError(ErrorCode::PEParseFailed, "truncated PE32 optional header");
        }
        image_base_ = oh.ImageBase;
        entry_point_rva_ = oh.AddressOfEntryPoint;
        size_of_image_ = oh.SizeOfImage;
        size_of_headers_ = oh.SizeOfHeaders;
        section_alignment_ = oh.SectionAlignment;
        file_alignment_ = oh.FileAlignment;
        subsystem_ = oh.Subsystem;
        off_checksum_field_ = off_optional_header_ + offsetof(OptionalHeader32, CheckSum);
        off_size_of_image_field_ = off_optional_header_ + offsetof(OptionalHeader32, SizeOfImage);
        u32 n = std::min<u32>(oh.NumberOfRvaAndSizes, DIR_COUNT);
        for (u32 i = 0; i < n; i++) data_dirs_[i] = oh.DataDirectories[i];
    } else if (magic_ == OPT_MAGIC_PE32PLUS) {
        OptionalHeader64 oh{};
        if (!src.read(off_optional_header_, &oh, sizeof(oh))) {
            throw EipError(ErrorCode::PEParseFailed, "truncated PE32+ optional header");
        }
        image_base_ = oh.ImageBase;
        entry_point_rva_ = oh.AddressOfEntryPoint;
        size_of_image_ = oh.SizeOfImage;
        size_of_headers_ = oh.SizeOfHeaders;
        section_alignment_ = oh.SectionAlignment;
        file_alignment_ = oh.FileAlignment;
        subsystem_ = oh.Subsystem;
        off_checksum_field_ = off_optional_header_ + offsetof(OptionalHeader64, CheckSum);
        off_size_of_image_field_ = off_optional_header_ + offsetof(OptionalHeader64, SizeOfImage);
        u32 n = std::min<u32>(oh.NumberOfRvaAndSizes, DIR_COUNT);
        for (u32 i = 0; i < n; i++) data_dirs_[i] = oh.DataDirectories[i];
    } else {
        throw EipError(ErrorCode::UnsupportedPE, "unrecognized optional header magic");
    }

    off_section_table_ = off_optional_header_ + fh.SizeOfOptionalHeader;

    sections_.clear();
    sections_.reserve(fh.NumberOfSections);
    for (u16 i = 0; i < fh.NumberOfSections; i++) {
        SectionHeader sh{};
        u64 pos = off_section_table_ + static_cast<u64>(i) * sizeof(SectionHeader);
        if (!src.read(pos, &sh, sizeof(sh))) {
            throw EipError(ErrorCode::PEParseFailed, "truncated section table");
        }
        SectionInfo s;
        s.name.assign(sh.Name, sh.Name + strnlen(sh.Name, 8));
        s.virtual_address = sh.VirtualAddress;
        s.virtual_size = sh.VirtualSize;
        s.raw_size = sh.SizeOfRawData;
        s.raw_offset = sh.PointerToRawData;
        s.characteristics = sh.Characteristics;
        sections_.push_back(s);
    }

    // Helper: resolve an RVA to a src-relative position using the sections
    // we just parsed (works for both OnDisk and Loaded, since src already
    // speaks the right coordinate system - file offset or RVA respectively).
    auto resolve = [&](RVA rva) -> std::optional<u64> {
        if (layout_ == PELayout::Loaded) return rva;
        if (rva < size_of_headers_) return rva;
        for (auto& s : sections_) {
            if (rva >= s.virtual_address && rva < s.virtual_address + std::max(s.virtual_size, s.raw_size)) {
                u64 delta = rva - s.virtual_address;
                if (delta >= s.raw_size) return std::nullopt; // in the zero-padded tail, not on disk
                return static_cast<u64>(s.raw_offset) + delta;
            }
        }
        return std::nullopt;
    };

    // ---- Exports -----------------------------------------------------
    if (data_dirs_[DIR_EXPORT].Size > 0) {
        if (auto off = resolve(data_dirs_[DIR_EXPORT].VirtualAddress)) {
            ExportDirectory ed{};
            if (src.read(*off, &ed, sizeof(ed))) {
                std::vector<RVA> func_rvas(ed.NumberOfFunctions);
                if (auto fo = resolve(ed.AddressOfFunctions))
                    src.read(*fo, func_rvas.data(), func_rvas.size() * sizeof(RVA));

                std::vector<RVA> name_rvas(ed.NumberOfNames);
                if (auto no = resolve(ed.AddressOfNames))
                    src.read(*no, name_rvas.data(), name_rvas.size() * sizeof(RVA));

                std::vector<u16> name_ords(ed.NumberOfNames);
                if (auto oo = resolve(ed.AddressOfNameOrdinals))
                    src.read(*oo, name_ords.data(), name_ords.size() * sizeof(u16));

                std::vector<std::string> names(ed.NumberOfNames);
                for (u32 i = 0; i < ed.NumberOfNames; i++) {
                    if (auto strOff = resolve(name_rvas[i])) {
                        char buf[512] = {0};
                        for (std::size_t k = 0; k < sizeof(buf) - 1; k++) {
                            char c = 0;
                            if (!src.read(*strOff + k, &c, 1) || c == 0) break;
                            buf[k] = c;
                        }
                        names[i] = buf;
                    }
                }

                std::vector<bool> has_name(ed.NumberOfFunctions, false);
                std::vector<std::string> fn_name(ed.NumberOfFunctions);
                for (u32 i = 0; i < ed.NumberOfNames; i++) {
                    if (name_ords[i] < ed.NumberOfFunctions) {
                        has_name[name_ords[i]] = true;
                        fn_name[name_ords[i]] = names[i];
                    }
                }

                RVA export_dir_start = data_dirs_[DIR_EXPORT].VirtualAddress;
                RVA export_dir_end = export_dir_start + data_dirs_[DIR_EXPORT].Size;
                for (u32 i = 0; i < ed.NumberOfFunctions; i++) {
                    if (func_rvas[i] == 0) continue;
                    ExportEntry e;
                    e.name = has_name[i] ? fn_name[i] : std::string();
                    e.ordinal = ed.Base + i;
                    e.rva = func_rvas[i];
                    e.is_forwarder = (func_rvas[i] >= export_dir_start && func_rvas[i] < export_dir_end);
                    if (e.is_forwarder) {
                        if (auto fwdOff = resolve(func_rvas[i])) {
                            char buf[512] = {0};
                            for (std::size_t k = 0; k < sizeof(buf) - 1; k++) {
                                char c = 0;
                                if (!src.read(*fwdOff + k, &c, 1) || c == 0) break;
                                buf[k] = c;
                            }
                            e.forwarder_target = buf;
                        }
                    }
                    exports_.push_back(std::move(e));
                }
            }
        }
    }

    // ---- Imports -------------------------------------------------------
    if (data_dirs_[DIR_IMPORT].Size > 0) {
        RVA cur = data_dirs_[DIR_IMPORT].VirtualAddress;
        for (;;) {
            auto off = resolve(cur);
            if (!off) break;
            ImportDescriptor id{};
            if (!src.read(*off, &id, sizeof(id))) break;
            if (id.Name == 0 && id.FirstThunk == 0 && id.OriginalFirstThunk == 0) break;

            ImportedModule mod;
            if (auto nOff = resolve(id.Name)) {
                char buf[256] = {0};
                for (std::size_t k = 0; k < sizeof(buf) - 1; k++) {
                    char c = 0;
                    if (!src.read(*nOff + k, &c, 1) || c == 0) break;
                    buf[k] = c;
                }
                mod.dll_name = buf;
            }

            RVA thunkRva = id.OriginalFirstThunk ? id.OriginalFirstThunk : id.FirstThunk;
            RVA iatRva = id.FirstThunk;
            bool pe32plus = is_pe32plus();
            for (u32 idx = 0;; idx++) {
                ImportedFunction fn;
                fn.iat_rva = iatRva + idx * (pe32plus ? 8 : 4);
                if (pe32plus) {
                    u64 thunk = 0;
                    auto tOff = resolve(thunkRva + idx * 8);
                    if (!tOff || !src.read(*tOff, &thunk, 8) || thunk == 0) break;
                    if (thunk & 0x8000000000000000ULL) {
                        fn.ordinal = static_cast<u16>(thunk & 0xFFFF);
                    } else {
                        RVA nameRva = static_cast<RVA>(thunk & 0x7FFFFFFF);
                        if (auto nOff = resolve(nameRva + 2)) { // skip Hint u16
                            char buf[256] = {0};
                            for (std::size_t k = 0; k < sizeof(buf) - 1; k++) {
                                char c = 0;
                                if (!src.read(*nOff + k, &c, 1) || c == 0) break;
                                buf[k] = c;
                            }
                            fn.name = buf;
                        }
                    }
                } else {
                    u32 thunk = 0;
                    auto tOff = resolve(thunkRva + idx * 4);
                    if (!tOff || !src.read(*tOff, &thunk, 4) || thunk == 0) break;
                    if (thunk & 0x80000000u) {
                        fn.ordinal = static_cast<u16>(thunk & 0xFFFF);
                    } else {
                        RVA nameRva = thunk & 0x7FFFFFFFu;
                        if (auto nOff = resolve(nameRva + 2)) {
                            char buf[256] = {0};
                            for (std::size_t k = 0; k < sizeof(buf) - 1; k++) {
                                char c = 0;
                                if (!src.read(*nOff + k, &c, 1) || c == 0) break;
                                buf[k] = c;
                            }
                            fn.name = buf;
                        }
                    }
                }
                mod.functions.push_back(std::move(fn));
            }
            imports_.push_back(std::move(mod));
            cur += sizeof(ImportDescriptor);
        }
    }

    // ---- Base relocations ----------------------------------------------
    if (data_dirs_[DIR_BASERELOC].Size > 0) {
        RVA base = data_dirs_[DIR_BASERELOC].VirtualAddress;
        u32 total = data_dirs_[DIR_BASERELOC].Size;
        u32 consumed = 0;
        while (consumed + sizeof(BaseRelocationBlockHeader) <= total) {
            auto off = resolve(base + consumed);
            if (!off) break;
            BaseRelocationBlockHeader hdr{};
            if (!src.read(*off, &hdr, sizeof(hdr)) || hdr.BlockSize < sizeof(hdr)) break;
            u32 entry_count = (hdr.BlockSize - sizeof(hdr)) / sizeof(u16);
            for (u32 i = 0; i < entry_count; i++) {
                u16 entry = 0;
                if (auto eOff = resolve(base + consumed + sizeof(hdr) + i * 2)) {
                    src.read(*eOff, &entry, 2);
                }
                u16 type = entry >> 12;
                u16 off_in_page = entry & 0x0FFF;
                if (type != 0) {
                    relocations_.push_back({hdr.PageRVA + off_in_page, type});
                }
            }
            consumed += hdr.BlockSize;
        }
    }

    // ---- TLS -------------------------------------------------------------
    if (data_dirs_[DIR_TLS].Size > 0) {
        if (auto off = resolve(data_dirs_[DIR_TLS].VirtualAddress)) {
            TlsInfo t{};
            if (is_pe32plus()) {
                TlsDirectory64 td{};
                if (src.read(*off, &td, sizeof(td))) {
                    t.start_address_of_raw_data = td.StartAddressOfRawData;
                    t.end_address_of_raw_data = td.EndAddressOfRawData;
                    t.address_of_index = td.AddressOfIndex;
                    t.address_of_callbacks = td.AddressOfCallBacks;
                    t.size_of_zero_fill = td.SizeOfZeroFill;
                    t.characteristics = td.Characteristics;
                }
            } else {
                TlsDirectory32 td{};
                if (src.read(*off, &td, sizeof(td))) {
                    t.start_address_of_raw_data = td.StartAddressOfRawData;
                    t.end_address_of_raw_data = td.EndAddressOfRawData;
                    t.address_of_index = td.AddressOfIndex;
                    t.address_of_callbacks = td.AddressOfCallBacks;
                    t.size_of_zero_fill = td.SizeOfZeroFill;
                    t.characteristics = td.Characteristics;
                }
            }
            if (t.address_of_callbacks != 0) {
                RVA cbRva = static_cast<RVA>(t.address_of_callbacks - image_base_);
                for (u32 i = 0; i < 64; i++) { // sane upper bound
                    Address cb = 0;
                    auto cbOff = resolve(cbRva + i * (is_pe32plus() ? 8 : 4));
                    if (!cbOff) break;
                    if (is_pe32plus()) {
                        u64 v = 0;
                        if (!src.read(*cbOff, &v, 8)) break;
                        cb = v;
                    } else {
                        u32 v = 0;
                        if (!src.read(*cbOff, &v, 4)) break;
                        cb = v;
                    }
                    if (cb == 0) break;
                    t.callbacks.push_back(cb);
                }
            }
            tls_ = t;
        }
    }

    // ---- Debug directory ---------------------------------------------
    if (data_dirs_[DIR_DEBUG].Size > 0) {
        u32 count = data_dirs_[DIR_DEBUG].Size / sizeof(DebugDirectoryEntry);
        for (u32 i = 0; i < count; i++) {
            auto off = resolve(data_dirs_[DIR_DEBUG].VirtualAddress + i * sizeof(DebugDirectoryEntry));
            if (!off) break;
            DebugDirectoryEntry de{};
            if (!src.read(*off, &de, sizeof(de))) break;
            debug_entries_.push_back({de.Type, de.SizeOfData, de.AddressOfRawData, de.PointerToRawData});
        }
    }

    // ---- Exception table (x64 .pdata) ----------------------------------
    if (arch_ == Arch::X64 && data_dirs_[DIR_EXCEPTION].Size > 0) {
        u32 count = data_dirs_[DIR_EXCEPTION].Size / sizeof(RuntimeFunction64);
        for (u32 i = 0; i < count; i++) {
            auto off = resolve(data_dirs_[DIR_EXCEPTION].VirtualAddress + i * sizeof(RuntimeFunction64));
            if (!off) break;
            RuntimeFunction64 rf{};
            if (!src.read(*off, &rf, sizeof(rf))) break;
            exception_table_.push_back({rf.BeginAddress, rf.EndAddress, rf.UnwindInfoAddress});
        }
    }

    resource_dir_rva_ = data_dirs_[DIR_RESOURCE].VirtualAddress;
}

// ---------------------------------------------------------------------------
const SectionInfo* PEImage::section_for_rva(RVA rva) const {
    for (auto& s : sections_) {
        if (rva >= s.virtual_address && rva < s.virtual_address + std::max(s.virtual_size, s.raw_size)) {
            return &s;
        }
    }
    return nullptr;
}

std::optional<u64> PEImage::rva_to_offset(RVA rva) const {
    if (layout_ == PELayout::Loaded) return rva;
    if (rva < size_of_headers_) return rva;
    if (auto* s = section_for_rva(rva)) {
        u64 delta = rva - s->virtual_address;
        if (delta >= s->raw_size) return std::nullopt;
        return static_cast<u64>(s->raw_offset) + delta;
    }
    return std::nullopt;
}

bool PEImage::try_read_rva(RVA rva, void* out, std::size_t size) const {
    if (layout_ == PELayout::Loaded) {
        return loaded_reader_ && loaded_reader_(rva, out, size);
    }
    auto off = rva_to_offset(rva);
    if (!off || *off + size > buffer_.size()) return false;
    std::memcpy(out, buffer_.data() + *off, size);
    return true;
}

std::vector<u8> PEImage::read_rva(RVA rva, std::size_t size) const {
    std::vector<u8> out(size);
    if (!try_read_rva(rva, out.data(), size)) {
        throw EipError(ErrorCode::AddressInvalid, "rva=0x" + std::to_string(rva));
    }
    return out;
}

std::optional<RVA> PEImage::find_export(const std::string& name) const {
    for (auto& e : exports_) {
        if (e.name == name) return e.rva;
    }
    return std::nullopt;
}

void PEImage::patch_bytes(RVA rva, const void* data, std::size_t size) {
    if (layout_ != PELayout::OnDisk) {
        throw EipError(ErrorCode::InvalidArgument, "patch_bytes requires an OnDisk-layout PEImage");
    }
    auto off = rva_to_offset(rva);
    if (!off || *off + size > buffer_.size()) {
        throw EipError(ErrorCode::AddressInvalid, "rva=0x" + std::to_string(rva) + " size=" + std::to_string(size));
    }
    std::memcpy(buffer_.data() + *off, data, size);
}

RVA PEImage::add_section(const std::string& name, const std::vector<u8>& data, u32 characteristics) {
    if (layout_ != PELayout::OnDisk) {
        throw EipError(ErrorCode::InvalidArgument, "add_section requires an OnDisk-layout PEImage");
    }
    if (name.size() > 8) {
        throw EipError(ErrorCode::InvalidArgument, "section name '" + name + "' exceeds 8 characters");
    }

    u16 old_count = static_cast<u16>(sections_.size());
    u64 header_table_end_needed = off_section_table_ + static_cast<u64>(old_count + 1) * sizeof(SectionHeader);
    u64 new_size_of_headers = align_up(header_table_end_needed, file_alignment_);

    u64 growth = (new_size_of_headers > size_of_headers_) ? (new_size_of_headers - size_of_headers_) : 0;

    if (growth > 0) {
        RVA first_section_va = sections_.empty() ? section_alignment_ : sections_.front().virtual_address;
        if (new_size_of_headers > first_section_va) {
            throw EipError(ErrorCode::PEWriteFailed,
                "not enough header slack to add a section without relocating the first section "
                "(needs " + std::to_string(growth) + " more bytes)");
        }
        // Shift everything from the old header boundary onward later by `growth`.
        buffer_.insert(buffer_.begin() + static_cast<long>(size_of_headers_), growth, 0);
        // Fix up every existing section's PointerToRawData (both our parsed
        // state and the raw bytes still sitting in the untouched header
        // table region before size_of_headers_).
        for (std::size_t i = 0; i < sections_.size(); i++) {
            sections_[i].raw_offset += static_cast<u32>(growth);
            u64 fieldOff = off_section_table_ + i * sizeof(SectionHeader) + offsetof(SectionHeader, PointerToRawData);
            u32 newVal = sections_[i].raw_offset;
            std::memcpy(buffer_.data() + fieldOff, &newVal, sizeof(newVal));
        }
        size_of_headers_ = static_cast<u32>(new_size_of_headers);
        // SizeOfHeaders lives in the Optional header, which is before
        // size_of_headers_ itself, so it was NOT shifted - patch directly.
        u32 sohVal = size_of_headers_;
        u64 sohFieldOff = off_optional_header_ + (is_pe32plus()
            ? offsetof(OptionalHeader64, SizeOfHeaders)
            : offsetof(OptionalHeader32, SizeOfHeaders));
        std::memcpy(buffer_.data() + sohFieldOff, &sohVal, sizeof(sohVal));
    }

    RVA last_end = section_alignment_;
    if (!sections_.empty()) {
        auto& last = sections_.back();
        last_end = static_cast<RVA>(align_up(last.virtual_address + std::max(last.virtual_size, last.raw_size), section_alignment_));
    }
    RVA new_va = last_end;
    u32 new_raw_size = static_cast<u32>(align_up(data.size(), file_alignment_));

    u64 new_raw_offset = align_up(buffer_.size(), file_alignment_);
    buffer_.resize(static_cast<std::size_t>(new_raw_offset)); // pad up to alignment
    buffer_.insert(buffer_.end(), data.begin(), data.end());
    buffer_.resize(static_cast<std::size_t>(new_raw_offset) + new_raw_size, 0); // pad tail to FileAlignment

    SectionHeader sh{};
    std::memset(&sh, 0, sizeof(sh));
    std::memcpy(sh.Name, name.data(), name.size());
    sh.VirtualAddress = new_va;
    sh.VirtualSize = static_cast<u32>(data.size());
    sh.PointerToRawData = static_cast<u32>(new_raw_offset);
    sh.SizeOfRawData = new_raw_size;
    sh.Characteristics = characteristics;

    u64 entryOff = off_section_table_ + static_cast<u64>(old_count) * sizeof(SectionHeader);
    if (entryOff + sizeof(SectionHeader) > buffer_.size()) {
        // Can happen if growth==0 but the slack sat beyond what resize() above
        // touched (header region itself, not section data) - ensure capacity.
        buffer_.resize(std::max<std::size_t>(buffer_.size(), entryOff + sizeof(SectionHeader)));
    }
    std::memcpy(buffer_.data() + entryOff, &sh, sizeof(sh));

    u16 newCount = static_cast<u16>(old_count + 1);
    u64 countFieldOff = off_file_header_ + offsetof(FileHeader, NumberOfSections);
    std::memcpy(buffer_.data() + countFieldOff, &newCount, sizeof(newCount));

    SectionInfo info;
    info.name = name;
    info.virtual_address = new_va;
    info.virtual_size = static_cast<u32>(data.size());
    info.raw_size = new_raw_size;
    info.raw_offset = static_cast<u32>(new_raw_offset);
    info.characteristics = characteristics;
    sections_.push_back(info);

    size_of_image_ = static_cast<u32>(align_up(new_va + info.virtual_size, section_alignment_));
    u32 sizeOfImageVal = size_of_image_;
    std::memcpy(buffer_.data() + off_size_of_image_field_, &sizeOfImageVal, sizeof(sizeOfImageVal));

    return new_va;
}

u32 PEImage::compute_checksum(const std::vector<u8>& file_bytes, std::size_t checksum_field_offset) {
    // Microsoft PE checksum algorithm: sum all 16-bit words (treating the
    // existing checksum field as zero), fold carries, then add the file size.
    u64 sum = 0;
    std::size_t len = file_bytes.size();
    for (std::size_t i = 0; i + 1 < len; i += 2) {
        if (i == checksum_field_offset || i == checksum_field_offset + 2) continue; // skip the 4-byte checksum field itself
        u16 word;
        std::memcpy(&word, file_bytes.data() + i, 2);
        sum += word;
        sum = (sum & 0xFFFFFFFF) + (sum >> 32);
    }
    if (len & 1) {
        sum += file_bytes[len - 1];
        sum = (sum & 0xFFFFFFFF) + (sum >> 32);
    }
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return static_cast<u32>(sum) + static_cast<u32>(len);
}

void PEImage::save(const std::string& path) const {
    if (layout_ != PELayout::OnDisk) {
        throw EipError(ErrorCode::InvalidArgument, "save() requires an OnDisk-layout PEImage");
    }
    std::vector<u8> out = buffer_;
    u32 checksum = compute_checksum(out, static_cast<std::size_t>(off_checksum_field_));
    std::memcpy(out.data() + off_checksum_field_, &checksum, sizeof(checksum));

    std::ofstream f(path, std::ios::binary | std::ios::trunc);
    if (!f) throw EipError(ErrorCode::IoError, "cannot open '" + path + "' for writing");
    f.write(reinterpret_cast<const char*>(out.data()), static_cast<std::streamsize>(out.size()));
    if (!f) throw EipError(ErrorCode::PEWriteFailed, "write failed for '" + path + "'");
}

} // namespace eip
