// Real, executable smoke test for the portable PE engine.
// Parses an actual mingw-built PE (path given as argv[1]) and checks real
// invariants: exported symbol resolution, section table sanity, round-trip
// save, and add_section(). This test runs for real (no mocks) because the
// PE engine itself has zero Windows API dependency.
#include "eip/pe.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>

#define CHECK(cond, msg) do { \
    if (!(cond)) { std::fprintf(stderr, "FAIL: %s (%s:%d)\n", msg, __FILE__, __LINE__); std::exit(1); } \
    else { std::printf("  ok: %s\n", msg); } \
} while (0)

int main(int argc, char** argv) {
    if (argc < 2) { std::fprintf(stderr, "usage: %s <path-to-pe>\n", argv[0]); return 2; }
    const char* path = argv[1];

    std::printf("[1] parse_file\n");
    eip::PEImage img = eip::PEImage::parse_file(path);
    CHECK(img.arch() == eip::Arch::X64, "arch is X64");
    CHECK(img.is_pe32plus(), "optional header is PE32+");
    CHECK(!img.sections().empty(), "has at least one section");
    CHECK(img.size_of_image() > 0, "SizeOfImage > 0");

    std::printf("[2] section table\n");
    bool found_text = false;
    for (auto& s : img.sections()) {
        std::printf("    %-8s VA=0x%-8x VSize=0x%-8x RawOff=0x%-8x RawSize=0x%-8x\n",
            s.name.c_str(), s.virtual_address, s.virtual_size, s.raw_offset, s.raw_size);
        if (s.name == ".text") { found_text = true; CHECK(s.executable(), ".text is executable"); }
    }
    CHECK(found_text, "found .text section");

    std::printf("[3] export table\n");
    bool found_export = false;
    for (auto& e : img.exports()) {
        std::printf("    export: %s rva=0x%x ordinal=%u\n", e.name.c_str(), e.rva, e.ordinal);
        if (e.name == "g_RunSpeed") found_export = true;
    }
    CHECK(found_export, "g_RunSpeed export found");

    auto rva = img.find_export("g_RunSpeed");
    CHECK(rva.has_value(), "find_export resolves g_RunSpeed");

    std::printf("[4] read_rva on resolved export (initial value == 10)\n");
    auto bytes = img.read_rva(*rva, 4);
    int32_t val = 0;
    std::memcpy(&val, bytes.data(), 4);
    std::printf("    g_RunSpeed initial = %d\n", val);
    CHECK(val == 10, "initial RunSpeed value is 10 as compiled");

    std::printf("[5] patch_bytes: RunSpeed 10 -> 20\n");
    int32_t newval = 20;
    img.patch_bytes(*rva, &newval, 4);
    auto bytes2 = img.read_rva(*rva, 4);
    int32_t val2 = 0;
    std::memcpy(&val2, bytes2.data(), 4);
    CHECK(val2 == 20, "patched value reads back as 20");

    std::printf("[6] add_section: inject a new .eip section\n");
    std::vector<uint8_t> payload = { 0xC3 }; // `ret` - minimal valid x64 code
    size_t section_count_before = img.sections().size();
    uint32_t new_va = img.add_section(".eip", payload, eip::pe_raw::SCN_MEM_READ | eip::pe_raw::SCN_MEM_EXECUTE | eip::pe_raw::SCN_CNT_CODE);
    CHECK(img.sections().size() == section_count_before + 1, "section count incremented");
    CHECK(new_va != 0, "new section got a non-zero RVA");
    auto injected = img.read_rva(new_va, 1);
    CHECK(injected[0] == 0xC3, "injected section bytes are readable back");

    std::printf("[7] save() round trip\n");
    std::string outPath = std::string(path) + ".patched.exe";
    img.save(outPath);

    eip::PEImage reparsed = eip::PEImage::parse_file(outPath);
    auto rva2 = reparsed.find_export("g_RunSpeed");
    CHECK(rva2.has_value(), "reparsed file still exports g_RunSpeed");
    auto rb = reparsed.read_rva(*rva2, 4);
    int32_t rv = 0;
    std::memcpy(&rv, rb.data(), 4);
    CHECK(rv == 20, "reparsed file shows patched value 20");

    bool found_eip_section = false;
    for (auto& s : reparsed.sections()) if (s.name == ".eip") found_eip_section = true;
    CHECK(found_eip_section, "reparsed file contains the injected .eip section");

    std::printf("ALL PE SMOKE TESTS PASSED\n");
    return 0;
}
