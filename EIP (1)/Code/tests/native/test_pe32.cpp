// Real test against an actual 32-bit (PE32, not PE32+) mingw binary, to
// verify the PE engine correctly distinguishes 32-bit from 64-bit images
// (spec requirement: "32-bit과 64-bit PE 구조를 구분한다").
#include "eip/pe.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>

#define CHECK(cond, msg) do { \
    if (!(cond)) { std::fprintf(stderr, "FAIL: %s (%s:%d)\n", msg, __FILE__, __LINE__); std::exit(1); } \
    else { std::printf("  ok: %s\n", msg); } \
} while (0)

int main(int argc, char** argv) {
    if (argc < 2) { std::fprintf(stderr, "usage: %s <path-to-32bit-pe>\n", argv[0]); return 2; }

    eip::PEImage img = eip::PEImage::parse_file(argv[1]);
    CHECK(img.arch() == eip::Arch::X86, "arch is X86 (32-bit)");
    CHECK(!img.is_pe32plus(), "optional header is plain PE32 (not PE32+)");
    CHECK(img.image_base() < 0x100000000ULL, "32-bit image base fits in 32 bits");

    auto rva = img.find_export("g_RunSpeed");
    CHECK(rva.has_value(), "find_export resolves g_RunSpeed on a 32-bit PE");

    auto bytes = img.read_rva(*rva, 4);
    int32_t val = 0;
    std::memcpy(&val, bytes.data(), 4);
    CHECK(val == 10, "32-bit image initial RunSpeed is 10");

    int32_t newval = 20;
    img.patch_bytes(*rva, &newval, 4);
    auto bytes2 = img.read_rva(*rva, 4);
    std::memcpy(&val, bytes2.data(), 4);
    CHECK(val == 20, "32-bit image patched RunSpeed reads back as 20");

    std::string outPath = std::string(argv[1]) + ".patched32.exe";
    img.save(outPath);
    eip::PEImage reparsed = eip::PEImage::parse_file(outPath);
    CHECK(reparsed.arch() == eip::Arch::X86, "reparsed 32-bit file still reports X86");
    auto rva2 = reparsed.find_export("g_RunSpeed");
    auto rb = reparsed.read_rva(*rva2, 4);
    std::memcpy(&val, rb.data(), 4);
    CHECK(val == 20, "reparsed 32-bit file shows patched value 20");

    std::printf("ALL PE32 TESTS PASSED\n");
    return 0;
}
