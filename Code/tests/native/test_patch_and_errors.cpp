// Real tests for: PersistentPatcher (apply + conflict detection + verify),
// and the native error-code vocabulary (section 9 of the spec). All of this
// is platform-independent, so it runs for real right here.
#include "eip/patch.h"
#include "eip/pe.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>

#define CHECK(cond, msg) do { \
    if (!(cond)) { std::fprintf(stderr, "FAIL: %s (%s:%d)\n", msg, __FILE__, __LINE__); std::exit(1); } \
    else { std::printf("  ok: %s\n", msg); } \
} while (0)

#define EXPECT_THROW_CODE(expr, expected_code, msg) do { \
    bool threw = false; \
    try { expr; } \
    catch (const eip::EipError& e) { threw = (e.code() == (expected_code)); } \
    CHECK(threw, msg); \
} while (0)

int main(int argc, char** argv) {
    if (argc < 2) { std::fprintf(stderr, "usage: %s <path-to-pe>\n", argv[0]); return 2; }
    const char* path = argv[1];

    std::printf("[1] PersistentPatcher basic apply + verify\n");
    eip::PEImage probe = eip::PEImage::parse_file(path);
    auto rva = probe.find_export("g_RunSpeed");
    CHECK(rva.has_value(), "found g_RunSpeed for patch test");

    {
        eip::PersistentPatcher patcher(path);
        int32_t newval = 77;
        std::vector<eip::u8> bytes(4);
        std::memcpy(bytes.data(), &newval, 4);
        patcher.add_value_change(*rva, bytes, "RunSpeed->77");
        std::string outPath = std::string(path) + ".patch_test.exe";
        auto plan = patcher.apply(outPath);
        CHECK(plan.size() == 1, "patch plan has 1 entry");

        std::vector<eip::PersistentValueChange> expected;
        expected.push_back({*rva, bytes, "RunSpeed->77"});
        CHECK(eip::PersistentPatcher::verify(outPath, expected), "verify() confirms the patched value on disk");
    }

    std::printf("[2] PersistentPatcher conflict detection\n");
    {
        eip::PersistentPatcher patcher(path);
        std::vector<eip::u8> a(4, 0x11), b(2, 0x22);
        patcher.add_value_change(*rva, a, "change A");
        patcher.add_value_change(*rva + 2, b, "change B (overlaps A)");
        EXPECT_THROW_CODE(patcher.apply(std::string(path) + ".conflict.exe"),
            eip::ErrorCode::PatchConflict, "overlapping changes raise PatchConflict");
    }

    std::printf("[3] PersistentPatcher.verify() rejects wrong values\n");
    {
        std::vector<eip::u8> wrong(4, 0xFF);
        std::vector<eip::PersistentValueChange> expected;
        expected.push_back({*rva, wrong, "should not match"});
        CHECK(!eip::PersistentPatcher::verify(std::string(path) + ".patch_test.exe", expected),
            "verify() correctly rejects a value that was never written");
    }

    std::printf("[4] error code round trip\n");
    CHECK(std::strcmp(eip::error_code_name(eip::ErrorCode::ProcessNotFound), "ProcessNotFound") == 0, "error_code_name(ProcessNotFound)");
    CHECK(std::strcmp(eip::error_code_name(eip::ErrorCode::ArchitectureMismatch), "ArchitectureMismatch") == 0, "error_code_name(ArchitectureMismatch)");
    try {
        throw eip::EipError(eip::ErrorCode::UnsupportedPE, "test detail");
    } catch (const eip::EipError& e) {
        CHECK(e.code() == eip::ErrorCode::UnsupportedPE, "thrown EipError preserves its code");
        CHECK(std::string(e.what()).find("test detail") != std::string::npos, "EipError::what() includes the detail string");
    }

    std::printf("[5] PEParseFailed on garbage input\n");
    {
        std::vector<eip::u8> garbage = {0x00, 0x01, 0x02, 0x03};
        EXPECT_THROW_CODE(eip::PEImage::parse_bytes(garbage), eip::ErrorCode::PEParseFailed, "garbage bytes raise PEParseFailed");
    }

    std::printf("[6] IoError on missing file\n");
    EXPECT_THROW_CODE(eip::PEImage::parse_file("/nonexistent/path/does_not_exist.exe"),
        eip::ErrorCode::IoError, "missing file raises IoError");

    std::printf("ALL PATCH + ERROR TESTS PASSED\n");
    return 0;
}
