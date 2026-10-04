// EIP native core - patch.h
// Persistent Patch: applies a set of changes to an on-disk PE file and
// writes the result to a new output file, without touching the original
// or requiring a live process (spec section 5 "Persistent Patch").
// Builds and runs on any platform, since it is pure PEImage mutation.
#pragma once
#include "eip/common.h"
#include "eip/pe.h"
#include <string>
#include <vector>
#include <variant>

namespace eip {

// A persistent change targets an RVA directly (resolved ahead of time by
// the caller from a symbol name via PEImage::find_export, since there is
// no live process here to do target-string resolution against modules).
struct PersistentValueChange {
    RVA rva;
    std::vector<u8> new_bytes; // already-encoded value bytes, same size as the original field
    std::string description;
};

struct PersistentCodeInjection {
    std::string section_name; // e.g. ".eip"
    std::vector<u8> code;
    u32 characteristics;
    std::string description;
};

using PersistentChange = std::variant<PersistentValueChange, PersistentCodeInjection>;

struct PatchPlanEntry {
    std::string description;
    ChangeState resulting_state;
};

class PersistentPatcher {
public:
    explicit PersistentPatcher(std::string input_path) : input_path_(std::move(input_path)) {}

    void add_value_change(RVA rva, std::vector<u8> new_bytes, std::string description);
    void add_code_injection(std::string section_name, std::vector<u8> code, u32 characteristics, std::string description);

    // Applies every queued change to a fresh copy of the input image and
    // writes it to `output_path`. Throws PatchConflict if two changes touch
    // overlapping byte ranges (detected before anything is written).
    // Returns the applied plan (for `eip status`-style reporting).
    std::vector<PatchPlanEntry> apply(const std::string& output_path);

    // Verifies a previously-written output is structurally valid and that
    // every planned value change is actually present at its RVA. Used by
    // tests and `eip inspect` to confirm a persistent patch really took.
    static bool verify(const std::string& output_path, const std::vector<PersistentValueChange>& expected);

private:
    std::string input_path_;
    std::vector<PersistentChange> changes_;
};

} // namespace eip
