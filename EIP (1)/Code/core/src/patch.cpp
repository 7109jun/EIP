#include "eip/patch.h"
#include <algorithm>
#include <cstring>

namespace eip {

void PersistentPatcher::add_value_change(RVA rva, std::vector<u8> new_bytes, std::string description) {
    changes_.push_back(PersistentValueChange{rva, std::move(new_bytes), std::move(description)});
}

void PersistentPatcher::add_code_injection(std::string section_name, std::vector<u8> code, u32 characteristics, std::string description) {
    changes_.push_back(PersistentCodeInjection{std::move(section_name), std::move(code), characteristics, std::move(description)});
}

std::vector<PatchPlanEntry> PersistentPatcher::apply(const std::string& output_path) {
    // Conflict detection: collect [rva, rva+size) ranges from every value
    // change and check for overlaps before mutating anything.
    struct Range { RVA start; RVA end; const std::string* desc; };
    std::vector<Range> ranges;
    for (auto& c : changes_) {
        if (auto* vc = std::get_if<PersistentValueChange>(&c)) {
            ranges.push_back({vc->rva, static_cast<RVA>(vc->rva + vc->new_bytes.size()), &vc->description});
        }
    }
    std::sort(ranges.begin(), ranges.end(), [](const Range& a, const Range& b) { return a.start < b.start; });
    for (std::size_t i = 1; i < ranges.size(); i++) {
        if (ranges[i].start < ranges[i - 1].end) {
            throw EipError(ErrorCode::PatchConflict,
                "'" + *ranges[i - 1].desc + "' overlaps '" + *ranges[i].desc + "'");
        }
    }

    PEImage img = PEImage::parse_file(input_path_);
    std::vector<PatchPlanEntry> plan;

    for (auto& c : changes_) {
        if (auto* vc = std::get_if<PersistentValueChange>(&c)) {
            img.patch_bytes(vc->rva, vc->new_bytes.data(), vc->new_bytes.size());
            plan.push_back({vc->description, ChangeState::Modified});
        } else if (auto* ci = std::get_if<PersistentCodeInjection>(&c)) {
            img.add_section(ci->section_name, ci->code, ci->characteristics);
            plan.push_back({ci->description, ChangeState::Added});
        }
    }

    img.save(output_path);
    return plan;
}

bool PersistentPatcher::verify(const std::string& output_path, const std::vector<PersistentValueChange>& expected) {
    std::optional<PEImage> img;
    try {
        img = PEImage::parse_file(output_path);
    } catch (const EipError&) {
        return false;
    }
    for (auto& e : expected) {
        std::vector<u8> actual;
        try {
            actual = img->read_rva(e.rva, e.new_bytes.size());
        } catch (const EipError&) {
            return false;
        }
        if (actual != e.new_bytes) return false;
    }
    return true;
}

} // namespace eip
