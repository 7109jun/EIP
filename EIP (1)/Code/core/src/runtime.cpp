#include "eip/runtime.h"
#include "eip/feature.h"

namespace eip {

void Runtime::record(ChangeKind kind, ChangeState state, const std::string& description, Address address) {
    changes_.push_back(ChangeRecord{next_seq_++, kind, state, description, address});
}

std::vector<ChangeRecord> Runtime::diff_since(std::size_t checkpoint) const {
    if (checkpoint >= changes_.size()) return {};
    return std::vector<ChangeRecord>(changes_.begin() + static_cast<long>(checkpoint), changes_.end());
}

Session::Session(ProcessHandle proc)
    : proc_(std::move(proc)),
      values_(proc_),
      functions_(proc_),
      hooks_(proc_),
      features_(std::make_unique<FeatureManager>(proc_, runtime_)) {}

Session::~Session() = default;

} // namespace eip
