// EIP native core - runtime.h
// Runtime ties everything together: the attached process plus every
// engine built on top of it (Value, Function, Hook, Feature), and the
// change log that answers "what has EIP actually done to this process"
// (spec section 10: Original/Modified/Added/Removed/Hooked/Restored).
#pragma once
#include "eip/common.h"
#include "eip/process.h"
#include "eip/value.h"
#include "eip/function.h"
#include "eip/hook.h"
#include <vector>
#include <string>
#include <memory>

namespace eip {

class FeatureManager; // see feature.h; only Session's .cpp needs the full type

struct ChangeRecord {
    u64 sequence;
    ChangeKind kind;
    ChangeState state;
    std::string description;
    Address address;
};

class Runtime {
public:
    void record(ChangeKind kind, ChangeState state, const std::string& description, Address address = 0);
    const std::vector<ChangeRecord>& changes() const { return changes_; }

    // A compact point-in-time snapshot (sequence -> count) usable to compute
    // "what changed between two moments" without storing full before/after
    // memory images (spec: "변경 전/후 상태를 비교할 수 있는 API").
    std::size_t checkpoint() const { return changes_.size(); }
    std::vector<ChangeRecord> diff_since(std::size_t checkpoint) const;

private:
    std::vector<ChangeRecord> changes_;
    u64 next_seq_ = 1;
};

// The live "attached program" object - what Python's `eip.attach(...)`
// returns under the hood. Owns the process handle and every engine that
// operates on it; nothing outlives this.
class Session {
public:
    explicit Session(ProcessHandle proc);
    ~Session();
    Session(const Session&) = delete;
    Session& operator=(const Session&) = delete;

    ProcessHandle& process() { return proc_; }
    const ProcessHandle& process() const { return proc_; }
    ValueEngine& values() { return values_; }
    FunctionEngine& functions() { return functions_; }
    HookEngine& hooks() { return hooks_; }
    Runtime& runtime() { return runtime_; }
    FeatureManager& features() { return *features_; }

private:
    ProcessHandle proc_;
    ValueEngine values_;
    FunctionEngine functions_;
    HookEngine hooks_;
    Runtime runtime_;
    std::unique_ptr<FeatureManager> features_;
};

} // namespace eip
