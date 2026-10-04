// EIP native core - feature.h
// Feature is the top-level unit of "install a new capability into the
// running program" (spec section 4: the most important high-level
// concept). A Feature bundles any number of value sets, function
// replacements, new functions, hooks and events into one named,
// installable/uninstallable unit, applied atomically via one Transaction.
#pragma once
#include "eip/common.h"
#include "eip/process.h"
#include "eip/value.h"
#include "eip/function.h"
#include "eip/hook.h"
#include "eip/event.h"
#include "eip/transaction.h"
#include <string>
#include <vector>
#include <memory>
#include <map>

namespace eip {

class Runtime;

// One queued change inside a Feature, expressed independently of
// Transaction so a Feature can be built up (add_value, add_function,
// add_hook, add_event) before anything has actually executed, then turned
// into real Operations only at install() time.
struct FeatureValueChange {
    std::string target;
    ValueType type;
    ScalarValue value;
    std::size_t capacity = 0;
};

struct FeatureFunctionChange {
    Address target;
    std::vector<u8> new_code; // written via FunctionEngine::add, then replace() jumps to it
};

struct FeatureHookChange {
    Address target;
    Address detour; // must already be allocated (e.g. via a prior add_function in the same feature)
};

struct FeatureEventChange {
    std::string name;
    Address target;
    u32 event_id;
};

class Feature {
public:
    Feature(std::string name, ProcessHandle& proc, Runtime& runtime)
        : name_(std::move(name)), proc_(proc), runtime_(runtime) {}

    const std::string& name() const { return name_; }

    void add_value(const std::string& target, ValueType type, ScalarValue value, std::size_t capacity = 0);
    void add_function(Address target, std::vector<u8> new_code); // allocates new_code, then replaces target to jump to it
    void add_hook(Address target, Address detour);
    void add_event(const std::string& event_name, Address target, u32 event_id);
    // "add_command" (spec section 4, feature.add_command) is a Python-side
    // concept (a CLI/API entry point the Feature exposes) with no native
    // memory effect, so it is recorded as metadata only - see python/eip/feature.py.
    void add_command(const std::string& command_name);

    bool installed() const { return installed_; }

    // Applies every queued change as one Transaction. On failure, nothing
    // is left applied (Transaction::commit's rollback guarantee).
    void install();

    // Reverses every applied change (hooks removed, replaced functions
    // restored, values... are NOT reverted to pre-feature state for value
    // changes with no captured "before", by design - use value_set's own
    // Transaction rollback semantics when that matters; Feature-level
    // uninstall targets hooks/functions, which are fully reversible).
    void uninstall();

    const std::vector<std::string>& commands() const { return commands_; }

private:
    std::string name_;
    ProcessHandle& proc_;
    Runtime& runtime_;

    std::vector<FeatureValueChange> value_changes_;
    std::vector<FeatureFunctionChange> function_changes_;
    std::vector<FeatureHookChange> hook_changes_;
    std::vector<FeatureEventChange> event_changes_;
    std::vector<std::string> commands_;

    std::unique_ptr<Transaction> tx_;
    std::vector<std::shared_ptr<HookRecord>> installed_hooks_;
    std::vector<std::shared_ptr<Address>> installed_function_addrs_;
    // Owned for the lifetime of the Feature (not just install()): the
    // Transaction's rollback closures capture these engines by pointer and
    // may run later from uninstall(), well after install() has returned.
    std::unique_ptr<ValueEngine> value_engine_;
    std::unique_ptr<FunctionEngine> function_engine_;
    std::unique_ptr<HookEngine> hook_engine_;
    std::unique_ptr<EventEngine> event_engine_;
    std::vector<std::shared_ptr<EventHookRecord>> installed_event_slots_;
    std::vector<EventHookRecord> installed_events_;
    bool installed_ = false;
};

// Owns every Feature created for one Session, keyed by name - this is what
// `program.feature.create("Export")` / lookups by name resolve against.
class FeatureManager {
public:
    FeatureManager(ProcessHandle& proc, Runtime& runtime) : proc_(proc), runtime_(runtime) {}

    Feature& create(const std::string& name);
    Feature& get(const std::string& name);
    bool exists(const std::string& name) const;
    std::vector<std::string> list() const;
    void remove(const std::string& name);

private:
    ProcessHandle& proc_;
    Runtime& runtime_;
    std::map<std::string, std::unique_ptr<Feature>> features_;
};

} // namespace eip
