// EIP native core - transaction.h
// All compound changes go through a Transaction: operations are queued,
// then commit() applies them in order. If any operation throws, every
// operation applied so far is rolled back (in reverse order) and the
// whole transaction fails - no partially-applied state is left behind
// (spec section 6).
#pragma once
#include "eip/common.h"
#include "eip/process.h"
#include "eip/value.h"
#include "eip/function.h"
#include "eip/hook.h"
#include <functional>
#include <vector>
#include <string>
#include <memory>

namespace eip {

class Runtime; // fwd decl; Transaction reports applied changes to it when attached

struct Operation {
    ChangeKind kind;
    std::string description; // human-readable, surfaced in `eip status` / diffs
    std::function<void()> apply;
    std::function<void()> rollback;
};

class Transaction {
public:
    // `runtime` is optional: when non-null, every successfully applied
    // operation is recorded into its change log (Runtime::record), which is
    // what powers `eip status` / Original-Modified-Hooked tracking.
    explicit Transaction(Runtime* runtime = nullptr) : runtime_(runtime) {}

    void add(Operation op);

    // --- convenience builders (push a fully-formed Operation) -------------
    void value_set(const ValueEngine& values, const std::string& target, ValueType type,
                    const ScalarValue& new_value, std::size_t capacity = 0);

    void memory_patch(const ProcessHandle& proc, Address addr, std::vector<u8> new_bytes);

    void function_replace(const FunctionEngine& functions, Address target, Address new_impl);

    // On success, `*out` receives the installed HookRecord (valid once
    // commit() has actually run this operation, not before).
    void hook_install(const HookEngine& hooks, Address target, Address detour,
                       std::shared_ptr<HookRecord> out);

    void function_add(const FunctionEngine& functions, std::vector<u8> machine_code,
                       std::shared_ptr<Address> out_address);

    // Applies every queued operation in order. On any failure, rolls back
    // everything already applied (reverse order) and throws
    // EipError(TransactionFailed) wrapping the original error's detail.
    // Throws EipError(TransactionEmpty) if there are no operations.
    void commit();

    // Explicitly undoes everything this transaction applied. No-op if this
    // transaction was never committed, or was already rolled back.
    void rollback();

    bool committed() const { return committed_; }
    std::size_t operation_count() const { return ops_.size(); }

private:
    Runtime* runtime_;
    std::vector<Operation> ops_;
    std::vector<std::size_t> applied_;
    bool committed_ = false;
};

} // namespace eip
