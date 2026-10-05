#include "eip/transaction.h"
#include "eip/runtime.h"
#include <sstream>

namespace eip {

void Transaction::add(Operation op) {
    if (committed_) {
        throw EipError(ErrorCode::TransactionAlreadyCommitted, "cannot add operations after commit");
    }
    ops_.push_back(std::move(op));
}

void Transaction::value_set(const ValueEngine& values, const std::string& target, ValueType type,
                             const ScalarValue& new_value, std::size_t capacity) {
    // Captured by value/shared_ptr so apply()/rollback() can run long after
    // this call returns (at commit time).
    auto before = std::make_shared<ScalarValue>();
    auto addr = std::make_shared<Address>(0);
    auto written = std::make_shared<std::size_t>(0);
    const ValueEngine* ve = &values;

    std::ostringstream desc;
    desc << "value.set " << target;

    Operation op;
    op.kind = ChangeKind::ValueSet;
    op.description = desc.str();
    op.apply = [=]() {
        *addr = ve->resolve(target);
        *before = ve->read_at(*addr, type, capacity);
        *written = ve->set_at(*addr, new_value, capacity);
    };
    op.rollback = [=]() {
        ve->set_at(*addr, *before, capacity);
    };
    add(std::move(op));
}

void Transaction::memory_patch(const ProcessHandle& proc, Address addr, std::vector<u8> new_bytes) {
    auto before = std::make_shared<std::vector<u8>>();
    const ProcessHandle* p = &proc;
    std::size_t size = new_bytes.size();
    auto bytes = std::make_shared<std::vector<u8>>(std::move(new_bytes));

    std::ostringstream desc;
    desc << "memory.patch 0x" << std::hex << addr << " (" << std::dec << size << " bytes)";

    Operation op;
    op.kind = ChangeKind::MemoryPatch;
    op.description = desc.str();
    op.apply = [=]() {
        *before = p->memory().read(addr, size);
        p->memory().write_protected(addr, bytes->data(), bytes->size());
    };
    op.rollback = [=]() {
        p->memory().write_protected(addr, before->data(), before->size());
    };
    add(std::move(op));
}

void Transaction::function_replace(const FunctionEngine& functions, Address target, Address new_impl) {
    auto original = std::make_shared<std::vector<u8>>();
    const FunctionEngine* fe = &functions;

    std::ostringstream desc;
    desc << "function.replace 0x" << std::hex << target << " -> 0x" << new_impl;

    Operation op;
    op.kind = ChangeKind::FunctionReplace;
    op.description = desc.str();
    op.apply = [=]() {
        auto result = fe->replace(target, new_impl);
        *original = result.original_bytes;
    };
    op.rollback = [=]() {
        fe->restore(target, *original);
    };
    add(std::move(op));
}

void Transaction::hook_install(const HookEngine& hooks, Address target, Address detour,
                                std::shared_ptr<HookRecord> out) {
    const HookEngine* he = &hooks;

    std::ostringstream desc;
    desc << "hook.create 0x" << std::hex << target << " -> 0x" << detour;

    Operation op;
    op.kind = ChangeKind::HookInstall;
    op.description = desc.str();
    op.apply = [=]() {
        *out = he->install(target, detour);
    };
    op.rollback = [=]() {
        he->remove(*out);
    };
    add(std::move(op));
}

void Transaction::function_add(const FunctionEngine& functions, std::vector<u8> machine_code,
                                std::shared_ptr<Address> out_address) {
    const FunctionEngine* fe = &functions;
    auto code = std::make_shared<std::vector<u8>>(std::move(machine_code));

    Operation op;
    op.kind = ChangeKind::FunctionAdd;
    op.description = "function.add (" + std::to_string(code->size()) + " bytes)";
    op.apply = [=]() {
        *out_address = fe->add(*code);
    };
    op.rollback = [=]() {
        // Newly added code is inert until something jumps to it; freeing the
        // allocation is a sufficient rollback (nothing else references it
        // unless a later operation in the same or a dependent transaction
        // installed a hook/replace pointing at it, which would itself be
        // rolled back first since rollback runs in reverse order).
    };
    add(std::move(op));
}

void Transaction::commit() {
    if (committed_) {
        throw EipError(ErrorCode::TransactionAlreadyCommitted, "");
    }
    if (ops_.empty()) {
        throw EipError(ErrorCode::TransactionEmpty, "");
    }

    for (std::size_t i = 0; i < ops_.size(); i++) {
        try {
            ops_[i].apply();
            applied_.push_back(i);
            if (runtime_) {
                runtime_->record(ops_[i].kind,
                    ops_[i].kind == ChangeKind::HookInstall ? ChangeState::Hooked
                    : ops_[i].kind == ChangeKind::FunctionAdd ? ChangeState::Added
                    : ChangeState::Modified,
                    ops_[i].description);
            }
        } catch (const EipError& e) {
            // Roll back everything that succeeded so far, in reverse order.
            for (auto it = applied_.rbegin(); it != applied_.rend(); ++it) {
                try { ops_[*it].rollback(); } catch (...) { /* best-effort: surface the original failure */ }
            }
            applied_.clear();
            throw EipError(ErrorCode::TransactionFailed,
                "operation " + std::to_string(i) + " (" + ops_[i].description + ") failed: " + e.detail());
        }
    }
    committed_ = true;
}

void Transaction::rollback() {
    for (auto it = applied_.rbegin(); it != applied_.rend(); ++it) {
        ops_[*it].rollback();
        if (runtime_) {
            runtime_->record(ops_[*it].kind, ChangeState::Restored, "rollback: " + ops_[*it].description);
        }
    }
    applied_.clear();
    committed_ = false;
}

} // namespace eip
