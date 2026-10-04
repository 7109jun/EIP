#include "eip/feature.h"
#include "eip/runtime.h"

namespace eip {

void Feature::add_value(const std::string& target, ValueType type, ScalarValue value, std::size_t capacity) {
    if (installed_) throw EipError(ErrorCode::FeatureAlreadyInstalled, name_);
    value_changes_.push_back({target, type, std::move(value), capacity});
}

void Feature::add_function(Address target, std::vector<u8> new_code) {
    if (installed_) throw EipError(ErrorCode::FeatureAlreadyInstalled, name_);
    function_changes_.push_back({target, std::move(new_code)});
}

void Feature::add_hook(Address target, Address detour) {
    if (installed_) throw EipError(ErrorCode::FeatureAlreadyInstalled, name_);
    hook_changes_.push_back({target, detour});
}

void Feature::add_event(const std::string& event_name, Address target, u32 event_id) {
    if (installed_) throw EipError(ErrorCode::FeatureAlreadyInstalled, name_);
    event_changes_.push_back({event_name, target, event_id});
}

void Feature::add_command(const std::string& command_name) {
    commands_.push_back(command_name);
}

void Feature::install() {
    if (installed_) throw EipError(ErrorCode::FeatureAlreadyInstalled, name_);

    value_engine_ = std::make_unique<ValueEngine>(proc_);
    function_engine_ = std::make_unique<FunctionEngine>(proc_);
    hook_engine_ = std::make_unique<HookEngine>(proc_);

    tx_ = std::make_unique<Transaction>(&runtime_);

    for (auto& vc : value_changes_) {
        tx_->value_set(*value_engine_, vc.target, vc.type, vc.value, vc.capacity);
    }

    installed_function_addrs_.clear();
    for (auto& fc : function_changes_) {
        auto out = std::make_shared<Address>(0);
        tx_->function_add(*function_engine_, fc.new_code, out);
        installed_function_addrs_.push_back(out);
        // Immediately queue the jump-in patch too, referencing the address
        // that will be filled once function_add's operation actually runs.
        // We capture `out` by shared_ptr so the lambda sees the real value.
        Address target = fc.target;
        Operation op;
        op.kind = ChangeKind::FunctionReplace;
        op.description = "feature function wire-up @0x" + std::to_string(target);
        auto originalBytes = std::make_shared<std::vector<u8>>();
        FunctionEngine* fePtr = function_engine_.get();
        op.apply = [=]() {
            auto result = fePtr->replace(target, *out);
            *originalBytes = result.original_bytes;
        };
        op.rollback = [=]() {
            fePtr->restore(target, *originalBytes);
        };
        tx_->add(std::move(op));
    }

    installed_hooks_.clear();
    for (auto& hc : hook_changes_) {
        auto rec = std::make_shared<HookRecord>();
        tx_->hook_install(*hook_engine_, hc.target, hc.detour, rec);
        installed_hooks_.push_back(rec);
    }

    // EventEngine must outlive the transaction's closures (they capture its
    // `this` pointer), so it is stored on the Feature itself rather than as
    // a local, mirroring how `functions`/`hooks` above are safe only because
    // install() itself doesn't return until commit() has finished using them.
    // For events specifically we persist installed records for inspection
    // (e.g. `eip status`), so we keep a dedicated owned engine + slot vector.
    event_engine_ = std::make_unique<EventEngine>(proc_);
    for (auto& ec : event_changes_) {
        RingBuffer ring = event_engine_->create_ring(64);
        std::string evName = ec.name;
        Address target = ec.target;
        u32 eventId = ec.event_id;
        EventEngine* eePtr = event_engine_.get();
        auto recSlot = std::make_shared<EventHookRecord>();

        Operation op;
        op.kind = ChangeKind::HookInstall;
        op.description = "event.install " + evName;
        op.apply = [=]() {
            *recSlot = eePtr->install(evName, target, eventId, ring);
        };
        op.rollback = [=]() {
            eePtr->remove(*recSlot);
        };
        tx_->add(std::move(op));
        installed_event_slots_.push_back(recSlot);
    }

    tx_->commit();

    for (auto& slot : installed_event_slots_) {
        installed_events_.push_back(*slot);
    }

    runtime_.record(ChangeKind::FeatureInstall, ChangeState::Added, "feature '" + name_ + "' installed");
    installed_ = true;
}

void Feature::uninstall() {
    if (!installed_) throw EipError(ErrorCode::FeatureNotFound, name_ + " is not installed");
    if (tx_) {
        tx_->rollback();
    }
    runtime_.record(ChangeKind::FeatureInstall, ChangeState::Removed, "feature '" + name_ + "' uninstalled");
    installed_ = false;
}

Feature& FeatureManager::create(const std::string& name) {
    if (features_.count(name)) {
        throw EipError(ErrorCode::FeatureAlreadyInstalled, "feature '" + name + "' already exists");
    }
    auto f = std::make_unique<Feature>(name, proc_, runtime_);
    Feature& ref = *f;
    features_[name] = std::move(f);
    return ref;
}

Feature& FeatureManager::get(const std::string& name) {
    auto it = features_.find(name);
    if (it == features_.end()) throw EipError(ErrorCode::FeatureNotFound, name);
    return *it->second;
}

bool FeatureManager::exists(const std::string& name) const {
    return features_.count(name) != 0;
}

std::vector<std::string> FeatureManager::list() const {
    std::vector<std::string> out;
    for (auto& [k, v] : features_) out.push_back(k);
    return out;
}

void FeatureManager::remove(const std::string& name) {
    auto it = features_.find(name);
    if (it == features_.end()) throw EipError(ErrorCode::FeatureNotFound, name);
    if (it->second->installed()) it->second->uninstall();
    features_.erase(it);
}

} // namespace eip
