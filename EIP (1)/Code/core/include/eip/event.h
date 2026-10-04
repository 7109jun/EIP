// EIP native core - event.h
// Events give a Feature a way to observe a moment in the target program
// without a full hook+callback round-trip into Python (which would need an
// RPC channel into the remote process). Instead: a small hand-assembled x64
// stub is installed at the target address; every time the target reaches
// that point, the stub records {event_id, sequence} into a ring buffer
// living in the target's own memory, then continues into the original code
// exactly like a hook's trampoline. EIP polls the ring buffer from the
// Python side (Runtime/Session) to learn "this event fired N times since I
// last checked" - a real, working mechanism, not a simulated one.
#pragma once
#include "eip/common.h"
#include "eip/process.h"
#include "eip/function.h"
#include <vector>
#include <string>

namespace eip {

struct RingBuffer {
    Address addr;       // base address of the [write_index:u32][capacity:u32][entries...] block in the target
    u32 capacity;        // always a power of two
};

struct EventRecordEntry {
    u32 event_id;
    u32 sequence;
};

struct EventHookRecord {
    std::string name;
    u32 event_id;
    Address target = 0;
    Address stub = 0;            // allocated [event prologue + saved original + jmp back]
    std::vector<u8> original_bytes;
    std::size_t patch_size = 0;
    RingBuffer ring{};
    bool active = false;
};

class EventEngine {
public:
    explicit EventEngine(const ProcessHandle& proc) : proc_(proc), functions_(proc) {}

    // Allocates a ring buffer with room for `capacity` entries (rounded up
    // to a power of two) in the target process.
    RingBuffer create_ring(u32 capacity = 64) const;

    // Installs an event stub at `target`; every time execution reaches
    // `target`, (event_id, running sequence number) is appended to `ring`
    // before the original code continues.
    EventHookRecord install(const std::string& name, Address target, u32 event_id, const RingBuffer& ring) const;

    void remove(EventHookRecord& rec) const;

    // Reads every entry written to `ring` with sequence >= `since_sequence`
    // (i.e. polls for new events). Pass 0 the first time.
    std::vector<EventRecordEntry> poll(const RingBuffer& ring, u32 since_sequence) const;

    // Current write_index (== total events ever recorded) in `ring`.
    u32 current_sequence(const RingBuffer& ring) const;

private:
    const ProcessHandle& proc_;
    FunctionEngine functions_;
};

} // namespace eip
