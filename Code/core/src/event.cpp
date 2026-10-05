#include "eip/event.h"
#include "eip/x86len.h"
#include <cstring>

namespace eip {

namespace {
constexpr std::size_t X64_JMP_STUB_SIZE = 12; // mov rax,imm64 (10) + jmp rax (2)

void append_u64_le(std::vector<u8>& v, u64 x) { for (int i = 0; i < 8; i++) v.push_back(static_cast<u8>((x >> (8 * i)) & 0xFF)); }
void append_u32_le(std::vector<u8>& v, u32 x) { for (int i = 0; i < 4; i++) v.push_back(static_cast<u8>((x >> (8 * i)) & 0xFF)); }

void append_jmp_abs64(std::vector<u8>& v, Address to) {
    v.push_back(0x48); v.push_back(0xB8); // mov rax, imm64
    append_u64_le(v, to);
    v.push_back(0xFF); v.push_back(0xE0); // jmp rax
}

// Hand-assembled x64 event-recording prologue. Ring buffer layout:
//   offset 0: u32 write_index (monotonically increasing total event count)
//   offset 4: u32 capacity (power of two)
//   offset 8 + i*8, for i = write_index & (capacity-1):
//     u32 event_id, u32 sequence (the write_index value at the time of this write)
//
// Fully preserves flags and every register it touches (rax/rbx/rcx/rdx),
// so it is safe to splice in front of arbitrary original code.
std::vector<u8> build_event_prologue(Address ring_addr, u32 event_id, u32 capacity_mask) {
    std::vector<u8> c;
    c.push_back(0x9C);                               // pushfq
    c.push_back(0x50);                               // push rax
    c.push_back(0x53);                               // push rbx
    c.push_back(0x51);                               // push rcx
    c.push_back(0x52);                               // push rdx

    c.push_back(0x48); c.push_back(0xB8);             // mov rax, imm64 ring_addr
    append_u64_le(c, ring_addr);

    c.push_back(0x8B); c.push_back(0x18);             // mov ebx, [rax]          ; ebx = write_index
    c.push_back(0x8B); c.push_back(0xCB);             // mov ecx, ebx            ; ecx = write_index
    c.push_back(0x81); c.push_back(0xE1);             // and ecx, capacity_mask
    append_u32_le(c, capacity_mask);
    c.push_back(0x6B); c.push_back(0xC9); c.push_back(0x08); // imul ecx, ecx, 8 ; slot byte offset

    c.push_back(0x48); c.push_back(0x8D); c.push_back(0x50); c.push_back(0x08); // lea rdx, [rax+8]
    c.push_back(0x48); c.push_back(0x01); c.push_back(0xCA);                     // add rdx, rcx     ; rdx = slot addr

    c.push_back(0xC7); c.push_back(0x02);              // mov dword [rdx], event_id
    append_u32_le(c, event_id);
    c.push_back(0x89); c.push_back(0x5A); c.push_back(0x04); // mov [rdx+4], ebx ; store sequence

    c.push_back(0xFF); c.push_back(0xC3);              // inc ebx
    c.push_back(0x89); c.push_back(0x18);               // mov [rax], ebx      ; write back write_index

    c.push_back(0x5A);                                  // pop rdx
    c.push_back(0x59);                                  // pop rcx
    c.push_back(0x5B);                                  // pop rbx
    c.push_back(0x58);                                  // pop rax
    c.push_back(0x9D);                                  // popfq
    return c;
}

std::size_t whole_instruction_span(const std::vector<u8>& window, std::size_t needed, bool is64) {
    std::size_t pos = 0;
    while (pos < needed) {
        auto len = x86len::decode_length(window.data() + pos, window.size() - pos, is64);
        if (!len || *len == 0) {
            throw EipError(ErrorCode::HookInstallFailed,
                "could not decode instruction at offset " + std::to_string(pos) + " while installing an event hook");
        }
        pos += *len;
    }
    return pos;
}
} // namespace

RingBuffer EventEngine::create_ring(u32 capacity) const {
    u32 cap = 1;
    while (cap < capacity) cap <<= 1;
    std::size_t total = 8 + static_cast<std::size_t>(cap) * 8;
    Address addr = proc_.memory().allocate(total, /*PAGE_READWRITE*/ 0x04);
    std::vector<u8> zero(total, 0);
    u32 capLE = cap;
    std::memcpy(zero.data() + 4, &capLE, 4);
    proc_.memory().write(addr, zero.data(), zero.size());
    return RingBuffer{addr, cap};
}

EventHookRecord EventEngine::install(const std::string& name, Address target, u32 event_id, const RingBuffer& ring) const {
    if (proc_.arch() != Arch::X64) {
        throw EipError(ErrorCode::NotImplementedOnPlatform, "event hooks currently support x64 targets only");
    }

    constexpr std::size_t WINDOW = 32;
    std::vector<u8> window(WINDOW);
    proc_.memory().read_into(target, window.data(), WINDOW);
    std::size_t span = whole_instruction_span(window, X64_JMP_STUB_SIZE, true);

    std::vector<u8> original(window.begin(), window.begin() + static_cast<long>(span));

    std::vector<u8> stubCode = build_event_prologue(ring.addr, event_id, ring.capacity - 1);
    for (u8 b : original) stubCode.push_back(b);
    append_jmp_abs64(stubCode, target + span);

    Address stubAddr = functions_.add(stubCode);

    std::vector<u8> patch(span, 0x90);
    std::vector<u8> jmpToStub;
    append_jmp_abs64(jmpToStub, stubAddr);
    std::memcpy(patch.data(), jmpToStub.data(), jmpToStub.size());
    proc_.memory().write_protected(target, patch.data(), patch.size());

    EventHookRecord rec;
    rec.name = name;
    rec.event_id = event_id;
    rec.target = target;
    rec.stub = stubAddr;
    rec.original_bytes = original;
    rec.patch_size = span;
    rec.ring = ring;
    rec.active = true;
    return rec;
}

void EventEngine::remove(EventHookRecord& rec) const {
    if (!rec.active) return;
    proc_.memory().write_protected(rec.target, rec.original_bytes.data(), rec.original_bytes.size());
    proc_.memory().free(rec.stub);
    rec.active = false;
}

std::vector<EventRecordEntry> EventEngine::poll(const RingBuffer& ring, u32 since_sequence) const {
    u32 writeIndex = current_sequence(ring);
    std::vector<EventRecordEntry> out;
    if (writeIndex <= since_sequence) return out;

    u32 count = writeIndex - since_sequence;
    if (count > ring.capacity) count = ring.capacity; // older entries were overwritten
    for (u32 i = writeIndex - count; i < writeIndex; i++) {
        u32 slot = i & (ring.capacity - 1);
        Address entryAddr = ring.addr + 8 + static_cast<u64>(slot) * 8;
        EventRecordEntry e{};
        proc_.memory().read_into(entryAddr, &e, sizeof(e));
        out.push_back(e);
    }
    return out;
}

u32 EventEngine::current_sequence(const RingBuffer& ring) const {
    u32 idx = 0;
    proc_.memory().read_into(ring.addr, &idx, sizeof(idx));
    return idx;
}

} // namespace eip
