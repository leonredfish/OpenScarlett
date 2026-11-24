#define OPENSCARLETT_BUILDING_ACPHAL 1
#include "openscarlett/audio/acphal_abi.h"
#include "openscarlett/audio/xma2_decoder.h"
#include "openscarlett/core/telemetry.h"

#include <algorithm>
#include <atomic>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <map>
#include <memory>
#include <mutex>
#include <new>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#if defined(_WIN32)
#  include <malloc.h>
#  include <windows.h>
#endif

namespace {

constexpr const char* kModName = "AcpHal.dll";
constexpr uint32_t kMaxAcpContexts = 256u;

inline int32_t RecordHr(const char* sym, int32_t hr, int32_t slot = -1) {
    openscarlett::CallTelemetry::Global().Record(
        kModName,
        sym,
        hr >= 0 ? openscarlett::CallOutcome::Ok : openscarlett::CallOutcome::Error,
        hr,
        slot);
    return hr;
}

inline void RecordOk(const char* sym, int32_t slot = -1) {
    openscarlett::CallTelemetry::Global().Record(
        kModName, sym, openscarlett::CallOutcome::Ok, 0, slot);
}

bool GuidEquals(const AcpHalGuid* a, const AcpHalGuid& b) {
    return a && std::memcmp(a, &b, sizeof(AcpHalGuid)) == 0;
}

openscarlett::Xma2Config ToXma2Config(const AcpHalXmaContextDesc& desc) {
    openscarlett::Xma2Config cfg{};
    cfg.sample_rate = desc.sampleRate != 0 ? desc.sampleRate : 48000u;
    cfg.channels = desc.channels != 0 ? desc.channels : 2u;
    cfg.block_size = desc.blockSize != 0 ? desc.blockSize : openscarlett::kXma2DefaultBlockSize;
    cfg.subframes_per_frame = desc.subframesPerFrame != 0 ? desc.subframesPerFrame : 4u;
    cfg.quant_bits = desc.quantBits != 0 ? desc.quantBits : 12u;
    return cfg;
}

struct AcpShapeAllocation {
    uint32_t num_xma = 0;
    uint32_t num_src = 0;
    uint32_t num_eq = 0;
    uint32_t num_dma = 0;
    void* stage_buffers[4] = {};
};

// Real retail Xbox Series X|S ACP_SHAPE_CONTEXTS (0x60 bytes, verified against fmod.dll).
struct XboxAcpShapeContexts {
    uint32_t numSrcContexts;      // +0x00 (32 bytes each -> srcContexts)
    uint32_t numEqCompContexts;   // +0x04 (32 bytes each -> eqCompContexts)
    uint32_t numFiltVolContexts;  // +0x08 (32 bytes each -> filtVolContexts)
    uint32_t numDmaContexts;      // +0x0C (16 bytes each -> dmaContexts)
    uint32_t numXmaContexts;      // +0x10 (64 bytes each -> xmaContexts)
    uint32_t numPcmContexts;      // +0x14 (64 bytes each -> pcmContexts)
    void* srcContexts;            // +0x18
    void* eqCompContexts;         // +0x20
    void* filtVolContexts;        // +0x28
    void* dmaContexts;            // +0x30
    void* xmaContexts;            // +0x38
    void* pcmContexts;            // +0x40
    uint64_t reserved[3];         // +0x48..0x5F
};
static_assert(sizeof(XboxAcpShapeContexts) == 0x60, "XboxAcpShapeContexts must be 96 bytes");

struct XboxAcpMessage {
    uint32_t type = 0;       // +0x00 (0x10 = CommandCompleted, 0x80 = Disconnected)
    uint32_t error = 0;      // +0x04 (0 = OK)
    uint64_t reserved = 0;   // +0x08
    uint64_t commandId = 0;  // +0x10
    uint32_t extra = 0;      // +0x18
};
static_assert(sizeof(XboxAcpMessage) == 0x20 || sizeof(XboxAcpMessage) == 0x1C, "XboxAcpMessage size");

// Real retail Xbox Series X|S IAcpHal vtable (does NOT inherit IUnknown;
// verified against Xbox fmod.dll:
//   slot 0 (+0x00): Connect(cmdQueueLen, msgQueueLen)
//   slot 1 (+0x08): Disconnect()
//   slot 2 (+0x10): SubmitCommand(cmdType, cmdId, flags, pData, dataFlags)
//   slot 3 (+0x18): PopMessage(ACP_MESSAGE* outMsg) -> bool
//   slot 4 (+0x20): RegisterEvent / GetQueueSpace
//   slot 5 (+0x28): Release()
class XboxRetailAcpHalImpl {
public:
    virtual int32_t OPENSCARLETT_ACPHAL_CALL Connect(
        uint32_t commandQueueLength, uint32_t messageQueueLength) {
        (void)commandQueueLength;
        (void)messageQueueLength;
        std::lock_guard<std::mutex> lk(mutex_);
        connected_ = true;
        messages_.clear();
        return RecordHr("IAcpHal::Connect", ACPHAL_S_OK, 0);
    }

    virtual int32_t OPENSCARLETT_ACPHAL_CALL Disconnect() {
        std::lock_guard<std::mutex> lk(mutex_);
        connected_ = false;
        XboxAcpMessage msg{};
        msg.type = 0x80u;  // ACP_MESSAGE_TYPE_DISCONNECTED
        msg.error = 0u;
        messages_.push_back(msg);
        return RecordHr("IAcpHal::Disconnect", ACPHAL_S_OK, 1);
    }

    virtual int32_t OPENSCARLETT_ACPHAL_CALL SubmitCommand(
        uint32_t commandType,
        uint64_t commandId,
        uint32_t waitFlags,
        const void* pCommandData,
        uint32_t extraFlags) {
        (void)commandType;
        (void)waitFlags;
        (void)pCommandData;
        (void)extraFlags;
        if (commandId != 0ull) {
            std::lock_guard<std::mutex> lk(mutex_);
            XboxAcpMessage msg{};
            msg.type = 0x10u;  // ACP_MESSAGE_TYPE_COMMAND_COMPLETED
            msg.error = 0u;
            msg.commandId = commandId;
            messages_.push_back(msg);
        }
        return RecordHr("IAcpHal::SubmitCommand", ACPHAL_S_OK, 2);
    }

    virtual bool OPENSCARLETT_ACPHAL_CALL PopMessage(void* pMessage) {
        std::lock_guard<std::mutex> lk(mutex_);
        if (messages_.empty()) {
            return false;
        }
        const XboxAcpMessage msg = messages_.front();
        messages_.pop_front();
        if (pMessage) {
            std::memcpy(pMessage, &msg, 0x1Cu);
        }
        return true;
    }

    virtual uint32_t OPENSCARLETT_ACPHAL_CALL GetCommandQueueSpace() {
        return 0x800u;
    }

    virtual uint32_t OPENSCARLETT_ACPHAL_CALL Release() {
        RecordOk("IAcpHal::Release", 5);
        delete this;
        return 0u;
    }

private:
    std::mutex mutex_;
    bool connected_ = false;
    std::deque<XboxAcpMessage> messages_;
};

std::atomic<bool> g_xbox_retail_acphal_mode{false};
std::mutex g_shape_alloc_mutex;
std::unordered_set<void*> g_synthetic_shape_allocs;
std::vector<void*> g_xbox_shape_buffers;

class AcpHalImpl final : public IAcpHal {
public:
    int32_t OPENSCARLETT_ACPHAL_CALL QueryInterface(
        const AcpHalGuid* riid, void** ppvObject) override {
        if (!ppvObject) return RecordHr("IAcpHal::QueryInterface", ACPHAL_E_POINTER, 0);
        *ppvObject = nullptr;
        if (!riid) return RecordHr("IAcpHal::QueryInterface", ACPHAL_E_INVALIDARG, 0);
        if (GuidEquals(riid, IID_OS_AcpHal_IUnknown) || GuidEquals(riid, IID_IAcpHal)) {
            AddRef();
            *ppvObject = static_cast<IAcpHal*>(this);
            return RecordHr("IAcpHal::QueryInterface", ACPHAL_S_OK, 0);
        }
        return RecordHr("IAcpHal::QueryInterface", ACPHAL_E_NOINTERFACE, 0);
    }

    uint32_t OPENSCARLETT_ACPHAL_CALL AddRef() override {
        RecordOk("IAcpHal::AddRef", 1);
        return ref_count_.fetch_add(1, std::memory_order_relaxed) + 1;
    }

    uint32_t OPENSCARLETT_ACPHAL_CALL Release() override {
        RecordOk("IAcpHal::Release", 2);
        const uint32_t rem = ref_count_.fetch_sub(1, std::memory_order_acq_rel) - 1;
        if (rem == 0) {
            delete this;
        }
        return rem;
    }

    int32_t OPENSCARLETT_ACPHAL_CALL ConfigureXmaContext(
        uint32_t contextIndex, const AcpHalXmaContextDesc* desc) override {
        if (contextIndex >= kMaxAcpContexts || !desc) {
            return RecordHr("IAcpHal::ConfigureXmaContext", ACPHAL_E_INVALIDARG, 3);
        }
        std::lock_guard<std::mutex> lk(mutex_);
        auto& dec = decoders_[contextIndex];
        if (!dec) {
            dec = std::make_unique<openscarlett::Xma2Decoder>();
        }
        const auto st = dec->Initialize(ToXma2Config(*desc));
        return RecordHr("IAcpHal::ConfigureXmaContext", st.ok() ? ACPHAL_S_OK : ACPHAL_E_INVALIDARG, 3);
    }

    int32_t OPENSCARLETT_ACPHAL_CALL SubmitCommand(const AcpHalCommand* command) override {
        if (!command) {
            return RecordHr("IAcpHal::SubmitCommand", ACPHAL_E_INVALIDARG, 4);
        }
        const int32_t hr = ExecuteCommand(*command);
        return RecordHr("IAcpHal::SubmitCommand", hr, 4);
    }

    int32_t OPENSCARLETT_ACPHAL_CALL SubmitCommands(
        uint32_t count, const AcpHalCommand* commands) override {
        if (count > 0 && !commands) {
            return RecordHr("IAcpHal::SubmitCommands", ACPHAL_E_INVALIDARG, 5);
        }
        for (uint32_t i = 0; i < count; ++i) {
            const int32_t hr = ExecuteCommand(commands[i]);
            if (hr < 0) {
                return RecordHr("IAcpHal::SubmitCommands", hr, 5);
            }
        }
        return RecordHr("IAcpHal::SubmitCommands", ACPHAL_S_OK, 5);
    }

    int32_t OPENSCARLETT_ACPHAL_CALL WaitIdle() override {
        std::lock_guard<std::mutex> lk(mutex_);
        return RecordHr("IAcpHal::WaitIdle", ACPHAL_S_OK, 6);
    }

    int32_t OPENSCARLETT_ACPHAL_CALL GetDecodedPacketCount(
        uint32_t contextIndex, uint64_t* packetCount) override {
        if (contextIndex >= kMaxAcpContexts || !packetCount) {
            return RecordHr("IAcpHal::GetDecodedPacketCount", ACPHAL_E_INVALIDARG, 7);
        }
        std::lock_guard<std::mutex> lk(mutex_);
        auto it = decoders_.find(contextIndex);
        *packetCount = (it != decoders_.end() && it->second)
                           ? it->second->Stats().packets_parsed
                           : 0u;
        return RecordHr("IAcpHal::GetDecodedPacketCount", ACPHAL_S_OK, 7);
    }

private:
    int32_t ExecuteCommand(const AcpHalCommand& cmd) {
        std::lock_guard<std::mutex> lk(mutex_);
        switch (cmd.type) {
            case AcpHalCommand_Nop:
            case AcpHalCommand_Flush:
                return ACPHAL_S_OK;

            case AcpHalCommand_ResetContext: {
                if (cmd.contextIndex >= kMaxAcpContexts) {
                    return ACPHAL_E_INVALIDARG;
                }
                auto it = decoders_.find(cmd.contextIndex);
                if (it != decoders_.end() && it->second) {
                    it->second->Reset();
                }
                return ACPHAL_S_OK;
            }

            case AcpHalCommand_XmaDecode: {
                if (cmd.contextIndex >= kMaxAcpContexts ||
                    !cmd.inputData || cmd.inputBytes == 0) {
                    return ACPHAL_E_INVALIDARG;
                }
                auto& dec = decoders_[cmd.contextIndex];
                if (!dec) {
                    dec = std::make_unique<openscarlett::Xma2Decoder>();
                }
                if (!dec->IsInitialized()) {
                    const auto init_st = dec->Initialize(ToXma2Config(cmd.xmaConfig));
                    if (!init_st.ok()) {
                        return ACPHAL_E_INVALIDARG;
                    }
                }

                if (cmd.outputFloatPcm) {
                    std::vector<float> pcm;
                    const auto st = dec->DecodePackets(cmd.inputData, cmd.inputBytes, pcm);
                    if (!st.ok()) {
                        return ACPHAL_E_FAIL;
                    }
                    const uint32_t to_copy = std::min<uint32_t>(
                        cmd.outputCapacitySamples, static_cast<uint32_t>(pcm.size()));
                    if (to_copy > 0) {
                        std::memcpy(cmd.outputFloatPcm, pcm.data(), to_copy * sizeof(float));
                    }
                    if (cmd.outSamplesWritten) {
                        *cmd.outSamplesWritten = to_copy;
                    }
                    return ACPHAL_S_OK;
                }

                if (cmd.outputInt16Pcm) {
                    std::vector<int16_t> pcm;
                    const auto st = dec->DecodePacketsInt16(cmd.inputData, cmd.inputBytes, pcm);
                    if (!st.ok()) {
                        return ACPHAL_E_FAIL;
                    }
                    const uint32_t to_copy = std::min<uint32_t>(
                        cmd.outputCapacitySamples, static_cast<uint32_t>(pcm.size()));
                    if (to_copy > 0) {
                        std::memcpy(cmd.outputInt16Pcm, pcm.data(), to_copy * sizeof(int16_t));
                    }
                    if (cmd.outSamplesWritten) {
                        *cmd.outSamplesWritten = to_copy;
                    }
                    return ACPHAL_S_OK;
                }

                return ACPHAL_E_INVALIDARG;
            }

            default:
                return ACPHAL_E_INVALIDARG;
        }
    }

    std::atomic<uint32_t> ref_count_{1};
    std::mutex mutex_;
    std::unordered_map<uint32_t, std::unique_ptr<openscarlett::Xma2Decoder>> decoders_;
};

// ---------------------------------------------------------------------------
// Thread-safe Xbox APU Audio Heap Manager (ApuCreateHeap / ApuAlloc / ApuFree /
// ApuHeapGetState / ApuIsVirtualAddressValid / ApuMapVirtualAddress / ApuMapApuAddress)
// ---------------------------------------------------------------------------

constexpr uint32_t kDefaultApuCachedHeapBytes = 64u * 1024u * 1024u;
constexpr uint32_t kDefaultApuNonCachedHeapBytes = 64u * 1024u * 1024u;
constexpr uint32_t kCachedApuSpaceBase = 0x10000000u;
constexpr uint32_t kCachedApuSpaceSize = 0x70000000u;
constexpr uint32_t kNonCachedApuSpaceBase = 0x80000000u;
constexpr uint32_t kNonCachedApuSpaceSize = 0x70000000u;
constexpr uint32_t kDefaultAlignmentBytes = 64u;
constexpr uint32_t kMaxApuAlignmentBytes = 0x10000000u;  // 256 MiB max alignment
constexpr uint64_t kMaxShapeStageBytes = 256ull * 1024ull * 1024ull;

inline bool IsPowerOfTwo(uint32_t v) {
    return v != 0u && (v & (v - 1u)) == 0u;
}

inline bool CheckedAlignUpU64(uint64_t value, uint64_t alignment, uint64_t& out) {
    if (alignment == 0ull || (alignment & (alignment - 1ull)) != 0ull) {
        return false;
    }
    const uint64_t mask = alignment - 1ull;
    if (value > UINT64_MAX - mask) {
        return false;
    }
    out = (value + mask) & ~mask;
    return true;
}

inline void* AlignedAllocHost(size_t size, size_t alignment) {
#if defined(_WIN32)
    return _aligned_malloc(size, alignment);
#else
    void* ptr = nullptr;
    if (posix_memalign(&ptr, std::max<size_t>(alignment, sizeof(void*)), size) != 0) {
        return nullptr;
    }
    return ptr;
#endif
}

inline void AlignedFreeHost(void* ptr) {
    if (!ptr) return;
#if defined(_WIN32)
    _aligned_free(ptr);
#else
    std::free(ptr);
#endif
}

struct ApuFreeRange {
    uint32_t start = 0;
    uint32_t size = 0;
};

struct ApuHeapPool {
    uint32_t space_base = 0;
    uint32_t space_size = 0;
    uint32_t capacity = 0;
    uint32_t bytes_allocated = 0;
    uint32_t bytes_lost = 0;
    uint32_t allocation_count = 0;
    std::vector<ApuFreeRange> free_ranges;

    void InitAddressSpace(uint32_t base, uint32_t size) {
        space_base = base;
        space_size = size;
        free_ranges.clear();
        free_ranges.push_back(ApuFreeRange{base, size});
    }

    bool IsRangeWithinSpace(uint64_t start, uint64_t span) const noexcept {
        if (span == 0ull || start + span < start) {
            return false;
        }
        const uint64_t end = start + span;
        const uint64_t space_end = static_cast<uint64_t>(space_base) + static_cast<uint64_t>(space_size);
        return start >= space_base && end <= space_end && end <= 0x100000000ull;
    }

    bool AllocateApuRange(uint32_t span, uint32_t alignment, APU_ADDRESS* out_addr) {
        if (!out_addr || span == 0u || alignment == 0u) {
            return false;
        }
        for (size_t i = 0; i < free_ranges.size(); ++i) {
            const uint64_t r_start = free_ranges[i].start;
            const uint64_t r_end = r_start + static_cast<uint64_t>(free_ranges[i].size);
            uint64_t aligned = 0ull;
            if (!CheckedAlignUpU64(r_start, alignment, aligned)) {
                continue;
            }
            const uint64_t alloc_end = aligned + static_cast<uint64_t>(span);
            if (alloc_end < aligned || alloc_end > r_end ||
                !IsRangeWithinSpace(aligned, static_cast<uint64_t>(span))) {
                continue;
            }

            const uint32_t alloc_start = static_cast<uint32_t>(aligned);
            const uint32_t prefix_size = static_cast<uint32_t>(aligned - r_start);
            const uint32_t suffix_size = static_cast<uint32_t>(r_end - alloc_end);

            if (prefix_size > 0u && suffix_size > 0u) {
                free_ranges[i].size = prefix_size;
                free_ranges.insert(
                    free_ranges.begin() + static_cast<std::ptrdiff_t>(i + 1u),
                    ApuFreeRange{static_cast<uint32_t>(alloc_end), suffix_size});
            } else if (prefix_size > 0u) {
                free_ranges[i].size = prefix_size;
            } else if (suffix_size > 0u) {
                free_ranges[i].start = static_cast<uint32_t>(alloc_end);
                free_ranges[i].size = suffix_size;
            } else {
                free_ranges.erase(free_ranges.begin() + static_cast<std::ptrdiff_t>(i));
            }

            *out_addr = alloc_start;
            return true;
        }
        return false;
    }

    bool FreeApuRange(APU_ADDRESS start, uint32_t span) {
        if (span == 0u || !IsRangeWithinSpace(start, span)) {
            return false;
        }
        const uint64_t entry_start = start;
        const uint64_t entry_end = entry_start + static_cast<uint64_t>(span);

        auto it = std::lower_bound(
            free_ranges.begin(),
            free_ranges.end(),
            start,
            [](const ApuFreeRange& r, uint32_t addr) { return r.start < addr; });

        // Reject overlapping frees to preserve free-list disjointness invariant.
        if (it != free_ranges.end() && entry_end > static_cast<uint64_t>(it->start)) {
            return false;
        }
        if (it != free_ranges.begin()) {
            const auto prev = it - 1;
            const uint64_t prev_end = static_cast<uint64_t>(prev->start) + prev->size;
            if (prev_end > entry_start) {
                return false;
            }
        }

        ApuFreeRange entry{start, span};
        it = free_ranges.insert(it, entry);

        // Coalesce with next range if contiguous.
        if (it + 1 != free_ranges.end()) {
            const uint64_t cur_end = static_cast<uint64_t>(it->start) + it->size;
            if (cur_end == (it + 1)->start) {
                it->size += (it + 1)->size;
                free_ranges.erase(it + 1);
            }
        }
        // Coalesce with previous range if contiguous.
        if (it != free_ranges.begin()) {
            auto prev = it - 1;
            const uint64_t prev_end = static_cast<uint64_t>(prev->start) + prev->size;
            if (prev_end == it->start) {
                prev->size += it->size;
                free_ranges.erase(it);
            }
        }
        return true;
    }
};

struct ApuAllocRecord {
    void* virtual_address = nullptr;
    APU_ADDRESS apu_address = APU_INVALID_ADDRESS;
    uint32_t requested_size = 0;
    uint32_t pad_bytes = 0;
    uint32_t apu_span = 0;
    bool non_cached = false;
};

class ApuHeapManager {
public:
    static ApuHeapManager& Instance() {
        static ApuHeapManager mgr;
        return mgr;
    }

    ApuHeapManager() {
        cached_.InitAddressSpace(kCachedApuSpaceBase, kCachedApuSpaceSize);
        non_cached_.InitAddressSpace(kNonCachedApuSpaceBase, kNonCachedApuSpaceSize);
    }

    ~ApuHeapManager() {
        std::lock_guard<std::mutex> lk(mutex_);
        for (const auto& kv : by_va_) {
            AlignedFreeHost(kv.second.virtual_address);
        }
        by_va_.clear();
        by_apu_.clear();
    }

    int32_t CreateHeap(uint32_t cached_bytes, uint32_t non_cached_bytes) {
        if ((cached_bytes == 0u && non_cached_bytes == 0u) ||
            cached_bytes > kCachedApuSpaceSize ||
            non_cached_bytes > kNonCachedApuSpaceSize) {
            return ACPHAL_E_INVALIDARG;
        }
        std::lock_guard<std::mutex> lk(mutex_);
        const uint64_t cached_used =
            static_cast<uint64_t>(cached_.bytes_allocated) + cached_.bytes_lost;
        const uint64_t non_cached_used =
            static_cast<uint64_t>(non_cached_.bytes_allocated) + non_cached_.bytes_lost;
        cached_.capacity = static_cast<uint32_t>(std::max<uint64_t>(cached_bytes, cached_used));
        non_cached_.capacity = static_cast<uint32_t>(std::max<uint64_t>(non_cached_bytes, non_cached_used));
        capacity_explicit_ = true;
        initialized_ = true;
        return ACPHAL_S_OK;
    }

    int32_t Alloc(
        void** virtual_address,
        APU_ADDRESS* physical_address,
        uint32_t size_in_bytes,
        uint32_t alignment_in_bytes,
        uint32_t flags) {
        if (physical_address) {
            *physical_address = APU_INVALID_ADDRESS;
        }
        if (!virtual_address) {
            return ACPHAL_E_POINTER;
        }
        *virtual_address = nullptr;

        if (size_in_bytes == 0u) {
            return ACPHAL_E_INVALIDARG;
        }
        if (alignment_in_bytes != 0u &&
            (!IsPowerOfTwo(alignment_in_bytes) || alignment_in_bytes > kMaxApuAlignmentBytes)) {
            return ACPHAL_E_INVALIDARG;
        }

        const uint32_t req_align =
            (alignment_in_bytes == 0u) ? kDefaultAlignmentBytes : alignment_in_bytes;
        const size_t os_align = std::max<size_t>(req_align, alignof(void*));
        const uint32_t apu_align = std::max<uint32_t>(req_align, 4u);
        const uint32_t pad_bytes =
            (size_in_bytes % 4u == 0u) ? 0u : (4u - (size_in_bytes % 4u));
        const uint64_t span64 = static_cast<uint64_t>(size_in_bytes) + pad_bytes;
        if (span64 > 0xFFFFFFFFull) {
            return ACPHAL_E_OUTOFMEMORY;
        }
        const uint32_t apu_span = static_cast<uint32_t>(span64);
        const bool retail_mode = g_xbox_retail_acphal_mode.load(std::memory_order_acquire);
        // Real Xbox GDK apu.h defines APU_ALLOC_CACHED = 1, APU_ALLOC_NONCACHED = 0;
        // our synthetic ABI header defines APU_ALLOC_NONCACHED = 1.
        const bool is_non_cached =
            retail_mode ? ((flags & 1u) == 0u) : ((flags & APU_ALLOC_NONCACHED) != 0u);

        std::lock_guard<std::mutex> lk(mutex_);
        if (!initialized_) {
            cached_.capacity = kDefaultApuCachedHeapBytes;
            non_cached_.capacity = kDefaultApuNonCachedHeapBytes;
            initialized_ = true;
        }

        bool use_non_cached =
            is_non_cached && (non_cached_.capacity > 0u || cached_.capacity == 0u);
        ApuHeapPool* pool_ptr = use_non_cached ? &non_cached_ : &cached_;
        uint64_t cur_used = static_cast<uint64_t>(pool_ptr->bytes_allocated) + pool_ptr->bytes_lost;
        if (span64 > pool_ptr->capacity || cur_used > pool_ptr->capacity ||
            span64 > pool_ptr->capacity - cur_used) {
            if (retail_mode) {
                // Retail fallback: if the requested pool is smaller than the allocation,
                // try the complementary pool (or expand capacity within APU address space).
                ApuHeapPool* alt = use_non_cached ? &cached_ : &non_cached_;
                const uint64_t alt_used = static_cast<uint64_t>(alt->bytes_allocated) + alt->bytes_lost;
                if (span64 <= alt->capacity && alt_used <= alt->capacity &&
                    span64 <= alt->capacity - alt_used) {
                    use_non_cached = !use_non_cached;
                    pool_ptr = alt;
                } else {
                    const uint64_t needed = cur_used + span64;
                    const uint32_t max_cap = use_non_cached ? kNonCachedApuSpaceSize : kCachedApuSpaceSize;
                    // Auto-expansion is only allowed for the default heap. Capacities set
                    // explicitly by ApuCreateHeap are a hard cap, exactly like real Xbox
                    // AcpHal, so callers can force (and observe) OOM + rollback.
                    if (!capacity_explicit_ && needed <= max_cap) {
                        pool_ptr->capacity = static_cast<uint32_t>(needed);
                    } else {
                        return ACPHAL_E_OUTOFMEMORY;
                    }
                }
            } else {
                return ACPHAL_E_OUTOFMEMORY;
            }
        }
        ApuHeapPool& pool = *pool_ptr;

        APU_ADDRESS apu_addr = APU_INVALID_ADDRESS;
        if (!pool.AllocateApuRange(apu_span, apu_align, &apu_addr)) {
            return ACPHAL_E_OUTOFMEMORY;
        }

        // Defensive overlap & 64-bit address-range overflow guard on active APU map.
        if (HasApuOverlapLocked(apu_addr, apu_span)) {
            pool.FreeApuRange(apu_addr, apu_span);
            return ACPHAL_E_OUTOFMEMORY;
        }

        void* ptr = AlignedAllocHost(size_in_bytes, os_align);
        if (!ptr) {
            pool.FreeApuRange(apu_addr, apu_span);
            return ACPHAL_E_OUTOFMEMORY;
        }

        const uintptr_t va_key = reinterpret_cast<uintptr_t>(ptr);
        if (va_key + static_cast<uintptr_t>(size_in_bytes) < va_key ||
            HasVaOverlapLocked(va_key, size_in_bytes)) {
            AlignedFreeHost(ptr);
            pool.FreeApuRange(apu_addr, apu_span);
            return ACPHAL_E_OUTOFMEMORY;
        }

        std::memset(ptr, 0, size_in_bytes);

        ApuAllocRecord rec{};
        rec.virtual_address = ptr;
        rec.apu_address = apu_addr;
        rec.requested_size = size_in_bytes;
        rec.pad_bytes = pad_bytes;
        rec.apu_span = apu_span;
        rec.non_cached = use_non_cached;

        by_va_[va_key] = rec;
        by_apu_[apu_addr] = va_key;

        pool.bytes_allocated += size_in_bytes;
        pool.bytes_lost += pad_bytes;
        pool.allocation_count += 1u;

        *virtual_address = ptr;
        if (physical_address) {
            *physical_address = apu_addr;
        }
        return ACPHAL_S_OK;
    }

    int32_t Free(void* virtual_address) {
        if (!virtual_address) {
            return ACPHAL_S_OK;
        }

        void* to_free = nullptr;
        {
            std::lock_guard<std::mutex> lk(mutex_);
            const uintptr_t va_key = reinterpret_cast<uintptr_t>(virtual_address);
            auto it = by_va_.find(va_key);
            if (it == by_va_.end()) {
                return ACPHAL_E_INVALIDARG;
            }

            const ApuAllocRecord rec = it->second;
            by_apu_.erase(rec.apu_address);
            by_va_.erase(it);

            ApuHeapPool& pool = rec.non_cached ? non_cached_ : cached_;
            (void)pool.FreeApuRange(rec.apu_address, rec.apu_span);
            pool.bytes_allocated -= rec.requested_size;
            pool.bytes_lost -= rec.pad_bytes;
            pool.allocation_count -= 1u;
            to_free = rec.virtual_address;
        }

        AlignedFreeHost(to_free);
        return ACPHAL_S_OK;
    }

    int32_t GetState(APU_HEAP_STATE* state, uint32_t flags) {
        if (!state) {
            return ACPHAL_E_POINTER;
        }
        std::memset(state, 0, sizeof(*state));

        std::lock_guard<std::mutex> lk(mutex_);
        if (!initialized_) {
            return ACPHAL_S_OK;
        }

        const bool is_non_cached = (flags & APU_ALLOC_NONCACHED) != 0u;
        const ApuHeapPool& pool = is_non_cached ? non_cached_ : cached_;
        const uint64_t used = static_cast<uint64_t>(pool.bytes_allocated) + pool.bytes_lost;
        const uint32_t free_bytes =
            (used < pool.capacity) ? static_cast<uint32_t>(pool.capacity - used) : 0u;

        state->bytesAllocated = pool.bytes_allocated;
        state->bytesFree = free_bytes;
        state->bytesLost = pool.bytes_lost;
        state->maximumBlockSizeAvailable = free_bytes;
        state->allocationCount = pool.allocation_count;
        return ACPHAL_S_OK;
    }

    int32_t IsVirtualAddressValid(const void* virtual_address, uint32_t size_in_bytes) {
        if (!virtual_address) {
            return 0;
        }
        const uintptr_t va = reinterpret_cast<uintptr_t>(virtual_address);
        if (va + static_cast<uintptr_t>(size_in_bytes) < va) {
            return 0;
        }
        std::lock_guard<std::mutex> lk(mutex_);
        auto it = by_va_.upper_bound(va);
        if (it == by_va_.begin()) {
            return 0;
        }
        --it;
        const uintptr_t base = it->first;
        const ApuAllocRecord& rec = it->second;
        if (va < base) {
            return 0;
        }
        const uint64_t offset = static_cast<uint64_t>(va - base);
        if (offset >= rec.requested_size) {
            return 0;
        }
        if (size_in_bytes == 0u) {
            return 1;
        }
        const uint64_t end_off = offset + static_cast<uint64_t>(size_in_bytes);
        if (end_off < offset) {
            return 0;
        }
        return (end_off <= rec.requested_size) ? 1 : 0;
    }

    APU_ADDRESS MapVirtualAddress(const void* virtual_address) {
        if (!virtual_address) {
            return APU_INVALID_ADDRESS;
        }
        const uintptr_t va = reinterpret_cast<uintptr_t>(virtual_address);
        std::lock_guard<std::mutex> lk(mutex_);
        auto it = by_va_.upper_bound(va);
        if (it == by_va_.begin()) {
            return APU_INVALID_ADDRESS;
        }
        --it;
        const uintptr_t base = it->first;
        const ApuAllocRecord& rec = it->second;
        if (va < base) {
            return APU_INVALID_ADDRESS;
        }
        const uint64_t offset = static_cast<uint64_t>(va - base);
        if (offset >= rec.requested_size) {
            return APU_INVALID_ADDRESS;
        }
        const uint64_t apu64 = static_cast<uint64_t>(rec.apu_address) + offset;
        if (apu64 > 0xFFFFFFFFull) {
            return APU_INVALID_ADDRESS;
        }
        return static_cast<APU_ADDRESS>(apu64);
    }

    void* MapApuAddress(APU_ADDRESS apu_address) {
        if (apu_address == APU_INVALID_ADDRESS) {
            return nullptr;
        }
        std::lock_guard<std::mutex> lk(mutex_);
        auto it = by_apu_.upper_bound(apu_address);
        if (it == by_apu_.begin()) {
            return nullptr;
        }
        --it;
        const APU_ADDRESS apu_base = it->first;
        if (apu_address < apu_base) {
            return nullptr;
        }
        auto va_it = by_va_.find(it->second);
        if (va_it == by_va_.end()) {
            return nullptr;
        }
        const ApuAllocRecord& rec = va_it->second;
        const uint32_t offset = apu_address - apu_base;
        if (offset >= rec.requested_size) {
            return nullptr;
        }
        return static_cast<uint8_t*>(rec.virtual_address) + offset;
    }

    // Validates that a caller-supplied APU range [apu_address, apu_address + size_in_bytes)
    // does not wrap 32-bit/64-bit address space and lies strictly inside a single live allocation
    // (or does not overlap any existing allocation when checking candidate placement).
    int32_t ValidateApuAddressRange(APU_ADDRESS apu_address, uint32_t size_in_bytes) {
        if (apu_address == APU_INVALID_ADDRESS || size_in_bytes == 0u) {
            return ACPHAL_E_INVALIDARG;
        }
        const uint64_t req_start = apu_address;
        const uint64_t req_end = req_start + static_cast<uint64_t>(size_in_bytes);
        if (req_end < req_start || req_end > 0x100000000ull) {
            return ACPHAL_E_INVALIDARG;
        }
        std::lock_guard<std::mutex> lk(mutex_);
        auto it = by_apu_.upper_bound(apu_address);
        if (it == by_apu_.begin()) {
            return ACPHAL_E_INVALIDARG;
        }
        --it;
        auto va_it = by_va_.find(it->second);
        if (va_it == by_va_.end()) {
            return ACPHAL_E_INVALIDARG;
        }
        const ApuAllocRecord& rec = va_it->second;
        const uint64_t rec_start = rec.apu_address;
        const uint64_t rec_end = rec_start + static_cast<uint64_t>(rec.requested_size);
        if (req_start < rec_start || req_end > rec_end) {
            return ACPHAL_E_INVALIDARG;
        }
        return ACPHAL_S_OK;
    }

    // Checks whether an arbitrary APU range [apu_start, apu_start + size_in_bytes) would overflow
    // or overlap any existing active allocation. Returns ACPHAL_S_OK if disjoint & in-space,
    // ACPHAL_E_INVALIDARG on overflow/overlap.
    int32_t CheckApuRangeDisjoint(APU_ADDRESS apu_start, uint32_t size_in_bytes) {
        if (apu_start == APU_INVALID_ADDRESS || size_in_bytes == 0u) {
            return ACPHAL_E_INVALIDARG;
        }
        const uint64_t req_start = apu_start;
        const uint64_t req_end = req_start + static_cast<uint64_t>(size_in_bytes);
        if (req_end < req_start || req_end > 0x100000000ull) {
            return ACPHAL_E_INVALIDARG;
        }
        std::lock_guard<std::mutex> lk(mutex_);
        if (!cached_.IsRangeWithinSpace(req_start, size_in_bytes) &&
            !non_cached_.IsRangeWithinSpace(req_start, size_in_bytes)) {
            return ACPHAL_E_INVALIDARG;
        }
        return HasApuOverlapLocked(apu_start, size_in_bytes) ? ACPHAL_E_INVALIDARG : ACPHAL_S_OK;
    }

private:
    bool HasApuOverlapLocked(APU_ADDRESS start, uint32_t span) const {
        const uint64_t s = start;
        const uint64_t e = s + static_cast<uint64_t>(span);
        if (e < s || e > 0x100000000ull) return true;
        auto it = by_apu_.lower_bound(start);
        if (it != by_apu_.end()) {
            if (static_cast<uint64_t>(it->first) < e) {
                return true;
            }
        }
        if (it != by_apu_.begin()) {
            auto prev = std::prev(it);
            auto va_it = by_va_.find(prev->second);
            if (va_it != by_va_.end()) {
                const uint64_t prev_end =
                    static_cast<uint64_t>(va_it->second.apu_address) + va_it->second.apu_span;
                if (prev_end > s) {
                    return true;
                }
            }
        }
        return false;
    }

    bool HasVaOverlapLocked(uintptr_t start, uint32_t size) const {
        const uint64_t s = static_cast<uint64_t>(start);
        const uint64_t e = s + static_cast<uint64_t>(size);
        if (e < s) return true;
        auto it = by_va_.lower_bound(start);
        if (it != by_va_.end()) {
            if (static_cast<uint64_t>(it->first) < e) {
                return true;
            }
        }
        if (it != by_va_.begin()) {
            auto prev = std::prev(it);
            const uint64_t prev_end =
                static_cast<uint64_t>(prev->first) + static_cast<uint64_t>(prev->second.requested_size);
            if (prev_end > s) {
                return true;
            }
        }
        return false;
    }

    std::mutex mutex_;
    bool initialized_ = false;
    // True once a guest called ApuCreateHeap with explicit capacities: those become a
    // hard retail cap, so Alloc() must NOT auto-expand them (see the retail OOM path).
    bool capacity_explicit_ = false;
    ApuHeapPool cached_{};
    ApuHeapPool non_cached_{};
    std::map<uintptr_t, ApuAllocRecord> by_va_;
    std::map<APU_ADDRESS, uintptr_t> by_apu_;
};

static bool IsWritableAcpPtr(void* ptr, size_t bytes) {
    if (!ptr || reinterpret_cast<uintptr_t>(ptr) < 0x10000ull) {
        return false;
    }
    const uintptr_t start = reinterpret_cast<uintptr_t>(ptr);
    if (start + bytes < start) {
        return false;
    }
#if defined(_WIN32)
    MEMORY_BASIC_INFORMATION mbi{};
    if (::VirtualQuery(ptr, &mbi, sizeof(mbi)) == 0 || mbi.State != MEM_COMMIT) {
        return false;
    }
    if ((mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS)) != 0u) {
        return false;
    }
    const DWORD prot = mbi.Protect & 0xFFu;
    const bool writable = (prot == PAGE_READWRITE || prot == PAGE_WRITECOPY ||
                           prot == PAGE_EXECUTE_READWRITE || prot == PAGE_EXECUTE_WRITECOPY);
    if (!writable) return false;
    const uintptr_t region_end = reinterpret_cast<uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
    return start + bytes <= region_end;
#else
    return true;
#endif
}

}  // namespace

extern "C" {

int32_t OPENSCARLETT_ACPHAL_CALL AcpHalCreate(IAcpHal** ppAcpHal) {
    if (!ppAcpHal) {
        return RecordHr("AcpHalCreate", ACPHAL_E_POINTER);
    }
    *ppAcpHal = nullptr;
    if (g_xbox_retail_acphal_mode.load(std::memory_order_acquire)) {
        auto* obj = new (std::nothrow) XboxRetailAcpHalImpl();
        if (!obj) {
            return RecordHr("AcpHalCreate", ACPHAL_E_OUTOFMEMORY);
        }
        *ppAcpHal = reinterpret_cast<IAcpHal*>(obj);
        return RecordHr("AcpHalCreate", ACPHAL_S_OK);
    }
    auto* obj = new (std::nothrow) AcpHalImpl();
    if (!obj) {
        return RecordHr("AcpHalCreate", ACPHAL_E_OUTOFMEMORY);
    }
    *ppAcpHal = obj;
    return RecordHr("AcpHalCreate", ACPHAL_S_OK);
}

int32_t OPENSCARLETT_ACPHAL_CALL AcpHalAllocateShapeContexts(
    const AcpHalShapeContexts* pRequested,
    AcpHalShapeContexts* pAllocated) {
    if (!pRequested) {
        return RecordHr("AcpHalAllocateShapeContexts", ACPHAL_E_INVALIDARG);
    }

    // Detect real retail Xbox 1-arg AcpHalAllocateShapeContexts(ACP_SHAPE_CONTEXTS* pShapeContexts)
    // vs OpenScarlett's synthetic 2-arg (pRequested, pAllocated):
    // In synthetic tests, pAllocated is a valid writable pointer AND pRequested->internalAllocation == nullptr.
    // In retail Xbox (fmod.dll), only 1 arg is passed (pAllocated is null or non-writable, or
    // offset +0x10 holds numXmaContexts != 0).
    const bool is_synthetic_2arg =
        IsWritableAcpPtr(pAllocated, sizeof(AcpHalShapeContexts)) &&
        (pRequested->internalAllocation == nullptr);

    if (!is_synthetic_2arg) {
        g_xbox_retail_acphal_mode.store(true, std::memory_order_release);
        auto* xbox_ctx = reinterpret_cast<XboxAcpShapeContexts*>(
            const_cast<AcpHalShapeContexts*>(pRequested));

        // 6 SHAPE pipeline stages in retail XboxAcpShapeContexts.
        // Validate ALL stage byte counts in 64-bit FIRST before committing any allocations,
        // and atomically roll back stages 0..N-1 on partial OOM leaving zero leaked APU memory!
        struct StageSpec {
            uint32_t count;
            uint32_t elem_bytes;
            void** out_slot;
        };
        StageSpec stages[6] = {
            {xbox_ctx->numSrcContexts,     32u, &xbox_ctx->srcContexts},
            {xbox_ctx->numEqCompContexts,  32u, &xbox_ctx->eqCompContexts},
            {xbox_ctx->numFiltVolContexts, 32u, &xbox_ctx->filtVolContexts},
            {xbox_ctx->numDmaContexts,     16u, &xbox_ctx->dmaContexts},
            {xbox_ctx->numXmaContexts,     64u, &xbox_ctx->xmaContexts},
            {xbox_ctx->numPcmContexts,     64u, &xbox_ctx->pcmContexts},
        };

        uint32_t stage_bytes[6] = {};
        for (size_t i = 0u; i < 6u; ++i) {
            const uint64_t total64 =
                static_cast<uint64_t>(stages[i].count) * static_cast<uint64_t>(stages[i].elem_bytes);
            if (total64 > kMaxShapeStageBytes || total64 > 0xFFFFFFFFull) {
                return RecordHr("AcpHalAllocateShapeContexts", ACPHAL_E_OUTOFMEMORY);
            }
            stage_bytes[i] = static_cast<uint32_t>(total64);
        }

        std::lock_guard<std::mutex> lk(g_shape_alloc_mutex);
        void* allocated_ptrs[6] = {};
        int32_t fail_hr = ACPHAL_S_OK;
        for (size_t i = 0u; i < 6u; ++i) {
            if (stage_bytes[i] == 0u) {
                continue;
            }
            void* va = nullptr;
            APU_ADDRESS pa = APU_INVALID_ADDRESS;
            const int32_t hr =
                ApuHeapManager::Instance().Alloc(&va, &pa, stage_bytes[i], 64u, APU_ALLOC_CACHED);
            if (hr != ACPHAL_S_OK || !va) {
                fail_hr = (hr < 0) ? hr : ACPHAL_E_OUTOFMEMORY;
                // Atomic rollback of stages 0..(i-1) without clobbering caller slots.
                for (size_t r = i; r > 0u; --r) {
                    if (allocated_ptrs[r - 1u]) {
                        (void)ApuHeapManager::Instance().Free(allocated_ptrs[r - 1u]);
                        allocated_ptrs[r - 1u] = nullptr;
                    }
                }
                return RecordHr("AcpHalAllocateShapeContexts", fail_hr);
            }
            allocated_ptrs[i] = va;
        }

        // All 6 stages succeeded — publish pointers and track for AcpHalReleaseShapeContexts.
        for (size_t i = 0u; i < 6u; ++i) {
            *stages[i].out_slot = allocated_ptrs[i];
            if (allocated_ptrs[i]) {
                g_xbox_shape_buffers.push_back(allocated_ptrs[i]);
            }
        }
        return RecordHr("AcpHalAllocateShapeContexts", ACPHAL_S_OK);
    }

    // Synthetic 2-arg path: validate counts, allocate per-stage APU backing buffers with
    // atomic rollback on stage N failure, zero leaked APU allocations or dangling handles.
    g_xbox_retail_acphal_mode.store(false, std::memory_order_release);
    std::memset(pAllocated, 0, sizeof(*pAllocated));

    const uint32_t req_counts[4] = {
        pRequested->numXmaContexts,
        pRequested->numSrcContexts,
        pRequested->numEqContexts,
        pRequested->numDmaContexts,
    };
    const uint32_t stage_elem_bytes[4] = {64u, 32u, 32u, 16u};
    uint32_t stage_bytes[4] = {};
    for (size_t i = 0u; i < 4u; ++i) {
        const uint64_t total64 =
            static_cast<uint64_t>(req_counts[i]) * static_cast<uint64_t>(stage_elem_bytes[i]);
        if (total64 > kMaxShapeStageBytes || total64 > 0xFFFFFFFFull) {
            return RecordHr("AcpHalAllocateShapeContexts", ACPHAL_E_INVALIDARG);
        }
        stage_bytes[i] = static_cast<uint32_t>(total64);
    }

    auto* alloc = new (std::nothrow) AcpShapeAllocation();
    if (!alloc) {
        return RecordHr("AcpHalAllocateShapeContexts", ACPHAL_E_OUTOFMEMORY);
    }

    for (size_t i = 0u; i < 4u; ++i) {
        if (stage_bytes[i] == 0u) continue;
        void* va = nullptr;
        APU_ADDRESS pa = APU_INVALID_ADDRESS;
        const int32_t hr =
            ApuHeapManager::Instance().Alloc(&va, &pa, stage_bytes[i], 64u, APU_ALLOC_CACHED);
        if (hr != ACPHAL_S_OK || !va) {
            // Atomic rollback of stages 0..(i-1)!
            for (size_t r = i; r > 0u; --r) {
                if (alloc->stage_buffers[r - 1u]) {
                    (void)ApuHeapManager::Instance().Free(alloc->stage_buffers[r - 1u]);
                    alloc->stage_buffers[r - 1u] = nullptr;
                }
            }
            delete alloc;
            return RecordHr("AcpHalAllocateShapeContexts", (hr < 0) ? hr : ACPHAL_E_OUTOFMEMORY);
        }
        alloc->stage_buffers[i] = va;
    }

    alloc->num_xma = std::min<uint32_t>(pRequested->numXmaContexts, kMaxAcpContexts);
    alloc->num_src = pRequested->numSrcContexts;
    alloc->num_eq = pRequested->numEqContexts;
    alloc->num_dma = pRequested->numDmaContexts;

    pAllocated->numXmaContexts = alloc->num_xma;
    pAllocated->numSrcContexts = alloc->num_src;
    pAllocated->numEqContexts = alloc->num_eq;
    pAllocated->numDmaContexts = alloc->num_dma;
    pAllocated->internalAllocation = alloc;
    {
        std::lock_guard<std::mutex> lk(g_shape_alloc_mutex);
        g_synthetic_shape_allocs.insert(alloc);
    }
    return RecordHr("AcpHalAllocateShapeContexts", ACPHAL_S_OK);
}

int32_t OPENSCARLETT_ACPHAL_CALL AcpHalReleaseShapeContexts(AcpHalShapeContexts* pAllocated) {
    {
        std::lock_guard<std::mutex> lk(g_shape_alloc_mutex);
        if (IsWritableAcpPtr(pAllocated, sizeof(AcpHalShapeContexts)) &&
            pAllocated->internalAllocation != nullptr &&
            g_synthetic_shape_allocs.erase(pAllocated->internalAllocation) > 0) {
            auto* alloc = static_cast<AcpShapeAllocation*>(pAllocated->internalAllocation);
            for (void* buf : alloc->stage_buffers) {
                if (buf) {
                    (void)ApuHeapManager::Instance().Free(buf);
                }
            }
            delete alloc;
            std::memset(pAllocated, 0, sizeof(*pAllocated));
            return RecordHr("AcpHalReleaseShapeContexts", ACPHAL_S_OK);
        }
        if (g_xbox_retail_acphal_mode.load(std::memory_order_acquire) || !g_xbox_shape_buffers.empty()) {
            for (void* ptr : g_xbox_shape_buffers) {
                if (ApuHeapManager::Instance().Free(ptr) != ACPHAL_S_OK) {
                    AlignedFreeHost(ptr);
                }
            }
            g_xbox_shape_buffers.clear();
            return RecordHr("AcpHalReleaseShapeContexts", ACPHAL_S_OK);
        }
    }
    if (!pAllocated) {
        return RecordHr("AcpHalReleaseShapeContexts", ACPHAL_E_INVALIDARG);
    }
    if (pAllocated->internalAllocation) {
        auto* alloc = static_cast<AcpShapeAllocation*>(pAllocated->internalAllocation);
        for (void* buf : alloc->stage_buffers) {
            if (buf) {
                (void)ApuHeapManager::Instance().Free(buf);
            }
        }
        delete alloc;
    }
    std::memset(pAllocated, 0, sizeof(*pAllocated));
    return RecordHr("AcpHalReleaseShapeContexts", ACPHAL_S_OK);
}

int32_t OPENSCARLETT_ACPHAL_CALL ApuValidateAddressRange(
    APU_ADDRESS apuAddress,
    uint32_t sizeInBytes) {
    return RecordHr(
        "ApuValidateAddressRange",
        ApuHeapManager::Instance().ValidateApuAddressRange(apuAddress, sizeInBytes));
}

int32_t OPENSCARLETT_ACPHAL_CALL ApuCheckAddressRangeDisjoint(
    APU_ADDRESS apuAddress,
    uint32_t sizeInBytes) {
    return RecordHr(
        "ApuCheckAddressRangeDisjoint",
        ApuHeapManager::Instance().CheckApuRangeDisjoint(apuAddress, sizeInBytes));
}

int32_t OPENSCARLETT_ACPHAL_CALL ApuCreateHeap(
    uint32_t cachedSizeInBytes,
    uint32_t nonCachedSizeInBytes) {
    const int32_t hr = ApuHeapManager::Instance().CreateHeap(cachedSizeInBytes, nonCachedSizeInBytes);
    if (hr < 0) {
        std::fprintf(stderr, "[OpenScarlett][AcpHal] ApuCreateHeap(cached=0x%X, nonCached=0x%X) -> 0x%08X\n",
                     cachedSizeInBytes, nonCachedSizeInBytes, static_cast<unsigned>(hr));
        std::fflush(stderr);
    }
    return RecordHr("ApuCreateHeap", hr);
}

int32_t OPENSCARLETT_ACPHAL_CALL ApuAlloc(
    void** virtualAddress,
    APU_ADDRESS* physicalAddress,
    uint32_t sizeInBytes,
    uint32_t alignmentInBytes,
    uint32_t flags) {
    return RecordHr(
        "ApuAlloc",
        ApuHeapManager::Instance().Alloc(
            virtualAddress, physicalAddress, sizeInBytes, alignmentInBytes, flags));
}

int32_t OPENSCARLETT_ACPHAL_CALL ApuFree(void* virtualAddress) {
    return RecordHr("ApuFree", ApuHeapManager::Instance().Free(virtualAddress));
}

int32_t OPENSCARLETT_ACPHAL_CALL ApuHeapGetState(
    APU_HEAP_STATE* state,
    uint32_t flags) {
    return RecordHr("ApuHeapGetState", ApuHeapManager::Instance().GetState(state, flags));
}

int32_t OPENSCARLETT_ACPHAL_CALL ApuIsVirtualAddressValid(
    const void* virtualAddress,
    uint32_t sizeInBytes) {
    const int32_t valid =
        ApuHeapManager::Instance().IsVirtualAddressValid(virtualAddress, sizeInBytes);
    RecordOk("ApuIsVirtualAddressValid");
    return valid;
}

APU_ADDRESS OPENSCARLETT_ACPHAL_CALL ApuMapVirtualAddress(const void* virtualAddress) {
    const APU_ADDRESS addr = ApuHeapManager::Instance().MapVirtualAddress(virtualAddress);
    RecordOk("ApuMapVirtualAddress");
    return addr;
}

void* OPENSCARLETT_ACPHAL_CALL ApuMapApuAddress(APU_ADDRESS apuAddress) {
    void* va = ApuHeapManager::Instance().MapApuAddress(apuAddress);
    RecordOk("ApuMapApuAddress");
    return va;
}

}  // extern "C"
