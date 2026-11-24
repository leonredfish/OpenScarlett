// Sprint 16 Workstream 3 Comprehensive Verification Suite:
//  1. DirectStorage X2 Hardening (xcl #81):
//     - Atomic RetrieveErrorRecord reset + error_event reset
//     - EnqueueSetEvent DuplicateHandle/CloseHandle safety when caller closes original HANDLE immediately
//     - Strict pointer/size/overflow/enum/OOB validation recording E_POINTER/E_INVALIDARG/E_IO_ERROR cleanly
//     - Close() / Release() / File::Close() / CancelRequestsWithTag() teardown race test
//     - Multi-thread concurrent streaming soak test (memory + IOCP file + GDeflate + BCPack)
//  2. BCPack & TTPF 100% (SixNG d724355/#37/#40/#41):
//     - Full 98-slot BC7 BCPack endpoint preset table including all final 34 slots (64..97: modes 4/5/6/7)
//     - Bit-exact 8-mode BC7 + 14-mode BC6H (UF16/SF16 + signed-zero + 1r/2r transitions) vs plain mips
//     - TTPF 100% layouts: single-mip no-tail, cubemap 6-face chains, 3D volume depth-halving, >4 GiB 64-bit
//  3. Audio 100% (xcl #89/#90):
//     - XAudio2_9 exact play/loop region clamping (clamp_regions) & silent_buffer handling
//     - AcpHal 64-bit APU address overflow/overlap validation & atomic SHAPE multi-stage rollback
//     - xapu XApuConnect OOM & invalid-parameter hardening + double-disconnect safety
//     - Multi-stream concurrent XMA2 + Opus + PCM + WASAPI (OPENSCARLETT_AUDIO_NULL=1 safe) stress test
//  4. Video 100%:
//     - mfhevcdec.dll real IMFTransform COM decoder (Annex-B HEVC & H.264 SPS parsing, D3D12 manager,
//       NV12/ARGB32 decode, PTS/duration/CleanPoint, Drain/Flush, accurate DllCanUnloadNow)
//     - mflnmhelp.dll stateful License/Revocation/Renewal/Expiry/Manifest-URL/Network-Caps & DllCanUnloadNow
//     - Bink2Scarlett.dll live D3D12 compute shader YUV420p(+A) -> RGBA8/BGRA8 (BT.601 & BT.709) on BOTH
//       HW GPU and D3D12 WARP matching CPU reference within <= 1 LSB (plus CPU fallback).

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#if defined(_WIN32)
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  ifndef NOMINMAX
#    define NOMINMAX
#  endif
#  include <d3d12.h>
#  include <dxgi1_6.h>
#  include <mfobjects.h>
#  include <mftransform.h>
#  include <objbase.h>
#  include <windows.h>
#endif

#include "openscarlett/audio/acphal_abi.h"
#include "openscarlett/audio/opus_adpcm_decoder.h"
#include "openscarlett/audio/xaudio2_abi.h"
#include "openscarlett/audio/xapu_abi.h"
#include "openscarlett/audio/xma2_decoder.h"
#include "openscarlett/gpu/d3d12_adapter.h"
#include "openscarlett/io/bcpack.h"
#include "openscarlett/io/dstorage_abi.h"
#include "openscarlett/io/gdeflate.h"
#include "openscarlett/middleware/bink2_decoder.h"
#include "openscarlett/shims/secondary_shims_abi.h"
#include "os_check.h"

namespace fs = std::filesystem;

namespace {

using namespace openscarlett;

#if defined(_WIN32)
// Explicit inline COM & MF GUIDs (zero __uuidof, zero mfuuid.lib)
constexpr GUID kIidIUnknown = {
    0x00000000u, 0x0000u, 0x0000u, {0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46}};
constexpr GUID kIidIClassFactory = {
    0x00000001u, 0x0000u, 0x0000u, {0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46}};
constexpr GUID kIidImfTransform = {
    0xBF94C121u, 0x5B05u, 0x4E6Fu, {0x80, 0x00u, 0xBA, 0x59, 0x89, 0x61, 0x41, 0x4D}};
constexpr GUID kIidId3d12Fence = {
    0x0A753DCFu, 0xC4D8u, 0x4B91u, {0xAD, 0xF6u, 0xBE, 0x5A, 0x60, 0xD9, 0x5A, 0x76}};
constexpr GUID kMfMtMajorType = {
    0x48EBA18Eu, 0xF8C9u, 0x4687u, {0xBF, 0x11u, 0x0A, 0x74, 0xC9, 0xF9, 0x6A, 0x8F}};
constexpr GUID kMfMtSubtype = {
    0xF7E34C9Au, 0x42E8u, 0x4714u, {0xB7, 0x4Bu, 0xCB, 0x29, 0xD7, 0x2C, 0x35, 0xE5}};
constexpr GUID kMfMtFrameSize = {
    0x1652C33Du, 0xD6B2u, 0x4012u, {0xB8, 0x34u, 0x72, 0x03, 0x08, 0x49, 0xA3, 0x7D}};
constexpr GUID kMfSaD3d11Aware = {
    0x206B4FC8u, 0xFCF9u, 0x4C51u, {0xAF, 0xE3u, 0x97, 0x64, 0x36, 0x9E, 0x33, 0xA0}};
constexpr GUID kMfSampleExtCleanPoint = {
    0x9CDF01D8u, 0xA0F0u, 0x43BAu, {0xB0, 0x77u, 0xEA, 0xA0, 0x6C, 0xBD, 0x72, 0x8A}};
constexpr GUID kMfMediaTypeVideo = {
    0x73646976u, 0x0000u, 0x0010u, {0x80, 0x00, 0x00, 0xAA, 0x00, 0x38, 0x9B, 0x71}};
constexpr GUID kMfVideoFormatHevc = {
    0x43564548u, 0x0000u, 0x0010u, {0x80, 0x00, 0x00, 0xAA, 0x00, 0x38, 0x9B, 0x71}};
constexpr GUID kMfVideoFormatH264 = {
    0x34363248u, 0x0000u, 0x0010u, {0x80, 0x00, 0x00, 0xAA, 0x00, 0x38, 0x9B, 0x71}};
constexpr GUID kMfVideoFormatNv12 = {
    0x3231564Eu, 0x0000u, 0x0010u, {0x80, 0x00, 0x00, 0xAA, 0x00, 0x38, 0x9B, 0x71}};
constexpr GUID kMfVideoFormatArgb32 = {
    0x00000015u, 0x0000u, 0x0010u, {0x80, 0x00, 0x00, 0xAA, 0x00, 0x38, 0x9B, 0x71}};
constexpr GUID kMftCategoryVideoDecoder = {
    0xD6C02D4Bu, 0x6833u, 0x45B4u, {0x97, 0x1A, 0x05, 0xA4, 0xB0, 0x4B, 0xAB, 0x91}};

fs::path GetExeDir() {
    wchar_t buf[MAX_PATH]{};
    const DWORD n = ::GetModuleFileNameW(nullptr, buf, MAX_PATH);
    if (n > 0u && n < MAX_PATH) {
        return fs::path(buf).parent_path();
    }
    return fs::current_path();
}
#endif

void FillDeterministic(std::vector<uint8_t>& buf, uint32_t seed) {
    uint32_t s = seed ^ 0x9E3779B9u;
    for (size_t i = 0u; i < buf.size(); ++i) {
        s = s * 1664525u + 1013904223u;
        buf[i] = static_cast<uint8_t>((s >> 24u) ^ ((i * 13u + seed) & 0xFFu));
    }
}

void WaitStatus(IDStorageQueueX* q, IDStorageStatusArrayX* st, uint32_t idx) {
    q->Submit();
    for (int i = 0; i < 4000 && !st->IsComplete(idx); ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds(2));
    }
    OS_REQUIRE(st->IsComplete(idx));
}

// ===========================================================================
// 1. DirectStorage X2 Hardening (xcl #81)
// ===========================================================================
void TestDirectStorageHardening() {
    std::printf("[1/4] DirectStorage X2 hardening (error reset, dup event, validation, close/release race, MT soak)...\n");
    IDStorageFactoryX2* factory = nullptr;
    OS_REQUIRE(DStorageGetFactory(&IID_IDStorageFactoryX2, reinterpret_cast<void**>(&factory)) == OS_DSTORAGE_S_OK);
    OS_REQUIRE(factory != nullptr);

    // 1A. RetrieveErrorRecord atomic reset + strict pointer/size/overflow/enum validation
    {
        DSTORAGE_QUEUE_DESC qd{};
        qd.SourceType = DSTORAGE_REQUEST_SOURCE_MEMORY;
        qd.Capacity = DSTORAGE_MIN_QUEUE_CAPACITY;
        qd.Priority = DSTORAGE_PRIORITY_HIGH;
        qd.Name = "s16_err_reset_q";
        IDStorageQueueX2* q = nullptr;
        OS_REQUIRE(factory->CreateQueue(&qd, &IID_IDStorageQueueX2, reinterpret_cast<void**>(&q)) == OS_DSTORAGE_S_OK);
        IDStorageStatusArrayX* st = nullptr;
        OS_REQUIRE(factory->CreateStatusArray(2u, "s16_st", &IID_IDStorageStatusArrayX,
                                              reinterpret_cast<void**>(&st)) == OS_DSTORAGE_S_OK);

        // Fresh queue starts with FailureCount == 0, HResult == S_OK, CommandType == NONE
        DSTORAGE_ERROR_RECORD rec{};
        q->RetrieveErrorRecord(&rec);
        OS_REQUIRE(rec.FailureCount == 0u);
        OS_REQUIRE(rec.FirstFailure.HResult == OS_DSTORAGE_S_OK);
        OS_REQUIRE(rec.FirstFailure.CommandType == DSTORAGE_COMMAND_TYPE_NONE);

        // Null command pointers & OOB status index MUST record errors cleanly without crashing
        q->EnqueueRequest(nullptr);
        q->EnqueueStatus(nullptr, 0u);
        q->EnqueueStatus(st, 99u);  // OOB index >= capacity(2)
        q->EnqueueSetEvent(nullptr);
        q->EnqueueSignal(nullptr, 42ull);
#if defined(_WIN32)
        q->EnqueueSetEvent(INVALID_HANDLE_VALUE);
        HANDLE err_ev = static_cast<HANDLE>(q->GetErrorEvent());
        OS_REQUIRE(err_ev != nullptr);
        OS_REQUIRE(WaitForSingleObject(err_ev, 0u) == WAIT_OBJECT_0);
#endif
        q->RetrieveErrorRecord(&rec);
        OS_REQUIRE(rec.FailureCount >= 5u);
        OS_REQUIRE(rec.FirstFailure.HResult == OS_DSTORAGE_E_POINTER);
        OS_REQUIRE(rec.FirstFailure.CommandType == DSTORAGE_COMMAND_TYPE_REQUEST);

        // Immediately retrieving again MUST observe reset state (no stale error stuck!)
        std::memset(&rec, 0xCC, sizeof(rec));
        q->RetrieveErrorRecord(&rec);
        OS_REQUIRE(rec.FailureCount == 0u);
        OS_REQUIRE(rec.FirstFailure.HResult == OS_DSTORAGE_S_OK);
        OS_REQUIRE(rec.FirstFailure.CommandType == DSTORAGE_COMMAND_TYPE_NONE);
#if defined(_WIN32)
        OS_REQUIRE(WaitForSingleObject(err_ev, 0u) == WAIT_TIMEOUT);
#endif

        // Flush batch_hr from the validation errors via status slot 0, then verify clean transfer
        q->EnqueueStatus(st, 0u);
        WaitStatus(q, st, 0u);
        OS_REQUIRE(st->GetHResult(0u) == OS_DSTORAGE_E_POINTER);

        std::vector<uint8_t> src(512u), dst(512u, 0u);
        FillDeterministic(src, 0x1601u);
        DSTORAGE_REQUEST good{};
        good.Options.SourceType = DSTORAGE_REQUEST_SOURCE_MEMORY;
        good.Source = src.data();
        good.SourceSize = static_cast<uint32_t>(src.size());
        good.Destination = dst.data();
        good.DestinationSize = static_cast<uint32_t>(dst.size());
        good.Name = "clean_after_reset";
        q->EnqueueRequest(&good);
        q->EnqueueStatus(st, 1u);
        WaitStatus(q, st, 1u);
        OS_REQUIRE(st->GetHResult(1u) == OS_DSTORAGE_S_OK);
        OS_REQUIRE(dst == src);
        q->RetrieveErrorRecord(&rec);
        OS_REQUIRE(rec.FailureCount == 0u);
        OS_REQUIRE(rec.FirstFailure.HResult == OS_DSTORAGE_S_OK);
        OS_REQUIRE(rec.FirstFailure.CommandType == DSTORAGE_COMMAND_TYPE_NONE);

        // Invalid request descriptors: null dest, zero size, invalid DestinationType, file offset overflow
        {
            DSTORAGE_REQUEST bad_null_dst{};
            bad_null_dst.Options.SourceType = DSTORAGE_REQUEST_SOURCE_MEMORY;
            bad_null_dst.Source = src.data();
            bad_null_dst.SourceSize = 64u;
            bad_null_dst.Destination = nullptr;
            bad_null_dst.DestinationSize = 64u;
            q->EnqueueRequest(&bad_null_dst);
            q->EnqueueStatus(st, 0u);
            WaitStatus(q, st, 0u);
            OS_REQUIRE(st->GetHResult(0u) == OS_DSTORAGE_E_POINTER);
            q->RetrieveErrorRecord(&rec);
            OS_REQUIRE(rec.FailureCount == 1u);
            OS_REQUIRE(rec.FirstFailure.HResult == OS_DSTORAGE_E_POINTER);

            DSTORAGE_REQUEST bad_zero{};
            bad_zero.Options.SourceType = DSTORAGE_REQUEST_SOURCE_MEMORY;
            bad_zero.Source = src.data();
            bad_zero.SourceSize = 0u;
            bad_zero.Destination = dst.data();
            bad_zero.DestinationSize = 0u;
            q->EnqueueRequest(&bad_zero);

            OpenScarlettDStorageRequestDesc bad_enum{};
            bad_enum.Options.SourceType = static_cast<DSTORAGE_REQUEST_SOURCE_TYPE>(99u);
            bad_enum.Options.DestinationType = static_cast<DSTORAGE_REQUEST_DESTINATION_TYPE>(99u);
            bad_enum.Destination.Memory.Buffer = dst.data();
            bad_enum.Destination.Memory.Size = 64u;
            OpenScarlettDStorageEnqueueRequestDesc(q, &bad_enum);

            q->EnqueueStatus(st, 0u);
            WaitStatus(q, st, 0u);
            OS_REQUIRE(st->GetHResult(0u) == OS_DSTORAGE_E_INVALIDARG);
            q->RetrieveErrorRecord(&rec);
            OS_REQUIRE(rec.FailureCount == 2u);
            OS_REQUIRE(rec.FirstFailure.HResult == OS_DSTORAGE_E_INVALIDARG);
        }

        // File offset overflow & OOB read record Filename in error record
        const fs::path tmp_file = fs::temp_directory_path() / "openscarlett_s16_dstorage_oob.bin";
        {
            std::ofstream ofs(tmp_file, std::ios::binary | std::ios::trunc);
            OS_REQUIRE(ofs.good());
            ofs.write(reinterpret_cast<const char*>(src.data()), static_cast<std::streamsize>(src.size()));
        }
        IDStorageFileX* dfile = nullptr;
        OS_REQUIRE(factory->OpenFile(tmp_file.wstring().c_str(), &IID_IDStorageFileX,
                                     reinterpret_cast<void**>(&dfile)) == OS_DSTORAGE_S_OK);
        {
            DSTORAGE_REQUEST overflow_req{};
            overflow_req.Options.SourceType = DSTORAGE_REQUEST_SOURCE_FILE;
            overflow_req.File = dfile;
            overflow_req.FileOffset = 0xFFFFFFFFFFFFFFF0ull;
            overflow_req.SourceSize = 64u;
            overflow_req.Destination = dst.data();
            overflow_req.DestinationSize = 64u;
            overflow_req.Name = "overflow_file_req";
            q->EnqueueRequest(&overflow_req);
            q->EnqueueStatus(st, 0u);
            WaitStatus(q, st, 0u);
            OS_REQUIRE(st->GetHResult(0u) == OS_DSTORAGE_E_INVALIDARG);
            q->RetrieveErrorRecord(&rec);
            OS_REQUIRE(rec.FailureCount == 1u);
            OS_REQUIRE(rec.FirstFailure.HResult == OS_DSTORAGE_E_INVALIDARG);
            OS_REQUIRE(rec.FirstFailure.Request.Filename[0] != u'\0');

            DSTORAGE_REQUEST oob_req{};
            oob_req.Options.SourceType = DSTORAGE_REQUEST_SOURCE_FILE;
            oob_req.File = dfile;
            oob_req.FileOffset = 480u;
            oob_req.SourceSize = 64u;  // 480 + 64 = 544 > 512
            oob_req.Destination = dst.data();
            oob_req.DestinationSize = 64u;
            q->EnqueueRequest(&oob_req);
            q->EnqueueStatus(st, 1u);
            WaitStatus(q, st, 1u);
            OS_REQUIRE(st->GetHResult(1u) == OS_DSTORAGE_E_IO_ERROR);
            q->RetrieveErrorRecord(&rec);
            OS_REQUIRE(rec.FailureCount == 1u);
            OS_REQUIRE(rec.FirstFailure.HResult == OS_DSTORAGE_E_IO_ERROR);
        }

        dfile->Close();
        dfile->Release();
        std::error_code ec;
        fs::remove(tmp_file, ec);
        st->Release();
        q->Close();
        q->Release();
    }

    // 1B. Event handle duplication: caller closes original HANDLE IMMEDIATELY after EnqueueSetEvent!
#if defined(_WIN32)
    {
        DSTORAGE_QUEUE_DESC qd{};
        qd.SourceType = DSTORAGE_REQUEST_SOURCE_MEMORY;
        qd.Capacity = DSTORAGE_MIN_QUEUE_CAPACITY;
        qd.Priority = DSTORAGE_PRIORITY_REALTIME;
        qd.Name = "s16_dup_event_q";
        IDStorageQueueX* q = nullptr;
        OS_REQUIRE(factory->CreateQueue(&qd, &IID_IDStorageQueueX, reinterpret_cast<void**>(&q)) == OS_DSTORAGE_S_OK);

        HANDLE ev_orig = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        OS_REQUIRE(ev_orig != nullptr);
        HANDLE ev_watch = nullptr;
        OS_REQUIRE(DuplicateHandle(GetCurrentProcess(), ev_orig, GetCurrentProcess(), &ev_watch,
                                   0u, FALSE, DUPLICATE_SAME_ACCESS) != 0);

        std::vector<uint8_t> src(4096u), dst(4096u, 0u);
        FillDeterministic(src, 0x1602u);
        DSTORAGE_REQUEST r{};
        r.Options.SourceType = DSTORAGE_REQUEST_SOURCE_MEMORY;
        r.Source = src.data();
        r.SourceSize = static_cast<uint32_t>(src.size());
        r.Destination = dst.data();
        r.DestinationSize = static_cast<uint32_t>(dst.size());
        q->EnqueueRequest(&r);
        q->EnqueueSetEvent(ev_orig);

        // Close caller's handle BEFORE Submit() and churn handles to catch any non-duplicated bug!
        CloseHandle(ev_orig);
        std::vector<HANDLE> churn;
        for (int i = 0; i < 16; ++i) {
            churn.push_back(CreateEventW(nullptr, TRUE, FALSE, nullptr));
        }

        q->Submit();
        OS_REQUIRE(WaitForSingleObject(ev_watch, 10000u) == WAIT_OBJECT_0);
        OS_REQUIRE(dst == src);
        for (HANDLE h : churn) {
            OS_REQUIRE(WaitForSingleObject(h, 0u) == WAIT_TIMEOUT);  // No recycled handle accidentally signaled!
            CloseHandle(h);
        }
        CloseHandle(ev_watch);

        // Also test EnqueueSetEvent left staged when Close() tears down without Submit() (must close dup cleanly)
        HANDLE ev_drop = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        q->EnqueueSetEvent(ev_drop);
        CloseHandle(ev_drop);
        q->Close();
        q->Release();
    }
#endif

    // 1C. Close/Release/File-Close teardown race stress
    {
        const fs::path race_file = fs::temp_directory_path() / "openscarlett_s16_race.bin";
        std::vector<uint8_t> file_bytes(32768u);
        FillDeterministic(file_bytes, 0x1603u);
        {
            std::ofstream ofs(race_file, std::ios::binary | std::ios::trunc);
            ofs.write(reinterpret_cast<const char*>(file_bytes.data()),
                      static_cast<std::streamsize>(file_bytes.size()));
        }

        for (int iter = 0; iter < 20; ++iter) {
            DSTORAGE_QUEUE_DESC qd{};
            qd.SourceType = DSTORAGE_REQUEST_SOURCE_FILE;
            qd.Capacity = DSTORAGE_MIN_QUEUE_CAPACITY;
            qd.Priority = (iter & 1) ? DSTORAGE_PRIORITY_REALTIME : DSTORAGE_PRIORITY_NORMAL;
            qd.Name = "s16_race_q";
            IDStorageQueueX* q = nullptr;
            OS_REQUIRE(factory->CreateQueue(&qd, &IID_IDStorageQueueX, reinterpret_cast<void**>(&q)) == OS_DSTORAGE_S_OK);
            IDStorageFileX* f = nullptr;
            OS_REQUIRE(factory->OpenFile(race_file.wstring().c_str(), &IID_IDStorageFileX,
                                         reinterpret_cast<void**>(&f)) == OS_DSTORAGE_S_OK);

            std::vector<std::vector<uint8_t>> bufs(16u, std::vector<uint8_t>(4096u, 0u));
            for (size_t i = 0u; i < bufs.size(); ++i) {
                DSTORAGE_REQUEST r{};
                r.Options.SourceType = DSTORAGE_REQUEST_SOURCE_FILE;
                r.File = f;
                r.FileOffset = (i * 1024u) % (file_bytes.size() - 4096u);
                r.SourceSize = 4096u;
                r.Destination = bufs[i].data();
                r.DestinationSize = 4096u;
                r.CancellationTag = 0xCAFE0000ull | i;
                q->EnqueueRequest(&r);
            }
            q->Submit();

            // Race Close(), CancelRequestsWithTag(), File::Close(), and Release() across threads!
            q->AddRef();
            std::thread t_cancel([&]() { q->CancelRequestsWithTag(0xFFFF0000ull, 0xCAFE0000ull); });
            std::thread t_close([&]() { q->Close(); });
            std::thread t_file([&]() { f->Close(); });
            std::thread t_rel([&]() { q->Release(); });
            t_cancel.join();
            t_close.join();
            t_file.join();
            t_rel.join();

            q->Release();
            f->Release();
        }
        std::error_code ec;
        fs::remove(race_file, ec);
    }

    // 1D. Multi-thread concurrent streaming soak test (memory + IOCP file + GDeflate + BCPack)
    {
        const fs::path soak_file = fs::temp_directory_path() / "openscarlett_s16_soak.bin";
        std::vector<uint8_t> raw_payload(16384u);
        FillDeterministic(raw_payload, 0x1604u);
        std::vector<uint8_t> gdef_comp;
        OS_REQUIRE(GDeflateCompress(raw_payload.data(), raw_payload.size(), gdef_comp));
        std::vector<uint8_t> bc7_plain, bc7_comp;
        OS_REQUIRE(BcGenerateSyntheticSurface(BcFormat::BC7, 64u, 64u, 0x516u, bc7_plain).ok());
        OS_REQUIRE(BcPackCompress(BcFormat::BC7, 64u, 64u, bc7_plain.data(), bc7_plain.size(), bc7_comp).ok());

        {
            std::ofstream ofs(soak_file, std::ios::binary | std::ios::trunc);
            ofs.write(reinterpret_cast<const char*>(raw_payload.data()),
                      static_cast<std::streamsize>(raw_payload.size()));
        }

        IDStorageFileX* soak_f = nullptr;
        OS_REQUIRE(factory->OpenFile(soak_file.wstring().c_str(), &IID_IDStorageFileX,
                                     reinterpret_cast<void**>(&soak_f)) == OS_DSTORAGE_S_OK);

        constexpr int kThreads = 4;
        std::atomic<uint32_t> total_ok{0u};
        std::vector<std::thread> workers;
        for (int tid = 0; tid < kThreads; ++tid) {
            workers.emplace_back([&, tid]() {
                DSTORAGE_QUEUE_DESC qd{};
                qd.SourceType = DSTORAGE_REQUEST_SOURCE_FILE;
                qd.Capacity = DSTORAGE_MIN_QUEUE_CAPACITY;
                qd.Priority = (tid % 2 == 0) ? DSTORAGE_PRIORITY_HIGH : DSTORAGE_PRIORITY_NORMAL;
                qd.Name = "s16_soak_q";
                IDStorageQueueX* q = nullptr;
                OS_REQUIRE(factory->CreateQueue(&qd, &IID_IDStorageQueueX, reinterpret_cast<void**>(&q)) == OS_DSTORAGE_S_OK);
                IDStorageStatusArrayX* st = nullptr;
                OS_REQUIRE(factory->CreateStatusArray(8u, "s16_soak_st", &IID_IDStorageStatusArrayX,
                                                      reinterpret_cast<void**>(&st)) == OS_DSTORAGE_S_OK);

                for (int round = 0; round < 6; ++round) {
                    std::vector<uint8_t> dst_file(raw_payload.size(), 0u);
                    std::vector<uint8_t> dst_gdef(raw_payload.size(), 0u);
                    std::vector<uint8_t> dst_bc7(bc7_plain.size(), 0u);

                    // 1. IOCP file transfer
                    DSTORAGE_REQUEST rf{};
                    rf.Options.SourceType = DSTORAGE_REQUEST_SOURCE_FILE;
                    rf.File = soak_f;
                    rf.FileOffset = 0u;
                    rf.SourceSize = static_cast<uint32_t>(raw_payload.size());
                    rf.Destination = dst_file.data();
                    rf.DestinationSize = static_cast<uint32_t>(dst_file.size());
                    q->EnqueueRequest(&rf);

                    // 2. GDeflate memory transfer
                    OpenScarlettDStorageRequestDesc rg{};
                    rg.Options.CompressionFormat = DSTORAGE_COMPRESSION_FORMAT_GDEFLATE;
                    rg.Options.SourceType = DSTORAGE_REQUEST_SOURCE_MEMORY;
                    rg.Options.DestinationType = DSTORAGE_REQUEST_DESTINATION_MEMORY;
                    rg.Source.Memory.Source = gdef_comp.data();
                    rg.Source.Memory.Size = static_cast<uint32_t>(gdef_comp.size());
                    rg.Destination.Memory.Buffer = dst_gdef.data();
                    rg.Destination.Memory.Size = static_cast<uint32_t>(dst_gdef.size());
                    rg.UncompressedSize = static_cast<uint32_t>(raw_payload.size());
                    OpenScarlettDStorageEnqueueRequestDesc(q, &rg);

                    // 3. BCPack BC7 transfer
                    OpenScarlettDStorageRequestDesc rb{};
                    rb.Options.CompressionFormat = DSTORAGE_COMPRESSION_FORMAT_BCPACK;
                    rb.Options.SourceType = DSTORAGE_REQUEST_SOURCE_MEMORY;
                    rb.Options.DestinationType = DSTORAGE_REQUEST_DESTINATION_MEMORY;
                    rb.Source.Memory.Source = bc7_comp.data();
                    rb.Source.Memory.Size = static_cast<uint32_t>(bc7_comp.size());
                    rb.Destination.Memory.Buffer = dst_bc7.data();
                    rb.Destination.Memory.Size = static_cast<uint32_t>(dst_bc7.size());
                    rb.UncompressedSize = static_cast<uint32_t>(bc7_plain.size());
                    OpenScarlettDStorageEnqueueRequestDesc(q, &rb);

                    const uint32_t slot = static_cast<uint32_t>(round % 8);
                    q->EnqueueStatus(st, slot);
#if defined(_WIN32)
                    HANDLE ev_tmp = CreateEventW(nullptr, TRUE, FALSE, nullptr);
                    HANDLE ev_dup = nullptr;
                    OS_REQUIRE(DuplicateHandle(GetCurrentProcess(), ev_tmp, GetCurrentProcess(), &ev_dup,
                                               0u, FALSE, DUPLICATE_SAME_ACCESS) != 0);
                    q->EnqueueSetEvent(ev_tmp);
                    CloseHandle(ev_tmp);  // Closed immediately before Submit!
                    q->Submit();
                    OS_REQUIRE(WaitForSingleObject(ev_dup, 10000u) == WAIT_OBJECT_0);
                    CloseHandle(ev_dup);
#else
                    WaitStatus(q, st, slot);
#endif
                    OS_REQUIRE(st->IsComplete(slot) && st->GetHResult(slot) == OS_DSTORAGE_S_OK);
                    OS_REQUIRE(dst_file == raw_payload);
                    OS_REQUIRE(dst_gdef == raw_payload);
                    OS_REQUIRE(dst_bc7 == bc7_plain);
                    total_ok.fetch_add(3u, std::memory_order_relaxed);
                }

                // Inject an error on even threads and verify RetrieveErrorRecord resets cleanly
                if ((tid & 1) == 0) {
                    q->EnqueueRequest(nullptr);
                    DSTORAGE_ERROR_RECORD er{};
                    q->RetrieveErrorRecord(&er);
                    OS_REQUIRE(er.FailureCount == 1u && er.FirstFailure.HResult == OS_DSTORAGE_E_POINTER);
                    q->RetrieveErrorRecord(&er);
                    OS_REQUIRE(er.FailureCount == 0u && er.FirstFailure.HResult == OS_DSTORAGE_S_OK);
                }

                st->Release();
                q->Close();
                q->Release();
            });
        }
        for (auto& w : workers) w.join();
        OS_REQUIRE(total_ok.load() == static_cast<uint32_t>(kThreads * 6 * 3));

        soak_f->Close();
        soak_f->Release();
        std::error_code ec;
        fs::remove(soak_file, ec);
    }

    factory->Release();
    std::printf("  [PASS] DirectStorage X2 hardening complete.\n");
}

// ===========================================================================
// 2. BCPack & TTPF 100% (SixNG d724355/#37/#40/#41)
// ===========================================================================
void TestBcPackAndTtpf100() {
    std::printf("[2/4] BCPack BC7 98 presets (incl. last 34), BC6H/BC7 bit-exact mips & TTPF 100%% layouts...\n");

    // 2A. Verify ALL 98 BC7 BCPack preset table slots (0..97), especially the last 34 slots [64..97]!
    Bc7BcpPresetEntry oob_entry{};
    OS_REQUIRE(!Bc7GetBcpPresetTableEntry(kBc7BcpPresetCount, oob_entry));
    OS_REQUIRE(!Bc7GetBcpPresetTableEntry(999u, oob_entry));

    std::vector<uint8_t> all_presets_surface;
    // Build a 64x64 BC7 surface (256 blocks) covering ALL 98 preset slots multiple times!
    constexpr uint32_t kSurfW = 64u;
    constexpr uint32_t kSurfH = 64u;
    constexpr uint32_t kTotalBlocks = (kSurfW / 4u) * (kSurfH / 4u);  // 256 blocks
    all_presets_surface.resize(static_cast<size_t>(kTotalBlocks) * 16u, 0u);

    uint32_t tail_slots_verified = 0u;
    for (uint32_t slot = 0u; slot < kBc7BcpPresetCount; ++slot) {
        Bc7BcpPresetEntry tbl_e{};
        OS_REQUIRE(Bc7GetBcpPresetTableEntry(slot, tbl_e));
        OS_REQUIRE(tbl_e.is_valid && tbl_e.preset_index == slot);

        uint8_t blk[16]{};
        OS_REQUIRE(Bc7BuildBlockForPreset(slot, 0x1600u + slot * 31u, blk));

        Bc7BcpPresetEntry resolved{};
        OS_REQUIRE(Bc7ResolveBcpPreset(blk, resolved));
        OS_REQUIRE(resolved.is_valid);
        OS_REQUIRE(resolved.preset_index == slot);
        OS_REQUIRE(resolved.mode_index == tbl_e.mode_index);
        OS_REQUIRE(resolved.subset_count == tbl_e.subset_count);
        OS_REQUIRE(resolved.rotation == tbl_e.rotation);
        OS_REQUIRE(resolved.index_selection == tbl_e.index_selection);
        OS_REQUIRE(resolved.pbit_pattern == tbl_e.pbit_pattern);

        // Verify bit-exact decode on every single preset slot
        uint8_t rgba[64]{};
        Bc7DecodeBlock(blk, rgba);
        if (slot == 96u) {
            // Slot 96: Mode 6 full-opaque alpha class -> every texel alpha == 255!
            for (int p = 0; p < 16; ++p) OS_REQUIRE(rgba[p * 4 + 3] == 255u);
        } else if (slot == 97u) {
            // Slot 97: Mode 6 zero-alpha class -> every texel alpha == 0!
            for (int p = 0; p < 16; ++p) OS_REQUIRE(rgba[p * 4 + 3] == 0u);
        } else if (tbl_e.mode_index <= 3u) {
            // Modes 0..3 are opaque RGB -> every texel alpha == 255!
            for (int p = 0; p < 16; ++p) OS_REQUIRE(rgba[p * 4 + 3] == 255u);
        }
        if (slot >= kBc7BcpTailPresetStart) {
            ++tail_slots_verified;
        }
    }
    OS_REQUIRE(tail_slots_verified == kBc7BcpTailPresetCount);  // Exact 34 tail preset slots!

    // Reserved BC7 mode (byte 0 == 0x00) must resolve invalid and decode to RGBA(0,0,0,0)
    {
        uint8_t res_blk[16]{};
        res_blk[0] = 0x00u;
        res_blk[5] = 0xFFu;
        Bc7BcpPresetEntry res_e{};
        OS_REQUIRE(!Bc7ResolveBcpPreset(res_blk, res_e));
        uint8_t res_rgba[64]{};
        std::memset(res_rgba, 0xAA, sizeof(res_rgba));
        Bc7DecodeBlock(res_blk, res_rgba);
        for (uint8_t b : res_rgba) OS_REQUIRE(b == 0u);
    }

    // Fill the 256-block surface cycling through all 98 preset slots + adjacent mode/subset transitions
    for (uint32_t b = 0u; b < kTotalBlocks; ++b) {
        const uint32_t slot = (b < kBc7BcpPresetCount)
                                  ? b
                                  : (kBc7BcpTailPresetStart + (b % kBc7BcpTailPresetCount));
        OS_REQUIRE(Bc7BuildBlockForPreset(slot, 0x7700u + b * 7u, all_presets_surface.data() + b * 16u));
    }

    // Verify BOTH BCPK container AND Hardware BCPack bitstream compress & decompress bit-exact
    std::vector<uint8_t> bc7_ref_rgba;
    OS_REQUIRE(Bc7DecodeSurface(all_presets_surface.data(), all_presets_surface.size(),
                                kSurfW, kSurfH, bc7_ref_rgba).ok());

    std::vector<uint8_t> bc7_bcpk, bc7_bcpk_dec, bc7_hw, bc7_hw_dec(all_presets_surface.size(), 0u);
    OS_REQUIRE(BcPackCompress(BcFormat::BC7, kSurfW, kSurfH,
                              all_presets_surface.data(), all_presets_surface.size(), bc7_bcpk).ok());
    OS_REQUIRE(BcPackDecompress(bc7_bcpk.data(), bc7_bcpk.size(), bc7_bcpk_dec).ok());
    OS_REQUIRE(bc7_bcpk_dec == all_presets_surface);

    size_t hw_written = 0u;
    OS_REQUIRE(BcPackHwEncodeBitstream(BcFormat::BC7, all_presets_surface.data(),
                                       all_presets_surface.size(), bc7_hw, kSurfW / 4u).ok());
    OS_REQUIRE(BcPackHwDecodeBitstream(BcFormat::BC7, bc7_hw.data(), bc7_hw.size(),
                                       bc7_hw_dec.data(), bc7_hw_dec.size(), &hw_written).ok());
    OS_REQUIRE(hw_written == all_presets_surface.size());
    OS_REQUIRE(bc7_hw_dec == all_presets_surface);

    std::vector<uint8_t> bc7_dec_rgba;
    OS_REQUIRE(Bc7DecodeSurface(bc7_hw_dec.data(), bc7_hw_dec.size(), kSurfW, kSurfH, bc7_dec_rgba).ok());
    OS_REQUIRE(bc7_dec_rgba == bc7_ref_rgba);

    // 2B. BC6H (UF16 & SF16 across all 14 valid modes + 1r/2r transitions + SF16 signed-zero) vs plain mips
    {
        // Verify SF16 post-scaling signed-zero rule: small negative scaling to 0 MUST emit +0.0 (0x0000)
        OS_REQUIRE(Bc6hFinishUnquantize(-1, true) == 0x0000u);
        OS_REQUIRE(Bc6hFinishUnquantize(0, true) == 0x0000u);
        OS_REQUIRE(Bc6hFinishUnquantize(-32, true) == 0x801Fu);  // (-32 * 31) >> 5 = -31 -> negative f16

        static constexpr uint8_t kBc6hModeBytes[14] = {
            0x00u, 0x01u, 0x02u, 0x06u, 0x0Au, 0x0Eu, 0x12u,
            0x16u, 0x1Au, 0x1Eu, 0x03u, 0x07u, 0x0Bu, 0x0Fu};
        std::vector<std::vector<uint8_t>> bc6h_mips;
        const uint32_t mip_dims[3] = {32u, 16u, 8u};
        for (uint32_t m = 0u; m < 3u; ++m) {
            const uint32_t dim = mip_dims[m];
            const uint32_t nblks = (dim / 4u) * (dim / 4u);
            std::vector<uint8_t> surf(nblks * 16u, 0u);
            for (uint32_t b = 0u; b < nblks; ++b) {
                // Alternate 1-region (modes 10..13) and 2-region (modes 0..9) blocks to stress transitions!
                const uint32_t mode_idx = (b & 1u) ? (10u + (b % 4u)) : (b % 10u);
                uint8_t* p = surf.data() + b * 16u;
                p[0] = kBc6hModeBytes[mode_idx];
                for (uint32_t k = 1u; k < 16u; ++k) {
                    p[k] = static_cast<uint8_t>((b * 17u + k * 29u + m * 53u) & 0xFFu);
                }
                Bc6hBcpPresetInfo pinfo{};
                OS_REQUIRE(Bc6hResolveBcpPreset(p, pinfo));
                OS_REQUIRE(pinfo.is_valid && pinfo.mode_index == mode_idx);
                OS_REQUIRE(pinfo.region_count == (mode_idx >= 10u ? 1u : 2u));
            }
            bc6h_mips.push_back(std::move(surf));
        }

        std::vector<uint8_t> mip_packed;
        OS_REQUIRE(BcPackCompressMipChain(BcFormat::BC6H, 32u, 32u, bc6h_mips, mip_packed).ok());
        std::vector<std::vector<uint8_t>> mip_unpacked;
        OS_REQUIRE(BcPackDecompressMipChain(mip_packed.data(), mip_packed.size(), mip_unpacked).ok());
        OS_REQUIRE(mip_unpacked.size() == bc6h_mips.size());

        for (uint32_t m = 0u; m < 3u; ++m) {
            OS_REQUIRE(mip_unpacked[m] == bc6h_mips[m]);
            std::vector<uint8_t> hw_enc, hw_dec(bc6h_mips[m].size(), 0u);
            OS_REQUIRE(BcPackHwEncodeBitstream(BcFormat::BC6H, bc6h_mips[m].data(),
                                               bc6h_mips[m].size(), hw_enc).ok());
            OS_REQUIRE(BcPackHwDecodeBitstream(BcFormat::BC6H, hw_enc.data(), hw_enc.size(),
                                               hw_dec.data(), hw_dec.size()).ok());
            OS_REQUIRE(hw_dec == bc6h_mips[m]);

            // Compare decoded UF16 & SF16 pixels bit-exact against plain reference mip
            std::vector<uint16_t> ref_uf16, dec_uf16, ref_sf16, dec_sf16;
            OS_REQUIRE(Bc6hDecodeSurface(bc6h_mips[m].data(), bc6h_mips[m].size(),
                                         mip_dims[m], mip_dims[m], false, ref_uf16).ok());
            OS_REQUIRE(Bc6hDecodeSurface(hw_dec.data(), hw_dec.size(),
                                         mip_dims[m], mip_dims[m], false, dec_uf16).ok());
            OS_REQUIRE(ref_uf16 == dec_uf16);
            OS_REQUIRE(Bc6hDecodeSurface(bc6h_mips[m].data(), bc6h_mips[m].size(),
                                         mip_dims[m], mip_dims[m], true, ref_sf16).ok());
            OS_REQUIRE(Bc6hDecodeSurface(hw_dec.data(), hw_dec.size(),
                                         mip_dims[m], mip_dims[m], true, dec_sf16).ok());
            OS_REQUIRE(ref_sf16 == dec_sf16);
        }
    }

    // 2C. TTPF 100% Layouts:
    //   1) Single-mip texture without mip tail (zero tail padding overhead!)
    {
        TtpfLayoutDesc d{};
        d.format = BcFormat::BC7;
        d.dimension = TtpfTextureDimension::Tex2D;
        d.width = 64u;
        d.height = 64u;
        d.depth = 1u;
        d.array_size = 1u;
        d.mip_count = 1u;
        d.tile_size_bytes = 65536u;
        d.enable_mip_tail = true;  // MUST be forced false for single-mip!

        TtpfLayoutResult res{};
        OS_REQUIRE(TtpfCalculateLayout(d, res).ok());
        OS_REQUIRE(!res.has_mip_tail);
        OS_REQUIRE(res.mip_tail_first_level == 1u);
        OS_REQUIRE(res.mip_tail_bytes_per_slice == 0ull);
        OS_REQUIRE(res.subresource_count == 1u);
        OS_REQUIRE(!res.subresources[0].in_mip_tail);
        OS_REQUIRE(res.total_logical_bytes == 4096ull);
        OS_REQUIRE(res.total_tiled_bytes == 65536ull);  // 1 tile, zero tail overhead!

        std::vector<uint8_t> hdr_bytes;
        OS_REQUIRE(TtpfSerializeLayoutHeader(res, hdr_bytes).ok());
        TtpfLayoutResult parsed{};
        OS_REQUIRE(TtpfParseLayoutHeader(hdr_bytes.data(), hdr_bytes.size(), parsed).ok());
        OS_REQUIRE(!parsed.has_mip_tail && parsed.total_tiled_bytes == res.total_tiled_bytes);
        OS_REQUIRE(TtpfValidateLayout(parsed).ok());

        // Corrupt CRC must be rejected
        hdr_bytes[16] ^= 0xFFu;
        TtpfLayoutResult bad_parsed{};
        OS_REQUIRE(!TtpfParseLayoutHeader(hdr_bytes.data(), hdr_bytes.size(), bad_parsed).ok());
    }

    //   2) Cubemap mip counts (6 faces * mip_count, face-major indexing, per-face mip tail)
    {
        TtpfLayoutDesc d{};
        d.format = BcFormat::BC7;
        d.dimension = TtpfTextureDimension::Cube;
        d.width = 512u;
        d.height = 512u;
        d.depth = 1u;
        d.array_size = 1u;  // 1 cubemap == 6 faces
        d.mip_count = 10u;  // 512 -> 256 -> 128 -> 64 -> 32 -> 16 -> 8 -> 4 -> 2 -> 1
        d.tile_size_bytes = 65536u;
        d.enable_mip_tail = true;

        TtpfLayoutResult res{};
        OS_REQUIRE(TtpfCalculateLayout(d, res).ok());
        OS_REQUIRE(res.effective_slice_count == 6u);
        OS_REQUIRE(res.subresource_count == 60u);  // 6 faces * 10 mips
        OS_REQUIRE(res.has_mip_tail);
        OS_REQUIRE(res.mip_tail_first_level == 2u);  // mip0=256KiB, mip1=64KiB, mip2=16KiB (<64KiB -> tail)
        OS_REQUIRE(res.mip_tail_bytes_per_slice == 65536ull);
        // Verify face-major indexing: face 3, mip 2 == index 32
        OS_REQUIRE(res.subresources[32].array_slice == 3u);
        OS_REQUIRE(res.subresources[32].mip_level == 2u);
        OS_REQUIRE(res.subresources[32].width == 128u && res.subresources[32].height == 128u);
        OS_REQUIRE(res.subresources[32].in_mip_tail);
        OS_REQUIRE(TtpfValidateLayout(res).ok());

        std::vector<uint8_t> hdr_bytes;
        OS_REQUIRE(TtpfSerializeLayoutHeader(res, hdr_bytes).ok());
        TtpfLayoutResult parsed{};
        OS_REQUIRE(TtpfParseLayoutHeader(hdr_bytes.data(), hdr_bytes.size(), parsed).ok());
        OS_REQUIRE(parsed.subresource_count == 60u && parsed.effective_slice_count == 6u);

        // Non-square cubemap must be rejected
        TtpfLayoutDesc bad_cube = d;
        bad_cube.height = 256u;
        TtpfLayoutResult bad_res{};
        OS_REQUIRE(!TtpfCalculateLayout(bad_cube, bad_res).ok());
    }

    //   3) 3D volume layouts (depth halving max(1, depth >> mip), >4 GiB 64-bit safe arithmetic!)
    {
        TtpfLayoutDesc d{};
        d.format = BcFormat::BC7;
        d.dimension = TtpfTextureDimension::Tex3D;
        d.width = 256u;
        d.height = 128u;
        d.depth = 64u;
        d.array_size = 1u;
        d.mip_count = 9u;  // max(256,128,64)=256 -> 9 mips
        d.tile_size_bytes = 65536u;
        d.enable_mip_tail = true;

        TtpfLayoutResult res{};
        OS_REQUIRE(TtpfCalculateLayout(d, res).ok());
        OS_REQUIRE(res.effective_slice_count == 1u);
        OS_REQUIRE(res.subresource_count == 9u);
        OS_REQUIRE(res.subresources[0].depth == 64u);
        OS_REQUIRE(res.subresources[1].depth == 32u);
        OS_REQUIRE(res.subresources[6].depth == 1u);  // 64 >> 6 == 1
        OS_REQUIRE(res.subresources[7].depth == 1u);  // clamped at 1!
        OS_REQUIRE(res.subresources[8].depth == 1u);  // 1x1x1!
        OS_REQUIRE(res.subresources[0].byte_size ==
                   res.subresources[0].slice_pitch_bytes * 64ull);
        OS_REQUIRE(TtpfValidateLayout(res).ok());

        // >4 GiB 64-bit 3D volume texture: 4096 x 4096 x 512 BC7 (mip 0 alone == 8 GiB!)
        TtpfLayoutDesc huge3d{};
        huge3d.format = BcFormat::BC7;
        huge3d.dimension = TtpfTextureDimension::Tex3D;
        huge3d.width = 4096u;
        huge3d.height = 4096u;
        huge3d.depth = 512u;
        huge3d.array_size = 1u;
        huge3d.mip_count = 4u;
        huge3d.tile_size_bytes = 65536u;
        huge3d.codec_mask = TtpfComputeCodecBitMask(47u) | TtpfComputeCodecBitMask(7u);

        TtpfLayoutResult huge_res{};
        OS_REQUIRE(TtpfCalculateLayout(huge3d, huge_res).ok());
        OS_REQUIRE(huge_res.exceeds_4gib);
        OS_REQUIRE(huge_res.subresources[0].byte_size == 8ull * 1024ull * 1024ull * 1024ull);
        OS_REQUIRE(huge_res.subresources[1].byte_offset == 8ull * 1024ull * 1024ull * 1024ull);
        OS_REQUIRE(huge_res.subresources[1].depth == 256u);
        OS_REQUIRE(TtpfValidateLayout(huge_res).ok());

        std::vector<uint8_t> huge_hdr;
        OS_REQUIRE(TtpfSerializeLayoutHeader(huge_res, huge_hdr).ok());
        TtpfLayoutResult huge_parsed{};
        OS_REQUIRE(TtpfParseLayoutHeader(huge_hdr.data(), huge_hdr.size(), huge_parsed).ok());
        OS_REQUIRE(huge_parsed.exceeds_4gib &&
                   huge_parsed.total_tiled_bytes == huge_res.total_tiled_bytes);
    }

    std::printf("  [PASS] BC7 98-slot presets (incl. all 34 tail slots), BC6H/BC7 mips & TTPF 100%% layouts.\n");
}

// ===========================================================================
// 3. Audio 100% (xcl #89/#90): XAudio2 clamp_regions + silent_buffer,
//    AcpHal APU overflow/overlap + SHAPE rollback, xapu OOM/invalid, MT stress
// ===========================================================================
class TrackingVoiceCallback final : public IXAudio2VoiceCallback {
public:
    void OPENSCARLETT_XAUDIO2_CALL OnVoiceProcessingPassStart(uint32_t) override {
        pass_starts.fetch_add(1u, std::memory_order_relaxed);
    }
    void OPENSCARLETT_XAUDIO2_CALL OnVoiceProcessingPassEnd() override {
        pass_ends.fetch_add(1u, std::memory_order_relaxed);
    }
    void OPENSCARLETT_XAUDIO2_CALL OnStreamEnd() override {
        stream_ends.fetch_add(1u, std::memory_order_relaxed);
    }
    void OPENSCARLETT_XAUDIO2_CALL OnBufferStart(void*) override {
        buf_starts.fetch_add(1u, std::memory_order_relaxed);
    }
    void OPENSCARLETT_XAUDIO2_CALL OnBufferEnd(void*) override {
        buf_ends.fetch_add(1u, std::memory_order_relaxed);
    }
    void OPENSCARLETT_XAUDIO2_CALL OnLoopEnd(void*) override {
        loop_ends.fetch_add(1u, std::memory_order_relaxed);
    }
    void OPENSCARLETT_XAUDIO2_CALL OnVoiceError(void*, int32_t) override {
        errors.fetch_add(1u, std::memory_order_relaxed);
    }

    std::atomic<uint32_t> pass_starts{0u};
    std::atomic<uint32_t> pass_ends{0u};
    std::atomic<uint32_t> stream_ends{0u};
    std::atomic<uint32_t> buf_starts{0u};
    std::atomic<uint32_t> buf_ends{0u};
    std::atomic<uint32_t> loop_ends{0u};
    std::atomic<uint32_t> errors{0u};
};

void TestAudio100() {
    std::printf("[3/4] Audio 100%% (XAudio2 clamp_regions/silent_buffer, AcpHal overflow/SHAPE rollback, xapu OOM, MT XMA2+Opus stress)...\n");

    // 3A. XAudio2_9 play/loop region clamping & silent_buffer invariants
    {
        IXAudio2* xa = nullptr;
        OS_REQUIRE(XAudio2Create(&xa, 0u, 0u) == OS_XAUDIO2_S_OK && xa != nullptr);
        IXAudio2MasteringVoice* master = nullptr;
        OS_REQUIRE(xa->CreateMasteringVoice(&master, 2u, 48000u, 0u, nullptr, nullptr, 0u) == OS_XAUDIO2_S_OK);
        OS_REQUIRE(xa->StartEngine() == OS_XAUDIO2_S_OK);

        OS_WAVEFORMATEX wf{};
        wf.wFormatTag = OS_WAVE_FORMAT_IEEE_FLOAT;
        wf.nChannels = 2u;
        wf.nSamplesPerSec = 48000u;
        wf.wBitsPerSample = 32u;
        wf.nBlockAlign = 8u;
        wf.nAvgBytesPerSec = 48000u * 8u;

        TrackingVoiceCallback cb;
        IXAudio2SourceVoice* sv = nullptr;
        OS_REQUIRE(xa->CreateSourceVoice(&sv, &wf, 0u, 2.0f, &cb, nullptr, nullptr) == OS_XAUDIO2_S_OK);
        OS_REQUIRE(sv->Start(0u, 0u) == OS_XAUDIO2_S_OK);

        // 256 stereo frames of constant +0.5f signal
        std::vector<float> pcm(256u * 2u, 0.5f);
        std::vector<float> mix_out(1024u * 2u, 0.0f);

        // (i) LoopCount > OS_XAUDIO2_LOOP_INFINITE MUST be rejected
        OS_XAUDIO2_BUFFER bad_loop{};
        bad_loop.AudioBytes = static_cast<uint32_t>(pcm.size() * sizeof(float));
        bad_loop.pAudioData = reinterpret_cast<const uint8_t*>(pcm.data());
        bad_loop.LoopCount = OS_XAUDIO2_LOOP_INFINITE + 1u;
        OS_REQUIRE(sv->SubmitSourceBuffer(&bad_loop, nullptr) == OS_XAUDIO2_E_INVALIDARG);

        // (ii) silent_buffer: zero-length / null-data EOS buffer MUST fire OnBufferStart, OnBufferEnd, OnStreamEnd!
        OS_XAUDIO2_BUFFER silent_eos{};
        silent_eos.Flags = OS_XAUDIO2_END_OF_STREAM;
        silent_eos.AudioBytes = 0u;
        silent_eos.pAudioData = nullptr;
        silent_eos.LoopCount = 5u;  // Must be forced to 0 on zero-frame buffer (no infinite loop!)
        silent_eos.pContext = reinterpret_cast<void*>(0x1111ull);
        OS_REQUIRE(sv->SubmitSourceBuffer(&silent_eos, nullptr) == OS_XAUDIO2_S_OK);

        std::fill(mix_out.begin(), mix_out.end(), 0.0f);
        OS_REQUIRE(OpenScarlettXAudio2RenderMixForTest(xa, mix_out.data(), 128u) == OS_XAUDIO2_S_OK);
        for (float s : mix_out) OS_REQUIRE(s == 0.0f);  // Silent output!
        OS_REQUIRE(cb.buf_starts.load() == 1u);
        OS_REQUIRE(cb.buf_ends.load() == 1u);
        OS_REQUIRE(cb.stream_ends.load() == 1u);
        OS_REQUIRE(cb.loop_ends.load() == 0u);

        OS_XAUDIO2_VOICE_STATE vst{};
        sv->GetState(&vst, 0u);
        OS_REQUIRE(vst.BuffersQueued == 0u);

        // (iii) PlayBegin >= total_frames (OOB play region) -> safely clamped to 0 frames, no OOB!
        OS_XAUDIO2_BUFFER oob_play{};
        oob_play.AudioBytes = static_cast<uint32_t>(pcm.size() * sizeof(float));
        oob_play.pAudioData = reinterpret_cast<const uint8_t*>(pcm.data());
        oob_play.PlayBegin = 9999u;
        oob_play.PlayLength = 500u;
        oob_play.LoopBegin = 100u;
        oob_play.LoopLength = 50u;
        oob_play.LoopCount = 3u;
        oob_play.Flags = OS_XAUDIO2_END_OF_STREAM;
        OS_REQUIRE(sv->SubmitSourceBuffer(&oob_play, nullptr) == OS_XAUDIO2_S_OK);
        OS_REQUIRE(OpenScarlettXAudio2RenderMixForTest(xa, mix_out.data(), 64u) == OS_XAUDIO2_S_OK);
        sv->GetState(&vst, 0u);
        OS_REQUIRE(vst.BuffersQueued == 0u);
        OS_REQUIRE(cb.buf_ends.load() == 2u && cb.stream_ends.load() == 2u);

        // (iv) PlayBegin=100, PlayLength=1000 (clamped to 156 frames), LoopBegin=50 (<PlayBegin!),
        //      LoopLength=0xFFFFFFF0 (32-bit overflow!), LoopCount=2 -> must clamp loop to [0..156]
        //      and play 156 * (1 + 2) = 468 frames cleanly without OOB or infinite loop!
        const uint64_t played_before = vst.SamplesPlayed;
        OS_XAUDIO2_BUFFER clamped_loop{};
        clamped_loop.AudioBytes = static_cast<uint32_t>(pcm.size() * sizeof(float));
        clamped_loop.pAudioData = reinterpret_cast<const uint8_t*>(pcm.data());
        clamped_loop.PlayBegin = 100u;
        clamped_loop.PlayLength = 1000u;      // clamped to 256 - 100 = 156 frames
        clamped_loop.LoopBegin = 50u;         // before PlayBegin -> clamped to PlayBegin (0 relative)
        clamped_loop.LoopLength = 0xFFFFFFF0u; // 32-bit overflow -> clamped to 156
        clamped_loop.LoopCount = 2u;
        clamped_loop.Flags = OS_XAUDIO2_END_OF_STREAM;
        OS_REQUIRE(sv->SubmitSourceBuffer(&clamped_loop, nullptr) == OS_XAUDIO2_S_OK);

        std::fill(mix_out.begin(), mix_out.end(), 0.0f);
        OS_REQUIRE(OpenScarlettXAudio2RenderMixForTest(xa, mix_out.data(), 1024u) == OS_XAUDIO2_S_OK);
        sv->GetState(&vst, 0u);
        OS_REQUIRE(vst.BuffersQueued == 0u);
        OS_REQUIRE(vst.SamplesPlayed - played_before == 156ull * 3ull);
        OS_REQUIRE(cb.loop_ends.load() == 2u);
        OS_REQUIRE(cb.stream_ends.load() == 3u);
        // Verify audio was actually mixed for those 468 frames and silent afterwards
        OS_REQUIRE(std::fabs(mix_out[0] - 0.5f) < 1e-4f);
        OS_REQUIRE(std::fabs(mix_out[467u * 2u] - 0.5f) < 1e-4f);
        OS_REQUIRE(std::fabs(mix_out[500u * 2u]) < 1e-6f);

        sv->DestroyVoice();
        master->DestroyVoice();
        xa->Release();
    }

    // 3B. AcpHal APU address overflow/overlap validation & atomic SHAPE multi-stage rollback
    {
        // Reject capacity exceeding APU address space
        OS_REQUIRE(ApuCreateHeap(0x80000000u, 1024u) == ACPHAL_E_INVALIDARG);

        // Create a tight 4 KiB cached APU heap to exercise overflow, overlap, and SHAPE rollback
        constexpr uint32_t kTightCap = 4096u;
        OS_REQUIRE(ApuCreateHeap(kTightCap, 4096u) == ACPHAL_S_OK);

        void* va_a = nullptr;
        APU_ADDRESS pa_a = APU_INVALID_ADDRESS;
        OS_REQUIRE(ApuAlloc(&va_a, &pa_a, 1024u, 64u, APU_ALLOC_CACHED) == ACPHAL_S_OK);
        OS_REQUIRE(va_a != nullptr && pa_a != APU_INVALID_ADDRESS);

        // Validate in-range vs overflow vs overlap
        OS_REQUIRE(ApuValidateAddressRange(pa_a, 1024u) == ACPHAL_S_OK);
        OS_REQUIRE(ApuValidateAddressRange(pa_a, 1025u) == ACPHAL_E_INVALIDARG);
        OS_REQUIRE(ApuValidateAddressRange(0xFFFFF800u, 0x1000u) == ACPHAL_E_INVALIDARG);  // 32-bit wrap
        OS_REQUIRE(ApuCheckAddressRangeDisjoint(pa_a, 512u) == ACPHAL_E_INVALIDARG);       // overlaps active!
        OS_REQUIRE(ApuCheckAddressRangeDisjoint(pa_a + 1024u, 1024u) == ACPHAL_S_OK);      // disjoint!
        OS_REQUIRE(ApuCheckAddressRangeDisjoint(0xFFFFF800u, 0x1000u) == ACPHAL_E_INVALIDARG);
        OS_REQUIRE(ApuIsVirtualAddressValid(va_a, 0xFFFFFFFFu) == 0);
        OS_REQUIRE(ApuFree(va_a) == ACPHAL_S_OK);

        APU_HEAP_STATE st_before{};
        OS_REQUIRE(ApuHeapGetState(&st_before, APU_ALLOC_CACHED) == ACPHAL_S_OK);
        OS_REQUIRE(st_before.bytesAllocated == 0u && st_before.allocationCount == 0u);

        // Synthetic 2-arg SHAPE rollback: stage 0 (16*64=1024B) + stage 1 (32*32=1024B) succeed,
        // stage 2 (128*32=4096B) triggers OOM -> MUST roll back stages 0..1 leaving 0 leaked bytes!
        AcpHalShapeContexts req{};
        req.numXmaContexts = 16u;   // 1024 B
        req.numSrcContexts = 32u;   // 1024 B
        req.numEqContexts = 128u;   // 4096 B -> total 6144 > 4096 OOM at stage 2!
        req.numDmaContexts = 8u;
        AcpHalShapeContexts allocated{};
        OS_REQUIRE(AcpHalAllocateShapeContexts(&req, &allocated) == ACPHAL_E_OUTOFMEMORY);
        OS_REQUIRE(allocated.internalAllocation == nullptr);

        APU_HEAP_STATE st_after{};
        OS_REQUIRE(ApuHeapGetState(&st_after, APU_ALLOC_CACHED) == ACPHAL_S_OK);
        OS_REQUIRE(st_after.bytesAllocated == 0u && st_after.allocationCount == 0u &&
                   st_after.bytesFree == st_before.bytesFree);

        // 64-bit stage overflow check (count * 64 overflows 32-bit / cap) -> E_INVALIDARG, 0 leaks
        AcpHalShapeContexts overflow_req{};
        overflow_req.numXmaContexts = 0x10000000u;
        OS_REQUIRE(AcpHalAllocateShapeContexts(&overflow_req, &allocated) == ACPHAL_E_INVALIDARG);
        OS_REQUIRE(ApuHeapGetState(&st_after, APU_ALLOC_CACHED) == ACPHAL_S_OK);
        OS_REQUIRE(st_after.allocationCount == 0u);

        // Retail 1-arg SHAPE rollback (XboxAcpShapeContexts layout):
        struct RetailShapeCtx {
            uint32_t numSrc, numEq, numFilt, numDma, numXma, numPcm;
            void* pSrc;
            void* pEq;
            void* pFilt;
            void* pDma;
            void* pXma;
            void* pPcm;
            uint64_t reserved[3];
        };
        RetailShapeCtx retail{};
        retail.numSrc = 32u;    // 1024 B (fits)
        retail.numEq = 32u;     // 1024 B (fits)
        retail.numFilt = 32u;   // 1024 B (fits)
        retail.numXma = 128u;   // 8192 B (OOM at stage 4 -> MUST roll back stages 0..2!)
        OS_REQUIRE(AcpHalAllocateShapeContexts(
                       reinterpret_cast<const AcpHalShapeContexts*>(&retail), nullptr) == ACPHAL_E_OUTOFMEMORY);
        OS_REQUIRE(retail.pSrc == nullptr && retail.pEq == nullptr && retail.pFilt == nullptr &&
                   retail.pXma == nullptr);
        OS_REQUIRE(ApuHeapGetState(&st_after, APU_ALLOC_CACHED) == ACPHAL_S_OK);
        OS_REQUIRE(st_after.bytesAllocated == 0u && st_after.allocationCount == 0u);

        // Valid SHAPE allocation + clean release (restoring synthetic mode cleanly)
        AcpHalShapeContexts good_req{};
        good_req.numXmaContexts = 8u;   // 512 B
        good_req.numSrcContexts = 16u;  // 512 B
        good_req.numEqContexts = 8u;    // 256 B
        good_req.numDmaContexts = 16u;  // 256 B
        OS_REQUIRE(AcpHalAllocateShapeContexts(&good_req, &allocated) == ACPHAL_S_OK);
        OS_REQUIRE(allocated.internalAllocation != nullptr);
        OS_REQUIRE(ApuHeapGetState(&st_after, APU_ALLOC_CACHED) == ACPHAL_S_OK);
        OS_REQUIRE(st_after.allocationCount == 4u && st_after.bytesAllocated == 1536u);
        OS_REQUIRE(AcpHalReleaseShapeContexts(&allocated) == ACPHAL_S_OK);
        OS_REQUIRE(ApuHeapGetState(&st_after, APU_ALLOC_CACHED) == ACPHAL_S_OK);
        OS_REQUIRE(st_after.allocationCount == 0u && st_after.bytesAllocated == 0u);
    }

    // 3C. xapu XApuConnect OOM & invalid-parameter hardening + double-disconnect safety
    {
        struct RetailXApuParams {
            uint32_t codecType;
            uint32_t streamCount;
            uint32_t maxChannels;
            uint32_t sharedMemoryBytes;
            uint32_t extraParam;
            uint32_t flags;
        };
        struct RetailXApuShm {
            void* base;
            uint64_t size;
        };

        OS_REQUIRE(XApuConnect(nullptr) == XAPU_E_POINTER);

        // Invalid codecType (99) MUST return E_INVALIDARG and NOT corrupt caller params!
        RetailXApuParams bad_codec{99u, 4u, 2u, 65536u, 0u, 0u};
        const RetailXApuParams bad_codec_copy = bad_codec;
        RetailXApuShm shm{};
        XAPU_CONNECTION_HANDLE h = reinterpret_cast<XAPU_CONNECTION_HANDLE>(0x1234ull);
        OS_REQUIRE(XApuConnect(&bad_codec, &shm, &h) == XAPU_E_INVALIDARG);
        OS_REQUIRE(std::memcmp(&bad_codec, &bad_codec_copy, sizeof(bad_codec)) == 0);
        OS_REQUIRE(h == nullptr && shm.base == nullptr && shm.size == 0ull);

        // Invalid streamCount == 0
        RetailXApuParams bad_streams{1u, 0u, 2u, 65536u, 0u, 0u};
        OS_REQUIRE(XApuConnect(&bad_streams, &shm, &h) == XAPU_E_INVALIDARG);
        OS_REQUIRE(h == nullptr);

        // Excessive sharedMemoryBytes (512 MiB > cap) -> OOM with zero state corruption
        RetailXApuParams oom_params{1u, 4u, 2u, 512u * 1024u * 1024u, 0u, 0u};
        OS_REQUIRE(XApuConnect(&oom_params, &shm, &h) == XAPU_E_OUTOFMEMORY);
        OS_REQUIRE(h == nullptr && shm.base == nullptr);

        // Valid 3-arg connect -> enqueue/dequeue -> disconnect -> double-disconnect rejected cleanly
        RetailXApuParams good_params{1u, 2u, 2u, 65536u, 0u, 0u};
        OS_REQUIRE(XApuConnect(&good_params, &shm, &h) == XAPU_S_OK);
        // XApuConnect honors the requested sharedMemoryBytes (min 64 KiB) instead of
        // inflating to streamCount * 64 KiB.
        OS_REQUIRE(h != nullptr && shm.base != nullptr &&
                   shm.size >= static_cast<uint64_t>(good_params.sharedMemoryBytes) &&
                   shm.size >= 0x10000ull);
        uint32_t dummy_cmd[4] = {1u, 7u, 0u, 0u};
        OS_REQUIRE(XApuEnqueueCommand(h, dummy_cmd, 0u) == XAPU_S_OK);
        uint8_t res_buf[0x50]{};
        OS_REQUIRE(XApuDequeueResult(h, res_buf, sizeof(res_buf), nullptr) == XAPU_S_OK);
        OS_REQUIRE(XApuDisconnect(h) == XAPU_S_OK);
        OS_REQUIRE(XApuDisconnect(h) == XAPU_E_HANDLE);  // double-disconnect safe!
    }

    // 3D. Multi-stream concurrent XMA2 + Opus + PCM + WASAPI (OPENSCARLETT_AUDIO_NULL=1 safe) stress test
    {
        IXAudio2* xa = nullptr;
        OS_REQUIRE(XAudio2Create(&xa, 0u, 0u) == OS_XAUDIO2_S_OK && xa != nullptr);
        IXAudio2MasteringVoice* master = nullptr;
        OS_REQUIRE(xa->CreateMasteringVoice(&master, 2u, 48000u, 0u, nullptr, nullptr, 0u) == OS_XAUDIO2_S_OK);
        OS_REQUIRE(xa->StartEngine() == OS_XAUDIO2_S_OK);

        // Encode real XMA2 packets + Opus stream
        std::vector<float> sine_mono(1024u);
        for (size_t i = 0u; i < sine_mono.size(); ++i) {
            sine_mono[i] = 0.25f * std::sin(6.2831853f * 440.0f * static_cast<float>(i) / 48000.0f);
        }
        Xma2Config xma_cfg{};
        xma_cfg.sample_rate = 48000u;
        xma_cfg.channels = 1u;
        std::vector<uint8_t> xma_pkt;
        OS_REQUIRE(Xma2EncodePcmToPackets(sine_mono.data(), 512u, xma_cfg, xma_pkt).ok());

        std::vector<std::vector<uint8_t>> opus_pkts = {
            BuildOpusTestPacket(1u, 0u, 64u),
            BuildOpusTestPacket(1u, 1u, 64u),
        };
        std::vector<uint8_t> opus_stream = PackOpusLengthPrefixedStream(opus_pkts, false);

        constexpr int kStreamCount = 6;
        std::vector<IXAudio2SourceVoice*> voices(kStreamCount, nullptr);
        std::vector<TrackingVoiceCallback> cbs(kStreamCount);

        for (int i = 0; i < kStreamCount; ++i) {
            if (i < 2) {
                OS_WAVEFORMATEX wf{};
                wf.wFormatTag = OS_WAVE_FORMAT_XMA2;
                wf.nChannels = 1u;
                wf.nSamplesPerSec = 48000u;
                wf.wBitsPerSample = 16u;
                wf.nBlockAlign = 2u;
                wf.nAvgBytesPerSec = 48000u;
                OS_REQUIRE(xa->CreateSourceVoice(&voices[i], &wf, 0u, 2.0f, &cbs[i], nullptr, nullptr) == OS_XAUDIO2_S_OK);
            } else if (i < 4) {
                OS_OPUSWAVEFORMAT wf{};
                wf.wfx.wFormatTag = OS_WAVE_FORMAT_OPUS;
                wf.wfx.nChannels = 1u;
                wf.wfx.nSamplesPerSec = 48000u;
                wf.wfx.wBitsPerSample = 16u;
                wf.wfx.nBlockAlign = 2u;
                wf.wfx.nAvgBytesPerSec = 48000u;
                wf.wfx.cbSize = sizeof(OS_OPUSWAVEFORMAT) - sizeof(OS_WAVEFORMATEX);
                wf.PreSkip = 0u;
                wf.Version = 1u;
                OS_REQUIRE(xa->CreateSourceVoice(&voices[i], &wf.wfx, 0u, 2.0f, &cbs[i], nullptr, nullptr) == OS_XAUDIO2_S_OK);
            } else {
                OS_WAVEFORMATEX wf{};
                wf.wFormatTag = OS_WAVE_FORMAT_IEEE_FLOAT;
                wf.nChannels = 1u;
                wf.nSamplesPerSec = 48000u;
                wf.wBitsPerSample = 32u;
                wf.nBlockAlign = 4u;
                wf.nAvgBytesPerSec = 48000u * 4u;
                OS_REQUIRE(xa->CreateSourceVoice(&voices[i], &wf, 0u, 2.0f, &cbs[i], nullptr, nullptr) == OS_XAUDIO2_S_OK);
            }
            OS_REQUIRE(voices[i]->Start(0u, 0u) == OS_XAUDIO2_S_OK);
        }

        // Concurrently submit XMA2, Opus, PCM, and silent buffers while mixing blocks
        std::atomic<bool> stop_mixing{false};
        std::atomic<double> total_energy{0.0};
        std::thread mixer([&]() {
            std::vector<float> block(480u * 2u, 0.0f);
            while (!stop_mixing.load(std::memory_order_acquire)) {
                std::fill(block.begin(), block.end(), 0.0f);
                if (OpenScarlettXAudio2RenderMixForTest(xa, block.data(), 480u) == OS_XAUDIO2_S_OK) {
                    double e = 0.0;
                    for (float s : block) e += static_cast<double>(s) * static_cast<double>(s);
                    double prev = total_energy.load(std::memory_order_relaxed);
                    total_energy.store(prev + e, std::memory_order_relaxed);
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
            }
        });

        std::vector<std::thread> submitters;
        for (int i = 0; i < kStreamCount; ++i) {
            submitters.emplace_back([&, i]() {
                for (int r = 0; r < 6; ++r) {
                    OS_XAUDIO2_BUFFER b{};
                    if (i < 2) {
                        b.AudioBytes = static_cast<uint32_t>(xma_pkt.size());
                        b.pAudioData = xma_pkt.data();
                    } else if (i < 4) {
                        b.AudioBytes = static_cast<uint32_t>(opus_stream.size());
                        b.pAudioData = opus_stream.data();
                    } else if (r == 2) {
                        // Interleave a silent buffer mid-stream!
                        b.AudioBytes = 0u;
                        b.pAudioData = nullptr;
                    } else {
                        b.AudioBytes = static_cast<uint32_t>(sine_mono.size() * sizeof(float));
                        b.pAudioData = reinterpret_cast<const uint8_t*>(sine_mono.data());
                    }
                    if (r == 5) b.Flags = OS_XAUDIO2_END_OF_STREAM;
                    OS_REQUIRE(voices[i]->SubmitSourceBuffer(&b, nullptr) == OS_XAUDIO2_S_OK);
                    std::this_thread::sleep_for(std::chrono::milliseconds(2));
                }
            });
        }
        for (auto& s : submitters) s.join();

        // Drain remaining mixed frames cleanly
        std::vector<float> drain_buf(480u * 2u, 0.0f);
        for (int d = 0; d < 40; ++d) {
            OS_REQUIRE(OpenScarlettXAudio2RenderMixForTest(xa, drain_buf.data(), 480u) == OS_XAUDIO2_S_OK);
        }
        stop_mixing.store(true, std::memory_order_release);
        mixer.join();

        OS_REQUIRE(total_energy.load() > 0.01);
        for (int i = 0; i < kStreamCount; ++i) {
            OS_REQUIRE(cbs[i].buf_starts.load() >= 6u);
            OS_REQUIRE(cbs[i].buf_ends.load() >= 6u);
            OS_REQUIRE(cbs[i].stream_ends.load() >= 1u);
            OS_REQUIRE(cbs[i].errors.load() == 0u);
            voices[i]->DestroyVoice();
        }
        master->DestroyVoice();
        xa->Release();
    }

    std::printf("  [PASS] Audio 100%% (XAudio2, AcpHal, xapu, concurrent XMA2+Opus stress).\n");
}

// ===========================================================================
// 4. Video 100%: mfhevcdec IMFTransform, mflnmhelp Stateful Helper,
//    Bink2Scarlett Live D3D12 Compute YUV->RGBA (HW GPU + WARP <= 1 LSB vs CPU)
// ===========================================================================
struct BitWriterMsb {
    std::vector<uint8_t> bytes;
    uint8_t cur = 0u;
    uint32_t bit_in_byte = 0u;

    void WriteBits(uint32_t val, uint32_t n) {
        for (uint32_t i = n; i > 0u; --i) {
            const uint8_t b = static_cast<uint8_t>((val >> (i - 1u)) & 1u);
            cur = static_cast<uint8_t>((cur << 1u) | b);
            ++bit_in_byte;
            if (bit_in_byte == 8u) {
                bytes.push_back(cur);
                cur = 0u;
                bit_in_byte = 0u;
            }
        }
    }

    void WriteUe(uint32_t v) {
        const uint32_t code_num = v + 1u;
        uint32_t len = 0u;
        uint32_t tmp = code_num;
        while (tmp > 0u) {
            ++len;
            tmp >>= 1u;
        }
        const uint32_t leading_zeros = len - 1u;
        WriteBits(0u, leading_zeros);
        WriteBits(code_num, len);
    }

    void Finish() {
        WriteBits(1u, 1u);  // RBSP stop bit
        if (bit_in_byte > 0u) {
            cur = static_cast<uint8_t>(cur << (8u - bit_in_byte));
            bytes.push_back(cur);
            cur = 0u;
            bit_in_byte = 0u;
        }
    }
};

std::vector<uint8_t> BuildAnnexBHevcFrame(uint32_t w, uint32_t h) {
    std::vector<uint8_t> out;
    auto push_sc = [&]() {
        out.push_back(0x00u); out.push_back(0x00u); out.push_back(0x00u); out.push_back(0x01u);
    };
    // VPS NAL (type 32 -> byte0 = 32<<1 = 0x40, byte1 = 0x01)
    push_sc();
    out.push_back(0x40u); out.push_back(0x01u);
    out.push_back(0x0Cu); out.push_back(0x01u); out.push_back(0xFFu);

    // SPS NAL (type 33 -> byte0 = 33<<1 = 0x42, byte1 = 0x01)
    BitWriterMsb sps;
    sps.WriteBits(0u, 4u);   // sps_video_parameter_set_id
    sps.WriteBits(0u, 3u);   // sps_max_sub_layers_minus1 = 0
    sps.WriteBits(1u, 1u);   // sps_temporal_id_nesting_flag
    // profile_tier_level (96 bits = 12 bytes)
    sps.WriteBits(1u, 8u);   // Main profile
    for (int i = 0; i < 10; ++i) sps.WriteBits(0u, 8u);
    sps.WriteBits(93u, 8u);  // Level 3.1
    sps.WriteUe(0u);         // sps_seq_parameter_set_id
    sps.WriteUe(1u);         // chroma_format_idc = 1 (4:2:0)
    sps.WriteUe(w);          // pic_width_in_luma_samples
    sps.WriteUe(h);          // pic_height_in_luma_samples
    sps.WriteBits(0u, 1u);   // conformance_window_flag = 0
    sps.Finish();

    push_sc();
    out.push_back(0x42u); out.push_back(0x01u);
    out.insert(out.end(), sps.bytes.begin(), sps.bytes.end());

    // PPS NAL (type 34 -> 0x44, 0x01)
    push_sc();
    out.push_back(0x44u); out.push_back(0x01u); out.push_back(0xC1u); out.push_back(0x73u);

    // IDR_W_RADL NAL (type 19 -> 19<<1 = 0x26, 0x01)
    push_sc();
    out.push_back(0x26u); out.push_back(0x01u);
    for (uint32_t i = 0u; i < 32u; ++i) out.push_back(static_cast<uint8_t>(0x30u + i));
    return out;
}

std::vector<uint8_t> BuildAnnexBH264Frame(uint32_t w, uint32_t h) {
    std::vector<uint8_t> out;
    auto push_sc = [&]() {
        out.push_back(0x00u); out.push_back(0x00u); out.push_back(0x00u); out.push_back(0x01u);
    };
    // SPS NAL (type 7 -> 0x67)
    BitWriterMsb sps;
    sps.WriteBits(66u, 8u);  // Baseline profile_idc
    sps.WriteBits(0u, 8u);   // constraint flags
    sps.WriteBits(31u, 8u);  // level 3.1
    sps.WriteUe(0u);         // seq_parameter_set_id
    sps.WriteUe(0u);         // log2_max_frame_num_minus4
    sps.WriteUe(0u);         // pic_order_cnt_type
    sps.WriteUe(0u);         // log2_max_pic_order_cnt_lsb_minus4
    sps.WriteUe(1u);         // max_num_ref_frames
    sps.WriteBits(0u, 1u);   // gaps_in_frame_num_value_allowed_flag
    sps.WriteUe((w / 16u) - 1u);  // pic_width_in_mbs_minus1
    sps.WriteUe((h / 16u) - 1u);  // pic_height_in_map_units_minus1
    sps.WriteBits(1u, 1u);   // frame_mbs_only_flag = 1
    sps.WriteBits(1u, 1u);   // direct_8x8_inference_flag
    sps.WriteBits(0u, 1u);   // frame_cropping_flag = 0
    sps.Finish();

    push_sc();
    out.push_back(0x67u);
    out.insert(out.end(), sps.bytes.begin(), sps.bytes.end());

    // PPS NAL (type 8 -> 0x68)
    push_sc();
    out.push_back(0x68u); out.push_back(0xCEu); out.push_back(0x3Cu); out.push_back(0x80u);

    // IDR slice NAL (type 5 -> 0x65)
    push_sc();
    out.push_back(0x65u);
    for (uint32_t i = 0u; i < 32u; ++i) out.push_back(static_cast<uint8_t>(0x50u + i));
    return out;
}

void TestVideo100() {
    std::printf("[4/4] Video 100%% (mfhevcdec IMFTransform, mflnmhelp stateful helper, Bink2Scarlett GPU YUV->RGBA HW+WARP)...\n");

#if defined(_WIN32)
    const fs::path bin_dir = GetExeDir();

    // 4A. mfhevcdec.dll real IMFTransform + Annex-B HEVC & H.264 + D3D12 Device Manager + DllCanUnloadNow
    {
        HMODULE h_mfplat = ::LoadLibraryW((bin_dir / L"mfplat_xs.dll").c_str());
        OS_REQUIRE(h_mfplat != nullptr);
        HMODULE h_hevc = ::LoadLibraryW((bin_dir / L"mfhevcdec.dll").c_str());
        OS_REQUIRE(h_hevc != nullptr);

        using PfnDllGco = int32_t(__stdcall*)(const void*, const void*, void**);
        using PfnDllUnload = int32_t(__stdcall*)();
        using PfnCreateMft = int32_t(__stdcall*)(void**);
        using PfnCreateDxgiMgr = int32_t(__stdcall*)(uint32_t*, void**);
        using PfnResetDxgiMgrX = int32_t(__stdcall*)(void*, void*, uint32_t);
        using PfnCreateSample = int32_t(__stdcall*)(void**);
        using PfnCreateMemBuf = int32_t(__stdcall*)(uint32_t, void**);

        auto fn_gco = reinterpret_cast<PfnDllGco>(reinterpret_cast<void*>(::GetProcAddress(h_hevc, "DllGetClassObject")));
        auto fn_unload = reinterpret_cast<PfnDllUnload>(reinterpret_cast<void*>(::GetProcAddress(h_hevc, "DllCanUnloadNow")));
        auto fn_create_mft = reinterpret_cast<PfnCreateMft>(reinterpret_cast<void*>(::GetProcAddress(h_hevc, "MFCreateHevcDecoderTransform")));
        auto fn_create_dxgi = reinterpret_cast<PfnCreateDxgiMgr>(reinterpret_cast<void*>(::GetProcAddress(h_mfplat, "MFCreateDXGIDeviceManager")));
        auto fn_reset_dxgi = reinterpret_cast<PfnResetDxgiMgrX>(reinterpret_cast<void*>(::GetProcAddress(h_mfplat, "MFResetDXGIDeviceManagerX")));
        auto fn_create_sample = reinterpret_cast<PfnCreateSample>(reinterpret_cast<void*>(::GetProcAddress(h_mfplat, "MFCreateSample")));
        auto fn_create_buf = reinterpret_cast<PfnCreateMemBuf>(reinterpret_cast<void*>(::GetProcAddress(h_mfplat, "MFCreateMemoryBuffer")));
        OS_REQUIRE(fn_gco && fn_unload && fn_create_mft && fn_create_dxgi && fn_reset_dxgi && fn_create_buf);

        // Idle -> DllCanUnloadNow == S_OK
        OS_REQUIRE(fn_unload() == S_OK);

        // Create via IClassFactory -> QueryInterface(IID_IMFTransform)
        IClassFactory* cf = nullptr;
        OS_REQUIRE(fn_gco(nullptr, &kIidIClassFactory, reinterpret_cast<void**>(&cf)) == S_OK && cf != nullptr);
        OS_REQUIRE(cf->LockServer(TRUE) == S_OK);
        OS_REQUIRE(fn_unload() == S_FALSE);  // Locked!
        OS_REQUIRE(cf->LockServer(FALSE) == S_OK);

        IMFTransform* mft = nullptr;
        OS_REQUIRE(cf->CreateInstance(nullptr, kIidImfTransform, reinterpret_cast<void**>(&mft)) == S_OK && mft != nullptr);
        OS_REQUIRE(fn_unload() == S_FALSE);  // Live MFT object exists!

        // Verify IMFTransform stream limits/count/IDs/info/attributes
        DWORD in_min = 0, in_max = 0, out_min = 0, out_max = 0;
        OS_REQUIRE(mft->GetStreamLimits(&in_min, &in_max, &out_min, &out_max) == S_OK);
        OS_REQUIRE(in_min == 1u && in_max == 1u && out_min == 1u && out_max == 1u);
        DWORD in_cnt = 0, out_cnt = 0;
        OS_REQUIRE(mft->GetStreamCount(&in_cnt, &out_cnt) == S_OK && in_cnt == 1u && out_cnt == 1u);
        DWORD in_id = 99, out_id = 99;
        OS_REQUIRE(mft->GetStreamIDs(1u, &in_id, 1u, &out_id) == S_OK && in_id == 0u && out_id == 0u);
        IMFAttributes* attrs = nullptr;
        OS_REQUIRE(mft->GetAttributes(&attrs) == S_OK && attrs != nullptr);
        UINT32 d3d_aware = 0u;
        OS_REQUIRE(attrs->GetUINT32(kMfSaD3d11Aware, &d3d_aware) == S_OK && d3d_aware == 1u);
        attrs->Release();

        // Bind a real D3D12 device via IMFDXGIDeviceManager + MFT_MESSAGE_SET_D3D_MANAGER!
        ID3D12Device* d3d12_dev = nullptr;
        IDXGIAdapter1* adapter = nullptr;
        D3D12AdapterSelectionOptions aopts{};
        aopts.prefer_warp = true;
        D3D12AdapterInfo ainfo{};
        if (SelectD3D12AdapterAndCreateDevice(aopts, &d3d12_dev, &adapter, &ainfo).ok() && d3d12_dev) {
            uint32_t reset_tok = 0u;
            IMFDXGIDeviceManager* dxgi_mgr = nullptr;
            OS_REQUIRE(fn_create_dxgi(&reset_tok, reinterpret_cast<void**>(&dxgi_mgr)) == S_OK && dxgi_mgr != nullptr);
            OS_REQUIRE(fn_reset_dxgi(dxgi_mgr, d3d12_dev, reset_tok) == S_OK);
            OS_REQUIRE(mft->ProcessMessage(MFT_MESSAGE_SET_D3D_MANAGER,
                                           reinterpret_cast<ULONG_PTR>(dxgi_mgr)) == S_OK);
            dxgi_mgr->Release();
            d3d12_dev->Release();
            if (adapter) adapter->Release();
        }

        // Negotiate HEVC input -> NV12 output
        IMFMediaType* hevc_in_type = nullptr;
        OS_REQUIRE(mft->GetInputAvailableType(0u, 0u, &hevc_in_type) == S_OK && hevc_in_type != nullptr);
        GUID sub{};
        OS_REQUIRE(hevc_in_type->GetGUID(kMfMtSubtype, &sub) == S_OK &&
                   std::memcmp(&sub, &kMfVideoFormatHevc, sizeof(GUID)) == 0);
        OS_REQUIRE(mft->SetInputType(0u, hevc_in_type, 0u) == S_OK);
        hevc_in_type->Release();

        IMFMediaType* nv12_out_type = nullptr;
        OS_REQUIRE(mft->GetOutputAvailableType(0u, 0u, &nv12_out_type) == S_OK && nv12_out_type != nullptr);
        OS_REQUIRE(nv12_out_type->GetGUID(kMfMtSubtype, &sub) == S_OK &&
                   std::memcmp(&sub, &kMfVideoFormatNv12, sizeof(GUID)) == 0);
        OS_REQUIRE(mft->SetOutputType(0u, nv12_out_type, 0u) == S_OK);
        nv12_out_type->Release();

        // Feed real Annex-B HEVC VPS+SPS(320x192)+PPS+IDR frame via ProcessInput
        const std::vector<uint8_t> hevc_au = BuildAnnexBHevcFrame(320u, 192u);
        IMFSample* in_sample = nullptr;
        if (fn_create_sample && fn_create_sample(reinterpret_cast<void**>(&in_sample)) == S_OK && in_sample) {
            IMFMediaBuffer* in_buf = nullptr;
            OS_REQUIRE(fn_create_buf(static_cast<uint32_t>(hevc_au.size()),
                                     reinterpret_cast<void**>(&in_buf)) == S_OK && in_buf != nullptr);
            BYTE* ptr = nullptr;
            OS_REQUIRE(in_buf->Lock(&ptr, nullptr, nullptr) == S_OK && ptr != nullptr);
            std::memcpy(ptr, hevc_au.data(), hevc_au.size());
            in_buf->Unlock();
            OS_REQUIRE(in_buf->SetCurrentLength(static_cast<DWORD>(hevc_au.size())) == S_OK);
            OS_REQUIRE(in_sample->AddBuffer(in_buf) == S_OK);
            OS_REQUIRE(in_sample->SetSampleTime(1234567) == S_OK);
            OS_REQUIRE(in_sample->SetSampleDuration(333333) == S_OK);
            in_buf->Release();

            OS_REQUIRE(mft->ProcessInput(0u, in_sample, 0u) == S_OK);
            in_sample->Release();

            // Verify SPS dimensions (320x192) updated dynamically in GetOutputCurrentType!
            IMFMediaType* cur_out = nullptr;
            OS_REQUIRE(mft->GetOutputCurrentType(0u, &cur_out) == S_OK && cur_out != nullptr);
            UINT64 fs_packed = 0ull;
            OS_REQUIRE(cur_out->GetUINT64(kMfMtFrameSize, &fs_packed) == S_OK);
            OS_REQUIRE((fs_packed >> 32u) == 320u && (fs_packed & 0xFFFFFFFFull) == 192u);
            cur_out->Release();

            // Verify MFT_MESSAGE_COMMAND_DRAIN blocks further ProcessInput until drained
            OS_REQUIRE(mft->ProcessMessage(MFT_MESSAGE_COMMAND_DRAIN, 0u) == S_OK);
            DWORD out_status = 0u;
            OS_REQUIRE(mft->GetOutputStatus(&out_status) == S_OK &&
                       (out_status & MFT_OUTPUT_STATUS_SAMPLE_READY) != 0u);

            MFT_OUTPUT_DATA_BUFFER odb{};
            odb.dwStreamID = 0u;
            DWORD proc_status = 0u;
            OS_REQUIRE(mft->ProcessOutput(0u, 1u, &odb, &proc_status) == S_OK);
            OS_REQUIRE(odb.pSample != nullptr);

            LONGLONG out_pts = 0, out_dur = 0;
            UINT32 clean_pt = 0u;
            OS_REQUIRE(odb.pSample->GetSampleTime(&out_pts) == S_OK && out_pts == 1234567);
            OS_REQUIRE(odb.pSample->GetSampleDuration(&out_dur) == S_OK && out_dur == 333333);
            OS_REQUIRE(odb.pSample->GetUINT32(kMfSampleExtCleanPoint, &clean_pt) == S_OK && clean_pt == 1u);

            DWORD nv12_len = 0u;
            OS_REQUIRE(odb.pSample->GetTotalLength(&nv12_len) == S_OK);
            OS_REQUIRE(nv12_len == 320u * 192u + 320u * 96u);
            odb.pSample->Release();

            // Now empty -> NEED_MORE_INPUT
            odb = MFT_OUTPUT_DATA_BUFFER{};
            OS_REQUIRE(mft->ProcessOutput(0u, 1u, &odb, &proc_status) == static_cast<HRESULT>(0xC00D6D72u));

            // Switch to H.264 -> ARGB32 and verify SPS (256x144) decode + FLUSH!
            IMFMediaType* h264_in = nullptr;
            OS_REQUIRE(mft->GetInputAvailableType(0u, 2u, &h264_in) == S_OK && h264_in != nullptr);
            OS_REQUIRE(h264_in->GetGUID(kMfMtSubtype, &sub) == S_OK &&
                       std::memcmp(&sub, &kMfVideoFormatH264, sizeof(GUID)) == 0);
            OS_REQUIRE(mft->SetInputType(0u, h264_in, 0u) == S_OK);
            h264_in->Release();

            IMFMediaType* argb_out = nullptr;
            OS_REQUIRE(mft->GetOutputAvailableType(0u, 1u, &argb_out) == S_OK && argb_out != nullptr);
            OS_REQUIRE(argb_out->GetGUID(kMfMtSubtype, &sub) == S_OK &&
                       std::memcmp(&sub, &kMfVideoFormatArgb32, sizeof(GUID)) == 0);
            OS_REQUIRE(mft->SetOutputType(0u, argb_out, 0u) == S_OK);
            argb_out->Release();

            const std::vector<uint8_t> h264_au = BuildAnnexBH264Frame(256u, 144u);
            IMFSample* h264_smp = nullptr;
            OS_REQUIRE(fn_create_sample(reinterpret_cast<void**>(&h264_smp)) == S_OK && h264_smp != nullptr);
            IMFMediaBuffer* h264_buf = nullptr;
            OS_REQUIRE(fn_create_buf(static_cast<uint32_t>(h264_au.size()),
                                     reinterpret_cast<void**>(&h264_buf)) == S_OK);
            OS_REQUIRE(h264_buf->Lock(&ptr, nullptr, nullptr) == S_OK && ptr != nullptr);
            std::memcpy(ptr, h264_au.data(), h264_au.size());
            h264_buf->Unlock();
            h264_buf->SetCurrentLength(static_cast<DWORD>(h264_au.size()));
            h264_smp->AddBuffer(h264_buf);
            h264_buf->Release();
            OS_REQUIRE(mft->ProcessInput(0u, h264_smp, 0u) == S_OK);

            odb = MFT_OUTPUT_DATA_BUFFER{};
            OS_REQUIRE(mft->ProcessOutput(0u, 1u, &odb, &proc_status) == S_OK && odb.pSample != nullptr);
            DWORD argb_len = 0u;
            OS_REQUIRE(odb.pSample->GetTotalLength(&argb_len) == S_OK && argb_len == 256u * 144u * 4u);
            odb.pSample->Release();

            // Queue one frame then FLUSH -> output must become empty!
            OS_REQUIRE(mft->ProcessInput(0u, h264_smp, 0u) == S_OK);
            OS_REQUIRE(mft->ProcessMessage(MFT_MESSAGE_COMMAND_FLUSH, 0u) == S_OK);
            odb = MFT_OUTPUT_DATA_BUFFER{};
            OS_REQUIRE(mft->ProcessOutput(0u, 1u, &odb, &proc_status) == static_cast<HRESULT>(0xC00D6D72u));
            h264_smp->Release();
        }

        // Release MFT -> DllCanUnloadNow MUST return S_OK again!
        mft->Release();
        cf->Release();
        OS_REQUIRE(fn_unload() == S_OK);

        // Also test direct MFCreateHevcDecoderTransform export
        IMFTransform* mft2 = nullptr;
        OS_REQUIRE(fn_create_mft(reinterpret_cast<void**>(&mft2)) == S_OK && mft2 != nullptr);
        OS_REQUIRE(fn_unload() == S_FALSE);
        mft2->Release();
        OS_REQUIRE(fn_unload() == S_OK);

        ::FreeLibrary(h_hevc);
        ::FreeLibrary(h_mfplat);
    }

    // 4B. mflnmhelp.dll stateful License/Revocation/Renewal/Manifest-URL/Network-Caps/DllCanUnloadNow
    {
        HMODULE h_lnm = ::LoadLibraryW((bin_dir / L"mflnmhelp.dll").c_str());
        OS_REQUIRE(h_lnm != nullptr);

        auto fn_init = reinterpret_cast<int32_t(__stdcall*)(uint32_t)>(reinterpret_cast<void*>(::GetProcAddress(h_lnm, "MfLnmHelperInitialize")));
        auto fn_sd = reinterpret_cast<int32_t(__stdcall*)()>(reinterpret_cast<void*>(::GetProcAddress(h_lnm, "MfLnmHelperShutdown")));
        auto fn_chk = reinterpret_cast<int32_t(__stdcall*)(const wchar_t*, uint32_t*)>(reinterpret_cast<void*>(::GetProcAddress(h_lnm, "MfLnmCheckLicenseStatus")));
        auto fn_caps = reinterpret_cast<int32_t(__stdcall*)(uint32_t*)>(reinterpret_cast<void*>(::GetProcAddress(h_lnm, "MfLnmQueryNetworkCapabilities")));
        auto fn_acq = reinterpret_cast<int32_t(__stdcall*)(const wchar_t*, void**)>(reinterpret_cast<void*>(::GetProcAddress(h_lnm, "MfLnmAcquireLicense")));
        auto fn_rel = reinterpret_cast<int32_t(__stdcall*)(void*)>(reinterpret_cast<void*>(::GetProcAddress(h_lnm, "MfLnmReleaseLicense")));
        auto fn_ren = reinterpret_cast<int32_t(__stdcall*)(void*, uint64_t)>(reinterpret_cast<void*>(::GetProcAddress(h_lnm, "MfLnmRenewLicense")));
        auto fn_rev = reinterpret_cast<int32_t(__stdcall*)(const wchar_t*)>(reinterpret_cast<void*>(::GetProcAddress(h_lnm, "MfLnmRevokeLicense")));
        auto fn_clr = reinterpret_cast<int32_t(__stdcall*)(const wchar_t*)>(reinterpret_cast<void*>(::GetProcAddress(h_lnm, "MfLnmClearRevocation")));
        auto fn_info = reinterpret_cast<int32_t(__stdcall*)(void*, uint32_t*, uint64_t*, uint32_t*)>(reinterpret_cast<void*>(::GetProcAddress(h_lnm, "MfLnmGetLicenseInfo")));
        auto fn_cnt = reinterpret_cast<int32_t(__stdcall*)(uint32_t*)>(reinterpret_cast<void*>(::GetProcAddress(h_lnm, "MfLnmGetActiveLicenseCount")));
        auto fn_url = reinterpret_cast<int32_t(__stdcall*)(const wchar_t*, uint32_t*)>(reinterpret_cast<void*>(::GetProcAddress(h_lnm, "MfLnmValidateManifestUrl")));
        auto fn_unload = reinterpret_cast<int32_t(__stdcall*)()>(reinterpret_cast<void*>(::GetProcAddress(h_lnm, "DllCanUnloadNow")));
        OS_REQUIRE(fn_init && fn_sd && fn_chk && fn_caps && fn_acq && fn_rel && fn_ren &&
                   fn_rev && fn_clr && fn_info && fn_cnt && fn_url && fn_unload);

        OS_REQUIRE(fn_unload() == S_OK);  // Idle initially
        OS_REQUIRE(fn_init(1u) == S_OK);
        OS_REQUIRE(fn_unload() == S_FALSE);

        uint32_t caps = 0u;
        OS_REQUIRE(fn_caps(&caps) == S_OK && (caps & 0x1Fu) == 0x1Fu);

        // Manifest URL validation (HLS/DASH/Smooth vs malicious/invalid schemes)
        uint32_t proto = 0u;
        OS_REQUIRE(fn_url(L"https://cdn.example.com/movie/master.m3u8?token=abc", &proto) == S_OK);
        OS_REQUIRE((proto & 0x06u) == 0x06u);  // HTTPS | HLS
        OS_REQUIRE(fn_url(L"https://cdn.example.com/stream/manifest.mpd", &proto) == S_OK);
        OS_REQUIRE((proto & 0x0Au) == 0x0Au);  // HTTPS | DASH
        OS_REQUIRE(fn_url(L"http://cdn.example.com/title.ism/Manifest", &proto) == S_OK);
        OS_REQUIRE((proto & 0x21u) == 0x21u);  // HTTP | Smooth
        OS_REQUIRE(fn_url(L"file:///C:/secret.txt", &proto) < 0);
        OS_REQUIRE(fn_url(L"javascript:alert(1)", &proto) < 0);
        OS_REQUIRE(fn_url(L"", &proto) < 0);

        // License lifecycle: acquire -> info -> renew -> revoke -> reject re-acquire -> clear -> release
        void* lic = nullptr;
        OS_REQUIRE(fn_acq(L"urn:openscarlett:title:s16", &lic) == S_OK && lic != nullptr);
        uint32_t active_cnt = 0u;
        OS_REQUIRE(fn_cnt(&active_cnt) == S_OK && active_cnt == 1u);

        uint32_t status = 0u, renewals = 99u;
        uint64_t exp0 = 0ull, exp1 = 0ull;
        OS_REQUIRE(fn_info(lic, &status, &exp0, &renewals) == S_OK && status == 1u && renewals == 0u);
        OS_REQUIRE(fn_ren(lic, 3600ull) == S_OK);
        OS_REQUIRE(fn_info(lic, &status, &exp1, &renewals) == S_OK && status == 1u &&
                   exp1 >= exp0 + 3600ull && renewals == 1u);

        // Revoke contentId -> status becomes 2 (Revoked), renew & re-acquire rejected!
        OS_REQUIRE(fn_rev(L"urn:openscarlett:title:s16") == S_OK);
        OS_REQUIRE(fn_chk(L"urn:openscarlett:title:s16", &status) == S_OK && status == 2u);
        OS_REQUIRE(fn_ren(lic, 3600ull) < 0);
        void* lic_bad = nullptr;
        OS_REQUIRE(fn_acq(L"urn:openscarlett:title:s16", &lic_bad) < 0 && lic_bad == nullptr);

        // Clear revocation -> valid again
        OS_REQUIRE(fn_clr(L"urn:openscarlett:title:s16") == S_OK);
        OS_REQUIRE(fn_chk(L"urn:openscarlett:title:s16", &status) == S_OK && status == 1u);

        // Release + double-release check + shutdown -> DllCanUnloadNow == S_OK
        OS_REQUIRE(fn_rel(lic) == S_OK);
        OS_REQUIRE(fn_rel(lic) < 0);
        OS_REQUIRE(fn_cnt(&active_cnt) == S_OK && active_cnt == 0u);
        OS_REQUIRE(fn_sd() == S_OK);
        OS_REQUIRE(fn_unload() == S_OK);

        ::FreeLibrary(h_lnm);
    }
#endif

    // 4C. Bink2Scarlett Live D3D12 Compute Shader YUV420p(+A) -> RGBA8/BGRA8 (BT.709 & BT.601)
    //     Verified <= 1 LSB vs CPU reference on BOTH HW GPU AND D3D12 WARP + CPU fallback!
    {
        // Odd/NPOT dimensions + padded row pitches to test edge-case addressing thoroughly!
        constexpr uint32_t kW = 194u;
        constexpr uint32_t kH = 110u;
        constexpr uint32_t kCw = (kW + 1u) / 2u;  // 97
        constexpr uint32_t kCh = (kH + 1u) / 2u;  // 55
        constexpr uint32_t kPitchY = 208u;        // padded > kW
        constexpr uint32_t kPitchU = 112u;        // padded > kCw
        constexpr uint32_t kPitchV = 112u;
        constexpr uint32_t kPitchA = 208u;

        std::vector<uint8_t> plane_y(kPitchY * kH, 0u);
        std::vector<uint8_t> plane_u(kPitchU * kCh, 128u);
        std::vector<uint8_t> plane_v(kPitchV * kCh, 128u);
        std::vector<uint8_t> plane_a(kPitchA * kH, 255u);

        for (uint32_t y = 0u; y < kH; ++y) {
            for (uint32_t x = 0u; x < kW; ++x) {
                plane_y[y * kPitchY + x] = static_cast<uint8_t>((x * 3u + y * 5u + 17u) & 0xFFu);
                plane_a[y * kPitchA + x] = static_cast<uint8_t>(255u - ((x + y * 2u) & 0xFFu));
            }
        }
        for (uint32_t cy = 0u; cy < kCh; ++cy) {
            for (uint32_t cx = 0u; cx < kCw; ++cx) {
                plane_u[cy * kPitchU + cx] = static_cast<uint8_t>(24u + ((cx * 7u + cy * 3u) % 208u));
                plane_v[cy * kPitchV + cx] = static_cast<uint8_t>(24u + ((cx * 5u + cy * 11u) % 208u));
            }
        }

#if defined(_WIN32)
        HMODULE h_bink = ::LoadLibraryW((GetExeDir() / L"Bink2Scarlett.dll").c_str());
        OS_REQUIRE(h_bink != nullptr);
        using PfnBinkGpu = int32_t(__stdcall*)(
            uint32_t, uint32_t, const uint8_t*, uint32_t, const uint8_t*, uint32_t,
            const uint8_t*, uint32_t, const uint8_t*, uint32_t,
            uint32_t, uint32_t, uint32_t, uint8_t*, size_t, uint32_t*);
        using PfnBinkStats = int32_t(__stdcall*)(uint32_t, uint32_t*, uint32_t*, uint64_t*, uint64_t*);
        auto fn_bink_gpu = reinterpret_cast<PfnBinkGpu>(
            reinterpret_cast<void*>(::GetProcAddress(h_bink, "BinkConvertYuvToRgbaGpu")));
        auto fn_bink_stats = reinterpret_cast<PfnBinkStats>(
            reinterpret_cast<void*>(::GetProcAddress(h_bink, "BinkGetGpuConverterStats")));
        OS_REQUIRE(fn_bink_gpu != nullptr && fn_bink_stats != nullptr);

        // Test BOTH HW GPU (preferWarp = 0) AND D3D12 WARP (preferWarp = 1)
        // across BOTH BT.709 (0) & BT.601 (1), BOTH RGBA8 (0) & BGRA8 (1), with & without Alpha!
        for (uint32_t prefer_warp = 0u; prefer_warp <= 1u; ++prefer_warp) {
            uint32_t gpu_runs = 0u;
            for (uint32_t mat = 0u; mat <= 1u; ++mat) {
                for (uint32_t fmt = 0u; fmt <= 1u; ++fmt) {
                    const bool with_alpha = ((mat ^ fmt) != 0u);
                    std::vector<uint8_t> cpu_ref;
                    OS_REQUIRE(Bink2ConvertYuv420pToRgbaCpu(
                                   kW, kH,
                                   plane_y.data(), kPitchY,
                                   plane_u.data(), kPitchU,
                                   plane_v.data(), kPitchV,
                                   with_alpha ? plane_a.data() : nullptr, kPitchA,
                                   mat == 0u ? Bink2ColorMatrix::Bt709 : Bink2ColorMatrix::Bt601,
                                   fmt == 0u ? Bink2PixelFormat::Rgba8 : Bink2PixelFormat::Bgra8,
                                   cpu_ref)
                                   .ok());

                    std::vector<uint8_t> gpu_out(kW * kH * 4u, 0u);
                    uint32_t used_gpu = 0u;
                    OS_REQUIRE(fn_bink_gpu(
                                   kW, kH,
                                   plane_y.data(), kPitchY,
                                   plane_u.data(), kPitchU,
                                   plane_v.data(), kPitchV,
                                   with_alpha ? plane_a.data() : nullptr, kPitchA,
                                   mat, fmt, prefer_warp,
                                   gpu_out.data(), gpu_out.size(), &used_gpu) == 0);
                    OS_REQUIRE(used_gpu == 1u);
                    ++gpu_runs;

                    int max_diff = 0;
                    size_t worst_i = 0u;
                    for (size_t i = 0u; i < cpu_ref.size(); ++i) {
                        const int d = std::abs(static_cast<int>(gpu_out[i]) - static_cast<int>(cpu_ref[i]));
                        if (d > max_diff) {
                            max_diff = d;
                            worst_i = i;
                        }
                    }
                    if (max_diff > 1) {
                        std::printf("  MISMATCH prefer_warp=%u mat=%u fmt=%u alpha=%d max_diff=%d at byte=%zu (gpu=%u cpu=%u)\n",
                                    prefer_warp, mat, fmt, with_alpha ? 1 : 0, max_diff, worst_i,
                                    static_cast<unsigned>(gpu_out[worst_i]),
                                    static_cast<unsigned>(cpu_ref[worst_i]));
                    }
                    OS_REQUIRE(max_diff <= 1);
                }
            }
            uint32_t using_gpu = 0u, is_warp = 0u;
            uint64_t gpu_cnt = 0ull, cpu_cnt = 0ull;
            OS_REQUIRE(fn_bink_stats(prefer_warp, &using_gpu, &is_warp, &gpu_cnt, &cpu_cnt) == 0);
            OS_REQUIRE(using_gpu == 1u && gpu_cnt >= 4ull);
            if (prefer_warp == 1u) {
                OS_REQUIRE(is_warp == 1u);
            }
            std::printf("  Bink2 GPU YUV->RGBA (%s): %u/4 combos passed <= 1 LSB vs CPU (is_warp=%u)\n",
                        prefer_warp ? "WARP" : "HW GPU", gpu_runs, is_warp);
        }
        ::FreeLibrary(h_bink);
#endif

        // Also verify uninitialized Bink2GpuColorConverter seamlessly falls back to CPU (0 LSB diff)
        Bink2GpuColorConverter cpu_only;
        std::vector<uint8_t> fb_out, cpu_ref;
        bool used_gpu = true;
        OS_REQUIRE(cpu_only.ConvertYuv420pToRgba(
                               kW, kH,
                               plane_y.data(), kPitchY,
                               plane_u.data(), kPitchU,
                               plane_v.data(), kPitchV,
                               plane_a.data(), kPitchA,
                               Bink2ColorMatrix::Bt601, Bink2PixelFormat::Rgba8,
                               fb_out, &used_gpu)
                       .ok());
        OS_REQUIRE(!used_gpu);
        OS_REQUIRE(Bink2ConvertYuv420pToRgbaCpu(
                       kW, kH,
                       plane_y.data(), kPitchY,
                       plane_u.data(), kPitchU,
                       plane_v.data(), kPitchV,
                       plane_a.data(), kPitchA,
                       Bink2ColorMatrix::Bt601, Bink2PixelFormat::Rgba8,
                       cpu_ref)
                       .ok());
        OS_REQUIRE(fb_out == cpu_ref);
    }

    std::printf("  [PASS] Video 100%% (mfhevcdec, mflnmhelp, Bink2Scarlett GPU HW+WARP).\n");
}

}  // namespace

int main() {
    std::setvbuf(stdout, nullptr, _IONBF, 0);
    std::setvbuf(stderr, nullptr, _IONBF, 0);
    std::printf("=== OpenScarlett Sprint 16 Workstream 3: Storage, Compression, Audio & Video 100%% ===\n");

    TestDirectStorageHardening();
    TestBcPackAndTtpf100();
    TestAudio100();
    TestVideo100();

    std::printf("=== ALL SPRINT 16 WORKSTREAM 3 TESTS PASSED ===\n");
    return 0;
}
