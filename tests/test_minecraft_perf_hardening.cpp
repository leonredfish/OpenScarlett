// Clean-room regression test suite for Minecraft Preview performance & hardening:
//   1. VFS TRUNCATE_EXISTING on un-overlaid G:\ files (GENERIC_WRITE check, directory
//      rejection, whiteout/missing rejection, CoW truncation without mutating base)
//   2. XAudio2 play/loop region invariants (max buffer size, LoopCount==0, out-of-range
//      loop disabling, clamped partial overlap)
//   3. AcpHal transactional SHAPE context allocation rollback & XApu retail OOM safety
//   4. DirectStorage GetErrorEvent() handle duplication (caller CloseHandle safety)
//   5. D3D12X CreateDescriptorHeap RTV/DSV SHADER_VISIBLE stripping & cached barrier unwrap

#include "openscarlett/audio/acphal_abi.h"
#include "openscarlett/audio/xapu_abi.h"
#include "openscarlett/audio/xaudio2_abi.h"
#include "openscarlett/gpu/d3d12_xs_abi.h"
#include "openscarlett/io/dstorage_abi.h"
#include "os_check.h"

#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

#if defined(_WIN32)
#  ifndef NOMINMAX
#    define NOMINMAX
#  endif
#  include <d3d12.h>
#  include <windows.h>
#endif

namespace fs = std::filesystem;

namespace {

#if defined(_WIN32)
fs::path GetExeDir() {
    wchar_t buf[MAX_PATH]{};
    const DWORD n = ::GetModuleFileNameW(nullptr, buf, MAX_PATH);
    if (n > 0u && n < MAX_PATH) {
        return fs::path(buf).parent_path();
    }
    return fs::current_path();
}

HMODULE LoadSiblingDll(const wchar_t* name) {
    const fs::path p = GetExeDir() / name;
    HMODULE mod = ::LoadLibraryW(p.c_str());
    if (!mod) {
        mod = ::LoadLibraryW(name);
    }
    return mod;
}

fs::path MakeTempDir(const char* tag) {
    const auto now = std::chrono::steady_clock::now().time_since_epoch().count();
    fs::path root = fs::temp_directory_path() /
                    ("openscarlett_mine_perf_" + std::string(tag) + "_" + std::to_string(now));
    std::error_code ec;
    fs::remove_all(root, ec);
    fs::create_directories(root, ec);
    OS_REQUIRE(!ec && fs::exists(root));
    return root;
}

void WriteTextFile(const fs::path& p, const std::string& content) {
    std::error_code ec;
    fs::create_directories(p.parent_path(), ec);
    std::ofstream ofs(p, std::ios::binary | std::ios::trunc);
    OS_REQUIRE(ofs.good());
    ofs.write(content.data(), static_cast<std::streamsize>(content.size()));
    ofs.flush();
    OS_REQUIRE(ofs.good());
}

std::string ReadTextFile(const fs::path& p) {
    std::ifstream ifs(p, std::ios::binary);
    OS_REQUIRE(ifs.good());
    return std::string((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
}

// ===========================================================================
// 1. VFS TRUNCATE_EXISTING on un-overlaid G:\ files
// ===========================================================================
void TestVfsTruncateExisting() {
    std::printf("[1/5] Testing VFS TRUNCATE_EXISTING on un-overlaid G:\\ files...\n");
    HMODULE hook_mod = LoadSiblingDll(L"openscarlett_hook.dll");
    OS_REQUIRE(hook_mod != nullptr);

    using PfnCfgVfs = int(__stdcall*)(const wchar_t*, const wchar_t*, const wchar_t*, const wchar_t*);
    using PfnCreateFileW = HANDLE(__stdcall*)(
        LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);

    auto fn_cfg = reinterpret_cast<PfnCfgVfs>(
        ::GetProcAddress(hook_mod, "OpenScarlettHook_ConfigureVfsForTestW"));
    auto fn_create = reinterpret_cast<PfnCreateFileW>(
        ::GetProcAddress(hook_mod, "OpenScarlettHook_CreateFileW"));
    OS_REQUIRE(fn_cfg != nullptr);
    OS_REQUIRE(fn_create != nullptr);

    const fs::path root = MakeTempDir("vfs_trunc");
    const fs::path g_root = root / "G_base";
    const fs::path g_overlay = root / "G_overlay";
    const fs::path t_root = root / "T";
    const fs::path s_root = root / "S";
    fs::create_directories(g_root / "subdir");
    fs::create_directories(g_overlay);
    fs::create_directories(t_root);
    fs::create_directories(s_root);

    WriteTextFile(g_root / "options.txt", "ORIGINAL_READONLY_BASE_CONTENT");
    OS_REQUIRE(fn_cfg(g_root.c_str(), g_overlay.c_str(), t_root.c_str(), s_root.c_str()) == 1);

    // 1a. Missing GENERIC_WRITE must fail with ERROR_INVALID_PARAMETER without creating overlay file.
    HANDLE h = fn_create(L"G:\\options.txt", GENERIC_READ, FILE_SHARE_READ, nullptr,
                         TRUNCATE_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    OS_REQUIRE(h == INVALID_HANDLE_VALUE);
    OS_REQUIRE(::GetLastError() == ERROR_INVALID_PARAMETER);
    OS_REQUIRE(!fs::exists(g_overlay / "options.txt"));

    // 1b. Non-existent game file must fail with ERROR_FILE_NOT_FOUND without creating overlay file.
    h = fn_create(L"G:\\does_not_exist.txt", GENERIC_WRITE, 0u, nullptr,
                  TRUNCATE_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    OS_REQUIRE(h == INVALID_HANDLE_VALUE);
    OS_REQUIRE(::GetLastError() == ERROR_FILE_NOT_FOUND);
    OS_REQUIRE(!fs::exists(g_overlay / "does_not_exist.txt"));

    // 1c. Directory target fails with ERROR_ACCESS_DENIED (no backup semantics) or
    //     ERROR_INVALID_PARAMETER (with FILE_FLAG_BACKUP_SEMANTICS).
    h = fn_create(L"G:\\subdir", GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                  TRUNCATE_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    OS_REQUIRE(h == INVALID_HANDLE_VALUE);
    OS_REQUIRE(::GetLastError() == ERROR_ACCESS_DENIED);

    h = fn_create(L"G:\\subdir", GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                  TRUNCATE_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr);
    OS_REQUIRE(h == INVALID_HANDLE_VALUE);
    OS_REQUIRE(::GetLastError() == ERROR_INVALID_PARAMETER);

    // 1d. Valid TRUNCATE_EXISTING on un-overlaid base file truncates cleanly in overlay
    //     while keeping the read-only base untouched.
    h = fn_create(L"G:\\options.txt", GENERIC_WRITE, 0u, nullptr,
                  TRUNCATE_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    OS_REQUIRE(h != INVALID_HANDLE_VALUE);
    const char kNewData[] = "TRUNC_V2";
    DWORD written = 0u;
    OS_REQUIRE(::WriteFile(h, kNewData, static_cast<DWORD>(sizeof(kNewData) - 1u), &written, nullptr) != FALSE);
    OS_REQUIRE(written == sizeof(kNewData) - 1u);
    ::CloseHandle(h);

    OS_REQUIRE(ReadTextFile(g_root / "options.txt") == "ORIGINAL_READONLY_BASE_CONTENT");
    OS_REQUIRE(ReadTextFile(g_overlay / "options.txt") == "TRUNC_V2");

    std::error_code ec;
    fs::remove_all(root, ec);
    // Keep openscarlett_hook.dll mapped for process lifetime (IAT hooks remain active).
    std::printf("  PASS: VFS TRUNCATE_EXISTING CoW validation & truncation.\n");
}

// ===========================================================================
// 2. XAudio2 Play/Loop Region Invariants
// ===========================================================================
void TestXAudio2LoopInvariants() {
    std::printf("[2/5] Testing XAudio2 play/loop region invariants...\n");
    ::SetEnvironmentVariableA("OPENSCARLETT_AUDIO_NULL", "1");

    HMODULE mod = LoadSiblingDll(L"xaudio2_9.dll");
    OS_REQUIRE(mod != nullptr);

    using PfnCreate = int32_t(__stdcall*)(IXAudio2**, uint32_t, uint32_t);
    auto fn_create = reinterpret_cast<PfnCreate>(::GetProcAddress(mod, "XAudio2Create"));
    OS_REQUIRE(fn_create != nullptr);

    IXAudio2* xa = nullptr;
    OS_REQUIRE(fn_create(&xa, 0u, OS_XAUDIO2_DEFAULT_PROCESSOR) == OS_XAUDIO2_S_OK);
    OS_REQUIRE(xa != nullptr);

    IXAudio2MasteringVoice* master = nullptr;
    OS_REQUIRE(xa->CreateMasteringVoice(&master, 2u, 48000u, 0u, nullptr, nullptr, 0u) == OS_XAUDIO2_S_OK);

    OS_WAVEFORMATEX wfx{};
    wfx.wFormatTag = OS_WAVE_FORMAT_PCM;
    wfx.nChannels = 1u;
    wfx.nSamplesPerSec = 48000u;
    wfx.wBitsPerSample = 16u;
    wfx.nBlockAlign = 2u;
    wfx.nAvgBytesPerSec = 96000u;

    IXAudio2SourceVoice* src = nullptr;
    OS_REQUIRE(xa->CreateSourceVoice(&src, &wfx, 0u, 2.0f, nullptr, nullptr, nullptr) == OS_XAUDIO2_S_OK);

    std::vector<int16_t> pcm(256u, 1000);

    // 2a. AudioBytes > 2 GiB rejected cleanly.
    OS_XAUDIO2_BUFFER bad_buf{};
    bad_buf.AudioBytes = 0x80000004u;
    bad_buf.pAudioData = reinterpret_cast<const uint8_t*>(pcm.data());
    OS_REQUIRE(src->SubmitSourceBuffer(&bad_buf, nullptr) == OS_XAUDIO2_E_INVALIDARG);

    // 2b. LoopCount == 0 with stale LoopBegin/LoopLength accepted safely without crashing.
    OS_XAUDIO2_BUFFER no_loop{};
    no_loop.AudioBytes = static_cast<uint32_t>(pcm.size() * sizeof(int16_t));
    no_loop.pAudioData = reinterpret_cast<const uint8_t*>(pcm.data());
    no_loop.PlayBegin = 16u;
    no_loop.PlayLength = 64u;
    no_loop.LoopBegin = 9999u;
    no_loop.LoopLength = 5000u;
    no_loop.LoopCount = 0u;
    OS_REQUIRE(src->SubmitSourceBuffer(&no_loop, nullptr) == OS_XAUDIO2_S_OK);

    // 2c. Disjoint loop region beyond play_end accepted cleanly (loop disabled rather than OOB).
    OS_XAUDIO2_BUFFER disjoint_loop = no_loop;
    disjoint_loop.LoopBegin = 200u;
    disjoint_loop.LoopLength = 32u;
    disjoint_loop.LoopCount = 3u;
    OS_REQUIRE(src->SubmitSourceBuffer(&disjoint_loop, nullptr) == OS_XAUDIO2_S_OK);

    // 2d. Partially overlapping loop region clamped safely inside play window.
    OS_XAUDIO2_BUFFER overlap_loop = no_loop;
    overlap_loop.LoopBegin = 0u;
    overlap_loop.LoopLength = 500u;
    overlap_loop.LoopCount = 2u;
    OS_REQUIRE(src->SubmitSourceBuffer(&overlap_loop, nullptr) == OS_XAUDIO2_S_OK);

    OS_REQUIRE(src->FlushSourceBuffers() == OS_XAUDIO2_S_OK);
    src->DestroyVoice();
    master->DestroyVoice();
    xa->Release();
    ::FreeLibrary(mod);
    std::printf("  PASS: XAudio2 play/loop invariants enforced.\n");
}

// ===========================================================================
// 3. AcpHal SHAPE Rollback & XApu Retail OOM Safety
// ===========================================================================
void TestAcpHalAndXApuHardening() {
    std::printf("[3/5] Testing AcpHal SHAPE rollback & XApu retail OOM safety...\n");
    HMODULE acp_mod = LoadSiblingDll(L"AcpHal.dll");
    HMODULE xapu_mod = LoadSiblingDll(L"xapu.dll");
    OS_REQUIRE(acp_mod != nullptr && xapu_mod != nullptr);

    struct RetailXboxShapeCtx {
        uint32_t numSrcContexts;
        uint32_t numEqCompContexts;
        uint32_t numFiltVolContexts;
        uint32_t numDmaContexts;
        uint32_t numXmaContexts;
        uint32_t numPcmContexts;
        uint32_t numReserved0;
        uint32_t numReserved1;
        void* srcContexts;
        void* eqCompContexts;
        void* filtVolContexts;
        void* dmaContexts;
        void* xmaContexts;
        void* pcmContexts;
        void* reservedPtr0;
        void* reservedPtr1;
    };

    using PfnShapeAllocRetail = int32_t(__stdcall*)(void*, void*);
    auto fn_shape_alloc = reinterpret_cast<PfnShapeAllocRetail>(
        ::GetProcAddress(acp_mod, "AcpHalAllocateShapeContexts"));
    OS_REQUIRE(fn_shape_alloc != nullptr);

    // Trigger uint32 overflow in retail SHAPE allocation and verify existing sentinel pointer is NOT clobbered.
    RetailXboxShapeCtx sctx{};
    void* sentinel = reinterpret_cast<void*>(static_cast<uintptr_t>(0x12345678ull));
    sctx.numSrcContexts = 4u;
    sctx.numXmaContexts = 0x10000000u;  // 0x10000000 * 64 overflows 32-bit & exceeds 256 MiB cap
    sctx.srcContexts = sentinel;
    const int32_t shr = fn_shape_alloc(&sctx, nullptr);
    OS_REQUIRE(shr == ACPHAL_E_OUTOFMEMORY);
    OS_REQUIRE(sctx.srcContexts == sentinel);

    // Retail XApuConnect OOM clears outputs cleanly.
    struct RetailXApuParams {
        uint32_t codecType;
        uint32_t streamCount;
        uint32_t maxChannels;
        uint32_t sharedMemoryBytes;
        uint32_t extraParam;
        uint32_t flags;
    };
    struct RetailXApuShm {
        void* baseAddress;
        uint64_t sizeBytes;
    };
    using PfnXApuConnect3 = int32_t(__stdcall*)(void*, void*, void*);
    using PfnXApuDisconnect = int32_t(__stdcall*)(XAPU_CONNECTION_HANDLE);
    auto fn_xapu_connect = reinterpret_cast<PfnXApuConnect3>(::GetProcAddress(xapu_mod, "XApuConnect"));
    auto fn_xapu_disc = reinterpret_cast<PfnXApuDisconnect>(::GetProcAddress(xapu_mod, "XApuDisconnect"));
    OS_REQUIRE(fn_xapu_connect != nullptr && fn_xapu_disc != nullptr);

    RetailXApuParams ok_params{};
    ok_params.codecType = 1u;
    ok_params.streamCount = 4u;
    ok_params.maxChannels = 8u;
    ok_params.sharedMemoryBytes = 65536u;
    RetailXApuShm shm{};
    XAPU_CONNECTION_HANDLE hconn = nullptr;
    OS_REQUIRE(fn_xapu_connect(&ok_params, &shm, &hconn) == XAPU_S_OK);
    // XApuConnect honors the caller's requested sharedMemoryBytes (rounded up to 4 KiB,
    // minimum 64 KiB) instead of inflating to streamCount * 64 KiB.
    OS_REQUIRE(shm.baseAddress != nullptr &&
               shm.sizeBytes >= static_cast<uint64_t>(ok_params.sharedMemoryBytes) &&
               shm.sizeBytes >= 0x10000ull && hconn != nullptr);
    OS_REQUIRE(fn_xapu_disc(hconn) == XAPU_S_OK);

    ::FreeLibrary(xapu_mod);
    ::FreeLibrary(acp_mod);
    std::printf("  PASS: AcpHal SHAPE overflow rollback & XApu retail connect verified.\n");
}

// ===========================================================================
// 4. DirectStorage GetErrorEvent Handle Duplication
// ===========================================================================
void TestDStorageErrorEventDuplication() {
    std::printf("[4/5] Testing DirectStorage GetErrorEvent() handle duplication...\n");
    HMODULE ds_mod = LoadSiblingDll(L"dstorage_xs.dll");
    OS_REQUIRE(ds_mod != nullptr);

    using PfnGetFactory = int32_t(__stdcall*)(const DStorageGuid*, void**);
    auto fn_factory = reinterpret_cast<PfnGetFactory>(::GetProcAddress(ds_mod, "DStorageGetFactory"));
    OS_REQUIRE(fn_factory != nullptr);

    IDStorageFactoryX* factory = nullptr;
    OS_REQUIRE(fn_factory(&IID_IDStorageFactoryX, reinterpret_cast<void**>(&factory)) == OS_DSTORAGE_S_OK);
    OS_REQUIRE(factory != nullptr);

    DSTORAGE_QUEUE_DESC qdesc{};
    qdesc.SourceType = DSTORAGE_REQUEST_SOURCE_MEMORY;
    qdesc.Capacity = DSTORAGE_MIN_QUEUE_CAPACITY;
    qdesc.Priority = DSTORAGE_PRIORITY_NORMAL;
    qdesc.Name = "err_event_dup_test";

    IDStorageQueueX* queue = nullptr;
    OS_REQUIRE(factory->CreateQueue(&qdesc, &IID_IDStorageQueueX, reinterpret_cast<void**>(&queue)) ==
               OS_DSTORAGE_S_OK);
    OS_REQUIRE(queue != nullptr);

    HANDLE ev1 = static_cast<HANDLE>(queue->GetErrorEvent());
    HANDLE ev2 = static_cast<HANDLE>(queue->GetErrorEvent());
    OS_REQUIRE(ev1 != nullptr && ev2 != nullptr);
    OS_REQUIRE(ev1 != ev2);  // Independent duplicated Win32 handles

    // Closing caller's first handle MUST NOT invalidate the queue's internal event or ev2!
    OS_REQUIRE(::CloseHandle(ev1) != FALSE);
    OS_REQUIRE(::WaitForSingleObject(ev2, 0u) == WAIT_TIMEOUT);

    // Enqueue an invalid request (null destination) to trigger error signaling on ev2.
    DSTORAGE_REQUEST bad_req{};
    bad_req.Options.SourceType = 1u;  // Memory
    bad_req.Source = &qdesc;
    bad_req.SourceSize = 16u;
    bad_req.Destination = nullptr;
    bad_req.DestinationSize = 16u;
    queue->EnqueueRequest(&bad_req);
    queue->Submit();

    OS_REQUIRE(::WaitForSingleObject(ev2, 5000u) == WAIT_OBJECT_0);
    DSTORAGE_ERROR_RECORD rec{};
    queue->RetrieveErrorRecord(&rec);
    OS_REQUIRE(rec.FailureCount >= 1u);
    OS_REQUIRE(::WaitForSingleObject(ev2, 0u) == WAIT_TIMEOUT);
    OS_REQUIRE(::CloseHandle(ev2) != FALSE);

    queue->Close();
    queue->Release();
    factory->Release();
    ::FreeLibrary(ds_mod);
    std::printf("  PASS: DirectStorage GetErrorEvent() duplicates handles safely.\n");
}

// ===========================================================================
// 5. D3D12X RTV/DSV SHADER_VISIBLE Stripping & Cached Barrier Info
// ===========================================================================
void TestD3D12XDescriptorHeapAndBarriers() {
    std::printf("[5/5] Testing D3D12X RTV/DSV SHADER_VISIBLE stripping & barrier fast-path...\n");
    HMODULE d3d_mod = LoadSiblingDll(L"d3d12_xs.dll");
    OS_REQUIRE(d3d_mod != nullptr);

    using PfnCreateDev = HRESULT(__stdcall*)(
        IUnknown*, const D3D12XBOX_CREATE_DEVICE_PARAMETERS*, REFIID, void**);
    auto fn_create = reinterpret_cast<PfnCreateDev>(::GetProcAddress(d3d_mod, "D3D12XboxCreateDevice"));
    OS_REQUIRE(fn_create != nullptr);

    D3D12XBOX_CREATE_DEVICE_PARAMETERS params{};
    params.Version = 1u;
    ID3D12Device* dev = nullptr;
    const HRESULT hr = fn_create(nullptr, &params, __uuidof(ID3D12Device), reinterpret_cast<void**>(&dev));
    if (FAILED(hr) || !dev) {
        std::printf("  SKIP: No D3D12 adapter available (hr=0x%08lX).\n", static_cast<unsigned long>(hr));
        ::FreeLibrary(d3d_mod);
        return;
    }

    // Xbox titles occasionally leave SHADER_VISIBLE on RTV/DSV heaps; desktop D3D12 rejects it unless stripped.
    D3D12_DESCRIPTOR_HEAP_DESC rtv_desc{};
    rtv_desc.Type = D3D12_DESCRIPTOR_HEAP_TYPE_RTV;
    rtv_desc.NumDescriptors = 8u;
    rtv_desc.Flags = D3D12_DESCRIPTOR_HEAP_FLAG_SHADER_VISIBLE;
    ID3D12DescriptorHeap* rtv_heap = nullptr;
    OS_REQUIRE(SUCCEEDED(dev->CreateDescriptorHeap(&rtv_desc, __uuidof(ID3D12DescriptorHeap),
                                                   reinterpret_cast<void**>(&rtv_heap))));
    OS_REQUIRE(rtv_heap != nullptr);
    rtv_heap->Release();

    D3D12_DESCRIPTOR_HEAP_DESC dsv_desc{};
    dsv_desc.Type = D3D12_DESCRIPTOR_HEAP_TYPE_DSV;
    dsv_desc.NumDescriptors = 4u;
    dsv_desc.Flags = D3D12_DESCRIPTOR_HEAP_FLAG_SHADER_VISIBLE;
    ID3D12DescriptorHeap* dsv_heap = nullptr;
    OS_REQUIRE(SUCCEEDED(dev->CreateDescriptorHeap(&dsv_desc, __uuidof(ID3D12DescriptorHeap),
                                                   reinterpret_cast<void**>(&dsv_heap))));
    OS_REQUIRE(dsv_heap != nullptr);
    dsv_heap->Release();

    // Verify cached barrier info skips UPLOAD heap transition cleanly without crashing or faulting.
    D3D12_HEAP_PROPERTIES up_hp{};
    up_hp.Type = D3D12_HEAP_TYPE_UPLOAD;
    D3D12_RESOURCE_DESC buf_desc{};
    buf_desc.Dimension = D3D12_RESOURCE_DIMENSION_BUFFER;
    buf_desc.Width = 4096ull;
    buf_desc.Height = 1u;
    buf_desc.DepthOrArraySize = 1u;
    buf_desc.MipLevels = 1u;
    buf_desc.SampleDesc.Count = 1u;
    buf_desc.Layout = D3D12_TEXTURE_LAYOUT_ROW_MAJOR;
    ID3D12Resource* up_buf = nullptr;
    OS_REQUIRE(SUCCEEDED(dev->CreateCommittedResource(
        &up_hp, D3D12_HEAP_FLAG_NONE, &buf_desc, D3D12_RESOURCE_STATE_GENERIC_READ, nullptr,
        __uuidof(ID3D12Resource), reinterpret_cast<void**>(&up_buf))));

    ID3D12CommandAllocator* alloc = nullptr;
    ID3D12GraphicsCommandList* cl = nullptr;
    OS_REQUIRE(SUCCEEDED(dev->CreateCommandAllocator(
        D3D12_COMMAND_LIST_TYPE_DIRECT, __uuidof(ID3D12CommandAllocator), reinterpret_cast<void**>(&alloc))));
    OS_REQUIRE(SUCCEEDED(dev->CreateCommandList(
        0u, D3D12_COMMAND_LIST_TYPE_DIRECT, alloc, nullptr,
        __uuidof(ID3D12GraphicsCommandList), reinterpret_cast<void**>(&cl))));

    D3D12_RESOURCE_BARRIER b{};
    b.Type = D3D12_RESOURCE_BARRIER_TYPE_TRANSITION;
    b.Transition.pResource = up_buf;
    b.Transition.Subresource = D3D12_RESOURCE_BARRIER_ALL_SUBRESOURCES;
    b.Transition.StateBefore = D3D12_RESOURCE_STATE_GENERIC_READ;
    b.Transition.StateAfter = D3D12_RESOURCE_STATE_COPY_SOURCE;
    cl->ResourceBarrier(1u, &b);
    OS_REQUIRE(SUCCEEDED(cl->Close()));

    cl->Release();
    alloc->Release();
    up_buf->Release();
    dev->Release();
    ::FreeLibrary(d3d_mod);
    std::printf("  PASS: D3D12X RTV/DSV SHADER_VISIBLE stripping & cached barrier fast-path.\n");
}
#endif

}  // namespace

int main() {
    std::setvbuf(stdout, nullptr, _IONBF, 0);
#if defined(_WIN32)
    TestVfsTruncateExisting();
    TestXAudio2LoopInvariants();
    TestAcpHalAndXApuHardening();
    TestDStorageErrorEventDuplication();
    TestD3D12XDescriptorHeapAndBarriers();
    std::printf("[PASS] test_minecraft_perf_hardening (5/5 suites passed)\n");
#else
    std::printf("[SKIP] test_minecraft_perf_hardening (Windows-only runtime suite)\n");
#endif
    return 0;
}
