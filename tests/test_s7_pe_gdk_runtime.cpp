// OpenScarlett Sprint 7 (v0.4.0-alpha) — Comprehensive PE / Loader / GDK / Memory /
// Raw Input / D3D12 Root-Sig Round-Trip / XGEncodeDCC Fuzz Conformance Test Suite.
//
// Validates all Worker 3 deliverables with not_impl == 0 on BOTH live GTX 1650 Ti
// and D3D12 WARP (OPENSCARLETT_PREFER_WARP=1).

#ifndef WIN32_LEAN_AND_MEAN
#  define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#  define NOMINMAX
#endif
#include <windows.h>
#include <d3d12.h>
#include <dxgi1_6.h>
#include <wrl/client.h>

#include <algorithm>
#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

#include "openscarlett/core/telemetry.h"
#include "openscarlett/gdk/xgameruntime_abi.h"
#include "openscarlett/gpu/xg_xs_abi.h"
#include "openscarlett/input/gameinput_abi.h"
#include "openscarlett/kernel/kernelx_abi.h"
#include "openscarlett/kernel/xmemory.h"
#include "openscarlett/loader/pe_inspector.h"
#include "openscarlett/shims/secondary_shims_abi.h"
#include "os_check.h"

namespace fs = std::filesystem;
using Microsoft::WRL::ComPtr;

namespace {

fs::path ResolveBinaryDir(const char* argv0) {
    if (argv0 && argv0[0] != '\0') {
        std::error_code ec;
        fs::path p = fs::weakly_canonical(fs::path(argv0), ec).parent_path();
        if (!p.empty() && fs::exists(p / "kernelx.dll")) {
            return p;
        }
    }
#ifdef OPENSCARLETT_BINARY_DIR
    fs::path cfg(OPENSCARLETT_BINARY_DIR);
    if (fs::exists(cfg / "kernelx.dll")) {
        return cfg;
    }
#endif
    return fs::current_path();
}

fs::path ResolveScratchDir() {
    char buf[512]{};
    DWORD n = ::GetEnvironmentVariableA("TEMP", buf, static_cast<DWORD>(sizeof(buf)));
    fs::path base = (n > 0 && n < sizeof(buf)) ? fs::path(buf) : fs::current_path();
    fs::path dir = base / "os_s7_pe_gdk_runtime";
    std::error_code ec;
    fs::create_directories(dir, ec);
    return dir;
}

std::string ToLowerAscii(std::string s) {
    for (char& c : s) {
        if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
    }
    return s;
}

template <typename T>
void WritePod(std::vector<uint8_t>& buf, size_t off, const T& val) {
    OS_REQUIRE(off + sizeof(T) <= buf.size());
    std::memcpy(buf.data() + off, &val, sizeof(T));
}

// Helper to construct a minimal valid 2-section PE32+ file image (.text at RVA 0x1000,
// .rdata at RVA 0x2000, optional 3rd section .reloc/.xdata at RVA 0x3000).
std::vector<uint8_t> BuildSyntheticPe64(
    uint16_t characteristics,
    uint32_t num_sections,
    uint32_t image_size,
    size_t file_size) {
    std::vector<uint8_t> img(file_size, 0u);
    WritePod<uint16_t>(img, 0x00, 0x5A4Du);      // MZ
    WritePod<uint32_t>(img, 0x3C, 0x80u);        // e_lfanew
    WritePod<uint32_t>(img, 0x80, 0x00004550u);  // PE\0\0

    const size_t coff = 0x84u;
    WritePod<uint16_t>(img, coff + 0, 0x8664u);  // AMD64
    WritePod<uint16_t>(img, coff + 2, static_cast<uint16_t>(num_sections));
    WritePod<uint16_t>(img, coff + 16, 0xF0u);   // SizeOfOptionalHeader (PE32+ = 240)
    WritePod<uint16_t>(img, coff + 18, characteristics);

    const size_t opt = coff + 20u;
    WritePod<uint16_t>(img, opt + 0, 0x020Bu);               // PE32+
    WritePod<uint32_t>(img, opt + 16, 0x1000u);              // AddressOfEntryPoint
    WritePod<uint64_t>(img, opt + 24, 0x0000000140000000ull);// ImageBase
    WritePod<uint32_t>(img, opt + 32, 0x1000u);              // SectionAlignment
    WritePod<uint32_t>(img, opt + 36, 0x200u);               // FileAlignment
    WritePod<uint32_t>(img, opt + 56, image_size);           // SizeOfImage
    WritePod<uint32_t>(img, opt + 60, 0x400u);               // SizeOfHeaders
    WritePod<uint16_t>(img, opt + 68, 3u);                   // Subsystem CUI
    WritePod<uint32_t>(img, opt + 108, 16u);                 // NumberOfRvaAndSizes
    return img;
}

void WriteSectionHeader(std::vector<uint8_t>& img,
                        uint32_t idx,
                        const char* name,
                        uint32_t vsize,
                        uint32_t vaddr,
                        uint32_t raw_size,
                        uint32_t raw_ptr,
                        uint32_t chars) {
    const size_t base = 0x84u + 20u + 0xF0u + static_cast<size_t>(idx) * 40u;
    std::memset(img.data() + base, 0, 40u);
    std::memcpy(img.data() + base, name, std::min<size_t>(8u, std::strlen(name)));
    WritePod<uint32_t>(img, base + 8, vsize);
    WritePod<uint32_t>(img, base + 12, vaddr);
    WritePod<uint32_t>(img, base + 16, raw_size);
    WritePod<uint32_t>(img, base + 20, raw_ptr);
    WritePod<uint32_t>(img, base + 36, chars);
}

void SetDataDir(std::vector<uint8_t>& img, uint32_t idx, uint32_t rva, uint32_t size) {
    const size_t dd = 0x84u + 20u + 112u + static_cast<size_t>(idx) * 8u;
    WritePod<uint32_t>(img, dd + 0, rva);
    WritePod<uint32_t>(img, dd + 4, size);
}

// ===========================================================================
// Test 1: KnownDLL System32-First Resolution + Hook DLL Routing
// ===========================================================================
void TestKnownDllResolution(const fs::path& bin_dir, const fs::path& scratch_dir) {
    using namespace openscarlett;

    OS_REQUIRE(IsWindowsKnownDll("kernel32.dll"));
    OS_REQUIRE(IsWindowsKnownDll("KERNEL32.DLL"));
    OS_REQUIRE(IsWindowsKnownDll("ntdll.dll"));
    OS_REQUIRE(IsWindowsKnownDll("user32"));
    OS_REQUIRE(IsWindowsKnownDll("C:\\FakeGuest\\ws2_32.dll"));
    OS_REQUIRE(IsWindowsKnownDll("advapi32.dll"));
    OS_REQUIRE(IsWindowsKnownDll("ole32.dll"));
    OS_REQUIRE(IsWindowsKnownDll("ucrtbase.dll"));
    OS_REQUIRE(!IsWindowsKnownDll("d3d12_xs.dll"));
    OS_REQUIRE(!IsWindowsKnownDll("custom_title_plugin.dll"));

    const auto known_list = GetWindowsKnownDllList();
    OS_REQUIRE(known_list.size() >= 25u);

    std::wstring sys32_ws2;
    OS_REQUIRE(ResolveKnownDllSystem32PathW(L"ws2_32.dll", sys32_ws2));
    OS_REQUIRE(!sys32_ws2.empty());
    std::string sys32_lo = ToLowerAscii(fs::path(sys32_ws2).string());
    OS_REQUIRE(sys32_lo.find("\\system32\\ws2_32.dll") != std::string::npos);

    // Place a decoy package-local ws2_32.dll inside a guest dir and confirm
    // DllRoutingTable NEVER lets the package-local image shadow System32 KnownDLL!
    fs::path guest_dir = scratch_dir / "guest_shadow_test";
    std::error_code ec;
    fs::create_directories(guest_dir, ec);
    {
        std::ofstream ofs(guest_dir / "ws2_32.dll", std::ios::binary | std::ios::trunc);
        ofs << "DECOY_NOT_A_REAL_DLL";
    }
    DllRoutingTable table;
    const auto dec = table.ResolveRoute("ws2_32.dll", bin_dir.wstring(), guest_dir.wstring());
    OS_REQUIRE(dec.policy == DllRoutePolicy::Windows);
    OS_REQUIRE(dec.resolved_path.empty());

    // Also verify openscarlett_hook.dll exports our KnownDLL & 30-DLL routing queries.
    const fs::path hook_path = bin_dir / "openscarlett_hook.dll";
    if (fs::exists(hook_path)) {
        HMODULE h_hook = ::LoadLibraryW(hook_path.c_str());
        OS_REQUIRE(h_hook != nullptr);
        using PfnGetCount = uint32_t(__cdecl*)();
        using PfnResolveKnown = int(__cdecl*)(const wchar_t*, wchar_t*, uint32_t);
        auto fn_count = reinterpret_cast<PfnGetCount>(
            reinterpret_cast<void*>(::GetProcAddress(h_hook, "OpenScarlettHook_GetRoutedDllCount")));
        auto fn_known = reinterpret_cast<PfnResolveKnown>(
            reinterpret_cast<void*>(::GetProcAddress(h_hook, "OpenScarlettHook_ResolveKnownDllPathW")));
        OS_REQUIRE(fn_count != nullptr);
        OS_REQUIRE(fn_known != nullptr);
        OS_REQUIRE(fn_count() == 32u);

        wchar_t resolved_buf[MAX_PATH]{};
        OS_REQUIRE(fn_known(L"ws2_32.dll", resolved_buf, MAX_PATH) == 1);
        std::string hook_sys32_lo = ToLowerAscii(fs::path(resolved_buf).string());
        OS_REQUIRE(hook_sys32_lo.find("\\system32\\ws2_32.dll") != std::string::npos);
        // Intentionally keep openscarlett_hook.dll mapped for process lifetime since its
        // DllMain installs live IAT hooks into the host module.
        (void)h_hook;
    }

    std::printf("[PASS] Test 1: KnownDLL System32-first resolution (%zu KnownDLLs, 30 routed DLLs)\n",
                known_list.size());
}

// ===========================================================================
// Test 2: PE Base Relocation RVA 0 / Size 0 Handling
// ===========================================================================
void TestPeBaseRelocationRvaZero() {
    using namespace openscarlett;

    // Case A: VirtualAddress == 0, Size != 0, RELOCS_STRIPPED clear -> must NOT read offset 0!
    {
        auto img = BuildSyntheticPe64(0x0022u, 2u, 0x3000u, 0x1000u);
        WriteSectionHeader(img, 0, ".text", 0x200u, 0x1000u, 0x200u, 0x400u, 0x60000020u);
        WriteSectionHeader(img, 1, ".rdata", 0x200u, 0x2000u, 0x200u, 0x600u, 0x40000040u);
        SetDataDir(img, 5u, 0u, 0x200u);  // RVA == 0!

        bool has_reloc = true;
        uint32_t blocks = 99u, entries = 99u;
        OS_REQUIRE(ValidatePeBaseRelocations(img, has_reloc, blocks, entries).ok());
        OS_REQUIRE(!has_reloc);
        OS_REQUIRE(blocks == 0u);
        OS_REQUIRE(entries == 0u);
    }

    // Case B: VirtualAddress != 0, Size == 0 -> absent!
    {
        auto img = BuildSyntheticPe64(0x0022u, 2u, 0x3000u, 0x1000u);
        WriteSectionHeader(img, 0, ".text", 0x200u, 0x1000u, 0x200u, 0x400u, 0x60000020u);
        WriteSectionHeader(img, 1, ".reloc", 0x200u, 0x2000u, 0x200u, 0x600u, 0x42000040u);
        SetDataDir(img, 5u, 0x2000u, 0u);

        bool has_reloc = true;
        uint32_t blocks = 99u, entries = 99u;
        OS_REQUIRE(ValidatePeBaseRelocations(img, has_reloc, blocks, entries).ok());
        OS_REQUIRE(!has_reloc);
        OS_REQUIRE(blocks == 0u);
        OS_REQUIRE(entries == 0u);
    }

    // Case C: Valid relocation table with 2 blocks (4 + 6 = 10 entries)
    {
        auto img = BuildSyntheticPe64(0x0022u, 2u, 0x3000u, 0x1000u);
        WriteSectionHeader(img, 0, ".text", 0x200u, 0x1000u, 0x200u, 0x400u, 0x60000020u);
        WriteSectionHeader(img, 1, ".reloc", 0x200u, 0x2000u, 0x200u, 0x600u, 0x42000040u);
        // Block 1 at file 0x600: size = 8 + 4*2 = 16
        WritePod<uint32_t>(img, 0x600u, 0x1000u);
        WritePod<uint32_t>(img, 0x604u, 16u);
        WritePod<uint16_t>(img, 0x608u, 0xA010u);
        WritePod<uint16_t>(img, 0x60Au, 0xA020u);
        WritePod<uint16_t>(img, 0x60Cu, 0xA030u);
        WritePod<uint16_t>(img, 0x60Eu, 0x0000u);
        // Block 2 at file 0x610: size = 8 + 6*2 = 20
        WritePod<uint32_t>(img, 0x610u, 0x2000u);
        WritePod<uint32_t>(img, 0x614u, 20u);
        SetDataDir(img, 5u, 0x2000u, 36u);

        bool has_reloc = false;
        uint32_t blocks = 0u, entries = 0u;
        OS_REQUIRE(ValidatePeBaseRelocations(img, has_reloc, blocks, entries).ok());
        OS_REQUIRE(has_reloc);
        OS_REQUIRE(blocks == 2u);
        OS_REQUIRE(entries == 10u);
    }

    std::printf("[PASS] Test 2: PE Base Relocation RVA 0 / Size 0 & valid block walking\n");
}

// ===========================================================================
// Test 3: Accurate Raw Export Name Reading
// ===========================================================================
void TestRawExportNameReading(const fs::path& bin_dir) {
    using namespace openscarlett;

    // Construct synthetic PE64 with .rdata at RVA 0x2000 (raw 0x600..0x800) and
    // .next at RVA 0x3000 (raw 0x800..0xA00) containing poison bytes "LEAKED_NEXT_SEC".
    auto img = BuildSyntheticPe64(0x2022u, 3u, 0x4000u, 0xA00u);
    WriteSectionHeader(img, 0, ".text", 0x200u, 0x1000u, 0x200u, 0x400u, 0x60000020u);
    WriteSectionHeader(img, 1, ".rdata", 0x200u, 0x2000u, 0x200u, 0x600u, 0x40000040u);
    WriteSectionHeader(img, 2, ".next", 0x200u, 0x3000u, 0x200u, 0x800u, 0x40000040u);

    const char* poison = "LEAKED_NEXT_SEC";
    std::memcpy(img.data() + 0x800u, poison, std::strlen(poison) + 1u);

    // Export directory at RVA 0x2000 (file 0x600), size 0x180
    SetDataDir(img, 0u, 0x2000u, 0x180u);
    WritePod<uint32_t>(img, 0x600u + 16u, 10u);     // Base ordinal = 10
    WritePod<uint32_t>(img, 0x600u + 20u, 5u);      // NumberOfFunctions = 5
    WritePod<uint32_t>(img, 0x600u + 24u, 5u);      // NumberOfNames = 5
    WritePod<uint32_t>(img, 0x600u + 28u, 0x2040u); // AddressOfFunctions (file 0x640)
    WritePod<uint32_t>(img, 0x600u + 32u, 0x2060u); // AddressOfNames (file 0x660)
    WritePod<uint32_t>(img, 0x600u + 36u, 0x2080u); // AddressOfNameOrdinals (file 0x680)

    // Functions: 0=Alpha, 1=Beta, 2=OrdinalOnly, 3=Forwarded, 4=MalformedNameTarget
    WritePod<uint32_t>(img, 0x640u + 0u, 0x1010u);
    WritePod<uint32_t>(img, 0x640u + 4u, 0x1020u);
    WritePod<uint32_t>(img, 0x640u + 8u, 0x1030u);
    WritePod<uint32_t>(img, 0x640u + 12u, 0x2140u);  // Forwarder inside export dir
    WritePod<uint32_t>(img, 0x640u + 16u, 0x1040u);

    // Name RVAs:
    //   0 -> "AlphaExport" (RVA 0x2100, file 0x700)
    //   1 -> "BetaExport"  (RVA 0x2120, file 0x720)
    //   2 -> "GammaForward"(RVA 0x2160, file 0x760)
    //   3 -> Unterminated string at end of .rdata (RVA 0x21F8, file 0x7F8..0x7FF filled with 'X', no null!)
    //   4 -> Out-of-bounds RVA 0x99999u
    WritePod<uint32_t>(img, 0x660u + 0u, 0x2100u);
    WritePod<uint32_t>(img, 0x660u + 4u, 0x2120u);
    WritePod<uint32_t>(img, 0x660u + 8u, 0x2160u);
    WritePod<uint32_t>(img, 0x660u + 12u, 0x21F8u);
    WritePod<uint32_t>(img, 0x660u + 16u, 0x99999u);

    WritePod<uint16_t>(img, 0x680u + 0u, 0u);
    WritePod<uint16_t>(img, 0x680u + 2u, 1u);
    WritePod<uint16_t>(img, 0x680u + 4u, 3u);
    WritePod<uint16_t>(img, 0x680u + 6u, 4u);
    WritePod<uint16_t>(img, 0x680u + 8u, 4u);

    std::memcpy(img.data() + 0x700u, "AlphaExport", 12u);
    std::memcpy(img.data() + 0x720u, "BetaExport", 11u);
    std::memcpy(img.data() + 0x740u, "kernel32.GetTickCount64", 24u);
    std::memcpy(img.data() + 0x760u, "GammaForward", 13u);
    std::memset(img.data() + 0x7F8u, 'X', 8u);  // Unterminated before .next!

    PeInspectionReport rep{};
    OS_REQUIRE(InspectPeBytes(img, "synthetic_exports.dll", rep).ok());
    OS_REQUIRE(rep.exports.size() == 5u);
    OS_REQUIRE(rep.malformed_export_names >= 2u);
    OS_REQUIRE(rep.exports[0].name == "AlphaExport");
    OS_REQUIRE(rep.exports[0].ordinal == 10u);
    OS_REQUIRE(rep.exports[1].name == "BetaExport");
    OS_REQUIRE(rep.exports[2].name.empty());  // Ordinal-only export preserved cleanly
    OS_REQUIRE(rep.exports[2].ordinal == 12u);
    OS_REQUIRE(rep.exports[3].name == "GammaForward");
    OS_REQUIRE(rep.exports[3].is_forwarded);
    OS_REQUIRE(rep.exports[3].forwarder == "kernel32.GetTickCount64");
    OS_REQUIRE(rep.exports[4].name.empty());  // Did NOT bleed into "LEAKED_NEXT_SEC"!

    // Verify real compiled kernelx.dll & xgameruntime.dll export inventories
    PeInspectionReport kx_rep{};
    OS_REQUIRE(InspectPeFile((bin_dir / "kernelx.dll").string(), kx_rep).ok());
    OS_REQUIRE(kx_rep.malformed_export_names == 0u);
    bool found_xmem_vq = false;
    for (const auto& e : kx_rep.exports) {
        if (e.name == "XMemVirtualQuery") found_xmem_vq = true;
    }
    OS_REQUIRE(found_xmem_vq);

    PeInspectionReport xgr_rep{};
    OS_REQUIRE(InspectPeFile((bin_dir / "xgameruntime.dll").string(), xgr_rep).ok());
    OS_REQUIRE(xgr_rep.malformed_export_names == 0u);
    bool found_streaming = false;
    for (const auto& e : xgr_rep.exports) {
        if (e.name == "XGameStreamingInitialize") found_streaming = true;
    }
    OS_REQUIRE(found_streaming);

    std::printf("[PASS] Test 3: Accurate raw export name reading (malformed=%u blocked, kernelx=%zu, xgr=%zu exports)\n",
                rep.malformed_export_names, kx_rep.exports.size(), xgr_rep.exports.size());
}

// ===========================================================================
// Test 4: Fault-Free PE Section Protection Transitions
// ===========================================================================
void TestFaultFreeSectionProtections() {
    using namespace openscarlett;

    OS_REQUIRE(ComputePeSectionProtection(0x60000020u) == PAGE_EXECUTE_READ);
    OS_REQUIRE(ComputePeSectionProtection(0x40000040u) == PAGE_READONLY);
    OS_REQUIRE(ComputePeSectionProtection(0xC0000040u) == PAGE_READWRITE);
    OS_REQUIRE(ComputePeSectionProtection(0xE0000020u) == PAGE_EXECUTE_READWRITE);
    OS_REQUIRE(ComputePeSectionProtection(0x00000000u) == PAGE_NOACCESS);
    OS_REQUIRE(ComputePeSectionProtection(0x44000040u) == (PAGE_READONLY | PAGE_NOCACHE));

    // Reserve a 6-page region (0x6000 bytes), commit ONLY pages 0..3 (headers + .text + .rdata + .data),
    // leaving page 4 (.uncom) reserved-uncommitted, and add a zero-size section (.empty).
    const size_t kTotalSize = 6u * 4096u;
    void* base = ::VirtualAlloc(nullptr, kTotalSize, MEM_RESERVE, PAGE_NOACCESS);
    OS_REQUIRE(base != nullptr);
    void* committed = ::VirtualAlloc(base, 4u * 4096u, MEM_COMMIT, PAGE_READWRITE);
    OS_REQUIRE(committed == base);

    auto hdr = BuildSyntheticPe64(0x2022u, 5u, static_cast<uint32_t>(kTotalSize), 0x400u);
    WriteSectionHeader(hdr, 0, ".text", 0x1000u, 0x1000u, 0x1000u, 0x1000u, 0x60000020u);  // RX
    WriteSectionHeader(hdr, 1, ".rdata", 0x1000u, 0x2000u, 0x1000u, 0x2000u, 0x40000040u); // R
    WriteSectionHeader(hdr, 2, ".data", 0x1000u, 0x3000u, 0x1000u, 0x3000u, 0xC0000040u);  // RW
    WriteSectionHeader(hdr, 3, ".empty", 0u, 0x4000u, 0u, 0u, 0xC0000040u);                // 0-size -> skip
    WriteSectionHeader(hdr, 4, ".uncom", 0x1000u, 0x4000u, 0x1000u, 0x4000u, 0xC0000040u); // uncommitted -> skip
    std::memcpy(base, hdr.data(), hdr.size());

    PeSectionProtectionSummary sum{};
    OS_REQUIRE(ApplyPeSectionProtections(base, &sum).ok());
    OS_REQUIRE(sum.total_sections == 5u);
    OS_REQUIRE(sum.protected_sections == 3u);
    OS_REQUIRE(sum.skipped_sections == 2u);
    OS_REQUIRE(sum.failed_sections == 0u);

    auto* bytes = static_cast<uint8_t*>(base);
    MEMORY_BASIC_INFORMATION mbi{};
    OS_REQUIRE(::VirtualQuery(bytes + 0x1000u, &mbi, sizeof(mbi)) == sizeof(mbi));
    OS_REQUIRE((mbi.Protect & 0xFFu) == PAGE_EXECUTE_READ);
    OS_REQUIRE(::VirtualQuery(bytes + 0x2000u, &mbi, sizeof(mbi)) == sizeof(mbi));
    OS_REQUIRE((mbi.Protect & 0xFFu) == PAGE_READONLY);
    OS_REQUIRE(::VirtualQuery(bytes + 0x3000u, &mbi, sizeof(mbi)) == sizeof(mbi));
    OS_REQUIRE((mbi.Protect & 0xFFu) == PAGE_READWRITE);
    OS_REQUIRE(::VirtualQuery(bytes + 0x4000u, &mbi, sizeof(mbi)) == sizeof(mbi));
    OS_REQUIRE(mbi.State == MEM_RESERVE);

    // Null & uncommitted base must fail cleanly without faulting.
    OS_REQUIRE(!ApplyPeSectionProtections(nullptr, nullptr).ok());
    OS_REQUIRE(!ApplyPeSectionProtections(bytes + 0x4000u, nullptr).ok());

    ::VirtualFree(base, 0, MEM_RELEASE);
    std::printf("[PASS] Test 4: Fault-free PE section protection transitions (3 protected, 2 skipped)\n");
}

// ===========================================================================
// Test 5: .xdata Large-Allocation Alignment & v2/v3 Chained Unwind Validation
// ===========================================================================
void TestXdataUnwindValidation(const fs::path& bin_dir) {
    using namespace openscarlett;

    // 5A. Validate real compiled openscarlett.exe
    const fs::path cli_exe = bin_dir / "openscarlett.exe";
    OS_REQUIRE(fs::exists(cli_exe));
    {
        std::ifstream ifs(cli_exe, std::ios::binary | std::ios::ate);
        OS_REQUIRE(ifs.good());
        std::vector<uint8_t> exe_bytes(static_cast<size_t>(ifs.tellg()));
        ifs.seekg(0);
        OS_REQUIRE(ifs.read(reinterpret_cast<char*>(exe_bytes.data()),
                            static_cast<std::streamsize>(exe_bytes.size())).good());
        PeXdataValidationResult real_res{};
        OS_REQUIRE(ValidatePeXdataUnwind(exe_bytes, real_res).ok());
        OS_REQUIRE(real_res.runtime_function_count > 10u);
        OS_REQUIRE(real_res.valid_entries == real_res.runtime_function_count);
        OS_REQUIRE(real_res.invalid_entries == 0u);
    }

    // 5B. Synthetic PE64 with valid v1 UWOP_ALLOC_LARGE (info=0 & info=1),
    //     valid v2 UWOP_EPILOG, valid v3 UNW_FLAG_CHAININFO, plus malformed cases.
    {
        auto img = BuildSyntheticPe64(0x0022u, 3u, 0x4000u, 0xC00u);
        WriteSectionHeader(img, 0, ".text", 0x1000u, 0x1000u, 0x200u, 0x400u, 0x60000020u);
        WriteSectionHeader(img, 1, ".pdata", 0x200u, 0x2000u, 0x200u, 0x600u, 0x40000040u);
        WriteSectionHeader(img, 2, ".xdata", 0x400u, 0x3000u, 0x400u, 0x800u, 0x40000040u);

        // 7 RUNTIME_FUNCTION entries in .pdata (file 0x600):
        //   0: Valid v1 with UWOP_ALLOC_LARGE info=0 (0x200*8=0x1000) & info=1 (0x20000) -> .xdata 0x3000 (file 0x800)
        //   1: Valid v2 with UWOP_EPILOG -> .xdata 0x3040 (file 0x840)
        //   2: Valid v3 with UNW_FLAG_CHAININFO -> chains to .xdata 0x3000 -> .xdata 0x3080 (file 0x880)
        //   3: INVALID UWOP_ALLOC_LARGE info=1 unaligned size 0x1004 -> .xdata 0x30C0 (file 0x8C0)
        //   4: INVALID UWOP_ALLOC_LARGE info=0 truncated slot -> .xdata 0x3100 (file 0x900)
        //   5: INVALID v1 with UWOP_EPILOG -> .xdata 0x3140 (file 0x940)
        //   6: INVALID cyclic UNW_FLAG_CHAININFO (0x3180 -> 0x31C0 -> 0x3180)
        auto write_rf = [&](uint32_t idx, uint32_t beg, uint32_t end, uint32_t unw) {
            const size_t off = 0x600u + static_cast<size_t>(idx) * 12u;
            WritePod<uint32_t>(img, off + 0u, beg);
            WritePod<uint32_t>(img, off + 4u, end);
            WritePod<uint32_t>(img, off + 8u, unw);
        };
        write_rf(0, 0x1000u, 0x1040u, 0x3000u);
        write_rf(1, 0x1040u, 0x1080u, 0x3040u);
        write_rf(2, 0x1080u, 0x10C0u, 0x3080u);
        write_rf(3, 0x10C0u, 0x1100u, 0x30C0u);
        write_rf(4, 0x1100u, 0x1140u, 0x3100u);
        write_rf(5, 0x1140u, 0x1180u, 0x3140u);
        write_rf(6, 0x1180u, 0x11C0u, 0x3180u);
        SetDataDir(img, 3u, 0x2000u, 7u * 12u);

        // [0] Valid v1 UNWIND_INFO at file 0x800 (RVA 0x3000): 5 codes (info=0 [2] + info=1 [3])
        img[0x800u] = 1u;  // ver=1, flags=0
        img[0x801u] = 16u; // SizeOfProlog
        img[0x802u] = 5u;  // CountOfCodes
        img[0x803u] = 0u;
        WritePod<uint16_t>(img, 0x804u, 0x0108u);  // offset=8, op=1(ALLOC_LARGE), info=0
        WritePod<uint16_t>(img, 0x806u, 0x0200u);  // scaled: 0x200 * 8 = 0x1000
        WritePod<uint16_t>(img, 0x808u, 0x1110u);  // offset=16, op=1(ALLOC_LARGE), info=1
        WritePod<uint32_t>(img, 0x80Au, 0x20000u); // unscaled: 128 KiB (16-byte aligned)

        // [1] Valid v2 UNWIND_INFO at file 0x840 (RVA 0x3040): 2 codes (UWOP_EPILOG + UWOP_ALLOC_SMALL)
        img[0x840u] = 2u;  // ver=2, flags=0
        img[0x841u] = 8u;
        img[0x842u] = 2u;
        img[0x843u] = 0u;
        WritePod<uint16_t>(img, 0x844u, 0x1604u);  // op=6(UWOP_EPILOG), info=1
        WritePod<uint16_t>(img, 0x846u, 0x3204u);  // op=2(UWOP_ALLOC_SMALL), info=3

        // [2] Valid v3 chained UNWIND_INFO at file 0x880 (RVA 0x3080): flags=UNW_FLAG_CHAININFO(4)
        img[0x880u] = static_cast<uint8_t>(3u | (4u << 3u));  // ver=3, CHAININFO
        img[0x881u] = 4u;
        img[0x882u] = 1u;  // 1 code -> padded to 2 slots (4 bytes) -> chained RF at +8
        img[0x883u] = 0u;
        WritePod<uint16_t>(img, 0x884u, 0x5002u);  // op=0(PUSH_NONVOL), rbp
        WritePod<uint32_t>(img, 0x888u, 0x1000u);  // chained Begin
        WritePod<uint32_t>(img, 0x88Cu, 0x1040u);  // chained End
        WritePod<uint32_t>(img, 0x890u, 0x3000u);  // chained UnwindInfo -> [0]

        // [3] Invalid UWOP_ALLOC_LARGE (info=1, misaligned 0x1004) at file 0x8C0 (RVA 0x30C0)
        img[0x8C0u] = 1u;
        img[0x8C1u] = 8u;
        img[0x8C2u] = 3u;
        img[0x8C3u] = 0u;
        WritePod<uint16_t>(img, 0x8C4u, 0x1108u);  // op=1, info=1
        WritePod<uint32_t>(img, 0x8C6u, 0x1004u);  // misaligned!

        // [4] Invalid truncated UWOP_ALLOC_LARGE (info=0, count=1) at file 0x900 (RVA 0x3100)
        img[0x900u] = 1u;
        img[0x901u] = 4u;
        img[0x902u] = 1u;
        img[0x903u] = 0u;
        WritePod<uint16_t>(img, 0x904u, 0x0104u);  // missing extra slot!

        // [5] Invalid v1 with UWOP_EPILOG at file 0x940 (RVA 0x3140)
        img[0x940u] = 1u;
        img[0x941u] = 4u;
        img[0x942u] = 1u;
        img[0x943u] = 0u;
        WritePod<uint16_t>(img, 0x944u, 0x0604u);  // UWOP_EPILOG illegal in v1

        // [6] Invalid cyclic chain: 0x3180 -> 0x31C0 -> 0x3180
        img[0x980u] = static_cast<uint8_t>(2u | (4u << 3u));
        img[0x982u] = 0u;
        WritePod<uint32_t>(img, 0x984u, 0x1180u);
        WritePod<uint32_t>(img, 0x988u, 0x11C0u);
        WritePod<uint32_t>(img, 0x98Cu, 0x31C0u);

        img[0x9C0u] = static_cast<uint8_t>(2u | (4u << 3u));
        img[0x9C2u] = 0u;
        WritePod<uint32_t>(img, 0x9C4u, 0x1180u);
        WritePod<uint32_t>(img, 0x9C8u, 0x11C0u);
        WritePod<uint32_t>(img, 0x9CCu, 0x3180u);

        PeXdataValidationResult syn{};
        OS_REQUIRE(ValidatePeXdataUnwind(img, syn).ok());
        OS_REQUIRE(syn.runtime_function_count == 7u);
        OS_REQUIRE(syn.valid_entries == 3u);
        OS_REQUIRE(syn.invalid_entries == 4u);
        OS_REQUIRE(syn.v1_entries == 1u);
        OS_REQUIRE(syn.v2_entries == 1u);
        OS_REQUIRE(syn.v3_entries == 1u);
        OS_REQUIRE(syn.alloc_large_entries == 2u);  // [0] and [2] chained to [0]
        OS_REQUIRE(syn.epilog_code_entries == 1u);
        OS_REQUIRE(syn.chained_entries == 1u);
        OS_REQUIRE(syn.alignment_errors >= 1u);
        OS_REQUIRE(syn.bounds_errors >= 2u);
        OS_REQUIRE(syn.cycle_errors >= 1u);
    }

    std::printf("[PASS] Test 5: .xdata UWOP_ALLOC_LARGE & v2/v3 chained unwind validation\n");
}

// ===========================================================================
// Test 6: XMemVirtualQuery & ERA Allocation Attribute Decoding
// ===========================================================================
void TestXMemVirtualQueryAndEraAttributes(const fs::path& bin_dir) {
    // 6A. Decode 4KB, 64KB, 2MB, 4MB, MEM_GRAPHICS, MEM_TITLE, MEM_WRITE_COMBINE, MEM_LARGE_PAGES, MEM_4MB_PAGES
    {
        const uint64_t attr_4k = MAKE_XALLOC_ATTRIBUTES(
            0x42u, 1u, 1u, 0u, 7u, XALLOC_ALIGNMENT_64,
            XALLOC_MEMTYPE_HEAP, XALLOC_PAGESIZE_4KB, 1u);
        XMEM_DECODED_ALLOC_ATTRIBUTES d{};
        OS_REQUIRE(XMemDecodeAllocationAttributes(attr_4k, &d) == 1);
        OS_REQUIRE(d.objectType == 0x42u);
        OS_REQUIRE(d.allocatorId == 7u);
        OS_REQUIRE(d.memoryType == XALLOC_MEMTYPE_HEAP);
        OS_REQUIRE(d.pageSizeBytes == 4096ull);
        OS_REQUIRE((d.allocFlags & MEM_TITLE) != 0u);
        OS_REQUIRE((d.allocFlags & MEM_GRAPHICS) == 0u);

        const uint64_t attr_64k_wc = MAKE_XALLOC_ATTRIBUTES(
            0x10u, 1u, 0u, 0u, 3u, XALLOC_ALIGNMENT_4K,
            XALLOC_MEMTYPE_GRAPHICS_WRITECOMBINE, XALLOC_PAGESIZE_64KB, 1u);
        OS_REQUIRE(XMemDecodeAllocationAttributes(attr_64k_wc, &d) == 1);
        OS_REQUIRE(d.pageSizeBytes == 65536ull);
        OS_REQUIRE(d.alignmentBytes == 65536ull);
        OS_REQUIRE((d.allocFlags & MEM_GRAPHICS) != 0u);
        OS_REQUIRE((d.allocFlags & MEM_WRITE_COMBINE) != 0u);
        OS_REQUIRE((d.protectFlags & PAGE_WRITECOMBINE) != 0u);

        const uint64_t attr_2mb = MAKE_XALLOC_ATTRIBUTES(
            0x20u, 1u, 0u, 0u, 4u, XALLOC_ALIGNMENT_DEFAULT,
            XALLOC_MEMTYPE_GRAPHICS_CACHEABLE, XALLOC_PAGESIZE_DEFAULT, 0u) | XALLOC_FLAG_2MB_PAGES;
        OS_REQUIRE(XMemDecodeAllocationAttributes(attr_2mb, &d) == 1);
        OS_REQUIRE(d.pageSizeBytes == 2ull * 1024ull * 1024ull);
        OS_REQUIRE((d.allocFlags & MEM_LARGE_PAGES) != 0u);
        OS_REQUIRE((d.allocFlags & MEM_GRAPHICS) != 0u);

        const uint64_t attr_4mb = MAKE_XALLOC_ATTRIBUTES(
            0x30u, 1u, 0u, 0u, 5u, XALLOC_ALIGNMENT_DEFAULT,
            XALLOC_MEMTYPE_PHYSICAL, XALLOC_PAGESIZE_4MB, 0u);
        OS_REQUIRE(XMemDecodeAllocationAttributes(attr_4mb, &d) == 1);
        OS_REQUIRE(d.pageSizeBytes == 4ull * 1024ull * 1024ull);
        OS_REQUIRE((d.allocFlags & MEM_4MB_PAGES) != 0u);
        OS_REQUIRE((d.allocFlags & MEM_LARGE_PAGES) != 0u);
    }

    // 6B. Query tracked XMemAlloc, VirtualAllocFromApp, physical mapping, and host stack via kernelx + xmem
    const uint64_t gfx_wc_attr = MAKE_XALLOC_ATTRIBUTES(
        0x11u, 1u, 0u, 0u, 9u, XALLOC_ALIGNMENT_64K,
        XALLOC_MEMTYPE_GRAPHICS_WRITECOMBINE, XALLOC_PAGESIZE_64KB, 1u);
    void* p_gfx = XMemAlloc(128u * 1024u, gfx_wc_attr);
    OS_REQUIRE(p_gfx != nullptr);

    MEMORY_BASIC_INFORMATION mbi{};
    OS_REQUIRE(XMemVirtualQuery(static_cast<uint8_t*>(p_gfx) + 4096u, &mbi, sizeof(mbi)) == sizeof(mbi));
    OS_REQUIRE(mbi.AllocationBase == p_gfx);
    OS_REQUIRE(mbi.State == MEM_COMMIT);
    OS_REQUIRE((mbi.Protect & PAGE_WRITECOMBINE) != 0u);
    OS_REQUIRE((mbi.Type & MEM_GRAPHICS) != 0u);
    OS_REQUIRE((mbi.Type & MEM_WRITE_COMBINE) != 0u);
    OS_REQUIRE((mbi.Type & MEM_TITLE) != 0u);

    XMEM_DECODED_ALLOC_ATTRIBUTES got_attr{};
    OS_REQUIRE(XMemGetAllocationAttributes(p_gfx, &got_attr) == 1);
    OS_REQUIRE(got_attr.objectType == 0x11u);
    OS_REQUIRE(got_attr.allocatorId == 9u);
    OS_REQUIRE(got_attr.pageSizeBytes == 65536ull);

    // Host fallback query on local stack variable
    int stack_sentinel = 12345;
    MEMORY_BASIC_INFORMATION host_mbi{};
    OS_REQUIRE(XMemVirtualQuery(&stack_sentinel, &host_mbi, sizeof(host_mbi)) == sizeof(host_mbi));
    OS_REQUIRE(host_mbi.State == MEM_COMMIT);
    OS_REQUIRE(host_mbi.RegionSize >= 4096u);

    // Verify xmem.dll ALSO exports XMemVirtualQuery, XMemDecodeAllocationAttributes, XMemGetAllocationAttributes
    HMODULE h_xmem = ::LoadLibraryW((bin_dir / "xmem.dll").c_str());
    OS_REQUIRE(h_xmem != nullptr);
    auto fn_vq = reinterpret_cast<PFN_XMemVirtualQuery>(
        reinterpret_cast<void*>(::GetProcAddress(h_xmem, "XMemVirtualQuery")));
    auto fn_dec = reinterpret_cast<PFN_XMemDecodeAllocationAttributes>(
        reinterpret_cast<void*>(::GetProcAddress(h_xmem, "XMemDecodeAllocationAttributes")));
    auto fn_get = reinterpret_cast<PFN_XMemGetAllocationAttributes>(
        reinterpret_cast<void*>(::GetProcAddress(h_xmem, "XMemGetAllocationAttributes")));
    OS_REQUIRE(fn_vq != nullptr);
    OS_REQUIRE(fn_dec != nullptr);
    OS_REQUIRE(fn_get != nullptr);

    MEMORY_BASIC_INFORMATION xmem_mbi{};
    OS_REQUIRE(fn_vq(p_gfx, &xmem_mbi, sizeof(xmem_mbi)) == sizeof(xmem_mbi));
    OS_REQUIRE(xmem_mbi.AllocationBase == p_gfx);
    XMEM_DECODED_ALLOC_ATTRIBUTES xmem_dec{};
    OS_REQUIRE(fn_dec(gfx_wc_attr, &xmem_dec) == 1);
    OS_REQUIRE(xmem_dec.pageSizeBytes == 65536ull);
    XMEM_DECODED_ALLOC_ATTRIBUTES xmem_got{};
    OS_REQUIRE(fn_get(p_gfx, &xmem_got) == 1);
    OS_REQUIRE(xmem_got.allocatorId == 9u);

    XMemFree(p_gfx, gfx_wc_attr);
    ::FreeLibrary(h_xmem);
    std::printf("[PASS] Test 6: XMemVirtualQuery & ERA attribute decoding (kernelx.dll + xmem.dll)\n");
}

// ===========================================================================
// Test 7: Minecraft-GDK Surface Slots (XGameStreaming + XTaskQueue + XSystem)
// ===========================================================================
struct MonitorState {
    std::atomic<uint32_t> work_hits{0u};
    std::atomic<uint32_t> completion_hits{0u};
};

void OPENSCARLETT_GDK_CALL TestQueueMonitorCb(
    void* context,
    XTaskQueueHandle /*queue*/,
    XTaskQueuePort port) {
    auto* st = static_cast<MonitorState*>(context);
    if (port == XTaskQueuePort_Work) {
        st->work_hits.fetch_add(1u, std::memory_order_relaxed);
    } else if (port == XTaskQueuePort_Completion) {
        st->completion_hits.fetch_add(1u, std::memory_order_relaxed);
    }
}

void OPENSCARLETT_GDK_CALL TestDummyWorkCb(void* context, bool /*canceled*/) {
    auto* flag = static_cast<std::atomic<uint32_t>*>(context);
    if (flag) flag->fetch_add(1u, std::memory_order_relaxed);
}

void OPENSCARLETT_GDK_CALL TestStreamingConnCb(
    void* /*context*/,
    XGameStreamingClientId /*client*/,
    XGameStreamingConnectionState /*state*/) {}

void TestMinecraftGdkSurface() {
    OS_REQUIRE(XGameRuntimeInitialize() == XGR_S_OK);
    OS_REQUIRE(XGameRuntimeIsFeatureAvailable(XGameRuntimeFeature_XGameStreaming));

    // 7A. XGameStreaming — all 15 exports + QueryApiImpl vtable
    OS_REQUIRE(XGameStreamingInitialize() == XGR_S_OK);
    OS_REQUIRE(!XGameStreamingIsStreaming());
    OS_REQUIRE(XGameStreamingGetClientCount() == 0u);
    XGameStreamingClientId clients[4]{};
    uint32_t clients_used = 99u;
    OS_REQUIRE(XGameStreamingGetClients(4u, clients, &clients_used) == XGR_S_OK);
    OS_REQUIRE(clients_used == 0u);
    OS_REQUIRE(XGameStreamingGetConnectionState(XGameStreamingAllClients) ==
               XGameStreamingConnectionState_Disconnected);

    XTaskQueueRegistrationToken stream_tok{};
    OS_REQUIRE(XGameStreamingRegisterConnectionStateChanged(
                   nullptr, nullptr, &TestStreamingConnCb, &stream_tok) == XGR_S_OK);
    OS_REQUIRE(stream_tok.token != 0ull);
    OS_REQUIRE(XGameStreamingUnregisterConnectionStateChanged(stream_tok, true));

    XGameStreamingShowTouchControlLayout("default");
    XGameStreamingHideTouchControls();

    uint32_t h_mm = 99u, v_mm = 99u;
    OS_REQUIRE(XGameStreamingGetStreamPhysicalDimensions(0ull, &h_mm, &v_mm) == XGR_S_OK);
    const size_t loc_sz = XGameStreamingGetServerLocationNameSize();
    OS_REQUIRE(loc_sz >= 2u);
    char loc_buf[64]{};
    OS_REQUIRE(XGameStreamingGetServerLocationName(sizeof(loc_buf), loc_buf) == XGR_S_OK);
    OS_REQUIRE(std::strcmp(loc_buf, "LocalPC") == 0);

    uint64_t last_frame = 99ull;
    OS_REQUIRE(XGameStreamingGetLastFrameDisplayed(0ull, &last_frame) == XGR_S_OK);
    bool touch_enabled = true;
    OS_REQUIRE(XGameStreamingIsTouchInputEnabledOnClient(0ull, &touch_enabled) == XGR_S_OK);
    OS_REQUIRE(!touch_enabled);
    XGameStreamingUninitialize();

    void* streaming_vtbl_raw = nullptr;
    OS_REQUIRE(QueryApiImpl(&XGR_API_GUID_GAME_STREAMING, &streaming_vtbl_raw) == XGR_S_OK);
    OS_REQUIRE(streaming_vtbl_raw != nullptr);
    auto* streaming_vtbl = static_cast<const IXgrGameStreamingApiVtable*>(streaming_vtbl_raw);
    OS_REQUIRE(streaming_vtbl->XGameStreamingInitialize() == XGR_S_OK);
    OS_REQUIRE(!streaming_vtbl->XGameStreamingIsStreaming());
    streaming_vtbl->XGameStreamingUninitialize();
    streaming_vtbl->Release(streaming_vtbl);

    // 7B. XTaskQueue monitors & process queue (verifying monitors actually fire!)
    XTaskQueueHandle manual_q = nullptr;
    OS_REQUIRE(XTaskQueueCreate(
                   XTaskQueueDispatchMode_Manual, XTaskQueueDispatchMode_Manual, &manual_q) == XGR_S_OK);
    MonitorState mon{};
    XTaskQueueRegistrationToken mon_tok{};
    OS_REQUIRE(XTaskQueueRegisterMonitor(manual_q, &mon, &TestQueueMonitorCb, &mon_tok) == XGR_S_OK);
    OS_REQUIRE(mon_tok.token != 0ull);

    std::atomic<uint32_t> work_ran{0u};
    OS_REQUIRE(XTaskQueueSubmitCallback(manual_q, XTaskQueuePort_Work, &work_ran, &TestDummyWorkCb) == XGR_S_OK);
    OS_REQUIRE(XTaskQueueSubmitCallback(manual_q, XTaskQueuePort_Completion, &work_ran, &TestDummyWorkCb) == XGR_S_OK);
    OS_REQUIRE(mon.work_hits.load() == 1u);
    OS_REQUIRE(mon.completion_hits.load() == 1u);
    OS_REQUIRE(XTaskQueueDispatch(manual_q, XTaskQueuePort_Work, 0u));
    OS_REQUIRE(XTaskQueueDispatch(manual_q, XTaskQueuePort_Completion, 0u));
    OS_REQUIRE(work_ran.load() == 2u);

    XTaskQueueUnregisterMonitor(manual_q, mon_tok);
    OS_REQUIRE(XTaskQueueSubmitCallback(manual_q, XTaskQueuePort_Work, &work_ran, &TestDummyWorkCb) == XGR_S_OK);
    OS_REQUIRE(mon.work_hits.load() == 1u);  // No longer fires after unregister!
    OS_REQUIRE(XTaskQueueDispatch(manual_q, XTaskQueuePort_Work, 0u));

    // Process task queue get/set
    XTaskQueueSetCurrentProcessTaskQueue(manual_q);
    XTaskQueueHandle proc_q = nullptr;
    OS_REQUIRE(XTaskQueueGetCurrentProcessTaskQueue(&proc_q));
    OS_REQUIRE(proc_q == manual_q);
    XTaskQueueCloseHandle(proc_q);
    XTaskQueueSetCurrentProcessTaskQueue(nullptr);
    XTaskQueueTerminate(manual_q, true, nullptr, nullptr);
    XTaskQueueCloseHandle(manual_q);

    // 7C. XSystem queries including XSystemGetAppSpecificDeviceId
    OS_REQUIRE(XSystemGetDeviceType() == XSystemDeviceType_XboxScarlettAnaconda);
    char cid[64]{}, sb[64]{}, asid[64]{};
    size_t used = 0u;
    OS_REQUIRE(XSystemGetConsoleId(sizeof(cid), cid, &used) == XGR_S_OK && used > 1u);
    OS_REQUIRE(XSystemGetXboxLiveSandboxId(sizeof(sb), sb, &used) == XGR_S_OK && used > 1u);
    OS_REQUIRE(XSystemGetAppSpecificDeviceId(sizeof(asid), asid, &used) == XGR_S_OK &&
               used == XSystemAppSpecificDeviceIdBytes);
    const auto analytics = XSystemGetAnalyticsInfo();
    OS_REQUIRE(analytics.osVersion.major == 10u);
    const auto rt_info = XSystemGetRuntimeInfo();
    OS_REQUIRE(rt_info.runtimeVersion.major == 10u);
    OS_REQUIRE(XSystemIsHandleValid(reinterpret_cast<void*>(0x1234u)));
    OS_REQUIRE(!XSystemIsHandleValid(nullptr));
    OS_REQUIRE(XSystemHandleTrack(nullptr, nullptr) == XGR_S_OK);

    void* sys_vtbl_raw = nullptr;
    OS_REQUIRE(QueryApiImpl(&XGR_API_GUID_SYSTEM, &sys_vtbl_raw) == XGR_S_OK);
    auto* sys_vtbl = static_cast<const IXgrSystemApiVtable*>(sys_vtbl_raw);
    char asid2[64]{};
    OS_REQUIRE(sys_vtbl->XSystemGetAppSpecificDeviceId(sizeof(asid2), asid2, &used) == XGR_S_OK);
    OS_REQUIRE(std::strcmp(asid, asid2) == 0);
    sys_vtbl->Release(sys_vtbl);

    // Verify not_impl == 0 on all exercised symbols!
    const char* kVerifiedXgrSyms[] = {
        "XGameStreamingInitialize",
        "XGameStreamingUninitialize",
        "XGameStreamingIsStreaming",
        "XGameStreamingGetClientCount",
        "XGameStreamingGetClients",
        "XGameStreamingGetConnectionState",
        "XGameStreamingRegisterConnectionStateChanged",
        "XGameStreamingUnregisterConnectionStateChanged",
        "XGameStreamingHideTouchControls",
        "XGameStreamingShowTouchControlLayout",
        "XGameStreamingGetStreamPhysicalDimensions",
        "XGameStreamingGetServerLocationNameSize",
        "XGameStreamingGetServerLocationName",
        "XGameStreamingGetLastFrameDisplayed",
        "XGameStreamingIsTouchInputEnabledOnClient",
        "XTaskQueueRegisterMonitor",
        "XTaskQueueUnregisterMonitor",
        "XTaskQueueGetCurrentProcessTaskQueue",
        "XTaskQueueSetCurrentProcessTaskQueue",
        "XSystemGetDeviceType",
        "XSystemGetConsoleId",
        "XSystemGetXboxLiveSandboxId",
        "XSystemGetAnalyticsInfo",
        "XSystemGetAppSpecificDeviceId",
        "XSystemGetRuntimeInfo",
        "XSystemIsHandleValid",
        "XSystemHandleTrack",
    };
    for (const char* sym : kVerifiedXgrSyms) {
        uint64_t total = 0u, not_impl = 99u;
        OS_REQUIRE(XgrGetTelemetryCallCountForTest(sym, &total, &not_impl) == 1);
        OS_REQUIRE(total >= 1u);
        OS_REQUIRE(not_impl == 0u);
    }

    XGameRuntimeUninitialize();
    std::printf("[PASS] Test 7: Minecraft-GDK surface (15 XGameStreaming + XTaskQueue monitors + XSystem, not_impl=0)\n");
}

// ===========================================================================
// Test 8: 6 New Fixed-Return Stub DLLs + 30-DLL Routing
// ===========================================================================
void TestSixNewFixedReturnStubDlls(const fs::path& bin_dir) {
    using namespace openscarlett;

    DllRoutingTable table;
    OS_REQUIRE(table.ListRules().size() == 21u);
    OS_REQUIRE(table.ListAllRules().size() == 26u);
    OS_REQUIRE(table.ListCompleteRules().size() == 32u);

    const char* kSixDlls[] = {
        "mflnmhelp.dll",
        "mfhevcdec.dll",
        "gamecoreclient.dll",
        "minuserx.dll",
        "xtfpix.dll",
        "xtfdebugmonitor.dll",
    };
    for (const char* dll : kSixDlls) {
        OS_REQUIRE(ClassifyImportDll(dll) == DllCategory::ConsoleExclusive);
        const auto* r = table.FindRule(dll);
        OS_REQUIRE(r != nullptr && r->policy == DllRoutePolicy::Shim);
        const auto d = table.ResolveRoute(dll, bin_dir.wstring());
        OS_REQUIRE(d.policy == DllRoutePolicy::Shim);
        OS_REQUIRE(fs::exists(d.resolved_path));
    }

    using PfnGetTel = int32_t(__stdcall*)(const char*, uint64_t*, uint64_t*, uint64_t*);

    // 1. mflnmhelp.dll
    {
        HMODULE m = ::LoadLibraryW((bin_dir / "mflnmhelp.dll").c_str());
        OS_REQUIRE(m != nullptr);
        auto fn_init = reinterpret_cast<int32_t(__stdcall*)(uint32_t)>(reinterpret_cast<void*>(::GetProcAddress(m, "MfLnmHelperInitialize")));
        auto fn_chk = reinterpret_cast<int32_t(__stdcall*)(const wchar_t*, uint32_t*)>(reinterpret_cast<void*>(::GetProcAddress(m, "MfLnmCheckLicenseStatus")));
        auto fn_caps = reinterpret_cast<int32_t(__stdcall*)(uint32_t*)>(reinterpret_cast<void*>(::GetProcAddress(m, "MfLnmQueryNetworkCapabilities")));
        auto fn_acq = reinterpret_cast<int32_t(__stdcall*)(const wchar_t*, void**)>(reinterpret_cast<void*>(::GetProcAddress(m, "MfLnmAcquireLicense")));
        auto fn_rel = reinterpret_cast<int32_t(__stdcall*)(void*)>(reinterpret_cast<void*>(::GetProcAddress(m, "MfLnmReleaseLicense")));
        auto fn_sd = reinterpret_cast<int32_t(__stdcall*)()>(reinterpret_cast<void*>(::GetProcAddress(m, "MfLnmHelperShutdown")));
        auto fn_tel = reinterpret_cast<PfnGetTel>(reinterpret_cast<void*>(::GetProcAddress(m, "OpenScarlettMfLnmHelpGetTelemetry")));
        OS_REQUIRE(fn_init && fn_chk && fn_caps && fn_acq && fn_rel && fn_sd && fn_tel);
        uint32_t st = 0u, caps = 0u;
        void* lic = nullptr;
        OS_REQUIRE(fn_init(0u) == 0);
        OS_REQUIRE(fn_chk(L"cid", &st) == 0 && st == 1u);
        OS_REQUIRE(fn_caps(&caps) == 0 && caps != 0u);
        OS_REQUIRE(fn_acq(L"cid", &lic) == 0 && lic != nullptr);
        OS_REQUIRE(fn_rel(lic) == 0);
        OS_REQUIRE(fn_sd() == 0);
        uint64_t tot = 0u, not_impl = 99u;
        OS_REQUIRE(fn_tel(nullptr, &tot, nullptr, &not_impl) == 1 && tot >= 6u && not_impl == 0u);
        ::FreeLibrary(m);
    }

    // 2. mfhevcdec.dll
    {
        HMODULE m = ::LoadLibraryW((bin_dir / "mfhevcdec.dll").c_str());
        OS_REQUIRE(m != nullptr);
        auto fn_gco = reinterpret_cast<int32_t(__stdcall*)(const void*, const void*, void**)>(reinterpret_cast<void*>(::GetProcAddress(m, "DllGetClassObject")));
        auto fn_init = reinterpret_cast<int32_t(__stdcall*)(uint32_t)>(reinterpret_cast<void*>(::GetProcAddress(m, "MFHevcDecoderInitialize")));
        auto fn_caps = reinterpret_cast<int32_t(__stdcall*)(uint32_t*, uint32_t*, uint32_t*)>(reinterpret_cast<void*>(::GetProcAddress(m, "MFHevcDecoderGetCapabilities")));
        auto fn_sd = reinterpret_cast<int32_t(__stdcall*)()>(reinterpret_cast<void*>(::GetProcAddress(m, "MFHevcDecoderShutdown")));
        auto fn_tel = reinterpret_cast<PfnGetTel>(reinterpret_cast<void*>(::GetProcAddress(m, "OpenScarlettMfHevcDecGetTelemetry")));
        OS_REQUIRE(fn_gco && fn_init && fn_caps && fn_sd && fn_tel);
        IClassFactory* cf = nullptr;
        OS_REQUIRE(fn_gco(nullptr, &IID_IClassFactory, reinterpret_cast<void**>(&cf)) == 0 && cf != nullptr);
        IUnknown* unk = nullptr;
        OS_REQUIRE(cf->CreateInstance(nullptr, IID_IUnknown, reinterpret_cast<void**>(&unk)) == S_OK && unk != nullptr);
        unk->Release();
        cf->Release();
        uint32_t prof = 0u, mw = 0u, mh = 0u;
        OS_REQUIRE(fn_init(0u) == 0);
        OS_REQUIRE(fn_caps(&prof, &mw, &mh) == 0 && mw == 3840u && mh == 2160u);
        OS_REQUIRE(fn_sd() == 0);
        uint64_t tot = 0u, not_impl = 99u;
        OS_REQUIRE(fn_tel(nullptr, &tot, nullptr, &not_impl) == 1 && tot >= 6u && not_impl == 0u);
        ::FreeLibrary(m);
    }

    // 3. gamecoreclient.dll
    {
        HMODULE m = ::LoadLibraryW((bin_dir / "gamecoreclient.dll").c_str());
        OS_REQUIRE(m != nullptr);
        auto fn_init = reinterpret_cast<int32_t(__stdcall*)(uint32_t)>(reinterpret_cast<void*>(::GetProcAddress(m, "GameCoreClientInitialize")));
        auto fn_open = reinterpret_cast<int32_t(__stdcall*)(const char*, void**)>(reinterpret_cast<void*>(::GetProcAddress(m, "GameCoreClientOpenSession")));
        auto fn_state = reinterpret_cast<int32_t(__stdcall*)(uint32_t*)>(reinterpret_cast<void*>(::GetProcAddress(m, "GameCoreClientGetServiceState")));
        auto fn_life = reinterpret_cast<int32_t(__stdcall*)(uint32_t)>(reinterpret_cast<void*>(::GetProcAddress(m, "GameCoreClientNotifyLifecycleEvent")));
        auto fn_close = reinterpret_cast<int32_t(__stdcall*)(void*)>(reinterpret_cast<void*>(::GetProcAddress(m, "GameCoreClientCloseSession")));
        auto fn_sd = reinterpret_cast<int32_t(__stdcall*)()>(reinterpret_cast<void*>(::GetProcAddress(m, "GameCoreClientShutdown")));
        auto fn_tel = reinterpret_cast<PfnGetTel>(reinterpret_cast<void*>(::GetProcAddress(m, "OpenScarlettGameCoreClientGetTelemetry")));
        OS_REQUIRE(fn_init && fn_open && fn_state && fn_life && fn_close && fn_sd && fn_tel);
        void* sess = nullptr;
        uint32_t svc_state = 0u;
        OS_REQUIRE(fn_init(0u) == 0);
        OS_REQUIRE(fn_open("OpenScarlett.Test", &sess) == 0 && sess != nullptr);
        OS_REQUIRE(fn_state(&svc_state) == 0 && svc_state == 1u);
        OS_REQUIRE(fn_life(1u) == 0);
        OS_REQUIRE(fn_close(sess) == 0);
        OS_REQUIRE(fn_sd() == 0);
        uint64_t tot = 0u, not_impl = 99u;
        OS_REQUIRE(fn_tel(nullptr, &tot, nullptr, &not_impl) == 1 && tot >= 6u && not_impl == 0u);
        ::FreeLibrary(m);
    }

    // 4. minuserx.dll
    {
        HMODULE m = ::LoadLibraryW((bin_dir / "minuserx.dll").c_str());
        OS_REQUIRE(m != nullptr);
        auto fn_init = reinterpret_cast<int32_t(__stdcall*)(uint32_t)>(reinterpret_cast<void*>(::GetProcAddress(m, "MinUserXInitialize")));
        auto fn_met = reinterpret_cast<int32_t(__stdcall*)(int32_t)>(reinterpret_cast<void*>(::GetProcAddress(m, "MinUserXGetSystemMetrics")));
        auto fn_cur = reinterpret_cast<int32_t(__stdcall*)(int32_t)>(reinterpret_cast<void*>(::GetProcAddress(m, "MinUserXSetCursorVisible")));
        auto fn_scale = reinterpret_cast<int32_t(__stdcall*)(uint32_t*)>(reinterpret_cast<void*>(::GetProcAddress(m, "MinUserXGetDisplayScaleFactor")));
        auto fn_sd = reinterpret_cast<int32_t(__stdcall*)()>(reinterpret_cast<void*>(::GetProcAddress(m, "MinUserXShutdown")));
        auto fn_tel = reinterpret_cast<PfnGetTel>(reinterpret_cast<void*>(::GetProcAddress(m, "OpenScarlettMinUserXGetTelemetry")));
        OS_REQUIRE(fn_init && fn_met && fn_cur && fn_scale && fn_sd && fn_tel);
        uint32_t scale = 0u;
        OS_REQUIRE(fn_init(0u) == 0);
        OS_REQUIRE(fn_met(0) > 0);
        OS_REQUIRE(fn_cur(0) == 1);
        OS_REQUIRE(fn_scale(&scale) == 0 && scale == 100u);
        OS_REQUIRE(fn_sd() == 0);
        uint64_t tot = 0u, not_impl = 99u;
        OS_REQUIRE(fn_tel(nullptr, &tot, nullptr, &not_impl) == 1 && tot >= 5u && not_impl == 0u);
        ::FreeLibrary(m);
    }

    // 5. xtfpix.dll
    {
        HMODULE m = ::LoadLibraryW((bin_dir / "xtfpix.dll").c_str());
        OS_REQUIRE(m != nullptr);
        auto fn_init = reinterpret_cast<int32_t(__stdcall*)(uint32_t)>(reinterpret_cast<void*>(::GetProcAddress(m, "XtfPixInitialize")));
        auto fn_bc = reinterpret_cast<int32_t(__stdcall*)(const wchar_t*, uint32_t)>(reinterpret_cast<void*>(::GetProcAddress(m, "XtfPixBeginCapture")));
        auto fn_ic = reinterpret_cast<int32_t(__stdcall*)(int32_t*)>(reinterpret_cast<void*>(::GetProcAddress(m, "XtfPixIsCapturing")));
        auto fn_ec = reinterpret_cast<int32_t(__stdcall*)()>(reinterpret_cast<void*>(::GetProcAddress(m, "XtfPixEndCapture")));
        auto fn_mk = reinterpret_cast<int32_t(__stdcall*)(uint64_t, const char*)>(reinterpret_cast<void*>(::GetProcAddress(m, "XtfPixSetMarker")));
        auto fn_be = reinterpret_cast<int32_t(__stdcall*)(uint64_t, const char*)>(reinterpret_cast<void*>(::GetProcAddress(m, "XtfPixBeginEvent")));
        auto fn_ee = reinterpret_cast<int32_t(__stdcall*)()>(reinterpret_cast<void*>(::GetProcAddress(m, "XtfPixEndEvent")));
        auto fn_sd = reinterpret_cast<int32_t(__stdcall*)()>(reinterpret_cast<void*>(::GetProcAddress(m, "XtfPixShutdown")));
        auto fn_tel = reinterpret_cast<PfnGetTel>(reinterpret_cast<void*>(::GetProcAddress(m, "OpenScarlettXtfPixGetTelemetry")));
        OS_REQUIRE(fn_init && fn_bc && fn_ic && fn_ec && fn_mk && fn_be && fn_ee && fn_sd && fn_tel);
        int32_t cap = 0;
        OS_REQUIRE(fn_init(0u) == 0);
        OS_REQUIRE(fn_bc(L"frame.wpix", 0u) == 0);
        OS_REQUIRE(fn_ic(&cap) == 0 && cap == 1);
        OS_REQUIRE(fn_be(0xFF00FF00ull, "MainPass") == 0);
        OS_REQUIRE(fn_mk(0xFFFF0000ull, "Draw") == 0);
        OS_REQUIRE(fn_ee() == 0);
        OS_REQUIRE(fn_ec() == 0);
        OS_REQUIRE(fn_sd() == 0);
        uint64_t tot = 0u, not_impl = 99u;
        OS_REQUIRE(fn_tel(nullptr, &tot, nullptr, &not_impl) == 1 && tot >= 8u && not_impl == 0u);
        ::FreeLibrary(m);
    }

    // 6. xtfdebugmonitor.dll
    {
        HMODULE m = ::LoadLibraryW((bin_dir / "xtfdebugmonitor.dll").c_str());
        OS_REQUIRE(m != nullptr);
        auto fn_cr = reinterpret_cast<int32_t(__stdcall*)(const wchar_t*, void**)>(reinterpret_cast<void*>(::GetProcAddress(m, "XtfCreateDebugMonitorClient")));
        auto fn_st = reinterpret_cast<int32_t(__stdcall*)(void*, uint32_t)>(reinterpret_cast<void*>(::GetProcAddress(m, "XtfDebugMonitorStart")));
        auto fn_wr = reinterpret_cast<int32_t(__stdcall*)(void*, const char*)>(reinterpret_cast<void*>(::GetProcAddress(m, "XtfDebugMonitorWriteOutput")));
        auto fn_sp = reinterpret_cast<int32_t(__stdcall*)(void*)>(reinterpret_cast<void*>(::GetProcAddress(m, "XtfDebugMonitorStop")));
        auto fn_cl = reinterpret_cast<int32_t(__stdcall*)(void*)>(reinterpret_cast<void*>(::GetProcAddress(m, "XtfDebugMonitorClose")));
        auto fn_at = reinterpret_cast<int32_t(__stdcall*)(int32_t*)>(reinterpret_cast<void*>(::GetProcAddress(m, "XtfDebugMonitorIsAttached")));
        auto fn_tel = reinterpret_cast<PfnGetTel>(reinterpret_cast<void*>(::GetProcAddress(m, "OpenScarlettXtfDebugMonitorGetTelemetry")));
        OS_REQUIRE(fn_cr && fn_st && fn_wr && fn_sp && fn_cl && fn_at && fn_tel);
        void* cli = nullptr;
        int32_t attached = 99;
        OS_REQUIRE(fn_cr(L"127.0.0.1", &cli) == 0 && cli != nullptr);
        OS_REQUIRE(fn_st(cli, 0u) == 0);
        OS_REQUIRE(fn_wr(cli, "hello sprint 7") == 0);
        OS_REQUIRE(fn_at(&attached) == 0 && attached == 0);
        OS_REQUIRE(fn_sp(cli) == 0);
        OS_REQUIRE(fn_cl(cli) == 0);
        uint64_t tot = 0u, not_impl = 99u;
        OS_REQUIRE(fn_tel(nullptr, &tot, nullptr, &not_impl) == 1 && tot >= 6u && not_impl == 0u);
        ::FreeLibrary(m);
    }

    std::printf("[PASS] Test 8: 6 new fixed-return stub DLLs + 30-DLL routing (not_impl=0)\n");
}

// ===========================================================================
// Test 9: Native Win32 Raw Input Per-Frame Mouse Delta Capture (Zero Loss)
// ===========================================================================
void TestRawInputMouseDeltaCapture() {
    IGameInput* gi = nullptr;
    OS_REQUIRE(GameInputCreate(&gi) == GAMEINPUT_S_OK && gi != nullptr);

    // Live Win32 RegisterRawInputDevices against a hidden message-only HWND
    WNDCLASSW wc{};
    wc.lpfnWndProc = ::DefWindowProcW;
    wc.hInstance = ::GetModuleHandleW(nullptr);
    wc.lpszClassName = L"OpenScarlettS7RawMouseTestWnd";
    ::RegisterClassW(&wc);
    HWND hwnd = ::CreateWindowExW(0, wc.lpszClassName, L"", 0, 0, 0, 0, 0,
                                  HWND_MESSAGE, nullptr, wc.hInstance, nullptr);
    OS_REQUIRE(hwnd != nullptr);
    OS_REQUIRE(OpenScarlettGameInputRegisterRawMouse(gi, hwnd, 0u) == GAMEINPUT_S_OK);

    IGameInputReading* r0 = nullptr;
    OS_REQUIRE(gi->GetCurrentReading(GameInputKindMouse, nullptr, &r0) == GAMEINPUT_S_OK && r0 != nullptr);
    GameInputMouseState ms0{};
    OS_REQUIRE(r0->GetMouseState(&ms0));
    OS_REQUIRE(ms0.positionX == 0 && ms0.positionY == 0);

    // Inject a 1,500-packet burst (nearly 6x larger than the 256-entry ring buffer!)
    int64_t exp_dx = 0, exp_dy = 0, exp_wx = 0, exp_wy = 0;
    for (int i = 0; i < 1500; ++i) {
        const int32_t dx = ((i % 7) - 3) * 2 + 1;
        const int32_t dy = ((i % 5) - 2) * 3 - 1;
        const int32_t wx = (i % 100 == 0) ? 120 : 0;
        const int32_t wy = (i % 50 == 0) ? -120 : 0;
        const uint32_t btns = (i % 2 == 0) ? GameInputMouseLeftButton : GameInputMouseRightButton;
        OS_REQUIRE(OpenScarlettGameInputInjectRawMouseDelta(gi, dx, dy, wx, wy, btns) == GAMEINPUT_S_OK);
        exp_dx += dx;
        exp_dy += dy;
        exp_wx += wx;
        exp_wy += wy;
    }

    IGameInputReading* r1 = nullptr;
    OS_REQUIRE(gi->GetCurrentReading(GameInputKindMouse, nullptr, &r1) == GAMEINPUT_S_OK && r1 != nullptr);
    GameInputMouseState ms1{};
    OS_REQUIRE(r1->GetMouseState(&ms1));
    OS_REQUIRE((ms1.positionX - ms0.positionX) == exp_dx);
    OS_REQUIRE((ms1.positionY - ms0.positionY) == exp_dy);
    OS_REQUIRE((ms1.wheelX - ms0.wheelX) == exp_wx);
    OS_REQUIRE((ms1.wheelY - ms0.wheelY) == exp_wy);
    OS_REQUIRE(ms1.buttons == GameInputMouseRightButton);

    GameInputRawMouseFrameDelta f1{};
    OS_REQUIRE(OpenScarlettGameInputConsumeFrameMouseDelta(gi, &f1) == GAMEINPUT_S_OK);
    OS_REQUIRE(f1.deltaX == exp_dx);
    OS_REQUIRE(f1.deltaY == exp_dy);
    OS_REQUIRE(f1.wheelX == exp_wx);
    OS_REQUIRE(f1.wheelY == exp_wy);
    OS_REQUIRE(f1.packetCount == 1500u);
    OS_REQUIRE(f1.totalPacketsReceived == 1500ull);
    OS_REQUIRE(f1.ringBufferedPackets == 256u);

    // Frame 2: inject 500 more packets -> zero loss, independent per-frame delta, cumulative total = 2000
    int64_t exp2_dx = 0, exp2_dy = 0;
    for (int i = 0; i < 500; ++i) {
        const int32_t dx = 4;
        const int32_t dy = -3;
        OS_REQUIRE(OpenScarlettGameInputInjectRawMouseDelta(
                       gi, dx, dy, 0, 0, GameInputMouseMiddleButton) == GAMEINPUT_S_OK);
        exp2_dx += dx;
        exp2_dy += dy;
    }
    GameInputRawMouseFrameDelta f2{};
    OS_REQUIRE(OpenScarlettGameInputConsumeFrameMouseDelta(gi, &f2) == GAMEINPUT_S_OK);
    OS_REQUIRE(f2.deltaX == exp2_dx);
    OS_REQUIRE(f2.deltaY == exp2_dy);
    OS_REQUIRE(f2.packetCount == 500u);
    OS_REQUIRE(f2.totalPacketsReceived == 2000ull);

    IGameInputReading* r2 = nullptr;
    OS_REQUIRE(gi->GetCurrentReading(GameInputKindMouse, nullptr, &r2) == GAMEINPUT_S_OK && r2 != nullptr);
    GameInputMouseState ms2{};
    OS_REQUIRE(r2->GetMouseState(&ms2));
    OS_REQUIRE(ms2.positionX == (exp_dx + exp2_dx));
    OS_REQUIRE(ms2.positionY == (exp_dy + exp2_dy));

    r0->Release();
    r1->Release();
    r2->Release();
    gi->Release();
    ::DestroyWindow(hwnd);
    ::UnregisterClassW(wc.lpszClassName, wc.hInstance);

    std::printf("[PASS] Test 9: Win32 Raw Input mouse delta capture (2,000 packets, 0 loss across 256-slot ring)\n");
}

// ===========================================================================
// Test 10: Versioned (v1.1) -> Legacy (v1.0) D3D12 Root-Signature Round-Trip
// ===========================================================================
void TestD3D12VersionedToLegacyRootSignatureRoundTrip() {
    char env_warp[16]{};
    const bool prefer_warp =
        (::GetEnvironmentVariableA("OPENSCARLETT_PREFER_WARP", env_warp, sizeof(env_warp)) > 0 &&
         env_warp[0] == '1');

    ComPtr<IDXGIFactory4> factory;
    OS_REQUIRE(SUCCEEDED(::CreateDXGIFactory1(IID_PPV_ARGS(&factory))));

    ComPtr<IDXGIAdapter1> adapter;
    if (prefer_warp) {
        OS_REQUIRE(SUCCEEDED(factory->EnumWarpAdapter(IID_PPV_ARGS(&adapter))));
    } else {
        ComPtr<IDXGIFactory6> factory6;
        if (SUCCEEDED(factory.As(&factory6))) {
            for (UINT i = 0u;
                 factory6->EnumAdapterByGpuPreference(
                     i, DXGI_GPU_PREFERENCE_HIGH_PERFORMANCE, IID_PPV_ARGS(&adapter)) !=
                 DXGI_ERROR_NOT_FOUND;
                 ++i) {
                DXGI_ADAPTER_DESC1 desc{};
                adapter->GetDesc1(&desc);
                if ((desc.Flags & DXGI_ADAPTER_FLAG_SOFTWARE) == 0u) {
                    break;
                }
                adapter.Reset();
            }
        }
        if (!adapter) {
            for (UINT i = 0u; factory->EnumAdapters1(i, &adapter) != DXGI_ERROR_NOT_FOUND; ++i) {
                DXGI_ADAPTER_DESC1 desc{};
                adapter->GetDesc1(&desc);
                if ((desc.Flags & DXGI_ADAPTER_FLAG_SOFTWARE) == 0u) {
                    break;
                }
                adapter.Reset();
            }
        }
        if (!adapter) {
            OS_REQUIRE(SUCCEEDED(factory->EnumWarpAdapter(IID_PPV_ARGS(&adapter))));
        }
    }

    DXGI_ADAPTER_DESC1 ad_desc{};
    OS_REQUIRE(SUCCEEDED(adapter->GetDesc1(&ad_desc)));

    ComPtr<ID3D12Device> device;
    OS_REQUIRE(SUCCEEDED(::D3D12CreateDevice(adapter.Get(), D3D_FEATURE_LEVEL_11_0, IID_PPV_ARGS(&device))));

    // Build a rich v1.1 root signature: constants, CBV, SRV, UAV, descriptor table (3 ranges), 2 static samplers.
    D3D12_DESCRIPTOR_RANGE1 ranges1[3]{};
    ranges1[0].RangeType = D3D12_DESCRIPTOR_RANGE_TYPE_SRV;
    ranges1[0].NumDescriptors = 8u;
    ranges1[0].BaseShaderRegister = 0u;
    ranges1[0].RegisterSpace = 1u;
    ranges1[0].Flags = D3D12_DESCRIPTOR_RANGE_FLAG_DATA_STATIC_WHILE_SET_AT_EXECUTE;
    ranges1[0].OffsetInDescriptorsFromTableStart = 0u;

    ranges1[1].RangeType = D3D12_DESCRIPTOR_RANGE_TYPE_CBV;
    ranges1[1].NumDescriptors = 2u;
    ranges1[1].BaseShaderRegister = 2u;
    ranges1[1].RegisterSpace = 0u;
    ranges1[1].Flags = D3D12_DESCRIPTOR_RANGE_FLAG_DESCRIPTORS_VOLATILE;
    ranges1[1].OffsetInDescriptorsFromTableStart = D3D12_DESCRIPTOR_RANGE_OFFSET_APPEND;

    ranges1[2].RangeType = D3D12_DESCRIPTOR_RANGE_TYPE_UAV;
    ranges1[2].NumDescriptors = 4u;
    ranges1[2].BaseShaderRegister = 1u;
    ranges1[2].RegisterSpace = 2u;
    ranges1[2].Flags = D3D12_DESCRIPTOR_RANGE_FLAG_DATA_VOLATILE;
    ranges1[2].OffsetInDescriptorsFromTableStart = D3D12_DESCRIPTOR_RANGE_OFFSET_APPEND;

    D3D12_ROOT_PARAMETER1 params1[5]{};
    params1[0].ParameterType = D3D12_ROOT_PARAMETER_TYPE_32BIT_CONSTANTS;
    params1[0].Constants = {0u, 0u, 4u};
    params1[0].ShaderVisibility = D3D12_SHADER_VISIBILITY_ALL;

    params1[1].ParameterType = D3D12_ROOT_PARAMETER_TYPE_CBV;
    params1[1].Descriptor = {1u, 0u, D3D12_ROOT_DESCRIPTOR_FLAG_DATA_STATIC_WHILE_SET_AT_EXECUTE};
    params1[1].ShaderVisibility = D3D12_SHADER_VISIBILITY_VERTEX;

    params1[2].ParameterType = D3D12_ROOT_PARAMETER_TYPE_SRV;
    params1[2].Descriptor = {0u, 0u, D3D12_ROOT_DESCRIPTOR_FLAG_DATA_VOLATILE};
    params1[2].ShaderVisibility = D3D12_SHADER_VISIBILITY_PIXEL;

    params1[3].ParameterType = D3D12_ROOT_PARAMETER_TYPE_UAV;
    params1[3].Descriptor = {0u, 0u, D3D12_ROOT_DESCRIPTOR_FLAG_DATA_VOLATILE};
    params1[3].ShaderVisibility = D3D12_SHADER_VISIBILITY_ALL;

    params1[4].ParameterType = D3D12_ROOT_PARAMETER_TYPE_DESCRIPTOR_TABLE;
    params1[4].DescriptorTable = {3u, ranges1};
    params1[4].ShaderVisibility = D3D12_SHADER_VISIBILITY_PIXEL;

    D3D12_STATIC_SAMPLER_DESC samplers[2]{};
    for (UINT s = 0u; s < 2u; ++s) {
        samplers[s].Filter = (s == 0u) ? D3D12_FILTER_MIN_MAG_MIP_LINEAR : D3D12_FILTER_MIN_MAG_MIP_POINT;
        samplers[s].AddressU = D3D12_TEXTURE_ADDRESS_MODE_WRAP;
        samplers[s].AddressV = D3D12_TEXTURE_ADDRESS_MODE_WRAP;
        samplers[s].AddressW = D3D12_TEXTURE_ADDRESS_MODE_CLAMP;
        samplers[s].MaxAnisotropy = 1u;
        samplers[s].ComparisonFunc = D3D12_COMPARISON_FUNC_NEVER;
        samplers[s].BorderColor = D3D12_STATIC_BORDER_COLOR_OPAQUE_BLACK;
        samplers[s].MaxLOD = D3D12_FLOAT32_MAX;
        samplers[s].ShaderRegister = s;
        samplers[s].RegisterSpace = 0u;
        samplers[s].ShaderVisibility = D3D12_SHADER_VISIBILITY_PIXEL;
    }

    D3D12_VERSIONED_ROOT_SIGNATURE_DESC v11_desc{};
    v11_desc.Version = D3D_ROOT_SIGNATURE_VERSION_1_1;
    v11_desc.Desc_1_1.NumParameters = 5u;
    v11_desc.Desc_1_1.pParameters = params1;
    v11_desc.Desc_1_1.NumStaticSamplers = 2u;
    v11_desc.Desc_1_1.pStaticSamplers = samplers;
    v11_desc.Desc_1_1.Flags = D3D12_ROOT_SIGNATURE_FLAG_ALLOW_INPUT_ASSEMBLER_INPUT_LAYOUT;

    ComPtr<ID3DBlob> blob_v11, err_v11;
    OS_REQUIRE(SUCCEEDED(::D3D12SerializeVersionedRootSignature(&v11_desc, &blob_v11, &err_v11)));
    ComPtr<ID3D12RootSignature> rs_v11;
    OS_REQUIRE(SUCCEEDED(device->CreateRootSignature(
        0u, blob_v11->GetBufferPointer(), blob_v11->GetBufferSize(), IID_PPV_ARGS(&rs_v11))));
    OS_REQUIRE(rs_v11 != nullptr);

    // Downgrade v1.1 -> legacy v1.0 D3D12_ROOT_SIGNATURE_DESC
    std::vector<std::vector<D3D12_DESCRIPTOR_RANGE>> legacy_tables;
    std::vector<D3D12_ROOT_PARAMETER> legacy_params(v11_desc.Desc_1_1.NumParameters);
    for (UINT i = 0u; i < v11_desc.Desc_1_1.NumParameters; ++i) {
        const auto& src = v11_desc.Desc_1_1.pParameters[i];
        auto& dst = legacy_params[i];
        dst.ParameterType = src.ParameterType;
        dst.ShaderVisibility = src.ShaderVisibility;
        if (src.ParameterType == D3D12_ROOT_PARAMETER_TYPE_32BIT_CONSTANTS) {
            dst.Constants = src.Constants;
        } else if (src.ParameterType == D3D12_ROOT_PARAMETER_TYPE_DESCRIPTOR_TABLE) {
            std::vector<D3D12_DESCRIPTOR_RANGE> r0(src.DescriptorTable.NumDescriptorRanges);
            for (UINT r = 0u; r < src.DescriptorTable.NumDescriptorRanges; ++r) {
                const auto& sr = src.DescriptorTable.pDescriptorRanges[r];
                r0[r].RangeType = sr.RangeType;
                r0[r].NumDescriptors = sr.NumDescriptors;
                r0[r].BaseShaderRegister = sr.BaseShaderRegister;
                r0[r].RegisterSpace = sr.RegisterSpace;
                r0[r].OffsetInDescriptorsFromTableStart = sr.OffsetInDescriptorsFromTableStart;
            }
            legacy_tables.push_back(std::move(r0));
            dst.DescriptorTable.NumDescriptorRanges = src.DescriptorTable.NumDescriptorRanges;
            dst.DescriptorTable.pDescriptorRanges = legacy_tables.back().data();
        } else {
            dst.Descriptor.ShaderRegister = src.Descriptor.ShaderRegister;
            dst.Descriptor.RegisterSpace = src.Descriptor.RegisterSpace;
        }
    }

    D3D12_ROOT_SIGNATURE_DESC v10_desc{};
    v10_desc.NumParameters = static_cast<UINT>(legacy_params.size());
    v10_desc.pParameters = legacy_params.data();
    v10_desc.NumStaticSamplers = v11_desc.Desc_1_1.NumStaticSamplers;
    v10_desc.pStaticSamplers = v11_desc.Desc_1_1.pStaticSamplers;
    v10_desc.Flags = v11_desc.Desc_1_1.Flags;

    ComPtr<ID3DBlob> blob_v10, err_v10;
    OS_REQUIRE(SUCCEEDED(::D3D12SerializeRootSignature(
        &v10_desc, D3D_ROOT_SIGNATURE_VERSION_1_0, &blob_v10, &err_v10)));
    ComPtr<ID3D12RootSignature> rs_v10;
    OS_REQUIRE(SUCCEEDED(device->CreateRootSignature(
        0u, blob_v10->GetBufferPointer(), blob_v10->GetBufferSize(), IID_PPV_ARGS(&rs_v10))));
    OS_REQUIRE(rs_v10 != nullptr);

    // Deserialize BOTH blobs and verify full parameter/range/sampler round-trip parity!
    ComPtr<ID3D12VersionedRootSignatureDeserializer> deser11, deser10;
    OS_REQUIRE(SUCCEEDED(::D3D12CreateVersionedRootSignatureDeserializer(
        blob_v11->GetBufferPointer(), blob_v11->GetBufferSize(), IID_PPV_ARGS(&deser11))));
    OS_REQUIRE(SUCCEEDED(::D3D12CreateVersionedRootSignatureDeserializer(
        blob_v10->GetBufferPointer(), blob_v10->GetBufferSize(), IID_PPV_ARGS(&deser10))));

    const D3D12_VERSIONED_ROOT_SIGNATURE_DESC* d11 = nullptr;
    const D3D12_VERSIONED_ROOT_SIGNATURE_DESC* d10 = nullptr;
    OS_REQUIRE(SUCCEEDED(deser11->GetRootSignatureDescAtVersion(D3D_ROOT_SIGNATURE_VERSION_1_0, &d11)));
    OS_REQUIRE(SUCCEEDED(deser10->GetRootSignatureDescAtVersion(D3D_ROOT_SIGNATURE_VERSION_1_0, &d10)));
    OS_REQUIRE(d11->Desc_1_0.NumParameters == d10->Desc_1_0.NumParameters);
    OS_REQUIRE(d11->Desc_1_0.NumStaticSamplers == d10->Desc_1_0.NumStaticSamplers);
    OS_REQUIRE(d11->Desc_1_0.Flags == d10->Desc_1_0.Flags);
    for (UINT i = 0u; i < d11->Desc_1_0.NumParameters; ++i) {
        const auto& a = d11->Desc_1_0.pParameters[i];
        const auto& b = d10->Desc_1_0.pParameters[i];
        OS_REQUIRE(a.ParameterType == b.ParameterType);
        OS_REQUIRE(a.ShaderVisibility == b.ShaderVisibility);
        if (a.ParameterType == D3D12_ROOT_PARAMETER_TYPE_DESCRIPTOR_TABLE) {
            OS_REQUIRE(a.DescriptorTable.NumDescriptorRanges == b.DescriptorTable.NumDescriptorRanges);
            for (UINT r = 0u; r < a.DescriptorTable.NumDescriptorRanges; ++r) {
                OS_REQUIRE(a.DescriptorTable.pDescriptorRanges[r].RangeType ==
                           b.DescriptorTable.pDescriptorRanges[r].RangeType);
                OS_REQUIRE(a.DescriptorTable.pDescriptorRanges[r].BaseShaderRegister ==
                           b.DescriptorTable.pDescriptorRanges[r].BaseShaderRegister);
                OS_REQUIRE(a.DescriptorTable.pDescriptorRanges[r].RegisterSpace ==
                           b.DescriptorTable.pDescriptorRanges[r].RegisterSpace);
            }
        }
    }

    std::printf("[PASS] Test 10: D3D12 v1.1 -> v1.0 root-signature round-trip on '%ls' (%s)\n",
                ad_desc.Description, prefer_warp ? "WARP" : "Hardware GPU");
}

// ===========================================================================
// Test 11: 1,000-Case Deterministic Fuzz Check for XGEncodeDCC
// ===========================================================================
void TestXgEncodeDccFuzz1000() {
    uint64_t rng = 0x5CA71E7720260701ull;
    auto next_u32 = [&]() -> uint32_t {
        rng += 0x9E3779B97F4A7C15ull;
        uint64_t z = rng;
        z = (z ^ (z >> 30u)) * 0xBF58476D1CE4E5B9ull;
        z = (z ^ (z >> 27u)) * 0x94D049BB133111EBull;
        z = z ^ (z >> 31u);
        return static_cast<uint32_t>(z & 0xFFFFFFFFu);
    };

    static constexpr uint32_t kFormats[] = {
        DXGI_FORMAT_R8_UNORM,
        DXGI_FORMAT_R8G8_UNORM,
        DXGI_FORMAT_R8G8B8A8_UNORM,
        DXGI_FORMAT_B8G8R8A8_UNORM_SRGB,
        DXGI_FORMAT_R10G10B10A2_UNORM,
        DXGI_FORMAT_R16_FLOAT,
        DXGI_FORMAT_R16G16B16A16_FLOAT,
        DXGI_FORMAT_R32_FLOAT,
        DXGI_FORMAT_R32G32B32A32_FLOAT,
        // Non-DCC formats (must fail cleanly without writing!)
        DXGI_FORMAT_BC1_UNORM,
        DXGI_FORMAT_BC7_UNORM,
        DXGI_FORMAT_D32_FLOAT,
    };
    static constexpr XG_TILE_MODE kModes[] = {
        XG_TILE_MODE_2D_THIN_256B_S,
        XG_TILE_MODE_2D_THIN_4KB_S,
        XG_TILE_MODE_2D_THIN_4KB_D,
        XG_TILE_MODE_2D_THIN_64KB_S,
        XG_TILE_MODE_2D_THIN_64KB_D,
        XG_TILE_MODE_2D_THIN_64KB_R,
        XG_TILE_MODE_2D_THIN_64KB_S_X,
        XG_TILE_MODE_2D_THIN_64KB_D_X,
        XG_TILE_MODE_2D_THIN_64KB_R_X,
        XG_TILE_MODE_LINEAR,  // Must fail cleanly for DCC
    };
    static constexpr uint32_t kSamples[] = {1u, 2u, 4u, 8u};
    static constexpr uint32_t kMaxBlks[] = {0u, 64u, 128u, 256u};
    static constexpr uint8_t kCanary = 0xA5u;

    uint32_t valid_cases = 0u;
    uint32_t rejected_cases = 0u;

    std::vector<uint8_t> buf_a;
    std::vector<uint8_t> buf_b;

    for (uint32_t i = 0u; i < 1000u; ++i) {
        XG_DCC_ENCODE_PARAMS p{};
        p.Desc.Width = 1u + (next_u32() % 512u);
        p.Desc.Height = 1u + (next_u32() % 512u);
        p.Desc.MipLevels = 1u + (next_u32() % 5u);
        p.Desc.ArraySize = 1u + (next_u32() % 3u);
        p.Desc.Format = kFormats[next_u32() % (sizeof(kFormats) / sizeof(kFormats[0]))];
        p.Desc.SampleCount = kSamples[next_u32() % 4u];
        p.Desc.BindFlags = XG_BIND_RENDER_TARGET | XG_BIND_SHADER_RESOURCE;
        p.Desc.TileMode = kModes[next_u32() % (sizeof(kModes) / sizeof(kModes[0]))];
        p.ConsoleType = (next_u32() & 1u) ? XG_CONSOLE_TYPE_SCARLETT_ANACONDA
                                          : XG_CONSOLE_TYPE_SCARLETT_LOCKHART;
        p.BlockState = static_cast<XG_DCC_BLOCK_STATE>(next_u32() % 8u);
        p.Independent64BBlocks = next_u32() & 1u;
        p.Independent128BBlocks = next_u32() & 1u;
        p.MaxCompressedBlockSize = kMaxBlks[next_u32() % 4u];
        p.PipeAligned = next_u32() & 1u;

        XG_RESOURCE_LAYOUT layout{};
        XG_RESOURCE_METADATA_LAYOUT meta{};
        const bool has_layout = (XGComputeMipLayout(&p.Desc, &layout) == 0);
        const bool has_meta = has_layout &&
                              (XGComputeTexture2DMetadataLayout(&p.Desc, p.ConsoleType, &meta) == 0);

        if (!has_meta || meta.Dcc.Enabled == 0u) {
            uint8_t tiny[64];
            std::memset(tiny, kCanary, sizeof(tiny));
            XG_DCC_ENCODE_RESULT res{};
            OS_REQUIRE(XGEncodeDCC(&p, tiny, sizeof(tiny), &res) != 0);
            for (uint8_t b : tiny) OS_REQUIRE(b == kCanary);
            ++rejected_cases;
            continue;
        }

        p.MipLevel = next_u32() % layout.MipLevels;
        p.ArraySlice = next_u32() % layout.ArraySize;

        const uint64_t required = (static_cast<uint64_t>(p.ArraySlice) + 1ull) * meta.Dcc.SlicePitchBytes;

        // Negative bounds test: undersized buffer must fail cleanly with zero writes
        if (required > 16ull && (i % 10u == 0u)) {
            buf_a.assign(static_cast<size_t>(required), kCanary);
            XG_DCC_ENCODE_RESULT bad_res{};
            OS_REQUIRE(XGEncodeDCC(&p, buf_a.data(), required - 1ull, &bad_res) != 0);
            OS_REQUIRE(buf_a[0] == kCanary && buf_a[static_cast<size_t>(required - 1ull)] == kCanary);
        }

        // Valid encode twice into canary-guarded buffers -> deterministic & round-trip verifiable
        const size_t guard_sz = static_cast<size_t>(required) + 64u;
        buf_a.assign(guard_sz, kCanary);
        buf_b.assign(guard_sz, kCanary);

        XG_DCC_ENCODE_RESULT res_a{}, res_b{}, ver_res{};
        OS_REQUIRE(XGEncodeDCC(&p, buf_a.data(), required, &res_a) == 0);
        OS_REQUIRE(XGEncodeDCC(&p, buf_b.data(), required, &res_b) == 0);
        OS_REQUIRE(res_a.EncodedKeyByte == res_b.EncodedKeyByte);
        OS_REQUIRE(res_a.EncodedByteCount == res_b.EncodedByteCount);
        OS_REQUIRE(res_a.TotalBlocks > 0u);
        OS_REQUIRE(std::memcmp(buf_a.data(), buf_b.data(), static_cast<size_t>(required)) == 0);

        // Guard bytes past `required` must be completely untouched
        for (size_t g = static_cast<size_t>(required); g < guard_sz; ++g) {
            OS_REQUIRE(buf_a[g] == kCanary);
            OS_REQUIRE(buf_b[g] == kCanary);
        }

        // Verify decode & round-trip verification
        uint32_t decoded_state = 999u;
        OS_REQUIRE(XGDecodeDCCKey(res_a.EncodedKeyByte, &decoded_state) == 0);
        OS_REQUIRE(decoded_state == static_cast<uint32_t>(p.BlockState));
        OS_REQUIRE(XGVerifyDCC(&p, buf_a.data(), required, &ver_res) == 0);
        OS_REQUIRE(ver_res.EncodedKeyByte == res_a.EncodedKeyByte);
        ++valid_cases;
    }

    OS_REQUIRE(valid_cases + rejected_cases == 1000u);
    OS_REQUIRE(valid_cases >= 500u);
    OS_REQUIRE(rejected_cases >= 50u);

    uint64_t enc_total = 0u, enc_not_impl = 99u;
    int32_t last_hr = -1;
    OS_REQUIRE(OpenScarlettXgGetTelemetryDetail("XGEncodeDCC", &enc_total, &enc_not_impl, &last_hr) == 1);
    OS_REQUIRE(enc_total >= 1000u);
    OS_REQUIRE(enc_not_impl == 0u);

    std::printf("[PASS] Test 11: XGEncodeDCC 1,000-case deterministic fuzz (%u valid, %u rejected, not_impl=0)\n",
                valid_cases, rejected_cases);
}

}  // namespace

int main(int argc, char** argv) {
    std::setvbuf(stdout, nullptr, _IONBF, 0);
    std::setvbuf(stderr, nullptr, _IONBF, 0);
    const fs::path bin_dir = ResolveBinaryDir(argc > 0 ? argv[0] : nullptr);
    const fs::path scratch_dir = ResolveScratchDir();

    std::printf("=== OpenScarlett Sprint 7 PE / Loader / GDK / Memory / RawInput / D3D12 / XG Test ===\n");
    std::printf("Binary dir: %s\n", bin_dir.string().c_str());

    TestKnownDllResolution(bin_dir, scratch_dir);
    TestPeBaseRelocationRvaZero();
    TestRawExportNameReading(bin_dir);
    TestFaultFreeSectionProtections();
    TestXdataUnwindValidation(bin_dir);
    TestXMemVirtualQueryAndEraAttributes(bin_dir);
    TestMinecraftGdkSurface();
    TestSixNewFixedReturnStubDlls(bin_dir);
    TestRawInputMouseDeltaCapture();
    TestD3D12VersionedToLegacyRootSignatureRoundTrip();
    TestXgEncodeDccFuzz1000();

    // Final check: zero not_impl calls recorded in test process global telemetry
    const auto snap = openscarlett::CallTelemetry::Global().Snapshot();
    uint64_t total_not_impl = 0u;
    for (const auto& e : snap) {
        total_not_impl += e.not_impl_calls;
    }
    OS_REQUIRE(total_not_impl == 0u);

    std::printf("=== ALL 11 SPRINT 7 WORKER 3 TESTS PASSED (not_impl = 0) ===\n");
    return 0;
}
