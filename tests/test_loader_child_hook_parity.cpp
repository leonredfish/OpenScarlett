#include <windows.h>

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>
#include <unordered_map>
#include <vector>

#include "openscarlett/loader/apc_injector.h"
#include "openscarlett/loader/pe_inspector.h"
#include "openscarlett/loader/vfs_mounts.h"
#include "os_check.h"

namespace fs = std::filesystem;

namespace {

fs::path ResolveRuntimeBinDir() {
    std::error_code ec;
    wchar_t self_buf[MAX_PATH]{};
    const DWORD self_len = ::GetModuleFileNameW(nullptr, self_buf, static_cast<DWORD>(MAX_PATH));
    if (self_len > 0 && self_len < MAX_PATH) {
        const fs::path exe_dir = fs::path(self_buf).parent_path();
        if (fs::exists(exe_dir / L"openscarlett_hook.dll", ec) &&
            fs::exists(exe_dir / L"winrt_xs.dll", ec)) {
            return exe_dir;
        }
    }
    return fs::path(OPENSCARLETT_BINARY_DIR);
}

fs::path ResolveScratchRoot() {
    const std::wstring work_dir = openscarlett::ResolveDefaultWorkDirW(ResolveRuntimeBinDir().wstring());
    if (!work_dir.empty()) {
        return (fs::path(work_dir) / L"test_loader_child_hook_parity").make_preferred();
    }
    return (ResolveRuntimeBinDir() / L".tmp_loader_child_hook_parity").make_preferred();
}

std::wstring ReadEnvW(const wchar_t* name) {
    const DWORD needed = ::GetEnvironmentVariableW(name, nullptr, 0);
    if (needed == 0) {
        return {};
    }
    std::wstring buf(needed, L'\0');
    const DWORD written = ::GetEnvironmentVariableW(name, buf.data(), needed);
    if (written == 0 || written >= needed) {
        return {};
    }
    buf.resize(written);
    return buf;
}

std::string ReadTextFile(const fs::path& p) {
    std::ifstream ifs(p, std::ios::binary);
    OS_REQUIRE(static_cast<bool>(ifs));
    std::ostringstream oss;
    oss << ifs.rdbuf();
    return oss.str();
}

void WriteTextFile(const fs::path& p, const std::string& data) {
    std::error_code ec;
    fs::create_directories(p.parent_path(), ec);
    std::ofstream ofs(p, std::ios::binary | std::ios::trunc);
    OS_REQUIRE(static_cast<bool>(ofs));
    ofs.write(data.data(), static_cast<std::streamsize>(data.size()));
    OS_REQUIRE(static_cast<bool>(ofs));
}

struct ScopedEnvVarW {
    std::wstring name;
    bool had_prev = false;
    std::wstring prev_val;

    explicit ScopedEnvVarW(std::wstring var_name) : name(std::move(var_name)) {
        const DWORD needed = ::GetEnvironmentVariableW(name.c_str(), nullptr, 0);
        if (needed > 0) {
            had_prev = true;
            prev_val.resize(needed, L'\0');
            const DWORD written = ::GetEnvironmentVariableW(name.c_str(), prev_val.data(), needed);
            prev_val.resize(written);
        }
    }
    ~ScopedEnvVarW() {
        if (had_prev) {
            ::SetEnvironmentVariableW(name.c_str(), prev_val.c_str());
        } else {
            ::SetEnvironmentVariableW(name.c_str(), nullptr);
        }
    }
};

struct DirSnapshot {
    uint64_t fnv1a_hash = 0;
    std::vector<std::string> entries;
};

DirSnapshot HashRegularTree(const fs::path& root) {
    DirSnapshot snap{};
    uint64_t h = 14695981039346656037ull;
    auto feed = [&](const void* data, size_t len) {
        const auto* p = static_cast<const uint8_t*>(data);
        for (size_t i = 0; i < len; ++i) {
            h ^= p[i];
            h *= 1099511628211ull;
        }
    };

    std::vector<fs::path> rel_paths;
    std::error_code ec;
    for (const auto& entry : fs::recursive_directory_iterator(
             root, fs::directory_options::skip_permission_denied, ec)) {
        // Do not recurse through directory junctions/symlinks when hashing base contents.
        const DWORD attrs = ::GetFileAttributesW(entry.path().c_str());
        if (attrs != INVALID_FILE_ATTRIBUTES && (attrs & FILE_ATTRIBUTE_REPARSE_POINT) != 0) {
            continue;
        }
        rel_paths.push_back(fs::relative(entry.path(), root, ec));
    }
    std::sort(rel_paths.begin(), rel_paths.end());

    for (const auto& rel : rel_paths) {
        const fs::path full = root / rel;
        const std::string rel_s = rel.generic_string();
        if (fs::is_directory(full, ec)) {
            const std::string tag = "D:" + rel_s;
            snap.entries.push_back(tag);
            feed(tag.data(), tag.size());
        } else if (fs::is_regular_file(full, ec)) {
            const std::string bytes = ReadTextFile(full);
            const std::string tag = "F:" + rel_s + ":" + std::to_string(bytes.size());
            snap.entries.push_back(tag);
            feed(tag.data(), tag.size());
            feed(bytes.data(), bytes.size());
        }
    }
    snap.fnv1a_hash = h;
    return snap;
}

bool CreateDirectoryJunctionW(const fs::path& link_path, const fs::path& target_path) {
    std::wstring cmd = L"cmd.exe /c mklink /J \"" + link_path.wstring() + L"\" \"" +
                       target_path.wstring() + L"\" >nul 2>&1";
    STARTUPINFOW si{};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};
    if (!::CreateProcessW(nullptr, cmd.data(), nullptr, nullptr, FALSE,
                          CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
        return false;
    }
    ::WaitForSingleObject(pi.hProcess, 10000);
    DWORD rc = 1;
    ::GetExitCodeProcess(pi.hProcess, &rc);
    ::CloseHandle(pi.hThread);
    ::CloseHandle(pi.hProcess);
    return rc == 0;
}

void RemoveJunctionIfPresent(const fs::path& link_path) {
    const DWORD attrs = ::GetFileAttributesW(link_path.c_str());
    if (attrs != INVALID_FILE_ATTRIBUTES && (attrs & FILE_ATTRIBUTE_REPARSE_POINT) != 0) {
        ::RemoveDirectoryW(link_path.c_str());
    }
}

std::unordered_map<std::wstring, std::wstring> ParseUnicodeEnvBlock(const std::vector<wchar_t>& block) {
    std::unordered_map<std::wstring, std::wstring> out;
    const wchar_t* cur = block.data();
    while (cur && *cur != L'\0') {
        std::wstring entry(cur);
        cur += entry.size() + 1;
        const size_t eq = entry.find(L'=', entry.front() == L'=' ? 1 : 0);
        if (eq == std::wstring::npos) {
            continue;
        }
        std::wstring key = entry.substr(0, eq);
        for (wchar_t& c : key) {
            if (c >= L'a' && c <= L'z') c = static_cast<wchar_t>(c - L'a' + L'A');
        }
        out[key] = entry.substr(eq + 1);
    }
    return out;
}

// ===========================================================================
// Test 1: Unified DLL Routing Table (XGamingRuntimeThunks + 5 New Shims + mfplat)
// ===========================================================================
void TestUnifiedDllRouting() {
    using namespace openscarlett;

    // 1A. ClassifyImportDll checks
    OS_REQUIRE(ClassifyImportDll("mfplat_xs.dll") == DllCategory::ConsoleExclusive);
    OS_REQUIRE(ClassifyImportDll("advapi32legacy.dll") == DllCategory::ConsoleExclusive);
    OS_REQUIRE(ClassifyImportDll("KernelTraceControl.dll") == DllCategory::ConsoleExclusive);
    OS_REQUIRE(ClassifyImportDll("hix_xs.dll") == DllCategory::ConsoleExclusive);
    OS_REQUIRE(ClassifyImportDll("xbtp.dll") == DllCategory::ConsoleExclusive);
    OS_REQUIRE(ClassifyImportDll("mfplat.dll") == DllCategory::WindowsNative);
    OS_REQUIRE(ClassifyImportDll("XGamingRuntimeThunks.dll") == DllCategory::GdkRuntime);

    // 1B. Built-in rule counts (21 core + 5 extended = 26 total)
    DllRoutingTable table;
    OS_REQUIRE(table.ListRules().size() == 21u);
    OS_REQUIRE(table.ListAllRules().size() == 26u);

    const char* kNewShims[] = {
        "mfplat_xs.dll",
        "advapi32legacy.dll",
        "KernelTraceControl.dll",
        "hix_xs.dll",
        "xbtp.dll",
    };

    const fs::path root = (ResolveScratchRoot() / "routing_parity").make_preferred();
    std::error_code ec;
    fs::remove_all(root, ec);
    const fs::path shim_dir = root / "shims";
    const fs::path guest_empty = root / "guest_empty";
    const fs::path guest_with_thunks = root / "guest_with_thunks";
    fs::create_directories(guest_empty, ec);
    WriteTextFile(shim_dir / "xgameruntime.dll", "SHIM_XGR");
    for (const char* dll : kNewShims) {
        WriteTextFile(shim_dir / dll, "SHIM_NEW");
    }
    WriteTextFile(guest_with_thunks / "XGamingRuntimeThunks.dll", "GUEST_THUNKS");
    WriteTextFile(guest_with_thunks / "hix_xs.dll", "GUEST_HIX");

    // Verify all 5 new diagnostic/media shims resolve to Shim
    for (const char* dll : kNewShims) {
        const DllRouteRule* r = table.FindRule(dll);
        OS_REQUIRE(r != nullptr);
        OS_REQUIRE(r->policy == DllRoutePolicy::Shim);
        auto d = table.ResolveRoute(dll, shim_dir.wstring(), guest_empty.wstring());
        OS_REQUIRE(d.policy == DllRoutePolicy::Shim);
        OS_REQUIRE(d.canonical_name == dll);
        OS_REQUIRE(d.resolved_path == (shim_dir / dll).wstring());
    }

    // 1C. XGamingRuntimeThunks.dll -> xgameruntime.dll alias routing (when not shipped in guest_dir)
    {
        const DllRouteRule* r = table.FindRule("XGamingRuntimeThunks.dll");
        OS_REQUIRE(r != nullptr);
        OS_REQUIRE(r->canonical_name == "xgameruntime.dll");
        OS_REQUIRE(r->policy == DllRoutePolicy::Shim);

        auto d_alias = table.ResolveRoute("XGamingRuntimeThunks.dll",
                                          shim_dir.wstring(),
                                          guest_empty.wstring());
        OS_REQUIRE(d_alias.policy == DllRoutePolicy::Shim);
        OS_REQUIRE(d_alias.aliased);
        OS_REQUIRE(!d_alias.from_override);
        OS_REQUIRE(d_alias.canonical_name == "xgameruntime.dll");
        OS_REQUIRE(d_alias.resolved_path == (shim_dir / "xgameruntime.dll").wstring());

        // When guest ships its own XGamingRuntimeThunks.dll and no override is active, keep NativeGuestDll
        auto d_guest = table.ResolveRoute("XGamingRuntimeThunks.dll",
                                          shim_dir.wstring(),
                                          guest_with_thunks.wstring());
        OS_REQUIRE(d_guest.policy == DllRoutePolicy::NativeGuestDll);
        OS_REQUIRE(!d_guest.aliased);
        OS_REQUIRE(d_guest.resolved_path == (guest_with_thunks / "XGamingRuntimeThunks.dll").wstring());
    }

    // 1D. mfplat.dll safety: desktop Win32 apps get WindowsNative; Xbox-imported gets mfplat_xs.dll
    {
        auto d_desktop = table.ResolveRoute("mfplat.dll", shim_dir.wstring(), guest_empty.wstring(), false);
        OS_REQUIRE(d_desktop.policy == DllRoutePolicy::Windows);
        OS_REQUIRE(!d_desktop.aliased);
        OS_REQUIRE(d_desktop.resolved_path.empty());

        auto d_xbox = table.ResolveRoute("mfplat.dll", shim_dir.wstring(), guest_empty.wstring(), true);
        OS_REQUIRE(d_xbox.policy == DllRoutePolicy::Shim);
        OS_REQUIRE(d_xbox.aliased);
        OS_REQUIRE(d_xbox.canonical_name == "mfplat_xs.dll");
        OS_REQUIRE(d_xbox.resolved_path == (shim_dir / "mfplat_xs.dll").wstring());
    }

    // 1E. OPENSCARLETT_DLL_ROUTING overrides for XGamingRuntimeThunks, mfplat, and new shims
    {
        ScopedEnvVarW guard_route(L"OPENSCARLETT_DLL_ROUTING");
        OS_REQUIRE(::SetEnvironmentVariableA(
                       "OPENSCARLETT_DLL_ROUTING",
                       "XGamingRuntimeThunks.dll=windows;"
                       "mfplat.dll=mfplat_xs.dll;"
                       "xbtp.dll=windows;"
                       "hix_xs.dll=guest") != 0);
        DllRoutingTable ov = DllRoutingTable::CreateWithEnvOverrides();

        auto o_thunks = ov.ResolveRoute("XGamingRuntimeThunks.dll", shim_dir.wstring(), guest_empty.wstring());
        OS_REQUIRE(o_thunks.policy == DllRoutePolicy::Windows);
        OS_REQUIRE(o_thunks.from_override);
        OS_REQUIRE(!o_thunks.aliased);

        auto o_mf = ov.ResolveRoute("mfplat.dll", shim_dir.wstring(), guest_empty.wstring(), false);
        OS_REQUIRE(o_mf.policy == DllRoutePolicy::Shim);
        OS_REQUIRE(o_mf.aliased);
        OS_REQUIRE(o_mf.from_override);
        OS_REQUIRE(o_mf.canonical_name == "mfplat_xs.dll");
        OS_REQUIRE(o_mf.resolved_path == (shim_dir / "mfplat_xs.dll").wstring());

        auto o_xbtp = ov.ResolveRoute("xbtp.dll", shim_dir.wstring(), guest_empty.wstring());
        OS_REQUIRE(o_xbtp.policy == DllRoutePolicy::Windows);
        OS_REQUIRE(o_xbtp.from_override);

        auto o_hix = ov.ResolveRoute("hix_xs.dll", shim_dir.wstring(), guest_with_thunks.wstring());
        OS_REQUIRE(o_hix.policy == DllRoutePolicy::NativeGuestDll);
        OS_REQUIRE(o_hix.from_override);
        OS_REQUIRE(o_hix.resolved_path == (guest_with_thunks / "hix_xs.dll").wstring());

        // Verify explicit mfplat.dll=windows overrides even xbox_import_context=true
        OS_REQUIRE(::SetEnvironmentVariableA(
                       "OPENSCARLETT_DLL_ROUTING",
                       "mfplat.dll=windows;XGamingRuntimeThunks.dll=xgameruntime.dll") != 0);
        DllRoutingTable ov2 = DllRoutingTable::CreateWithEnvOverrides();

        auto o_mf_win = ov2.ResolveRoute("mfplat.dll", shim_dir.wstring(), guest_empty.wstring(), true);
        OS_REQUIRE(o_mf_win.policy == DllRoutePolicy::Windows);
        OS_REQUIRE(o_mf_win.from_override);

        auto o_thunks_force = ov2.ResolveRoute("XGamingRuntimeThunks.dll",
                                               shim_dir.wstring(),
                                               guest_with_thunks.wstring());
        OS_REQUIRE(o_thunks_force.policy == DllRoutePolicy::Shim);
        OS_REQUIRE(o_thunks_force.aliased);
        OS_REQUIRE(o_thunks_force.from_override);
        OS_REQUIRE(o_thunks_force.canonical_name == "xgameruntime.dll");
    }

    std::printf("[PASS] Unified DLL routing table (XGamingRuntimeThunks alias + 5 diagnostic/media shims + mfplat + env overrides)\n");
}

// ===========================================================================
// Test 2: Hardened CoW VFS (Nested G:\ Sub-Mounts, Junctions, Normalization, Zero C:\)
// ===========================================================================
void TestHardenedCowVfs() {
    using namespace openscarlett;

    const fs::path root = (ResolveScratchRoot() / "vfs_hardening").make_preferred();
    std::error_code ec;
    // Remove any leftover junctions from interrupted prior runs before remove_all.
    RemoveJunctionIfPresent(root / "G_base" / "local_link");
    RemoveJunctionIfPresent(root / "G_base" / "escape_link");
    RemoveJunctionIfPresent(root / "G_overlay" / "sneaky_link");
    fs::remove_all(root, ec);

    const fs::path g_base = root / "G_base";
    const fs::path g_dlc1 = root / "G_dlc_pack1";
    const fs::path g_dlc1_hd = root / "G_dlc_pack1_hd";
    const fs::path g_ovl = root / "G_overlay";
    const fs::path t_dir = root / "T";
    const fs::path s_dir = root / "S_saves";
    const fs::path outside = root / "outside_secret";

    WriteTextFile(g_base / "DLC" / "base_file.txt", "BASE_DLC_FILE");
    WriteTextFile(g_base / "real_sub" / "inside.txt", "INTRA_JUNCTION_CONTENT");
    WriteTextFile(g_dlc1 / "data" / "level.pak", "DLC_PACK1_ORIG");
    WriteTextFile(g_dlc1_hd / "sky.dds", "DLC_HD_SKY_ORIG");
    WriteTextFile(outside / "secret.txt", "OUTSIDE_SECRET_DO_NOT_READ");
    fs::create_directories(g_ovl, ec);

    const DirSnapshot base_before = HashRegularTree(g_base);
    const DirSnapshot dlc1_before = HashRegularTree(g_dlc1);
    const DirSnapshot dlc1_hd_before = HashRegularTree(g_dlc1_hd);
    const DirSnapshot outside_before = HashRegularTree(outside);

    // Create real NTFS directory junctions (no admin privileges required on Windows)
    const bool j1_ok = CreateDirectoryJunctionW(g_base / "local_link", g_base / "real_sub");
    const bool j2_ok = CreateDirectoryJunctionW(g_base / "escape_link", outside);
    const bool j3_ok = CreateDirectoryJunctionW(g_ovl / "sneaky_link", g_base);
    OS_REQUIRE(j1_ok && j2_ok && j3_ok);

    VfsMountConfig cfg{};
    cfg.g_root = g_base.wstring();
    cfg.t_root = t_dir.wstring();
    cfg.s_root = s_dir.wstring();
    cfg.g_overlay_root = g_ovl.wstring();
    // Only forbid system-drive writes on this scratch mount when the scratch root itself is off C:\;
    // section 2D explicitly verifies forbid_system_drive_writes=true against C:\ regardless of host drive.
    cfg.forbid_system_drive_writes = !IsPathOnSystemDriveW(root.wstring());

    VfsMounts vfs(cfg);
    OS_REQUIRE(vfs.AddGameSubMount(L"DLC/Pack1", g_dlc1.wstring()));
    OS_REQUIRE(vfs.AddGameSubMount(L"G:\\DLC\\Pack1\\HD", g_dlc1_hd.wstring()));
    OS_REQUIRE(vfs.GetGameSubMounts().size() == 2u);
    OS_REQUIRE(!vfs.AddGameSubMount(L"../escape", g_dlc1.wstring()));

    std::wstring out;

    // 2A. Nested sub-mount longest-prefix lookup + relative path normalization (.. / . / / / \\?\)
    OS_REQUIRE(vfs.TranslateForAccessW(L"G:\\DLC/Pack1/./maps/../data/level.pak",
                                       VfsAccessMode::ReadOnly, out) == VfsTranslateStatus::Translated);
    OS_REQUIRE(out == (g_dlc1 / L"data" / L"level.pak").wstring());

    OS_REQUIRE(vfs.TranslateForAccessW(L"\\\\?\\GAME:\\DLC\\Pack1\\HD\\textures\\..\\sky.dds",
                                       VfsAccessMode::ReadOnly, out) == VfsTranslateStatus::Translated);
    OS_REQUIRE(out == L"\\\\?\\" + (g_dlc1_hd / L"sky.dds").wstring());

    // '..' collapsing escapes sub-mount back into G_base cleanly without escaping G:\ root
    OS_REQUIRE(vfs.TranslateForAccessW(L"G:\\DLC\\Pack1\\..\\base_file.txt",
                                       VfsAccessMode::ReadOnly, out) == VfsTranslateStatus::Translated);
    OS_REQUIRE(out == (g_base / L"DLC" / L"base_file.txt").wstring());

    // Escaping above G:\ root is rejected
    OS_REQUIRE(vfs.TranslateForAccessW(L"G:\\DLC\\..\\..\\escape.txt",
                                       VfsAccessMode::ReadOnly, out) == VfsTranslateStatus::RejectedTraversal);

    // 2B. CoW write & delete inside nested sub-mounts redirect to G_overlay with ZERO writes to sub-mount base!
    OS_REQUIRE(vfs.TranslateForAccessW(L"G:\\DLC\\Pack1\\data\\level.pak",
                                       VfsAccessMode::WriteModify, out) == VfsTranslateStatus::Translated);
    OS_REQUIRE(out == (g_ovl / L"DLC" / L"Pack1" / L"data" / L"level.pak").wstring());
    OS_REQUIRE(ReadTextFile(out) == "DLC_PACK1_ORIG");
    WriteTextFile(out, "DLC_PACK1_MODIFIED_IN_OVERLAY");

    OS_REQUIRE(vfs.TranslateForAccessW(L"GAME:/DLC/Pack1/data/level.pak",
                                       VfsAccessMode::ReadOnly, out) == VfsTranslateStatus::Translated);
    OS_REQUIRE(out == (g_ovl / L"DLC" / L"Pack1" / L"data" / L"level.pak").wstring());
    OS_REQUIRE(ReadTextFile(out) == "DLC_PACK1_MODIFIED_IN_OVERLAY");

    uint32_t win_err = 0;
    OS_REQUIRE(vfs.DeleteVirtualFileW(L"G:\\DLC\\Pack1\\HD\\sky.dds", win_err));
    bool was_wo = false;
    OS_REQUIRE(vfs.TranslateForAccessW(L"GAME:\\DLC\\Pack1\\HD\\sky.dds",
                                       VfsAccessMode::ReadOnly, out, &was_wo) ==
               VfsTranslateStatus::DeletedWhiteout);
    OS_REQUIRE(was_wo);

    // 2C. NTFS junction hardening: intra-mount junction allowed (CoW on write); escaping junctions BLOCKED!
    OS_REQUIRE(vfs.TranslateForAccessW(L"G:\\local_link\\inside.txt",
                                       VfsAccessMode::ReadOnly, out) == VfsTranslateStatus::Translated);
    OS_REQUIRE(ReadTextFile(out) == "INTRA_JUNCTION_CONTENT");

    OS_REQUIRE(vfs.TranslateForAccessW(L"G:\\local_link\\inside.txt",
                                       VfsAccessMode::WriteModify, out) == VfsTranslateStatus::Translated);
    OS_REQUIRE(out == (g_ovl / L"local_link" / L"inside.txt").wstring());
    WriteTextFile(out, "INTRA_JUNCTION_OVERLAY_V2");

    OS_REQUIRE(vfs.TranslateForAccessW(L"G:\\escape_link\\secret.txt",
                                       VfsAccessMode::ReadOnly, out) == VfsTranslateStatus::RejectedTraversal);
    OS_REQUIRE(vfs.TranslateForAccessW(L"G:\\escape_link\\secret.txt",
                                       VfsAccessMode::WriteModify, out) == VfsTranslateStatus::RejectedTraversal);
    OS_REQUIRE(vfs.TranslateForAccessW(L"G:\\sneaky_link\\pwn.txt",
                                       VfsAccessMode::WriteCreate, out) == VfsTranslateStatus::RejectedTraversal);

    // 2D. S:\ -> OPENSCARLETT_SAVE_ROOT & strict zero-C:\ write protection
    {
        ScopedEnvVarW g_s(L"OPENSCARLETT_VFS_S");
        ScopedEnvVarW g_save(L"OPENSCARLETT_SAVE_ROOT");
        ScopedEnvVarW g_ovl_env(L"OPENSCARLETT_VFS_G_OVERLAY");
        ScopedEnvVarW g_sub_env(L"OPENSCARLETT_VFS_G_SUBMOUNTS");

        const fs::path custom_save_root = root / "explicit_save_root";
        ::SetEnvironmentVariableW(L"OPENSCARLETT_VFS_S", nullptr);
        ::SetEnvironmentVariableW(L"OPENSCARLETT_SAVE_ROOT", custom_save_root.c_str());
        ::SetEnvironmentVariableW(L"OPENSCARLETT_VFS_G_OVERLAY", nullptr);
        const std::wstring sub_spec = L"DLC\\Pack1=" + g_dlc1.wstring();
        ::SetEnvironmentVariableW(L"OPENSCARLETT_VFS_G_SUBMOUNTS", sub_spec.c_str());

        const VfsMountConfig def_cfg = VfsMounts::BuildDefaultConfig(g_base.wstring(), (root / "def_vfs").wstring());
        OS_REQUIRE(def_cfg.s_root == custom_save_root.wstring());
        OS_REQUIRE(def_cfg.g_sub_mounts.size() == 1u);
        OS_REQUIRE(def_cfg.g_sub_mounts[0].virtual_prefix == L"DLC\\Pack1");
        if (!IsPathOnSystemDriveW(root.wstring())) {
            OS_REQUIRE(!IsPathOnSystemDriveW(def_cfg.s_root));
            OS_REQUIRE(!IsPathOnSystemDriveW(def_cfg.g_overlay_root));
            OS_REQUIRE(!IsPathOnSystemDriveW(def_cfg.t_root));

            // With OPENSCARLETT_FORBID_SYSTEM_DRIVE_WRITES=1, poisoning env vars with C:\ paths is rejected!
            ScopedEnvVarW g_forbid(L"OPENSCARLETT_FORBID_SYSTEM_DRIVE_WRITES");
            ::SetEnvironmentVariableW(L"OPENSCARLETT_FORBID_SYSTEM_DRIVE_WRITES", L"1");
            ::SetEnvironmentVariableW(L"OPENSCARLETT_SAVE_ROOT", L"C:\\OpenScarlettForbiddenSaves");
            ::SetEnvironmentVariableW(L"OPENSCARLETT_VFS_G_OVERLAY", L"C:\\OpenScarlettForbiddenOvl");
            const VfsMountConfig safe_cfg =
                VfsMounts::BuildDefaultConfig(g_base.wstring(), (root / "def_vfs").wstring());
            OS_REQUIRE(safe_cfg.forbid_system_drive_writes);
            OS_REQUIRE(!IsPathOnSystemDriveW(safe_cfg.s_root));
            OS_REQUIRE(!IsPathOnSystemDriveW(safe_cfg.g_overlay_root));
            OS_REQUIRE(safe_cfg.s_root == (root / "def_vfs" / "S").wstring());
            OS_REQUIRE(safe_cfg.g_overlay_root == (root / "def_vfs" / "G_overlay").wstring());
        }

        // Direct VfsMounts with forbid_system_drive_writes=true blocks any C:\ write without touching C:\!
        VfsMountConfig c_bad{};
        c_bad.g_root = g_base.wstring();
        c_bad.t_root = L"C:\\OpenScarlettForbiddenT";
        c_bad.s_root = L"C:\\OpenScarlettForbiddenS";
        c_bad.g_overlay_root = L"C:\\OpenScarlettForbiddenOvl";
        c_bad.forbid_system_drive_writes = true;
        VfsMounts blocked_vfs(c_bad);
        OS_REQUIRE(!blocked_vfs.EnsureWritableMounts());
        OS_REQUIRE(blocked_vfs.TranslateForAccessW(L"S:\\slot0.sav", VfsAccessMode::WriteCreate, out, nullptr, true) ==
                   VfsTranslateStatus::ReadOnlyViolation);
        OS_REQUIRE(blocked_vfs.TranslateForAccessW(L"G:\\new.txt", VfsAccessMode::WriteCreate, out, nullptr, true) ==
                   VfsTranslateStatus::ReadOnlyViolation);
        OS_REQUIRE(!fs::exists(L"C:\\OpenScarlettForbiddenS", ec));
        OS_REQUIRE(!fs::exists(L"C:\\OpenScarlettForbiddenOvl", ec));
    }

    // Prove ZERO mutations to G_base, G_dlc_pack1, G_dlc_pack1_hd, and outside_secret!
    OS_REQUIRE(HashRegularTree(g_base).fnv1a_hash == base_before.fnv1a_hash);
    OS_REQUIRE(HashRegularTree(g_dlc1).fnv1a_hash == dlc1_before.fnv1a_hash);
    OS_REQUIRE(HashRegularTree(g_dlc1_hd).fnv1a_hash == dlc1_hd_before.fnv1a_hash);
    OS_REQUIRE(HashRegularTree(outside).fnv1a_hash == outside_before.fnv1a_hash);

    // Clean up junctions cleanly
    RemoveJunctionIfPresent(g_base / "local_link");
    RemoveJunctionIfPresent(g_base / "escape_link");
    RemoveJunctionIfPresent(g_ovl / "sneaky_link");

    std::printf("[PASS] Hardened CoW VFS (nested G:\\ sub-mounts, normalization, NTFS junction containment, zero base & C:\\ writes)\n");
}

// ===========================================================================
// Test 3: Per-PID Telemetry Formatting & Custom Environment Block Merging
// ===========================================================================
void TestTelemetryFormattingAndEnvMerge() {
    using namespace openscarlett;

    // 3A. Per-PID child telemetry path formatting
    OS_REQUIRE(FormatChildTelemetryPathW(L"E:\\tmp\\game_telemetry.json", 1234u) ==
               L"E:\\tmp\\game_pid1234_telemetry.json");
    OS_REQUIRE(FormatChildTelemetryPathW(L"E:\\tmp\\launcher.json", 5678u) ==
               L"E:\\tmp\\launcher_pid5678_telemetry.json");
    OS_REQUIRE(FormatChildTelemetryPathW(L"E:\\tmp\\launcher_pid5678_telemetry.json", 9012u) ==
               L"E:\\tmp\\launcher_pid9012_telemetry.json");
    OS_REQUIRE(FormatChildTelemetryPathUtf8("E:\\tmp\\run_telemetry.json", 42u) ==
               "E:\\tmp\\run_pid42_telemetry.json");
    OS_REQUIRE(FormatChildTelemetryPathW(L"", 42u).empty());

    // 3B. Custom ANSI and Unicode lpEnvironment merging preserves caller vars AND OPENSCARLETT_* vars
    ScopedEnvVarW g_route(L"OPENSCARLETT_DLL_ROUTING");
    ScopedEnvVarW g_save(L"OPENSCARLETT_SAVE_ROOT");
    ::SetEnvironmentVariableW(L"OPENSCARLETT_DLL_ROUTING", L"CustomA.dll=winrt_xs.dll");
    ::SetEnvironmentVariableW(L"OPENSCARLETT_SAVE_ROOT", L"E:\\OpenScarlett\\.tmp\\env_merge_saves");

    const char ansi_env[] = "CUSTOM_ANSI_KEY=ansi_val_77\0PATH=E:\\UserBin\0";
    const std::vector<wchar_t> merged_a = MergeOpenScarlettEnvironmentBlockW(
        ansi_env,
        false,
        L"E:\\ShimBin",
        L"E:\\ShimBin\\openscarlett_hook.dll",
        L"E:\\tmp\\base_telemetry.json",
        true);
    const auto map_a = ParseUnicodeEnvBlock(merged_a);
    OS_REQUIRE(map_a.at(L"CUSTOM_ANSI_KEY") == L"ansi_val_77");
    OS_REQUIRE(map_a.at(L"OPENSCARLETT_SHIM_DIR") == L"E:\\ShimBin");
    OS_REQUIRE(map_a.at(L"OPENSCARLETT_HOOK_DLL") == L"E:\\ShimBin\\openscarlett_hook.dll");
    OS_REQUIRE(map_a.at(L"OPENSCARLETT_DLL_ROUTING") == L"CustomA.dll=winrt_xs.dll");
    OS_REQUIRE(map_a.at(L"OPENSCARLETT_SAVE_ROOT") == L"E:\\OpenScarlett\\.tmp\\env_merge_saves");
    OS_REQUIRE(map_a.at(L"OPENSCARLETT_TELEMETRY_BASE") == L"E:\\tmp\\base_telemetry.json");
    OS_REQUIRE(map_a.at(L"OPENSCARLETT_CHILD_TELEMETRY_PER_PID") == L"1");
    OS_REQUIRE(map_a.at(L"PATH").rfind(L"E:\\ShimBin;", 0) == 0);

    const wchar_t wide_env[] = L"CUSTOM_WIDE_KEY=wide_val_88\0OPENSCARLETT_CUSTOM_KEEP=caller_wins\0";
    const std::vector<wchar_t> merged_w = MergeOpenScarlettEnvironmentBlockW(
        wide_env,
        true,
        L"E:\\ShimBin",
        L"E:\\ShimBin\\openscarlett_hook.dll",
        L"E:\\tmp\\base_telemetry.json",
        true);
    const auto map_w = ParseUnicodeEnvBlock(merged_w);
    OS_REQUIRE(map_w.at(L"CUSTOM_WIDE_KEY") == L"wide_val_88");
    OS_REQUIRE(map_w.at(L"OPENSCARLETT_CUSTOM_KEEP") == L"caller_wins");
    OS_REQUIRE(map_w.at(L"OPENSCARLETT_HOOK_DLL") == L"E:\\ShimBin\\openscarlett_hook.dll");
    OS_REQUIRE(map_w.at(L"OPENSCARLETT_CHILD_TELEMETRY_PER_PID") == L"1");

    std::printf("[PASS] Per-PID telemetry path formatting & custom ANSI/Unicode lpEnvironment merging verified\n");
}

// ===========================================================================
// Test 4: LIVE 2-Process Parent -> Child Hook Propagation (--parent / --child-w / --child-a)
// ===========================================================================
int RunChildMode(bool is_ansi_child) {
    auto fail = [is_ansi_child](const char* msg, DWORD err = 0) -> int {
        std::fprintf(stderr, "[child-%s] FAIL: %s (err=%lu)\n",
                     is_ansi_child ? "a" : "w", msg, static_cast<unsigned long>(err));
        return 1;
    };

    // 1. Verify openscarlett_hook.dll was APC-injected into this child!
    if (::GetModuleHandleW(L"openscarlett_hook.dll") == nullptr) {
        return fail("openscarlett_hook.dll is NOT loaded in child process");
    }

    // 2. Verify custom caller environment variable survived merging
    if (is_ansi_child) {
        if (ReadEnvW(L"CUSTOM_ANSI_MARKER") != L"from_parent_a") {
            return fail("CUSTOM_ANSI_MARKER missing or corrupted in CreateProcessA child");
        }
    } else {
        if (ReadEnvW(L"CUSTOM_UNICODE_MARKER") != L"from_parent_w") {
            return fail("CUSTOM_UNICODE_MARKER missing or corrupted in CreateProcessW child");
        }
    }

    // 3. Verify OPENSCARLETT_* env vars propagated intact
    if (ReadEnvW(L"OPENSCARLETT_SHIM_DIR").empty()) return fail("OPENSCARLETT_SHIM_DIR missing");
    if (ReadEnvW(L"OPENSCARLETT_HOOK_DLL").empty()) return fail("OPENSCARLETT_HOOK_DLL missing");
    if (ReadEnvW(L"OPENSCARLETT_SAVE_ROOT").empty()) return fail("OPENSCARLETT_SAVE_ROOT missing");
    if (ReadEnvW(L"OPENSCARLETT_VFS_G").empty()) return fail("OPENSCARLETT_VFS_G missing");
    if (ReadEnvW(L"OPENSCARLETT_VFS_G_OVERLAY").empty()) return fail("OPENSCARLETT_VFS_G_OVERLAY missing");
    if (ReadEnvW(L"OPENSCARLETT_DLL_ROUTING") != L"CustomTestAlias.dll=winrt_xs.dll") {
        return fail("OPENSCARLETT_DLL_ROUTING mismatch in child");
    }

    // 4. Verify non-clobbering per-PID child telemetry path (<stem>_pid<N>_telemetry.json)
    const DWORD own_pid = ::GetCurrentProcessId();
    const std::wstring expected_suffix = L"_pid" + std::to_wstring(own_pid) + L"_telemetry.json";
    const std::wstring child_tel = ReadEnvW(L"OPENSCARLETT_TELEMETRY_PATH");
    if (child_tel.size() < expected_suffix.size() ||
        child_tel.compare(child_tel.size() - expected_suffix.size(), expected_suffix.size(), expected_suffix) != 0) {
        return fail("OPENSCARLETT_TELEMETRY_PATH does not match expected per-PID format");
    }

    // 5. Exercise live DLL routing hook + GetProcAddress telemetry inside the child!
    HMODULE h_alias = ::LoadLibraryA("CustomTestAlias.dll");
    if (!h_alias) {
        return fail("LoadLibraryA(CustomTestAlias.dll -> winrt_xs.dll) failed in child", ::GetLastError());
    }
    using PfnRoInit = int32_t(__cdecl*)(uint32_t);
    auto fn_ro = reinterpret_cast<PfnRoInit>(::GetProcAddress(h_alias, "RoInitialize"));
    if (!fn_ro || fn_ro(1) != 0) {
        ::FreeLibrary(h_alias);
        return fail("GetProcAddress(RoInitialize) failed in child", ::GetLastError());
    }
    ::FreeLibrary(h_alias);

    // 6. Exercise live VFS hook (S:\ save write -> OPENSCARLETT_SAVE_ROOT) inside the child!
    const wchar_t* save_vpath = is_ansi_child ? L"S:\\child_a.sav" : L"S:\\child_w.sav";
    HANDLE h_sav = ::CreateFileW(save_vpath, GENERIC_WRITE, 0, nullptr,
                                 CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h_sav == INVALID_HANDLE_VALUE) {
        return fail("CreateFileW(S:\\child_*.sav) failed in child", ::GetLastError());
    }
    const char* payload = is_ansi_child ? "CHILD_A_SAVE_OK" : "CHILD_W_SAVE_OK";
    DWORD written = 0;
    ::WriteFile(h_sav, payload, static_cast<DWORD>(std::strlen(payload)), &written, nullptr);
    ::CloseHandle(h_sav);

    return 0;
}

int RunParentMode(const fs::path& pid_report_file) {
    auto fail = [](const char* msg, DWORD err = 0) -> int {
        std::fprintf(stderr, "[parent] FAIL: %s (err=%lu)\n", msg, static_cast<unsigned long>(err));
        return 1;
    };

    if (::GetModuleHandleW(L"openscarlett_hook.dll") == nullptr) {
        return fail("openscarlett_hook.dll not loaded in parent process");
    }

    wchar_t self_buf[MAX_PATH]{};
    const DWORD self_len = ::GetModuleFileNameW(nullptr, self_buf, MAX_PATH);
    if (self_len == 0 || self_len >= MAX_PATH) {
        return fail("GetModuleFileNameW failed in parent");
    }
    const std::wstring self_w(self_buf, self_len);
    const std::string self_a = openscarlett::WideToUtf8(self_w);
    const std::wstring sys_root_w = ReadEnvW(L"SystemRoot");
    const std::string sys_root_a = openscarlett::WideToUtf8(sys_root_w);

    // 1. Spawn Child W via CreateProcessW with custom Unicode lpEnvironment (normal non-suspended launch)
    std::vector<wchar_t> custom_env_w;
    auto push_w = [&](const std::wstring& kv) {
        custom_env_w.insert(custom_env_w.end(), kv.begin(), kv.end());
        custom_env_w.push_back(L'\0');
    };
    push_w(L"CUSTOM_UNICODE_MARKER=from_parent_w");
    if (!sys_root_w.empty()) {
        push_w(L"SystemRoot=" + sys_root_w);
    }
    custom_env_w.push_back(L'\0');

    std::wstring cmd_w = L"\"" + self_w + L"\" --child-w";
    STARTUPINFOW si_w{};
    si_w.cb = sizeof(si_w);
    PROCESS_INFORMATION pi_w{};
    if (!::CreateProcessW(self_w.c_str(),
                          cmd_w.data(),
                          nullptr,
                          nullptr,
                          FALSE,
                          CREATE_UNICODE_ENVIRONMENT,
                          custom_env_w.data(),
                          nullptr,
                          &si_w,
                          &pi_w)) {
        return fail("CreateProcessW(--child-w) failed", ::GetLastError());
    }
    if (::WaitForSingleObject(pi_w.hProcess, 30000) != WAIT_OBJECT_0) {
        ::TerminateProcess(pi_w.hProcess, 1);
        ::CloseHandle(pi_w.hThread);
        ::CloseHandle(pi_w.hProcess);
        return fail("Child W timed out");
    }
    DWORD exit_w = 999;
    ::GetExitCodeProcess(pi_w.hProcess, &exit_w);
    const DWORD pid_w = pi_w.dwProcessId;
    ::CloseHandle(pi_w.hThread);
    ::CloseHandle(pi_w.hProcess);
    if (exit_w != 0) {
        return fail("Child W exited with non-zero code", exit_w);
    }

    // 2. Spawn Child A via CreateProcessA with custom ANSI lpEnvironment AND CREATE_SUSPENDED
    std::vector<char> custom_env_a;
    auto push_a = [&](const std::string& kv) {
        custom_env_a.insert(custom_env_a.end(), kv.begin(), kv.end());
        custom_env_a.push_back('\0');
    };
    push_a("CUSTOM_ANSI_MARKER=from_parent_a");
    if (!sys_root_a.empty()) {
        push_a("SystemRoot=" + sys_root_a);
    }
    custom_env_a.push_back('\0');

    std::string cmd_a = "\"" + self_a + "\" --child-a";
    STARTUPINFOA si_a{};
    si_a.cb = sizeof(si_a);
    PROCESS_INFORMATION pi_a{};
    if (!::CreateProcessA(self_a.c_str(),
                          cmd_a.data(),
                          nullptr,
                          nullptr,
                          FALSE,
                          CREATE_SUSPENDED,
                          custom_env_a.data(),
                          nullptr,
                          &si_a,
                          &pi_a)) {
        return fail("CreateProcessA(--child-a) failed", ::GetLastError());
    }

    // Verify our hook preserved caller's CREATE_SUSPENDED flag (did NOT prematurely resume Child A!)
    if (::WaitForSingleObject(pi_a.hProcess, 50) != WAIT_TIMEOUT) {
        ::CloseHandle(pi_a.hThread);
        ::CloseHandle(pi_a.hProcess);
        return fail("Child A exited before caller called ResumeThread (CREATE_SUSPENDED not preserved!)");
    }
    const DWORD prev_suspend = ::ResumeThread(pi_a.hThread);
    if (prev_suspend != 1u) {
        ::TerminateProcess(pi_a.hProcess, 1);
        ::CloseHandle(pi_a.hThread);
        ::CloseHandle(pi_a.hProcess);
        return fail("Child A suspend count was not 1 after CreateProcessA(CREATE_SUSPENDED)", prev_suspend);
    }

    if (::WaitForSingleObject(pi_a.hProcess, 30000) != WAIT_OBJECT_0) {
        ::TerminateProcess(pi_a.hProcess, 1);
        ::CloseHandle(pi_a.hThread);
        ::CloseHandle(pi_a.hProcess);
        return fail("Child A timed out");
    }
    DWORD exit_a = 999;
    ::GetExitCodeProcess(pi_a.hProcess, &exit_a);
    const DWORD pid_a = pi_a.dwProcessId;
    ::CloseHandle(pi_a.hThread);
    ::CloseHandle(pi_a.hProcess);
    if (exit_a != 0) {
        return fail("Child A exited with non-zero code", exit_a);
    }

    // 3. Verify spawning a Windows System32 process gracefully skips injection without breaking launch!
    {
        wchar_t sys_dir[MAX_PATH]{};
        const UINT slen = ::GetSystemDirectoryW(sys_dir, MAX_PATH);
        if (slen > 0 && slen < MAX_PATH) {
            const std::wstring cmd_exe = std::wstring(sys_dir, slen) + L"\\cmd.exe";
            std::wstring sys_cmd = L"\"" + cmd_exe + L"\" /c exit 0";
            STARTUPINFOW si_sys{};
            si_sys.cb = sizeof(si_sys);
            PROCESS_INFORMATION pi_sys{};
            if (!::CreateProcessW(cmd_exe.c_str(), sys_cmd.data(), nullptr, nullptr, FALSE,
                                  CREATE_NO_WINDOW, nullptr, nullptr, &si_sys, &pi_sys)) {
                return fail("CreateProcessW(System32\\cmd.exe) failed", ::GetLastError());
            }
            ::WaitForSingleObject(pi_sys.hProcess, 15000);
            DWORD sys_rc = 999;
            ::GetExitCodeProcess(pi_sys.hProcess, &sys_rc);
            ::CloseHandle(pi_sys.hThread);
            ::CloseHandle(pi_sys.hProcess);
            if (sys_rc != 0) {
                return fail("System32\\cmd.exe exited non-zero", sys_rc);
            }
        }
    }

    // Report spawned child PIDs back to the test harness
    std::ofstream ofs(pid_report_file, std::ios::binary | std::ios::trunc);
    if (!ofs) {
        return fail("Failed writing child PID report file");
    }
    ofs << pid_w << "\n" << pid_a << "\n";
    return 0;
}

void TestLiveParentChildHookPropagation(const fs::path& self_exe) {
    using namespace openscarlett;

    const fs::path build_dir = ResolveRuntimeBinDir();
    OS_REQUIRE(fs::exists(build_dir / "openscarlett_hook.dll"));
    OS_REQUIRE(fs::exists(build_dir / "winrt_xs.dll"));

    const fs::path sandbox = (ResolveScratchRoot() / "live_child_prop").make_preferred();
    std::error_code ec;
    fs::remove_all(sandbox, ec);
    fs::create_directories(sandbox, ec);

    const fs::path pkg_dir = sandbox / "pkg";
    const fs::path ovl_dir = sandbox / "overlay";
    const fs::path t_dir = sandbox / "T";
    const fs::path s_dir = sandbox / "saves";
    const fs::path parent_tel = sandbox / "live_chain_telemetry.json";
    const fs::path pid_file = sandbox / "child_pids.txt";
    fs::create_directories(pkg_dir, ec);

    ScopedEnvVarW guard_route(L"OPENSCARLETT_DLL_ROUTING");
    OS_REQUIRE(::SetEnvironmentVariableA("OPENSCARLETT_DLL_ROUTING",
                                         "CustomTestAlias.dll=winrt_xs.dll") != 0);

    LaunchOptions opts{};
    opts.exe_path = self_exe.string();
    opts.arguments = "--parent \"" + pid_file.string() + "\"";
    opts.shim_dir = build_dir.string();
    opts.vfs_g = pkg_dir.string();
    opts.vfs_g_overlay = ovl_dir.string();
    opts.vfs_t = t_dir.string();
    opts.vfs_s = s_dir.string();
    opts.telemetry_output_path = parent_tel.string();
    opts.timeout_ms = 45000;
    opts.inherit_console = true;

    LaunchResult res{};
    Status st = LaunchWithApcHook(opts, res);
    OS_REQUIRE(st.ok());
    OS_REQUIRE(!res.timed_out);
    OS_REQUIRE(res.exit_code == 0);

    // 1. Read spawned child PIDs
    OS_REQUIRE(fs::exists(pid_file));
    std::ifstream ifs(pid_file);
    uint32_t pid_w = 0;
    uint32_t pid_a = 0;
    ifs >> pid_w >> pid_a;
    OS_REQUIRE(pid_w != 0u && pid_a != 0u && pid_w != pid_a);

    // 2. Verify parent telemetry was NOT clobbered and recorded child hook propagation
    OS_REQUIRE(fs::exists(parent_tel));
    const std::string parent_json = ReadTextFile(parent_tel);
    OS_REQUIRE(parent_json.find("CreateProcessW:child_hook_propagated") != std::string::npos);
    OS_REQUIRE(parent_json.find("CreateProcessA:child_hook_propagated") != std::string::npos);
    OS_REQUIRE(parent_json.find("CreateProcessW:child_skipped_protected") != std::string::npos);

    // 3. Verify BOTH children wrote their own non-clobbering <stem>_pid<N>_telemetry.json reports!
    const fs::path child_w_tel =
        sandbox / ("live_chain_pid" + std::to_string(pid_w) + "_telemetry.json");
    const fs::path child_a_tel =
        sandbox / ("live_chain_pid" + std::to_string(pid_a) + "_telemetry.json");
    OS_REQUIRE(fs::exists(child_w_tel));
    OS_REQUIRE(fs::exists(child_a_tel));

    const std::string child_w_json = ReadTextFile(child_w_tel);
    OS_REQUIRE(child_w_json.find("child_hook_attached") != std::string::npos);
    OS_REQUIRE(child_w_json.find("dll_alias:CustomTestAlias.dll->winrt_xs.dll") != std::string::npos);
    OS_REQUIRE(child_w_json.find("\"module\": \"winrt_xs.dll\"") != std::string::npos);
    OS_REQUIRE(child_w_json.find("\"symbol\": \"RoInitialize\"") != std::string::npos);

    const std::string child_a_json = ReadTextFile(child_a_tel);
    OS_REQUIRE(child_a_json.find("child_hook_attached") != std::string::npos);
    OS_REQUIRE(child_a_json.find("dll_alias:CustomTestAlias.dll->winrt_xs.dll") != std::string::npos);
    OS_REQUIRE(child_a_json.find("\"module\": \"winrt_xs.dll\"") != std::string::npos);
    OS_REQUIRE(child_a_json.find("\"symbol\": \"RoInitialize\"") != std::string::npos);

    // 4. Verify child S:\ saves landed cleanly in OPENSCARLETT_SAVE_ROOT
    OS_REQUIRE(fs::exists(s_dir / "child_w.sav"));
    OS_REQUIRE(ReadTextFile(s_dir / "child_w.sav") == "CHILD_W_SAVE_OK");
    OS_REQUIRE(fs::exists(s_dir / "child_a.sav"));
    OS_REQUIRE(ReadTextFile(s_dir / "child_a.sav") == "CHILD_A_SAVE_OK");

    std::printf("[PASS] LIVE 2-process parent -> child hook propagation (CreateProcessW + CreateProcessA, custom env merge, CREATE_SUSPENDED, per-PID telemetry pid=%u/%u)\n",
                pid_w, pid_a);
}

}  // namespace

int main(int argc, char** argv) {
    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "--child-w") == 0) {
            return RunChildMode(false);
        }
        if (std::strcmp(argv[i], "--child-a") == 0) {
            return RunChildMode(true);
        }
        if (std::strcmp(argv[i], "--parent") == 0 && i + 1 < argc) {
            return RunParentMode(fs::path(argv[i + 1]));
        }
    }

    TestUnifiedDllRouting();
    TestHardenedCowVfs();
    TestTelemetryFormattingAndEnvMerge();

    wchar_t mod_buf[MAX_PATH]{};
    const DWORD len = ::GetModuleFileNameW(nullptr, mod_buf, MAX_PATH);
    OS_REQUIRE(len > 0 && len < MAX_PATH);
    const fs::path self_exe(std::wstring(mod_buf, len));

    TestLiveParentChildHookPropagation(self_exe);

    std::printf("[PASS] test_loader_child_hook_parity (all DLL routing, hardened CoW VFS, and live parent->child hook propagation tests passed)\n");
    return 0;
}
