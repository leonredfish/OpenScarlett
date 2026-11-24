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
#include "openscarlett/loader/game_config.h"
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
        if (fs::exists(exe_dir / L"openscarlett.exe", ec) &&
            fs::exists(exe_dir / L"openscarlett_hook.dll", ec)) {
            return exe_dir;
        }
    }
    return fs::path(OPENSCARLETT_BINARY_DIR);
}

fs::path ResolveScratchRoot() {
    const std::wstring work_dir = openscarlett::ResolveDefaultWorkDirW(ResolveRuntimeBinDir().wstring());
    if (!work_dir.empty()) {
        return (fs::path(work_dir) / L"test_loader_vfs_config").make_preferred();
    }
    return (ResolveRuntimeBinDir() / L".tmp_loader_vfs_config").make_preferred();
}

// ---------------------------------------------------------------------------
// File & Deterministic Directory Hash Helpers (proves 100% byte-identical G:\)
// ---------------------------------------------------------------------------
std::string ReadFileBytes(const fs::path& p) {
    std::ifstream ifs(p, std::ios::binary);
    OS_REQUIRE(static_cast<bool>(ifs));
    std::ostringstream oss;
    oss << ifs.rdbuf();
    return oss.str();
}

void WriteFileBytes(const fs::path& p, const std::string& data) {
    std::error_code ec;
    fs::create_directories(p.parent_path(), ec);
    std::ofstream ofs(p, std::ios::binary | std::ios::trunc);
    OS_REQUIRE(static_cast<bool>(ofs));
    ofs.write(data.data(), static_cast<std::streamsize>(data.size()));
    OS_REQUIRE(static_cast<bool>(ofs));
}

void WriteBinaryVec(const fs::path& p, const std::vector<uint8_t>& data) {
    std::error_code ec;
    fs::create_directories(p.parent_path(), ec);
    std::ofstream ofs(p, std::ios::binary | std::ios::trunc);
    OS_REQUIRE(static_cast<bool>(ofs));
    ofs.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()));
    OS_REQUIRE(static_cast<bool>(ofs));
}

struct DirSnapshot {
    uint64_t fnv1a_hash = 0;
    std::vector<std::string> entries;
};

DirSnapshot HashDirectoryTree(const fs::path& root) {
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
    for (const auto& entry : fs::recursive_directory_iterator(root)) {
        rel_paths.push_back(fs::relative(entry.path(), root));
    }
    std::sort(rel_paths.begin(), rel_paths.end());

    for (const auto& rel : rel_paths) {
        const fs::path full = root / rel;
        const std::string rel_s = rel.generic_string();
        if (fs::is_directory(full)) {
            std::string tag = "D:" + rel_s;
            snap.entries.push_back(tag);
            feed(tag.data(), tag.size());
        } else {
            const std::string bytes = ReadFileBytes(full);
            std::string tag = "F:" + rel_s + ":" + std::to_string(bytes.size());
            snap.entries.push_back(tag);
            feed(tag.data(), tag.size());
            feed(bytes.data(), bytes.size());
        }
    }
    snap.fnv1a_hash = h;
    return snap;
}

template <typename T>
void WritePod(std::vector<uint8_t>& buf, size_t off, const T& val) {
    OS_REQUIRE(off + sizeof(T) <= buf.size());
    std::memcpy(buf.data() + off, &val, sizeof(T));
}

// ---------------------------------------------------------------------------
// Synthetic PE32+ Builders (Exports/Forwarders, TLS, .pdata)
// ---------------------------------------------------------------------------
struct SynthExportSpec {
    std::string name;       // Empty for ordinal-only
    uint16_t ordinal_offset = 0;
    uint32_t rva = 0;       // Used when forwarder is empty
    std::string forwarder;  // Non-empty => forwarded export
};

// Builds a valid minimal PE32+ x64 DLL with 1 section (.rdata/.edata at RVA 0x1000, raw 0x200)
// that can BOTH be parsed by InspectPeBytes AND loaded directly by Windows LoadLibraryW!
std::vector<uint8_t> BuildSyntheticExportDll(const std::string& dll_name,
                                             uint32_t ordinal_base,
                                             const std::vector<SynthExportSpec>& specs) {
    constexpr uint32_t kFileAlign = 0x200;
    constexpr uint32_t kSecAlign = 0x1000;
    constexpr uint32_t kSecRva = 0x1000;
    constexpr uint32_t kSecRaw = 0x200;
    constexpr uint32_t kSecSize = 0x1000;
    constexpr uint32_t kImageSize = 0x2000;

    std::vector<uint8_t> img(kSecRaw + kSecSize, 0u);

    // DOS header
    IMAGE_DOS_HEADER dos{};
    dos.e_magic = IMAGE_DOS_SIGNATURE;
    dos.e_lfanew = 0x80;
    WritePod(img, 0, dos);

    // NT64 headers
    IMAGE_NT_HEADERS64 nt{};
    nt.Signature = IMAGE_NT_SIGNATURE;
    nt.FileHeader.Machine = IMAGE_FILE_MACHINE_AMD64;
    nt.FileHeader.NumberOfSections = 1;
    nt.FileHeader.SizeOfOptionalHeader = sizeof(IMAGE_OPTIONAL_HEADER64);
    nt.FileHeader.Characteristics =
        IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_LARGE_ADDRESS_AWARE | IMAGE_FILE_DLL;

    nt.OptionalHeader.Magic = IMAGE_NT_OPTIONAL_HDR64_MAGIC;
    nt.OptionalHeader.MajorLinkerVersion = 14;
    nt.OptionalHeader.AddressOfEntryPoint = 0;  // Entryless DLL (valid per PE/COFF spec)
    nt.OptionalHeader.ImageBase = 0x180000000ull;
    nt.OptionalHeader.SectionAlignment = kSecAlign;
    nt.OptionalHeader.FileAlignment = kFileAlign;
    nt.OptionalHeader.MajorOperatingSystemVersion = 6;
    nt.OptionalHeader.MajorSubsystemVersion = 6;
    nt.OptionalHeader.SizeOfImage = kImageSize;
    nt.OptionalHeader.SizeOfHeaders = kSecRaw;
    nt.OptionalHeader.Subsystem = IMAGE_SUBSYSTEM_WINDOWS_CUI;
    nt.OptionalHeader.DllCharacteristics =
        IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE | IMAGE_DLLCHARACTERISTICS_NX_COMPAT;
    nt.OptionalHeader.NumberOfRvaAndSizes = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;

    // Build section payload inside [kSecRaw, kSecRaw + kSecSize)
    uint16_t max_ord_off = 0;
    std::vector<const SynthExportSpec*> named;
    for (const auto& s : specs) {
        if (s.ordinal_offset > max_ord_off) max_ord_off = s.ordinal_offset;
        if (!s.name.empty()) named.push_back(&s);
    }
    std::sort(named.begin(), named.end(),
              [](const SynthExportSpec* a, const SynthExportSpec* b) { return a->name < b->name; });

    const uint32_t num_funcs = specs.empty() ? 0u : static_cast<uint32_t>(max_ord_off) + 1u;
    const uint32_t num_names = static_cast<uint32_t>(named.size());

    uint32_t cursor = 0;
    const uint32_t exp_dir_off = cursor;
    cursor += sizeof(IMAGE_EXPORT_DIRECTORY);

    const uint32_t funcs_off = cursor;
    cursor += num_funcs * sizeof(uint32_t);

    const uint32_t names_off = cursor;
    cursor += num_names * sizeof(uint32_t);

    const uint32_t ords_off = cursor;
    cursor += num_names * sizeof(uint16_t);
    cursor = (cursor + 3u) & ~3u;

    auto append_str = [&](const std::string& s) -> uint32_t {
        const uint32_t off = cursor;
        OS_REQUIRE(kSecRaw + cursor + s.size() + 1 <= img.size());
        std::memcpy(img.data() + kSecRaw + cursor, s.c_str(), s.size() + 1);
        cursor += static_cast<uint32_t>(s.size() + 1);
        return kSecRva + off;
    };

    const uint32_t dll_name_rva = append_str(dll_name);

    std::vector<uint32_t> func_rvas(num_funcs, 0u);
    for (const auto& s : specs) {
        if (!s.forwarder.empty()) {
            func_rvas[s.ordinal_offset] = append_str(s.forwarder);
        } else {
            func_rvas[s.ordinal_offset] = s.rva;
        }
    }

    for (uint32_t i = 0; i < num_funcs; ++i) {
        WritePod(img, kSecRaw + funcs_off + i * sizeof(uint32_t), func_rvas[i]);
    }
    for (uint32_t i = 0; i < num_names; ++i) {
        const uint32_t nrva = append_str(named[i]->name);
        WritePod(img, kSecRaw + names_off + i * sizeof(uint32_t), nrva);
        WritePod(img, kSecRaw + ords_off + i * sizeof(uint16_t), named[i]->ordinal_offset);
    }

    IMAGE_EXPORT_DIRECTORY exp{};
    exp.Name = dll_name_rva;
    exp.Base = ordinal_base;
    exp.NumberOfFunctions = num_funcs;
    exp.NumberOfNames = num_names;
    exp.AddressOfFunctions = kSecRva + funcs_off;
    exp.AddressOfNames = kSecRva + names_off;
    exp.AddressOfNameOrdinals = kSecRva + ords_off;
    WritePod(img, kSecRaw + exp_dir_off, exp);

    nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress = kSecRva + exp_dir_off;
    nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size = cursor;
    WritePod(img, static_cast<size_t>(dos.e_lfanew), nt);

    IMAGE_SECTION_HEADER sec{};
    std::memcpy(sec.Name, ".edata", 6);
    sec.Misc.VirtualSize = kSecSize;
    sec.VirtualAddress = kSecRva;
    sec.SizeOfRawData = kSecSize;
    sec.PointerToRawData = kSecRaw;
    sec.Characteristics = IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ;
    WritePod(img, static_cast<size_t>(dos.e_lfanew) + sizeof(IMAGE_NT_HEADERS64), sec);

    return img;
}

// ---------------------------------------------------------------------------
// Test 1: MicrosoftGame.Config XML Parser & Package Target Resolution
// ---------------------------------------------------------------------------
void TestGameConfigParserAndResolution() {
    using namespace openscarlett;

    // 1A. Full-featured XML with UTF-8 BOM, comments, irregular whitespace, single & double quotes,
    //     entity escapes (&amp; &lt; &gt; &quot; &apos; &#38; &#x26;), multiple executables.
    const std::string rich_xml =
        "\xEF\xBB\xBF"
        "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n"
        "<!-- Leading comment before root -->\n"
        "<Game   configVersion = '1' >\n"
        "  <!-- Identity with entities & irregular newlines -->\n"
        "  <Identity\n"
        "      Name = \"OpenScarlett.Sample_A&amp;B\"\n"
        "      Publisher = 'CN=OpenScarlett &lt;Studio&gt;, O=&quot;MIT&quot; &apos;Org&apos;'\n"
        "      Version = \"2.4.1.0\" />\n"
        "  <TitleId>  0x7e750470 \t </TitleId>\n"
        "  <MSAAppId>\n    000000004C26CAD4\n  </MSAAppId>\n"
        "  <ShellVisuals DefaultDisplayName = \"Hero&#38;Quest &#x26; &lt;Scarlett&gt;\" />\n"
        "  <ExecutableList>\n"
        "    <Executable Name=\"DevTool.exe\" Id=\"Dev\" TargetDeviceFamily=\"Scarlett\" IsDevOnly=\"true\" />\n"
        "    <Executable Name=\"Game_PC.exe\" Id=\"PC\" TargetDeviceFamily=\"PC\" />\n"
        "    <Executable Name=\"Game_XB1.exe\" Id=\"XB1\" TargetDeviceFamily=\"XboxOne\" />\n"
        "    <Executable Name=\"Game_XS.exe\" Id=\"Game\" TargetDeviceFamily=\"Scarlett\" OverrideDisplayName=\"Hero XS\" IsDevOnly=\"false\" />\n"
        "  </ExecutableList>\n"
        "</Game>\n"
        "<!-- Trailing comment -->\n";

    GameConfig cfg{};
    OS_REQUIRE(ParseGameConfigXml(rich_xml, "memory_rich.config", cfg).ok());
    OS_REQUIRE(cfg.config_version == "1");
    OS_REQUIRE(cfg.identity.name == "OpenScarlett.Sample_A&B");
    OS_REQUIRE(cfg.identity.publisher == "CN=OpenScarlett <Studio>, O=\"MIT\" 'Org'");
    OS_REQUIRE(cfg.identity.version == "2.4.1.0");
    OS_REQUIRE(cfg.title_id == "0x7e750470");
    OS_REQUIRE(cfg.has_title_id);
    OS_REQUIRE(cfg.title_id_value == 0x7E750470u);
    OS_REQUIRE(FormatTitleIdFolderName(cfg) == "7E750470");
    OS_REQUIRE(cfg.msa_app_id == "000000004C26CAD4");
    OS_REQUIRE(cfg.display_name == "Hero&Quest & <Scarlett>");
    OS_REQUIRE(cfg.executables.size() == 4);
    OS_REQUIRE(cfg.executables[0].is_dev_only);
    OS_REQUIRE(!cfg.executables[3].is_dev_only);
    OS_REQUIRE(cfg.executables[3].override_display_name == "Hero XS");

    // Primary executable must skip IsDevOnly="true" and select Scarlett non-dev-only entry!
    const GameExecutableEntry* primary = cfg.SelectPrimaryExecutable();
    OS_REQUIRE(primary != nullptr);
    OS_REQUIRE(primary->name == "Game_XS.exe");
    OS_REQUIRE(primary->target_device_family == "Scarlett");

    // 1B. TitleId without 0x prefix + XboxOne preferred over PC when no Scarlett entry exists
    const std::string xb_xml =
        "<Game configVersion=\"0\">"
        "  <TitleId>12AB34CD</TitleId>"
        "  <ExecutableList>"
        "    <Executable Name=\"pc.exe\" TargetDeviceFamily=\"PC\"/>"
        "    <Executable Name=\"xb.exe\" TargetDeviceFamily=\"XboxOne\"/>"
        "  </ExecutableList>"
        "</Game>";
    GameConfig cfg_xb{};
    OS_REQUIRE(ParseGameConfigXml(xb_xml, "xb.config", cfg_xb).ok());
    OS_REQUIRE(cfg_xb.has_title_id);
    OS_REQUIRE(cfg_xb.title_id_value == 0x12AB34CDu);
    OS_REQUIRE(cfg_xb.SelectPrimaryExecutable() != nullptr);
    OS_REQUIRE(cfg_xb.SelectPrimaryExecutable()->name == "xb.exe");

    // 1C. Malformed XML rejection
    GameConfig bad{};
    OS_REQUIRE(!ParseGameConfigXml("<NotGame/>", "bad1", bad).ok());
    OS_REQUIRE(!ParseGameConfigXml("<Game><TitleId>ZZZZ</TitleId></Game>", "bad2", bad).ok());
    OS_REQUIRE(!ParseGameConfigXml("<Game><!-- unterminated", "bad3", bad).ok());
    OS_REQUIRE(!ParseGameConfigXml("<Game><TitleId>1234</Wrong></Game>", "bad4", bad).ok());

    // 1D. ResolvePackageLaunchTarget (dir, config file, direct exe with sibling config)
    const fs::path sandbox = (ResolveScratchRoot() / "resolve_pkg").make_preferred();
    std::error_code ec;
    fs::remove_all(sandbox, ec);
    fs::create_directories(sandbox, ec);

    WriteFileBytes(sandbox / "Game_XS.exe", "MZ_FAKE_EXE");
    WriteFileBytes(sandbox / "microsoftgame.config",
                   "<?xml version=\"1.0\" encoding=\"utf-8\"?>"
                   "<Game configVersion=\"1\">"
                   "<Identity Name=\"PkgTest\" Publisher=\"CN=Test\" Version=\"1.0.0.0\"/>"
                   "<TitleId>ABCDEF01</TitleId>"
                   "<ExecutableList><Executable Name=\"Game_XS.exe\" TargetDeviceFamily=\"Scarlett\"/></ExecutableList>"
                   "</Game>");

    ResolvedPackageTarget t_dir{};
    OS_REQUIRE(ResolvePackageLaunchTarget(sandbox.string(), t_dir).ok());
    OS_REQUIRE(t_dir.has_config);
    OS_REQUIRE(fs::path(t_dir.exe_path).filename() == "Game_XS.exe");
    OS_REQUIRE(t_dir.config.title_id_value == 0xABCDEF01u);

    ResolvedPackageTarget t_cfg{};
    OS_REQUIRE(ResolvePackageLaunchTarget((sandbox / "microsoftgame.config").string(), t_cfg).ok());
    OS_REQUIRE(t_cfg.has_config);
    OS_REQUIRE(fs::path(t_cfg.exe_path).filename() == "Game_XS.exe");

    ResolvedPackageTarget t_exe{};
    OS_REQUIRE(ResolvePackageLaunchTarget((sandbox / "Game_XS.exe").string(), t_exe).ok());
    OS_REQUIRE(t_exe.has_config);
    OS_REQUIRE(t_exe.config.title_id_value == 0xABCDEF01u);

    // 1E. Optional validation against official MIT Microsoft Xbox-GDK-Samples configs if checked out locally
    const fs::path gdk_ds_mgc(
        R"(E:\OpenScarlett\packages\Xbox-GDK-Samples\Samples\System\SimpleDirectStorageCombo\MicrosoftGameConfig.mgc)");
    if (fs::exists(gdk_ds_mgc)) {
        GameConfig ds_cfg{};
        OS_REQUIRE(LoadGameConfigFile(gdk_ds_mgc.string(), ds_cfg).ok());
        OS_REQUIRE(ds_cfg.SelectPrimaryExecutable() != nullptr);
        OS_REQUIRE(ds_cfg.SelectPrimaryExecutable()->name == "SimpleDirectStorageCombo_xs.exe");
    }
    const fs::path gdk_save_mgc(
        R"(E:\OpenScarlett\packages\Xbox-GDK-Samples\Samples\System\GameSaveCombo\MicrosoftGameConfig.mgc)");
    if (fs::exists(gdk_save_mgc)) {
        GameConfig save_cfg{};
        OS_REQUIRE(LoadGameConfigFile(gdk_save_mgc.string(), save_cfg).ok());
        OS_REQUIRE(save_cfg.has_title_id);
        OS_REQUIRE(save_cfg.title_id_value == 0x7E750470u);
        OS_REQUIRE(save_cfg.msa_app_id == "000000004C26CAD4");
    }

    std::printf("[PASS] MicrosoftGame.Config XML parser & ResolvePackageLaunchTarget verified\n");
}

// ---------------------------------------------------------------------------
// Test 2: CoW Overlay VFS Unit Suite (G:\ and GAME:\ + Whiteouts + ReadOnly)
// ---------------------------------------------------------------------------
void TestCowVfsUnit() {
    using namespace openscarlett;

    const fs::path root = (ResolveScratchRoot() / "cow_unit").make_preferred();
    std::error_code ec;
    fs::remove_all(root, ec);

    const fs::path g_base = root / "G_base";
    const fs::path g_ovl = root / "G_overlay";
    const fs::path t_dir = root / "T";
    const fs::path s_dir = root / "S";

    WriteFileBytes(g_base / "base.txt", "IMMUTABLE_BASE_V1");
    WriteFileBytes(g_base / "sub" / "nested.bin", "NESTED_BASE");
    const DirSnapshot base_before = HashDirectoryTree(g_base);

    // 2A. Drive detection for G:, GAME:, T:, S: (case-insensitive, '\\?\' prefix)
    OS_REQUIRE(VfsMounts::DetectVirtualDriveW(L"G:\\foo.txt") == VfsDrive::Game);
    OS_REQUIRE(VfsMounts::DetectVirtualDriveW(L"GAME:\\foo.txt") == VfsDrive::Game);
    OS_REQUIRE(VfsMounts::DetectVirtualDriveW(L"game:/sub/bar.bin") == VfsDrive::Game);
    OS_REQUIRE(VfsMounts::DetectVirtualDriveW(L"\\\\?\\Game:\\bar.bin") == VfsDrive::Game);
    OS_REQUIRE(VfsMounts::DetectVirtualDriveA("GAME:/foo.txt") == VfsDrive::Game);
    OS_REQUIRE(VfsMounts::DetectVirtualDriveA("game:\\foo.txt") == VfsDrive::Game);
    OS_REQUIRE(VfsMounts::DetectVirtualDriveA("gameplay.txt") == VfsDrive::None);
    OS_REQUIRE(VfsMounts::DetectVirtualDriveW(L"GAMES:\\foo.txt") == VfsDrive::None);

    // 2B. Without g_overlay_root configured, mutating operations on G: MUST be blocked!
    VfsMounts ro_only(VfsMountConfig{g_base.wstring(), t_dir.wstring(), s_dir.wstring(), {}});
    std::wstring out;
    OS_REQUIRE(ro_only.TranslateForAccessW(L"GAME:\\base.txt", VfsAccessMode::ReadOnly, out) ==
               VfsTranslateStatus::Translated);
    OS_REQUIRE(out == (g_base / L"base.txt").wstring());
    OS_REQUIRE(ro_only.TranslateForAccessW(L"G:\\base.txt", VfsAccessMode::WriteModify, out) ==
               VfsTranslateStatus::ReadOnlyViolation);
    OS_REQUIRE(ro_only.TranslateForAccessW(L"GAME:\\new.txt", VfsAccessMode::WriteCreate, out) ==
               VfsTranslateStatus::ReadOnlyViolation);
    OS_REQUIRE(ro_only.TranslateForAccessW(L"G:\\base.txt", VfsAccessMode::Delete, out) ==
               VfsTranslateStatus::ReadOnlyViolation);

    // 2C. Full CoW overlay behavior
    VfsMounts vfs(VfsMountConfig{g_base.wstring(), t_dir.wstring(), s_dir.wstring(), g_ovl.wstring()});

    // Read base before any modification -> returns g_base path
    bool was_wo = false;
    OS_REQUIRE(vfs.TranslateForAccessW(L"GAME:/base.txt", VfsAccessMode::ReadOnly, out, &was_wo) ==
               VfsTranslateStatus::Translated);
    OS_REQUIRE(!was_wo);
    OS_REQUIRE(out == (g_base / L"base.txt").wstring());

    // WriteModify on existing base file -> CoW-copies base -> overlay and returns overlay path!
    OS_REQUIRE(vfs.TranslateForAccessW(L"G:\\base.txt", VfsAccessMode::WriteModify, out, &was_wo) ==
               VfsTranslateStatus::Translated);
    OS_REQUIRE(out == (g_ovl / L"base.txt").wstring());
    OS_REQUIRE(fs::exists(g_ovl / "base.txt"));
    OS_REQUIRE(ReadFileBytes(g_ovl / "base.txt") == "IMMUTABLE_BASE_V1");
    WriteFileBytes(g_ovl / "base.txt", "OVERLAY_UPDATED_V2");

    // Subsequent ReadOnly via GAME:\ returns overlay copy!
    OS_REQUIRE(vfs.TranslateForAccessW(L"game:\\base.txt", VfsAccessMode::ReadOnly, out, &was_wo) ==
               VfsTranslateStatus::Translated);
    OS_REQUIRE(out == (g_ovl / L"base.txt").wstring());
    OS_REQUIRE(ReadFileBytes(out) == "OVERLAY_UPDATED_V2");

    // Delete base file -> removes overlay copy + writes whiteout; subsequent ReadOnly reports DeletedWhiteout!
    OS_REQUIRE(vfs.TranslateForAccessW(L"G:\\base.txt", VfsAccessMode::Delete, out, &was_wo) ==
               VfsTranslateStatus::Translated);
    OS_REQUIRE(was_wo);
    OS_REQUIRE(!fs::exists(g_ovl / "base.txt"));
    OS_REQUIRE(vfs.TranslateForAccessW(L"GAME:\\base.txt", VfsAccessMode::ReadOnly, out, &was_wo) ==
               VfsTranslateStatus::DeletedWhiteout);
    OS_REQUIRE(was_wo);

    // Re-creating via WriteCreate clears whiteout!
    OS_REQUIRE(vfs.TranslateForAccessW(L"GAME:\\base.txt", VfsAccessMode::WriteCreate, out, &was_wo) ==
               VfsTranslateStatus::Translated);
    OS_REQUIRE(!was_wo);
    WriteFileBytes(out, "REBORN_V3");
    OS_REQUIRE(vfs.TranslateForAccessW(L"G:\\base.txt", VfsAccessMode::ReadOnly, out, &was_wo) ==
               VfsTranslateStatus::Translated);
    OS_REQUIRE(ReadFileBytes(out) == "REBORN_V3");

    // Prove G_base is 100% byte-identical!
    const DirSnapshot base_after = HashDirectoryTree(g_base);
    OS_REQUIRE(base_after.fnv1a_hash == base_before.fnv1a_hash);
    OS_REQUIRE(base_after.entries == base_before.entries);

    std::printf("[PASS] CoW overlay VFS unit suite (G:/GAME:, CoW copy, whiteout, 0 base mutation)\n");
}

// ---------------------------------------------------------------------------
// Test 3: PE Export-Forwarder Parsing & Chained Resolution
// ---------------------------------------------------------------------------
void TestPeExportForwarders() {
    using namespace openscarlett;

    // 3A. ParseExportForwarder syntax tests
    PeForwarderTarget tgt{};
    OS_REQUIRE(ParseExportForwarder("kernelbase.CreateFileW", tgt));
    OS_REQUIRE(tgt.dll_name == "kernelbase.dll");
    OS_REQUIRE(!tgt.by_ordinal && tgt.symbol_name == "CreateFileW");

    OS_REQUIRE(ParseExportForwarder("Microsoft.Xbox.Services.GDK.C.XblInitialize", tgt));
    OS_REQUIRE(tgt.dll_name == "Microsoft.Xbox.Services.GDK.C.dll");
    OS_REQUIRE(!tgt.by_ordinal && tgt.symbol_name == "XblInitialize");

    OS_REQUIRE(ParseExportForwarder("beta.dll.#42", tgt));
    OS_REQUIRE(tgt.dll_name == "beta.dll");
    OS_REQUIRE(tgt.by_ordinal && tgt.ordinal == 42);

    OS_REQUIRE(!ParseExportForwarder("no_dot_symbol", tgt));
    OS_REQUIRE(!ParseExportForwarder("dll.#notanumber", tgt));

    // 3B. Multi-hop synthetic PE32+ forwarder chain + ordinal forwarding + cycle detection + max depth
    std::unordered_map<std::string, std::vector<uint8_t>> modules;
    modules["alpha.dll"] = BuildSyntheticExportDll("alpha.dll", 1, {
        {"EntryByName", 0, 0, "beta.HopFunc"},
        {"EntryByOrd", 1, 0, "beta.#12"},
        {"CycleStart", 2, 0, "cycle_b.Loop"},
        {"DeepStart", 3, 0, "deep1.Step"},
    });
    modules["beta.dll"] = BuildSyntheticExportDll("beta.dll", 10, {
        {"HopFunc", 0, 0, "Microsoft.Xbox.Services.GDK.C.XblFinalFunc"},
        {"", 2, 0, "Microsoft.Xbox.Services.GDK.C.#7"},  // ordinal 10 + 2 = 12
    });
    modules["microsoft.xbox.services.gdk.c.dll"] = BuildSyntheticExportDll(
        "Microsoft.Xbox.Services.GDK.C.dll", 5, {
            {"XblFinalFunc", 0, 0x1234u, ""},
            {"OrdSevenFn", 2, 0x1568u, ""},  // ordinal 5 + 2 = 7
        });
    modules["cycle_b.dll"] = BuildSyntheticExportDll("cycle_b.dll", 1, {
        {"Loop", 0, 0, "alpha.CycleStart"},
    });
    modules["deep1.dll"] = BuildSyntheticExportDll("deep1.dll", 1, {{"Step", 0, 0, "deep2.Step"}});
    modules["deep2.dll"] = BuildSyntheticExportDll("deep2.dll", 1, {{"Step", 0, 0, "deep3.Step"}});
    modules["deep3.dll"] = BuildSyntheticExportDll("deep3.dll", 1, {{"Step", 0, 0, "deep4.Step"}});
    modules["deep4.dll"] = BuildSyntheticExportDll("deep4.dll", 1, {{"Step", 0, 0x1111u, ""}});

    // InspectPeBytes must parse forwarded exports accurately
    PeInspectionReport alpha_rep{};
    OS_REQUIRE(InspectPeBytes(modules["alpha.dll"], "alpha.dll", alpha_rep).ok());
    OS_REQUIRE(alpha_rep.exports.size() == 4);
    OS_REQUIRE(alpha_rep.exports[0].name == "EntryByName");
    OS_REQUIRE(alpha_rep.exports[0].is_forwarded);
    OS_REQUIRE(alpha_rep.exports[0].forwarder == "beta.HopFunc");

    auto resolver = [&](const std::string& dll, std::vector<uint8_t>& out_bytes) -> Status {
        std::string lo = dll;
        for (char& c : lo) {
            if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
        }
        auto it = modules.find(lo);
        if (it == modules.end()) {
            return Status::Error(StatusCode::NotFound, "Missing synthetic DLL: " + dll);
        }
        out_bytes = it->second;
        return Status::Ok();
    };

    // Named 3-hop chain: alpha!EntryByName -> beta!HopFunc -> Microsoft.Xbox.Services.GDK.C!XblFinalFunc
    PeForwarderResolution res{};
    OS_REQUIRE(ResolveExportForwarderChain("alpha.dll", "EntryByName", 0, false, resolver, res).ok());
    OS_REQUIRE(res.final_dll == "Microsoft.Xbox.Services.GDK.C.dll");
    OS_REQUIRE(res.final_symbol == "XblFinalFunc");
    OS_REQUIRE(res.final_rva == 0x1234u);
    OS_REQUIRE(res.chain.size() == 3);

    // Ordinal chain: alpha!EntryByOrd -> beta!#12 -> Microsoft.Xbox.Services.GDK.C!#7
    OS_REQUIRE(ResolveExportForwarderChain("alpha.dll", "EntryByOrd", 0, false, resolver, res).ok());
    OS_REQUIRE(res.final_ordinal == 7);
    OS_REQUIRE(res.final_rva == 0x1568u);
    OS_REQUIRE(res.chain.size() == 3);

    // Cycle detection
    auto cyc_st = ResolveExportForwarderChain("alpha.dll", "CycleStart", 0, false, resolver, res);
    OS_REQUIRE(!cyc_st.ok());
    OS_REQUIRE(cyc_st.code == StatusCode::ParseError);

    // Max depth guard
    auto depth_st = ResolveExportForwarderChain("alpha.dll", "DeepStart", 0, false, resolver, res, 2);
    OS_REQUIRE(!depth_st.ok());
    OS_REQUIRE(ResolveExportForwarderChain("alpha.dll", "DeepStart", 0, false, resolver, res, 8).ok());
    OS_REQUIRE(res.final_rva == 0x1111u);

    // 3C. Real Windows kernel32.dll export-forwarder inspection
    wchar_t sys_dir[MAX_PATH]{};
    UINT sys_len = ::GetSystemDirectoryW(sys_dir, MAX_PATH);
    OS_REQUIRE(sys_len > 0 && sys_len < MAX_PATH);
    const fs::path k32_path = fs::path(std::wstring(sys_dir, sys_len)) / "kernel32.dll";
    if (fs::exists(k32_path)) {
        PeInspectionReport k32_rep{};
        OS_REQUIRE(InspectPeFile(k32_path.string(), k32_rep).ok());
        size_t fwd_count = 0;
        for (const auto& exp : k32_rep.exports) {
            if (exp.is_forwarded && !exp.forwarder.empty()) ++fwd_count;
        }
        OS_REQUIRE(fwd_count > 10);
        std::printf("[PASS] PE export-forwarder parsing & chained resolution (%zu real kernel32.dll forwarders)\n",
                    fwd_count);
    } else {
        std::printf("[PASS] PE export-forwarder parsing & chained resolution\n");
    }
}

// ---------------------------------------------------------------------------
// Test 4: TLS Callback RVA Parsing & Live Invocation
// ---------------------------------------------------------------------------
struct TlsTestState {
    void* last_base = nullptr;
    DWORD last_reason = 0;
    std::vector<int> order;
};

void NTAPI SynthTlsCallback1(PVOID dll_handle, DWORD reason, PVOID reserved) {
    auto* st = static_cast<TlsTestState*>(reserved);
    if (st) {
        st->last_base = dll_handle;
        st->last_reason = reason;
        st->order.push_back(1);
    }
}

void NTAPI SynthTlsCallback2(PVOID dll_handle, DWORD reason, PVOID reserved) {
    auto* st = static_cast<TlsTestState*>(reserved);
    if (st) {
        st->last_base = dll_handle;
        st->last_reason = reason;
        st->order.push_back(2);
    }
}

void TestPeTlsCallbacks() {
    using namespace openscarlett;

    constexpr uint64_t kImgBase = 0x140000000ull;
    constexpr uint32_t kSecRva = 0x1000;
    constexpr uint32_t kSecRaw = 0x200;
    constexpr uint32_t kSecSize = 0x1000;
    constexpr uint32_t kImageSize = 0x2000;

    // 4A. File-layout PE32+ image for InspectPeBytes TLS RVA parsing
    std::vector<uint8_t> pe_file(kSecRaw + kSecSize, 0u);
    IMAGE_DOS_HEADER dos{};
    dos.e_magic = IMAGE_DOS_SIGNATURE;
    dos.e_lfanew = 0x80;
    WritePod(pe_file, 0, dos);

    IMAGE_NT_HEADERS64 nt{};
    nt.Signature = IMAGE_NT_SIGNATURE;
    nt.FileHeader.Machine = IMAGE_FILE_MACHINE_AMD64;
    nt.FileHeader.NumberOfSections = 1;
    nt.FileHeader.SizeOfOptionalHeader = sizeof(IMAGE_OPTIONAL_HEADER64);
    nt.FileHeader.Characteristics = IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_LARGE_ADDRESS_AWARE;
    nt.OptionalHeader.Magic = IMAGE_NT_OPTIONAL_HDR64_MAGIC;
    nt.OptionalHeader.ImageBase = kImgBase;
    nt.OptionalHeader.SectionAlignment = 0x1000;
    nt.OptionalHeader.FileAlignment = 0x200;
    nt.OptionalHeader.SizeOfImage = kImageSize;
    nt.OptionalHeader.SizeOfHeaders = kSecRaw;
    nt.OptionalHeader.NumberOfRvaAndSizes = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;
    nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress = kSecRva;
    nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size = sizeof(IMAGE_TLS_DIRECTORY64);
    WritePod(pe_file, 0x80, nt);

    IMAGE_SECTION_HEADER sec{};
    std::memcpy(sec.Name, ".tls", 4);
    sec.Misc.VirtualSize = kSecSize;
    sec.VirtualAddress = kSecRva;
    sec.SizeOfRawData = kSecSize;
    sec.PointerToRawData = kSecRaw;
    WritePod(pe_file, 0x80 + sizeof(IMAGE_NT_HEADERS64), sec);

    constexpr uint32_t kCbArrayRva = kSecRva + 0x100;
    IMAGE_TLS_DIRECTORY64 tls{};
    tls.AddressOfCallBacks = kImgBase + kCbArrayRva;
    WritePod(pe_file, kSecRaw, tls);

    const uint64_t cb_vas[3] = {kImgBase + 0x1200u, kImgBase + 0x1340u, 0ull};
    WritePod(pe_file, kSecRaw + 0x100, cb_vas);

    PeInspectionReport rep{};
    OS_REQUIRE(InspectPeBytes(pe_file, "synth_tls.exe", rep).ok());
    OS_REQUIRE(rep.has_tls);
    OS_REQUIRE(rep.tls_callback_rvas.size() == 2);
    OS_REQUIRE(rep.tls_callback_rvas[0] == 0x1200u);
    OS_REQUIRE(rep.tls_callback_rvas[1] == 0x1340u);

    // 4B. Mapped in-memory PE32+ image for live InvokePeTlsCallbacks invocation
    std::vector<uint8_t> mapped(kImageSize, 0u);
    WritePod(mapped, 0, dos);
    WritePod(mapped, 0x80, nt);
    IMAGE_TLS_DIRECTORY64 mapped_tls{};
    mapped_tls.AddressOfCallBacks = reinterpret_cast<uint64_t>(mapped.data() + kCbArrayRva);
    WritePod(mapped, kSecRva, mapped_tls);

    const uint64_t live_cbs[3] = {
        reinterpret_cast<uint64_t>(&SynthTlsCallback1),
        reinterpret_cast<uint64_t>(&SynthTlsCallback2),
        0ull,
    };
    WritePod(mapped, kCbArrayRva, live_cbs);

    TlsTestState state{};
    const uint32_t invoked = InvokePeTlsCallbacks(mapped.data(), DLL_PROCESS_ATTACH, &state);
    OS_REQUIRE(invoked == 2);
    OS_REQUIRE(state.last_base == mapped.data());
    OS_REQUIRE(state.last_reason == DLL_PROCESS_ATTACH);
    OS_REQUIRE(state.order.size() == 2 && state.order[0] == 1 && state.order[1] == 2);

    std::printf("[PASS] PE TLS callback RVA parsing & live InvokePeTlsCallbacks verified\n");
}

// ---------------------------------------------------------------------------
// Test 5: x64 .pdata SEH Unwind Parsing + Live RtlAddFunctionTable/RtlLookupFunctionEntry
// ---------------------------------------------------------------------------
void TestPeExceptionTableRegistration() {
    using namespace openscarlett;

    constexpr uint32_t kImageSize = 0x4000;
    constexpr uint32_t kCodeRva = 0x1000;
    constexpr uint32_t kPdataRva = 0x2000;
    constexpr uint32_t kXdataRva = 0x3000;

    // 5A. InspectPeBytes .pdata entry count parsing
    std::vector<uint8_t> pe_file(0x400, 0u);
    IMAGE_DOS_HEADER dos{};
    dos.e_magic = IMAGE_DOS_SIGNATURE;
    dos.e_lfanew = 0x80;
    WritePod(pe_file, 0, dos);

    IMAGE_NT_HEADERS64 nt{};
    nt.Signature = IMAGE_NT_SIGNATURE;
    nt.FileHeader.Machine = IMAGE_FILE_MACHINE_AMD64;
    nt.FileHeader.NumberOfSections = 0;
    nt.FileHeader.SizeOfOptionalHeader = sizeof(IMAGE_OPTIONAL_HEADER64);
    nt.OptionalHeader.Magic = IMAGE_NT_OPTIONAL_HDR64_MAGIC;
    nt.OptionalHeader.ImageBase = 0x140000000ull;
    nt.OptionalHeader.SizeOfImage = kImageSize;
    nt.OptionalHeader.NumberOfRvaAndSizes = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;
    nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress = kPdataRva;
    nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size =
        2u * static_cast<uint32_t>(sizeof(RUNTIME_FUNCTION));
    WritePod(pe_file, 0x80, nt);

    PeInspectionReport rep{};
    OS_REQUIRE(InspectPeBytes(pe_file, "synth_pdata.exe", rep).ok());
    OS_REQUIRE(rep.exception_dir_rva == kPdataRva);
    OS_REQUIRE(rep.exception_dir_size == 24u);
    OS_REQUIRE(rep.exception_entry_count == 2u);

    // 5B. Live RtlAddFunctionTable -> RtlLookupFunctionEntry -> RtlDeleteFunctionTable
    void* mem = ::VirtualAlloc(nullptr, kImageSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    OS_REQUIRE(mem != nullptr);
    auto* base = static_cast<uint8_t*>(mem);

    nt.OptionalHeader.ImageBase = reinterpret_cast<uint64_t>(base);
    nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress = kPdataRva;
    nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size =
        static_cast<uint32_t>(sizeof(RUNTIME_FUNCTION));
    std::memcpy(base, &dos, sizeof(dos));
    std::memcpy(base + 0x80, &nt, sizeof(nt));

    // Minimal valid x64 UNWIND_INFO (version=1, flags=0, prolog=0, codes=0)
    const uint8_t unwind_info[4] = {0x01, 0x00, 0x00, 0x00};
    std::memcpy(base + kXdataRva, unwind_info, sizeof(unwind_info));

    RUNTIME_FUNCTION rf{};
    rf.BeginAddress = kCodeRva;
    rf.EndAddress = kCodeRva + 0x40u;
    rf.UnwindData = kXdataRva;
    std::memcpy(base + kPdataRva, &rf, sizeof(rf));

    const DWORD64 probe_pc = reinterpret_cast<DWORD64>(base + kCodeRva + 0x10u);
    DWORD64 found_base = 0;
    OS_REQUIRE(::RtlLookupFunctionEntry(probe_pc, &found_base, nullptr) == nullptr);

    uint32_t registered_count = 0;
    OS_REQUIRE(RegisterPeExceptionTableFromImage(base, &registered_count));
    OS_REQUIRE(registered_count == 1u);

    PRUNTIME_FUNCTION found = ::RtlLookupFunctionEntry(probe_pc, &found_base, nullptr);
    OS_REQUIRE(found != nullptr);
    OS_REQUIRE(found_base == reinterpret_cast<DWORD64>(base));
    OS_REQUIRE(found->BeginAddress == kCodeRva);
    OS_REQUIRE(found->EndAddress == kCodeRva + 0x40u);
    OS_REQUIRE(found->UnwindData == kXdataRva);

    OS_REQUIRE(UnregisterPeExceptionTable(base, kPdataRva));
    OS_REQUIRE(::RtlLookupFunctionEntry(probe_pc, &found_base, nullptr) == nullptr);

    ::VirtualFree(mem, 0, MEM_RELEASE);
    std::printf("[PASS] x64 .pdata SEH parsing + live RtlAddFunctionTable/RtlLookupFunctionEntry verified\n");
}

// ---------------------------------------------------------------------------
// Test 6: Data-Driven Per-DLL Routing Table (All 21 Core Shims + Env Overrides)
// ---------------------------------------------------------------------------
void TestDllRoutingTable() {
    using namespace openscarlett;

    DllRoutingTable table;
    const auto rules = table.ListRules();
    OS_REQUIRE(rules.size() == 21);

    // Verify all 21 core shim DLL names & exact priorities
    const std::vector<std::pair<const char*, int>> expected_shims = {
        {"kernelx.dll", 0},
        {"xgameruntime.dll", 0},
        {"GameInput.dll", 0},
        {"XAudio2_9.dll", 0},
        {"d3d12_xs.dll", 1},
        {"xg_xs.dll", 1},
        {"AcpHal.dll", 1},
        {"xapu.dll", 1},
        {"chad.dll", 1},
        {"dstorage_xs.dll", 1},
        {"winrt_xs.dll", 1},
        {"xmem.dll", 1},
        {"pixevt.dll", 1},
        {"xcrdapi.dll", 1},
        {"libHttpClient.GDK.dll", 1},
        {"XCurl.dll", 1},
        {"Bink2Scarlett.dll", 1},
        {"amd_fidelityfx_upscaler_xbox.dll", 1},
        {"XboxBvhBuilder.dll", 1},
        {"Microsoft.Xbox.Services.GDK.C.dll", 2},
        {"amd_fidelityfx_loader_xbox.dll", 2},
    };
    for (const auto& [name, prio] : expected_shims) {
        const DllRouteRule* r = table.FindRule(name);
        OS_REQUIRE(r != nullptr);
        OS_REQUIRE(r->policy == DllRoutePolicy::Shim);
        OS_REQUIRE(r->load_priority == prio);
    }

    // Create temp shim_dir and guest_dir to verify filesystem-backed resolution
    const fs::path root = (ResolveScratchRoot() / "routing_unit").make_preferred();
    std::error_code ec;
    fs::remove_all(root, ec);
    const fs::path shim_dir = root / "shims";
    const fs::path guest_dir = root / "guest";
    WriteFileBytes(shim_dir / "dstorage_xs.dll", "SHIM");
    WriteFileBytes(shim_dir / "custom_shim.dll", "SHIM");
    WriteFileBytes(guest_dir / "foo.dll", "GUEST");
    WriteFileBytes(guest_dir / "dstorage_xs.dll", "GUEST");
    WriteFileBytes(guest_dir / "xmem.dll", "GUEST_FALLBACK");

    // Built-in shim found in shim_dir -> Shim
    auto d1 = table.ResolveRoute("DSTORAGE_XS", shim_dir.wstring(), guest_dir.wstring());
    OS_REQUIRE(d1.policy == DllRoutePolicy::Shim);
    OS_REQUIRE(d1.resolved_path == (shim_dir / L"dstorage_xs.dll").wstring());

    // Built-in shim missing from shim_dir but present in guest_dir -> NativeGuestDll fallback
    auto d2 = table.ResolveRoute("xmem.dll", shim_dir.wstring(), guest_dir.wstring());
    OS_REQUIRE(d2.policy == DllRoutePolicy::NativeGuestDll);
    OS_REQUIRE(d2.resolved_path == (guest_dir / L"xmem.dll").wstring());

    // Unlisted non-Windows DLL present in guest_dir -> NativeGuestDll
    auto d3 = table.ResolveRoute("foo.dll", shim_dir.wstring(), guest_dir.wstring());
    OS_REQUIRE(d3.policy == DllRoutePolicy::NativeGuestDll);
    OS_REQUIRE(d3.resolved_path == (guest_dir / L"foo.dll").wstring());

    // Windows native DLL -> Windows
    auto d4 = table.ResolveRoute("user32.dll", shim_dir.wstring(), guest_dir.wstring());
    OS_REQUIRE(d4.policy == DllRoutePolicy::Windows);
    OS_REQUIRE(d4.resolved_path.empty());

    // Env overrides via OPENSCARLETT_DLL_ROUTING
    OS_REQUIRE(::SetEnvironmentVariableA(
                   "OPENSCARLETT_DLL_ROUTING",
                   "dstorage_xs.dll=guest;custom_shim.dll=shim;GameInput.dll=windows;foo.dll=guest") != 0);
    DllRoutingTable env_table = DllRoutingTable::CreateWithEnvOverrides();
    OS_REQUIRE(::SetEnvironmentVariableA("OPENSCARLETT_DLL_ROUTING", nullptr) != 0);

    auto o1 = env_table.ResolveRoute("dstorage_xs.dll", shim_dir.wstring(), guest_dir.wstring());
    OS_REQUIRE(o1.policy == DllRoutePolicy::NativeGuestDll);
    OS_REQUIRE(o1.from_override);
    OS_REQUIRE(o1.resolved_path == (guest_dir / L"dstorage_xs.dll").wstring());

    auto o2 = env_table.ResolveRoute("custom_shim.dll", shim_dir.wstring(), guest_dir.wstring());
    OS_REQUIRE(o2.policy == DllRoutePolicy::Shim);
    OS_REQUIRE(o2.from_override);
    OS_REQUIRE(o2.resolved_path == (shim_dir / L"custom_shim.dll").wstring());

    auto o3 = env_table.ResolveRoute("GameInput.dll", shim_dir.wstring(), guest_dir.wstring());
    OS_REQUIRE(o3.policy == DllRoutePolicy::Windows);
    OS_REQUIRE(o3.from_override);

    std::printf("[PASS] Data-driven DllRoutingTable verified (19 shims + OPENSCARLETT_DLL_ROUTING overrides)\n");
}

// ---------------------------------------------------------------------------
// Test 7: Live End-to-End Package Launch & Injected Guest CoW Overlay + Forwarder Test
// ---------------------------------------------------------------------------
bool ReadWin32FileW(const wchar_t* path, std::string& out) {
    HANDLE h = ::CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, nullptr,
                             OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    char buf[1024]{};
    DWORD rd = 0;
    BOOL ok = ::ReadFile(h, buf, sizeof(buf) - 1, &rd, nullptr);
    ::CloseHandle(h);
    if (!ok) return false;
    out.assign(buf, rd);
    return true;
}

std::wstring ReadEnvStrW(const wchar_t* name) {
    DWORD n = ::GetEnvironmentVariableW(name, nullptr, 0);
    if (n == 0) return {};
    std::wstring s(n, L'\0');
    DWORD w = ::GetEnvironmentVariableW(name, s.data(), n);
    if (w == 0 || w >= n) return {};
    s.resize(w);
    return s;
}

int RunCowGuestChild() {
    auto fail = [](const char* msg, DWORD err = 0) -> int {
        std::fprintf(stderr, "[cow-guest-child] FAIL: %s (err=%lu)\n", msg, static_cast<unsigned long>(err));
        return 1;
    };

    // 1. Verify MicrosoftGame.Config metadata propagated via child env block
    if (ReadEnvStrW(L"OPENSCARLETT_TITLE_ID") != L"41525331") {
        return fail("OPENSCARLETT_TITLE_ID mismatch");
    }
    if (ReadEnvStrW(L"OPENSCARLETT_PACKAGE_ID") != L"OpenScarlett.CowVfsTest") {
        return fail("OPENSCARLETT_PACKAGE_ID mismatch");
    }
    std::wstring ovl_env = ReadEnvStrW(L"OPENSCARLETT_VFS_G_OVERLAY");
    std::wstring save_env = ReadEnvStrW(L"OPENSCARLETT_VFS_S");
    if (ovl_env.find(L"41525331") == std::wstring::npos) {
        return fail("OPENSCARLETT_VFS_G_OVERLAY missing per-TitleId folder");
    }
    if (save_env.find(L"41525331") == std::wstring::npos) {
        return fail("OPENSCARLETT_VFS_S missing per-TitleId folder");
    }

    // 2. Read base file via BOTH G:\ and GAME:\ prefixes
    std::string content;
    if (!ReadWin32FileW(L"G:\\base_data.txt", content) || content != "BASE_ORIGINAL_BYTES_V1") {
        return fail("Initial read of G:\\base_data.txt failed", ::GetLastError());
    }
    if (!ReadWin32FileW(L"GAME:/base_data.txt", content) || content != "BASE_ORIGINAL_BYTES_V1") {
        return fail("Initial read of GAME:/base_data.txt failed", ::GetLastError());
    }

    // 3. In-place CoW modification of existing base file under G:\ (OPEN_EXISTING + GENERIC_WRITE)
    HANDLE h_mod = ::CreateFileW(L"G:\\base_data.txt",
                                 GENERIC_READ | GENERIC_WRITE,
                                 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h_mod == INVALID_HANDLE_VALUE) {
        return fail("CreateFileW(G:\\base_data.txt, OPEN_EXISTING|WRITE) failed", ::GetLastError());
    }
    ::SetFilePointer(h_mod, 5, nullptr, FILE_BEGIN);
    const char* patch = "MODIFIED";
    DWORD written = 0;
    if (!::WriteFile(h_mod, patch, 8, &written, nullptr) || written != 8) {
        ::CloseHandle(h_mod);
        return fail("WriteFile CoW in-place modification failed", ::GetLastError());
    }
    ::CloseHandle(h_mod);

    if (!ReadWin32FileW(L"game:\\base_data.txt", content) || content != "BASE_MODIFIED_BYTES_V1") {
        return fail("Post-CoW read of game:\\base_data.txt mismatch");
    }

    // 4. Create brand-new subdir and file under GAME:\ (CreateDirectoryW + CreateFileA CREATE_NEW)
    if (!::CreateDirectoryW(L"G:\\created_sub", nullptr)) {
        return fail("CreateDirectoryW(G:\\created_sub) failed", ::GetLastError());
    }
    HANDLE h_new = ::CreateFileA("GAME:\\created_sub\\brand_new.txt",
                                 GENERIC_WRITE, 0, nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h_new == INVALID_HANDLE_VALUE) {
        return fail("CreateFileA(GAME:\\created_sub\\brand_new.txt, CREATE_NEW) failed", ::GetLastError());
    }
    const char* new_payload = "BRAND_NEW_IN_OVERLAY";
    ::WriteFile(h_new, new_payload, static_cast<DWORD>(std::strlen(new_payload)), &written, nullptr);
    ::CloseHandle(h_new);

    if (::GetFileAttributesA("G:\\created_sub\\brand_new.txt") == INVALID_FILE_ATTRIBUTES) {
        return fail("GetFileAttributesA did not see brand_new.txt");
    }
    WIN32_FILE_ATTRIBUTE_DATA fad{};
    if (!::GetFileAttributesExW(L"GAME:/created_sub/brand_new.txt", GetFileExInfoStandard, &fad)) {
        return fail("GetFileAttributesExW did not see brand_new.txt");
    }
    if (!ReadWin32FileW(L"G:\\created_sub\\brand_new.txt", content) || content != new_payload) {
        return fail("Read back of G:\\created_sub\\brand_new.txt failed");
    }

    // 5. MoveFileExW on a base file -> source whiteouted, destination readable in overlay
    if (!::MoveFileExW(L"G:\\move_me.txt", L"GAME:\\moved_dest.txt", MOVEFILE_REPLACE_EXISTING)) {
        return fail("MoveFileExW(G:\\move_me.txt -> GAME:\\moved_dest.txt) failed", ::GetLastError());
    }
    if (::GetFileAttributesW(L"G:\\move_me.txt") != INVALID_FILE_ATTRIBUTES ||
        ::GetLastError() != ERROR_FILE_NOT_FOUND) {
        return fail("Moved source G:\\move_me.txt still visible after MoveFileExW");
    }
    if (!ReadWin32FileW(L"G:\\moved_dest.txt", content) || content != "MOVE_PAYLOAD_77") {
        return fail("Moved destination G:\\moved_dest.txt content mismatch");
    }

    // 6. DeleteFileW and DeleteFileA on base files -> whiteout verified!
    if (!::DeleteFileW(L"G:\\delete_me_w.txt")) {
        return fail("DeleteFileW(G:\\delete_me_w.txt) failed", ::GetLastError());
    }
    if (!::DeleteFileA("GAME:\\delete_me_a.txt")) {
        return fail("DeleteFileA(GAME:\\delete_me_a.txt) failed", ::GetLastError());
    }
    if (::GetFileAttributesW(L"G:\\delete_me_w.txt") != INVALID_FILE_ATTRIBUTES ||
        ::GetLastError() != ERROR_FILE_NOT_FOUND) {
        return fail("Whiteouted G:\\delete_me_w.txt still visible via GetFileAttributesW");
    }
    if (::GetFileAttributesA("GAME:\\delete_me_a.txt") != INVALID_FILE_ATTRIBUTES ||
        ::GetLastError() != ERROR_FILE_NOT_FOUND) {
        return fail("Whiteouted GAME:\\delete_me_a.txt still visible via GetFileAttributesA");
    }
    HANDLE h_del_open = ::CreateFileW(L"G:\\delete_me_w.txt", GENERIC_READ, FILE_SHARE_READ,
                                      nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h_del_open != INVALID_HANDLE_VALUE || ::GetLastError() != ERROR_FILE_NOT_FOUND) {
        if (h_del_open != INVALID_HANDLE_VALUE) ::CloseHandle(h_del_open);
        return fail("CreateFileW(OPEN_EXISTING) succeeded on whiteouted file");
    }
    WIN32_FIND_DATAW fdw{};
    HANDLE h_find_del = ::FindFirstFileW(L"G:\\delete_me_w.txt", &fdw);
    if (h_find_del != INVALID_HANDLE_VALUE || ::GetLastError() != ERROR_FILE_NOT_FOUND) {
        if (h_find_del != INVALID_HANDLE_VALUE) ::FindClose(h_find_del);
        return fail("FindFirstFileW found whiteouted file");
    }

    // 7. RemoveDirectoryW on an empty base directory -> whiteouted, base untouched!
    if (!::RemoveDirectoryW(L"G:\\empty_base_dir")) {
        return fail("RemoveDirectoryW(G:\\empty_base_dir) failed", ::GetLastError());
    }
    if (::GetFileAttributesW(L"GAME:\\empty_base_dir") != INVALID_FILE_ATTRIBUTES ||
        ::GetLastError() != ERROR_FILE_NOT_FOUND) {
        return fail("Whiteouted G:\\empty_base_dir still visible");
    }

    // 8. Live Hook_GetProcAddress forwarded-export routing to winrt_xs.dll shim!
    HMODULE h_fwd = ::LoadLibraryW(L"G:\\fwd_to_winrt.dll");
    if (!h_fwd) {
        return fail("LoadLibraryW(G:\\fwd_to_winrt.dll) failed", ::GetLastError());
    }
    using PfnRoInit = int32_t(__cdecl*)(uint32_t);
    auto p_fwd_ro_init = reinterpret_cast<PfnRoInit>(::GetProcAddress(h_fwd, "ForwardRoInit"));
    if (!p_fwd_ro_init) {
        ::FreeLibrary(h_fwd);
        return fail("GetProcAddress(fwd_to_winrt.dll, ForwardRoInit) failed", ::GetLastError());
    }
    if (p_fwd_ro_init(1) != 0) {
        ::FreeLibrary(h_fwd);
        return fail("Forwarded RoInitialize call returned non-zero");
    }
    ::FreeLibrary(h_fwd);

    // 9. Live versioned/thunk GDK DLL alias routing via Hook_LoadLibraryW!
    HMODULE h_xsapi_thunk = ::LoadLibraryW(L"Microsoft.Xbox.Services.141.GDK.C.Thunks.dll");
    if (!h_xsapi_thunk) {
        return fail("LoadLibraryW(Microsoft.Xbox.Services.141.GDK.C.Thunks.dll) failed", ::GetLastError());
    }
    ::FreeLibrary(h_xsapi_thunk);

    std::printf("[cow-guest-child] PASS: CoW G:/GAME: writes/deletes/moves/whiteouts + forwarder & alias routing OK\n");
    std::fflush(stdout);
    return 0;
}

void TestLivePackageLaunchAndCowOverlay(const fs::path& self_exe) {
    const fs::path build_dir = ResolveRuntimeBinDir();
    const fs::path cli_exe = build_dir / "openscarlett.exe";
    const fs::path dummy_exe = build_dir / "test_guest_dummy.exe";
    OS_REQUIRE(fs::exists(cli_exe));
    OS_REQUIRE(fs::exists(dummy_exe));
    OS_REQUIRE(fs::exists(self_exe));

    const fs::path sandbox = (ResolveScratchRoot() / "live_pkg_cow").make_preferred();
    std::error_code ec;
    fs::remove_all(sandbox, ec);

    // --- Part A: Launch `test_guest_dummy.exe` purely via `openscarlett run <package_dir>` ---
    {
        const fs::path pkg_dir = sandbox / "dummy_pkg";
        fs::create_directories(pkg_dir, ec);
        fs::copy_file(dummy_exe, pkg_dir / "DummyTitle_xs.exe", fs::copy_options::overwrite_existing);
        WriteFileBytes(pkg_dir / "game_asset.txt", "OPENSCARLETT_GAME_ASSET_V1");
        WriteFileBytes(
            pkg_dir / "MicrosoftGame.Config",
            "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n"
            "<Game configVersion=\"1\">\n"
            "  <Identity Name=\"OpenScarlett.DummyPkg\" Publisher=\"CN=Test\" Version=\"1.0.0.0\"/>\n"
            "  <TitleId>7E750470</TitleId>\n"
            "  <ExecutableList>\n"
            "    <Executable Name=\"DummyTitle_xs.exe\" Id=\"Game\" TargetDeviceFamily=\"Scarlett\"/>\n"
            "  </ExecutableList>\n"
            "</Game>\n");

        const DirSnapshot snap_before = HashDirectoryTree(pkg_dir);
        const fs::path tel_path = sandbox / "dummy_pkg_telemetry.json";
        const fs::path vfs_t = sandbox / "dummy_T";

        std::wstring cmd =
            L"\"" + cli_exe.wstring() + L"\" run \"" + pkg_dir.wstring() +
            L"\" --shim-dir \"" + build_dir.wstring() +
            L"\" --vfs-t \"" + vfs_t.wstring() +
            L"\" --telemetry \"" + tel_path.wstring() +
            L"\" --timeout-ms 30000";

        STARTUPINFOW si{};
        si.cb = sizeof(si);
        PROCESS_INFORMATION pi{};
        OS_REQUIRE(::CreateProcessW(cli_exe.c_str(), cmd.data(), nullptr, nullptr, TRUE,
                                    0, nullptr, nullptr, &si, &pi) != 0);
        OS_REQUIRE(::WaitForSingleObject(pi.hProcess, 30000) == WAIT_OBJECT_0);
        DWORD rc = 999;
        OS_REQUIRE(::GetExitCodeProcess(pi.hProcess, &rc) != 0);
        ::CloseHandle(pi.hThread);
        ::CloseHandle(pi.hProcess);
        OS_REQUIRE(rc == 0);

        const DirSnapshot snap_after = HashDirectoryTree(pkg_dir);
        OS_REQUIRE(snap_after.fnv1a_hash == snap_before.fnv1a_hash);
        OS_REQUIRE(snap_after.entries == snap_before.entries);
        std::printf("[PASS] openscarlett run <package_dir> launched DummyTitle_xs.exe from MicrosoftGame.Config\n");
    }

    // --- Part B: Full live CoW overlay + forwarder test proving 100% byte-identical G:\ ---
    {
        const fs::path pkg_dir = sandbox / "cow_pkg";
        fs::create_directories(pkg_dir / "empty_base_dir", ec);
        fs::copy_file(self_exe, pkg_dir / "CowGuest.exe", fs::copy_options::overwrite_existing);
        WriteFileBytes(pkg_dir / "base_data.txt", "BASE_ORIGINAL_BYTES_V1");
        WriteFileBytes(pkg_dir / "move_me.txt", "MOVE_PAYLOAD_77");
        WriteFileBytes(pkg_dir / "delete_me_w.txt", "DELETE_W_PAYLOAD");
        WriteFileBytes(pkg_dir / "delete_me_a.txt", "DELETE_A_PAYLOAD");

        // Write synthetic entryless forwarder DLL: ForwardRoInit -> winrt_xs.RoInitialize
        const auto fwd_dll = BuildSyntheticExportDll("fwd_to_winrt.dll", 1, {
            {"ForwardRoInit", 0, 0, "winrt_xs.RoInitialize"},
        });
        WriteBinaryVec(pkg_dir / "fwd_to_winrt.dll", fwd_dll);

        WriteFileBytes(
            pkg_dir / "MicrosoftGame.Config",
            "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n"
            "<Game configVersion=\"1\">\n"
            "  <Identity Name=\"OpenScarlett.CowVfsTest\" Publisher=\"CN=OpenScarlett\" Version=\"1.0.0.0\"/>\n"
            "  <TitleId>41525331</TitleId>\n"
            "  <ExecutableList>\n"
            "    <Executable Name=\"CowGuest.exe\" Id=\"Game\" TargetDeviceFamily=\"Scarlett\"/>\n"
            "  </ExecutableList>\n"
            "</Game>\n");

        // Ensure no inherited OPENSCARLETT_VFS_G_OVERLAY / S overrides interfere with per-TitleId auto-derivation,
        // and wipe any stale per-TitleId overlay from previous runs so the test is 100% idempotent.
        ::SetEnvironmentVariableW(L"OPENSCARLETT_VFS_G_OVERLAY", nullptr);
        ::SetEnvironmentVariableW(L"OPENSCARLETT_VFS_S", nullptr);
        ::SetEnvironmentVariableW(L"OPENSCARLETT_VFS_G", nullptr);
        const std::wstring default_vfs_root = openscarlett::ResolveDefaultVfsRootW(build_dir.wstring());
        if (!default_vfs_root.empty()) {
            fs::remove_all(fs::path(default_vfs_root) / L"G_overlay" / L"41525331", ec);
            fs::remove_all(fs::path(default_vfs_root) / L"S" / L"41525331", ec);
        }
        const std::wstring env_temp = ReadEnvStrW(L"TEMP");
        if (!env_temp.empty()) {
            fs::remove_all(fs::path(env_temp) / L"vfs" / L"G_overlay" / L"41525331", ec);
        }
        const std::wstring env_save = ReadEnvStrW(L"OPENSCARLETT_SAVE_ROOT");
        if (!env_save.empty()) {
            fs::remove_all(fs::path(env_save) / L"41525331", ec);
        }

        const DirSnapshot snap_before = HashDirectoryTree(pkg_dir);
        const fs::path tel_path = sandbox / "cow_pkg_telemetry.json";
        const fs::path vfs_t = sandbox / "cow_T";

        std::wstring cmd =
            L"\"" + cli_exe.wstring() + L"\" run \"" + pkg_dir.wstring() +
            L"\" --shim-dir \"" + build_dir.wstring() +
            L"\" --vfs-t \"" + vfs_t.wstring() +
            L"\" --telemetry \"" + tel_path.wstring() +
            L"\" --timeout-ms 30000 -- --cow-guest-child";

        STARTUPINFOW si{};
        si.cb = sizeof(si);
        PROCESS_INFORMATION pi{};
        OS_REQUIRE(::CreateProcessW(cli_exe.c_str(), cmd.data(), nullptr, nullptr, TRUE,
                                    0, nullptr, nullptr, &si, &pi) != 0);
        OS_REQUIRE(::WaitForSingleObject(pi.hProcess, 30000) == WAIT_OBJECT_0);
        DWORD rc = 999;
        OS_REQUIRE(::GetExitCodeProcess(pi.hProcess, &rc) != 0);
        ::CloseHandle(pi.hThread);
        ::CloseHandle(pi.hProcess);
        OS_REQUIRE(rc == 0);

        // Verify original target package directory is 100% BYTE-IDENTICAL!
        const DirSnapshot snap_after = HashDirectoryTree(pkg_dir);
        OS_REQUIRE(snap_after.fnv1a_hash == snap_before.fnv1a_hash);
        OS_REQUIRE(snap_after.entries == snap_before.entries);

        // Verify telemetry recorded forwarded export resolution, versioned DLL alias routing & CoW VFS calls
        OS_REQUIRE(fs::exists(tel_path));
        const std::string tel_json = ReadFileBytes(tel_path);
        OS_REQUIRE(tel_json.find("ForwardRoInit->winrt_xs.RoInitialize") != std::string::npos);
        OS_REQUIRE(tel_json.find("dll_alias:Microsoft.Xbox.Services.141.GDK.C.Thunks.dll->Microsoft.Xbox.Services.GDK.C.dll") != std::string::npos);
        OS_REQUIRE(tel_json.find("DeleteFileW") != std::string::npos);
        OS_REQUIRE(tel_json.find("MoveFileExW") != std::string::npos);
        OS_REQUIRE(tel_json.find("RemoveDirectoryW") != std::string::npos);

        std::printf("[PASS] Live CoW overlay VFS + forwarder GetProcAddress + versioned alias routing verified "
                    "(G:\\ pkg hash=0x%016llX byte-identical)\n",
                    static_cast<unsigned long long>(snap_after.fnv1a_hash));
    }
}

// ---------------------------------------------------------------------------
// Test 8: Default Work / VFS / Telemetry Path Resolution (Zero C:\ Leak)
// ---------------------------------------------------------------------------
struct ScopedEnvVarW {
    std::wstring name;
    bool had_prev = false;
    std::wstring prev_val;

    explicit ScopedEnvVarW(std::wstring var_name) : name(std::move(var_name)) {
        DWORD needed = ::GetEnvironmentVariableW(name.c_str(), nullptr, 0);
        if (needed > 0) {
            had_prev = true;
            prev_val.resize(needed, L'\0');
            DWORD written = ::GetEnvironmentVariableW(name.c_str(), prev_val.data(), needed);
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

bool StartsWithDriveCW(std::wstring_view path) noexcept {
    return path.size() >= 2 && (path[0] == L'C' || path[0] == L'c') && path[1] == L':';
}

void TestDefaultWorkDirResolution() {
    using namespace openscarlett;

    const fs::path sandbox = (ResolveScratchRoot() / "workdir_resolution").make_preferred();
    std::error_code ec;
    fs::remove_all(sandbox, ec);
    fs::create_directories(sandbox, ec);

    ScopedEnvVarW guard_work(L"OPENSCARLETT_WORK_DIR");
    ScopedEnvVarW guard_temp(L"TEMP");
    ScopedEnvVarW guard_tmp(L"TMP");
    ScopedEnvVarW guard_vfs_t(L"OPENSCARLETT_VFS_T");
    ScopedEnvVarW guard_vfs_s(L"OPENSCARLETT_VFS_S");
    ScopedEnvVarW guard_vfs_ovl(L"OPENSCARLETT_VFS_G_OVERLAY");
    ScopedEnvVarW guard_save(L"OPENSCARLETT_SAVE_ROOT");

    ::SetEnvironmentVariableW(L"OPENSCARLETT_WORK_DIR", nullptr);
    ::SetEnvironmentVariableW(L"OPENSCARLETT_VFS_T", nullptr);
    ::SetEnvironmentVariableW(L"OPENSCARLETT_VFS_S", nullptr);
    ::SetEnvironmentVariableW(L"OPENSCARLETT_VFS_G_OVERLAY", nullptr);
    ::SetEnvironmentVariableW(L"OPENSCARLETT_SAVE_ROOT", nullptr);
    // Simulate default Windows %TEMP% pointing at C:\!
    ::SetEnvironmentVariableW(L"TEMP", L"C:\\Users\\SimulatedUser\\AppData\\Local\\Temp");
    ::SetEnvironmentVariableW(L"TMP", L"C:\\Users\\SimulatedUser\\AppData\\Local\\Temp");

    // 8A. Executable inside a build\ directory -> lands under <parent>\.tmp\openscarlett_run
    //     (never falls back to C:\...\Temp; stays off C:\ whenever the bundle/repo itself is off C:\!)
    const bool sandbox_off_c = !StartsWithDriveCW(sandbox.wstring());
    const fs::path repo_root = sandbox / "fake_repo";
    const fs::path fake_build = repo_root / "build";
    fs::create_directories(fake_build, ec);

    // Anchors on C:\ are skipped on purpose, so when this test itself runs from C:\ every
    // anchor below resolves to the simulated %TEMP%\openscarlett instead.
    const std::wstring c_temp_fallback = L"C:\\Users\\SimulatedUser\\AppData\\Local\\Temp\\openscarlett";
    const std::wstring expect_build_work =
        sandbox_off_c ? (repo_root / L".tmp" / L"openscarlett_run").wstring() : c_temp_fallback;

    const std::wstring work_build = ResolveDefaultWorkDirW(fake_build.wstring());
    if (sandbox_off_c) {
        OS_REQUIRE(!StartsWithDriveCW(work_build));
    }
    OS_REQUIRE(work_build == expect_build_work);

    const std::wstring vfs_build = ResolveDefaultVfsRootW(fake_build.wstring());
    if (sandbox_off_c) {
        OS_REQUIRE(!StartsWithDriveCW(vfs_build));
    }
    OS_REQUIRE(vfs_build == (fs::path(expect_build_work) / L"vfs").wstring());

    const std::wstring tel_build = ResolveDefaultTelemetryDirW(fake_build.wstring());
    if (sandbox_off_c) {
        OS_REQUIRE(!StartsWithDriveCW(tel_build));
    }
    OS_REQUIRE(tel_build == (fs::path(expect_build_work) / L"telemetry").wstring());

    // Multi-config build\Release walks up to <repo_root>\.tmp\openscarlett_run
    const fs::path fake_build_rel = fake_build / "Release";
    fs::create_directories(fake_build_rel, ec);
    OS_REQUIRE(ResolveDefaultWorkDirW(fake_build_rel.wstring()) == expect_build_work);

    // 8B. Standalone release directory -> lands under <dir>\.openscarlett_tmp
    const fs::path standalone_dir = sandbox / "standalone_release";
    fs::create_directories(standalone_dir, ec);
    const std::wstring work_standalone = ResolveDefaultWorkDirW(standalone_dir.wstring());
    if (sandbox_off_c) {
        OS_REQUIRE(!StartsWithDriveCW(work_standalone));
    }
    OS_REQUIRE(work_standalone ==
               (sandbox_off_c ? (standalone_dir / L".openscarlett_tmp").wstring() : c_temp_fallback));

    // 8C. Default BuildDefaultConfig() from this E:\ binary NEVER leaks to C:\ even with TEMP=C:\...!
    const fs::path bin_dir = ResolveRuntimeBinDir();
    if (!StartsWithDriveCW(bin_dir.wstring())) {
        const VfsMountConfig def_cfg = VfsMounts::BuildDefaultConfig(L"E:\\DummyGame");
        OS_REQUIRE(!StartsWithDriveCW(def_cfg.t_root));
        OS_REQUIRE(!StartsWithDriveCW(def_cfg.s_root));
        OS_REQUIRE(!StartsWithDriveCW(def_cfg.g_overlay_root));
    }

    // 8D. OPENSCARLETT_WORK_DIR override takes highest precedence
    const fs::path explicit_work = sandbox / "custom_work_dir";
    ::SetEnvironmentVariableW(L"OPENSCARLETT_WORK_DIR", explicit_work.c_str());
    OS_REQUIRE(ResolveDefaultWorkDirW(fake_build.wstring()) == explicit_work.wstring());
    OS_REQUIRE(ResolveDefaultVfsRootW(fake_build.wstring()) == (explicit_work / L"vfs").wstring());
    OS_REQUIRE(ResolveDefaultTelemetryDirW(fake_build.wstring()) == (explicit_work / L"telemetry").wstring());
    const VfsMountConfig env_cfg = VfsMounts::BuildDefaultConfig(L"E:\\DummyGame");
    OS_REQUIRE(env_cfg.t_root == (explicit_work / L"vfs" / L"T").wstring());
    OS_REQUIRE(env_cfg.s_root == (explicit_work / L"vfs" / L"S").wstring());
    OS_REQUIRE(env_cfg.g_overlay_root == (explicit_work / L"vfs" / L"G_overlay").wstring());

    // 8E. Explicitly redirected non-C:\ %TEMP% (e.g. build.cmd / build_wt.cmd) is honored without C:\ leakage
    ::SetEnvironmentVariableW(L"OPENSCARLETT_WORK_DIR", nullptr);
    const fs::path custom_non_c_temp = sandbox / "non_c_temp";
    fs::create_directories(custom_non_c_temp, ec);
    ::SetEnvironmentVariableW(L"TEMP", custom_non_c_temp.c_str());
    ::SetEnvironmentVariableW(L"TMP", custom_non_c_temp.c_str());
    if (!StartsWithDriveCW(custom_non_c_temp.wstring())) {
        OS_REQUIRE(ResolveDefaultWorkDirW(fake_build.wstring()) == custom_non_c_temp.wstring());
    }

    // 8F. Fallback to %TEMP%\openscarlett ONLY when the anchor directory is unwritable
    ::SetEnvironmentVariableW(L"TEMP", L"C:\\Users\\SimulatedUser\\AppData\\Local\\Temp");
    ::SetEnvironmentVariableW(L"TMP", L"C:\\Users\\SimulatedUser\\AppData\\Local\\Temp");

    // Place a regular file where ".openscarlett_tmp" directory would be created to simulate read-only failure.
    // Note: ResolveDefaultWorkDirW only returns the fallback path string and does NOT touch C:\ on disk.
    const fs::path unwritable_anchor = sandbox / "unwritable_dir";
    fs::create_directories(unwritable_anchor, ec);
    WriteFileBytes(unwritable_anchor / ".openscarlett_tmp", "BLOCK_DIR_CREATION");
    OS_REQUIRE(ResolveDefaultWorkDirW(unwritable_anchor.wstring()) ==
               L"C:\\Users\\SimulatedUser\\AppData\\Local\\Temp\\openscarlett");

    std::printf("[PASS] Default work/VFS/telemetry path resolution verified (OPENSCARLETT_WORK_DIR + zero C:\\ leak)\n");
}

// ---------------------------------------------------------------------------
// Test 9: Versioned & Thunk GDK DLL Routing Aliases + Passthrough Overrides
// ---------------------------------------------------------------------------
void TestVersionedAndThunkDllAliases() {
    using namespace openscarlett;

    // 9A. ClassifyImportDll recognizes versioned/thunk GDK DLLs and XGamingRuntimeThunks.dll
    OS_REQUIRE(ClassifyImportDll("Microsoft.Xbox.Services.141.GDK.C.Thunks.dll") == DllCategory::GdkRuntime);
    OS_REQUIRE(ClassifyImportDll("Microsoft.Xbox.Services.142.GDK.C.Thunks.dll") == DllCategory::GdkRuntime);
    OS_REQUIRE(ClassifyImportDll("Microsoft.Xbox.Services.141.GDK.C.dll") == DllCategory::GdkRuntime);
    OS_REQUIRE(ClassifyImportDll("libHttpClient.141.GDK.C.dll") == DllCategory::GdkRuntime);
    OS_REQUIRE(ClassifyImportDll("libHttpClient.GDK.C.dll") == DllCategory::GdkRuntime);
    OS_REQUIRE(ClassifyImportDll("XGamingRuntimeThunks.dll") == DllCategory::GdkRuntime);

    // 9B. ResolveShimAlias exact & pattern matching
    std::string canon;
    OS_REQUIRE(ResolveShimAlias("Microsoft.Xbox.Services.140.GDK.C.Thunks.dll", canon));
    OS_REQUIRE(canon == "Microsoft.Xbox.Services.GDK.C.dll");
    OS_REQUIRE(ResolveShimAlias("Microsoft.Xbox.Services.141.GDK.C.Thunks.dll", canon));
    OS_REQUIRE(canon == "Microsoft.Xbox.Services.GDK.C.dll");
    OS_REQUIRE(ResolveShimAlias("Microsoft.Xbox.Services.142.GDK.C.Thunks.dll", canon));
    OS_REQUIRE(canon == "Microsoft.Xbox.Services.GDK.C.dll");
    OS_REQUIRE(ResolveShimAlias("Microsoft.Xbox.Services.143.GDK.C.Thunks.dll", canon));
    OS_REQUIRE(canon == "Microsoft.Xbox.Services.GDK.C.dll");
    OS_REQUIRE(ResolveShimAlias("Microsoft.Xbox.Services.141.GDK.C.dll", canon));
    OS_REQUIRE(canon == "Microsoft.Xbox.Services.GDK.C.dll");
    OS_REQUIRE(ResolveShimAlias("Microsoft.Xbox.Services.GDK.C.Thunks.dll", canon));
    OS_REQUIRE(canon == "Microsoft.Xbox.Services.GDK.C.dll");
    OS_REQUIRE(ResolveShimAlias(R"(D:\Game\Plugins\x86_64\Microsoft.Xbox.Services.141.GDK.C.Thunks.dll)", canon));
    OS_REQUIRE(canon == "Microsoft.Xbox.Services.GDK.C.dll");
    OS_REQUIRE(ResolveShimAlias("xsapi.dll", canon));
    OS_REQUIRE(canon == "Microsoft.Xbox.Services.GDK.C.dll");

    OS_REQUIRE(ResolveShimAlias("libHttpClient.141.GDK.C.dll", canon));
    OS_REQUIRE(canon == "libHttpClient.GDK.dll");
    OS_REQUIRE(ResolveShimAlias("libHttpClient.142.GDK.dll", canon));
    OS_REQUIRE(canon == "libHttpClient.GDK.dll");
    OS_REQUIRE(ResolveShimAlias("libHttpClient.GDK.C.dll", canon));
    OS_REQUIRE(canon == "libHttpClient.GDK.dll");
    OS_REQUIRE(ResolveShimAlias("libHttpClient.141.GDK.C.Thunks.dll", canon));
    OS_REQUIRE(canon == "libHttpClient.GDK.dll");

    // Canonical names & XGamingRuntimeThunks.dll are NOT aliased by default
    OS_REQUIRE(!ResolveShimAlias("Microsoft.Xbox.Services.GDK.C.dll", canon));
    OS_REQUIRE(!ResolveShimAlias("libHttpClient.GDK.dll", canon));
    OS_REQUIRE(!ResolveShimAlias("XGamingRuntimeThunks.dll", canon));

    // 9C. DllRoutingTable resolution with filesystem backing
    const fs::path root = (ResolveScratchRoot() / "alias_routing_unit").make_preferred();
    std::error_code ec;
    fs::remove_all(root, ec);
    const fs::path shim_dir = root / "shims";
    const fs::path guest_dir = root / "guest";
    WriteFileBytes(shim_dir / "Microsoft.Xbox.Services.GDK.C.dll", "SHIM_XSAPI");
    WriteFileBytes(shim_dir / "libHttpClient.GDK.dll", "SHIM_LHC");
    WriteFileBytes(shim_dir / "xgameruntime.dll", "SHIM_XGR");
    WriteFileBytes(guest_dir / "XGamingRuntimeThunks.dll", "GUEST_THUNKS");
    WriteFileBytes(guest_dir / "Microsoft.Xbox.Services.141.GDK.C.Thunks.dll", "GUEST_XSAPI_THUNKS");

    DllRoutingTable table;
    auto r1 = table.ResolveRoute("Microsoft.Xbox.Services.141.GDK.C.Thunks.dll",
                                 shim_dir.wstring(), guest_dir.wstring());
    OS_REQUIRE(r1.policy == DllRoutePolicy::Shim);
    OS_REQUIRE(r1.aliased);
    OS_REQUIRE(r1.requested_name == "Microsoft.Xbox.Services.141.GDK.C.Thunks.dll");
    OS_REQUIRE(r1.canonical_name == "Microsoft.Xbox.Services.GDK.C.dll");
    OS_REQUIRE(r1.resolved_path == (shim_dir / L"Microsoft.Xbox.Services.GDK.C.dll").wstring());

    auto r2 = table.ResolveRoute("Microsoft.Xbox.Services.142.GDK.C.Thunks.dll",
                                 shim_dir.wstring(), guest_dir.wstring());
    OS_REQUIRE(r2.policy == DllRoutePolicy::Shim);
    OS_REQUIRE(r2.aliased);
    OS_REQUIRE(r2.canonical_name == "Microsoft.Xbox.Services.GDK.C.dll");

    auto r3 = table.ResolveRoute("libHttpClient.141.GDK.C.dll",
                                 shim_dir.wstring(), guest_dir.wstring());
    OS_REQUIRE(r3.policy == DllRoutePolicy::Shim);
    OS_REQUIRE(r3.aliased);
    OS_REQUIRE(r3.canonical_name == "libHttpClient.GDK.dll");
    OS_REQUIRE(r3.resolved_path == (shim_dir / L"libHttpClient.GDK.dll").wstring());

    // XGamingRuntimeThunks.dll defaults to NativeGuestDll when present in guest_dir (lets it call LoadLibrary("xgameruntime.dll"))
    auto r4 = table.ResolveRoute("XGamingRuntimeThunks.dll",
                                 shim_dir.wstring(), guest_dir.wstring());
    OS_REQUIRE(r4.policy == DllRoutePolicy::NativeGuestDll);
    OS_REQUIRE(!r4.aliased);
    OS_REQUIRE(r4.resolved_path == (guest_dir / L"XGamingRuntimeThunks.dll").wstring());

    // 9D. OPENSCARLETT_DLL_ROUTING custom source=target and source=passthrough overrides
    {
        ScopedEnvVarW guard_route(L"OPENSCARLETT_DLL_ROUTING");
        OS_REQUIRE(::SetEnvironmentVariableA(
                       "OPENSCARLETT_DLL_ROUTING",
                       "XGamingRuntimeThunks.dll=xgameruntime.dll;"
                       "Microsoft.Xbox.Services.141.GDK.C.Thunks.dll=passthrough;"
                       "CustomHttp.dll=libHttpClient.GDK.dll") != 0);
        DllRoutingTable custom = DllRoutingTable::CreateWithEnvOverrides();

        auto c1 = custom.ResolveRoute("XGamingRuntimeThunks.dll",
                                      shim_dir.wstring(), guest_dir.wstring());
        OS_REQUIRE(c1.policy == DllRoutePolicy::Shim);
        OS_REQUIRE(c1.aliased);
        OS_REQUIRE(c1.from_override);
        OS_REQUIRE(c1.canonical_name == "xgameruntime.dll");
        OS_REQUIRE(c1.resolved_path == (shim_dir / L"xgameruntime.dll").wstring());

        auto c2 = custom.ResolveRoute("Microsoft.Xbox.Services.141.GDK.C.Thunks.dll",
                                      shim_dir.wstring(), guest_dir.wstring());
        OS_REQUIRE(c2.policy == DllRoutePolicy::Windows);
        OS_REQUIRE(!c2.aliased);
        OS_REQUIRE(c2.from_override);
        OS_REQUIRE(c2.resolved_path.empty());

        // Unrelated versioned variant STILL aliases normally!
        auto c3 = custom.ResolveRoute("Microsoft.Xbox.Services.142.GDK.C.Thunks.dll",
                                      shim_dir.wstring(), guest_dir.wstring());
        OS_REQUIRE(c3.policy == DllRoutePolicy::Shim);
        OS_REQUIRE(c3.aliased);
        OS_REQUIRE(c3.canonical_name == "Microsoft.Xbox.Services.GDK.C.dll");

        auto c4 = custom.ResolveRoute("CustomHttp.dll",
                                      shim_dir.wstring(), guest_dir.wstring());
        OS_REQUIRE(c4.policy == DllRoutePolicy::Shim);
        OS_REQUIRE(c4.aliased);
        OS_REQUIRE(c4.from_override);
        OS_REQUIRE(c4.canonical_name == "libHttpClient.GDK.dll");
        OS_REQUIRE(c4.resolved_path == (shim_dir / L"libHttpClient.GDK.dll").wstring());
    }

    std::printf("[PASS] Versioned/thunk GDK DLL aliases & OPENSCARLETT_DLL_ROUTING target/passthrough overrides verified\n");
}

// ---------------------------------------------------------------------------
// Test 10: Microsoft Store / Xbox Play Anywhere Bootstrapper Diagnostics
// ---------------------------------------------------------------------------
void TestStoreBootstrapDiagnostics() {
    using namespace openscarlett;

    // 10A. WindowsApps gamelaunchhelper.exe exiting with 0 and 0 tracked symbols -> detected!
    {
        LaunchResult lr{};
        lr.exit_code = 0;
        lr.timed_out = false;
        lr.resolved_exe_path = R"(C:\Program Files\WindowsApps\Publisher.Title_1.0.0.0_x64__abc\gamelaunchhelper.exe)";
        const StoreBootstrapDiagnostic d = DiagnoseStoreBootstrapper(lr, 0, false);
        OS_REQUIRE(d.suspected_store_bootstrapper);
        OS_REQUIRE(d.in_windows_apps);
        OS_REQUIRE(d.is_gamelaunchhelper);
        OS_REQUIRE(d.message.find("GamingServices") != std::string::npos);
        OS_REQUIRE(d.message.find("AppModel") != std::string::npos);
        OS_REQUIRE(d.message.find("unpacked package directory") != std::string::npos);
    }

    // 10B. XboxGames package with MicrosoftGame.config exiting 0 with 0 symbols -> detected!
    {
        LaunchResult lr{};
        lr.exit_code = 0;
        lr.timed_out = false;
        lr.resolved_exe_path = R"(E:\XboxGames\SampleTitle\Content\Game.exe)";
        lr.resolved_config_path = R"(E:\XboxGames\SampleTitle\Content\MicrosoftGame.config)";
        const StoreBootstrapDiagnostic d = DiagnoseStoreBootstrapper(lr, 0, true);
        OS_REQUIRE(d.suspected_store_bootstrapper);
        OS_REQUIRE(d.in_xbox_games);
        OS_REQUIRE(d.has_game_config);
        OS_REQUIRE(d.reason.find("XboxGames") != std::string::npos);
    }

    // 10C. Normal GDK title with tracked symbols -> NOT flagged!
    {
        LaunchResult lr{};
        lr.exit_code = 0;
        lr.timed_out = false;
        lr.resolved_exe_path = R"(E:\XboxGames\SampleTitle\Content\Game.exe)";
        lr.resolved_config_path = R"(E:\XboxGames\SampleTitle\Content\MicrosoftGame.config)";
        const StoreBootstrapDiagnostic d = DiagnoseStoreBootstrapper(lr, 12, true);
        OS_REQUIRE(!d.suspected_store_bootstrapper);
    }

    // 10D. Non-zero exit or timeout -> NOT flagged!
    {
        LaunchResult lr{};
        lr.exit_code = 1;
        lr.timed_out = false;
        lr.resolved_exe_path = R"(C:\Program Files\WindowsApps\Publisher.Title\gamelaunchhelper.exe)";
        OS_REQUIRE(!DiagnoseStoreBootstrapper(lr, 0, false).suspected_store_bootstrapper);

        lr.exit_code = 0;
        lr.timed_out = true;
        OS_REQUIRE(!DiagnoseStoreBootstrapper(lr, 0, false).suspected_store_bootstrapper);
    }

    std::printf("[PASS] Store-bootstrapper diagnostic helper verified\n");
}

}  // namespace

int main(int argc, char** argv) {
    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "--cow-guest-child") == 0) {
            return RunCowGuestChild();
        }
    }

    TestGameConfigParserAndResolution();
    TestCowVfsUnit();
    TestPeExportForwarders();
    TestPeTlsCallbacks();
    TestPeExceptionTableRegistration();
    TestDllRoutingTable();
    TestDefaultWorkDirResolution();
    TestVersionedAndThunkDllAliases();
    TestStoreBootstrapDiagnostics();

    fs::path self_exe;
    wchar_t mod_buf[MAX_PATH]{};
    DWORD len = ::GetModuleFileNameW(nullptr, mod_buf, MAX_PATH);
    OS_REQUIRE(len > 0 && len < MAX_PATH);
    self_exe = fs::path(std::wstring(mod_buf, len));

    TestLivePackageLaunchAndCowOverlay(self_exe);

    std::printf("[PASS] test_loader_vfs_config (all MicrosoftGame.Config, CoW VFS, PE forwarder/TLS/.pdata, routing, workdir, alias & diagnostic checks passed)\n");
    return 0;
}
