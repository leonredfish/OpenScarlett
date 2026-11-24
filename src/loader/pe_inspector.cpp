#include "openscarlett/loader/pe_inspector.h"

#include <algorithm>
#include <cctype>
#include <cstring>
#include <fstream>
#include <unordered_map>
#include <unordered_set>

#include "openscarlett/loader/vfs_mounts.h"

#if defined(_WIN32)
#include <windows.h>
#endif

namespace openscarlett {

namespace {

template <typename T>
bool ReadPod(const std::vector<uint8_t>& buf, size_t offset, T& out) {
    if (offset > buf.size() || sizeof(T) > buf.size() - offset) return false;
    std::memcpy(&out, buf.data() + offset, sizeof(T));
    return true;
}

bool ReadCString(const std::vector<uint8_t>& buf, size_t offset, size_t max_len, std::string& out) {
    if (offset >= buf.size()) return false;
    size_t limit = std::min(buf.size() - offset, max_len);
    size_t len = 0;
    while (len < limit && buf[offset + len] != 0) ++len;
    if (len == limit && (offset + len >= buf.size() || buf[offset + len] != 0)) return false;
    out.assign(reinterpret_cast<const char*>(buf.data() + offset), len);
    return true;
}

std::string ToLower(std::string_view s) {
    std::string out(s);
    for (char& c : out) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return out;
}

std::string TrimAscii(std::string_view s) {
    size_t b = 0;
    while (b < s.size() && std::isspace(static_cast<unsigned char>(s[b])) != 0) ++b;
    size_t e = s.size();
    while (e > b && std::isspace(static_cast<unsigned char>(s[e - 1])) != 0) --e;
    return std::string(s.substr(b, e - b));
}

struct SectionRange {
    uint32_t vaddr = 0;
    uint32_t vsize = 0;
    uint32_t raw_ptr = 0;
    uint32_t raw_size = 0;
    uint32_t characteristics = 0;
};

bool RvaToFileOffset(const std::vector<SectionRange>& sections, uint32_t rva, size_t file_size, size_t& out_off) {
    for (const auto& s : sections) {
        uint32_t span = std::max(s.vsize, s.raw_size);
        if (rva >= s.vaddr && rva - s.vaddr < span) {
            uint32_t delta = rva - s.vaddr;
            if (delta >= s.raw_size) return false;
            size_t off = static_cast<size_t>(s.raw_ptr) + delta;
            if (off >= file_size) return false;
            out_off = off;
            return true;
        }
    }
    return false;
}

bool RvaToSectionSlice(const std::vector<SectionRange>& sections,
                       uint32_t rva,
                       size_t file_size,
                       size_t& out_off,
                       size_t& out_avail) {
    for (const auto& s : sections) {
        const uint32_t span = std::max(s.vsize, s.raw_size);
        if (rva >= s.vaddr && rva - s.vaddr < span) {
            const uint32_t delta = rva - s.vaddr;
            if (delta >= s.raw_size) {
                return false;
            }
            const size_t sec_raw_end =
                std::min<size_t>(file_size, static_cast<size_t>(s.raw_ptr) + static_cast<size_t>(s.raw_size));
            const size_t off = static_cast<size_t>(s.raw_ptr) + static_cast<size_t>(delta);
            if (off >= sec_raw_end) {
                return false;
            }
            out_off = off;
            out_avail = sec_raw_end - off;
            return true;
        }
    }
    return false;
}

bool ReadExportNameString(const std::vector<uint8_t>& buf,
                          size_t offset,
                          size_t section_avail,
                          size_t max_len,
                          std::string& out) {
    out.clear();
    if (offset >= buf.size() || section_avail == 0u) {
        return false;
    }
    const size_t limit = std::min<size_t>({buf.size() - offset, section_avail, max_len});
    size_t len = 0u;
    while (len < limit && buf[offset + len] != 0u) {
        const uint8_t ch = buf[offset + len];
        if (ch < 0x20u || ch == 0x7Fu) {
            return false;
        }
        ++len;
    }
    if (len == 0u || len >= limit || buf[offset + len] != 0u) {
        return false;
    }
    out.assign(reinterpret_cast<const char*>(buf.data() + offset), len);
    return true;
}

std::string NormalizeKnownDllBasename(std::string_view raw_name) {
    std::string trimmed = TrimAscii(raw_name);
    if (trimmed.empty()) {
        return {};
    }
    const size_t slash = trimmed.find_last_of("\\/");
    if (slash != std::string::npos) {
        trimmed = trimmed.substr(slash + 1);
    }
    if (trimmed.empty()) {
        return {};
    }
    std::string lo = ToLower(trimmed);
    if (lo.size() < 4 || lo.compare(lo.size() - 4, 4, ".dll") != 0) {
        lo.append(".dll");
    }
    return lo;
}

const std::unordered_set<std::string>& KnownDllSet() {
    static const std::unordered_set<std::string> s_known = []() {
        std::unordered_set<std::string> set;
        static constexpr const char* kFallbackKnownDlls[] = {
            "ntdll.dll",     "kernel32.dll",  "kernelbase.dll", "user32.dll",
            "gdi32.dll",     "advapi32.dll",  "ole32.dll",      "oleaut32.dll",
            "rpcrt4.dll",    "sechost.dll",   "combase.dll",    "shlwapi.dll",
            "ws2_32.dll",    "ucrtbase.dll",  "shell32.dll",    "msvcrt.dll",
            "imm32.dll",     "setupapi.dll",  "clbcatq.dll",    "comdlg32.dll",
            "coml2.dll",     "difxapi.dll",   "gdiplus.dll",    "imagehlp.dll",
            "msctf.dll",     "normaliz.dll",  "nsi.dll",        "psapi.dll",
            "shcore.dll",    "wldap32.dll",   "wow64.dll",      "wow64cpu.dll",
            "wow64win.dll",  "crypt32.dll",   "bcrypt.dll",
        };
        for (const char* name : kFallbackKnownDlls) {
            set.insert(name);
        }
#if defined(_WIN32)
        HKEY hkey = nullptr;
        if (::RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                            L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\KnownDLLs",
                            0,
                            KEY_READ,
                            &hkey) == ERROR_SUCCESS &&
            hkey != nullptr) {
            for (DWORD idx = 0;; ++idx) {
                wchar_t val_name[256]{};
                DWORD val_name_len = 256u;
                DWORD val_type = 0u;
                wchar_t val_data[260]{};
                DWORD val_data_bytes = sizeof(val_data);
                const LSTATUS st = ::RegEnumValueW(hkey,
                                                   idx,
                                                   val_name,
                                                   &val_name_len,
                                                   nullptr,
                                                   &val_type,
                                                   reinterpret_cast<LPBYTE>(val_data),
                                                   &val_data_bytes);
                if (st == ERROR_NO_MORE_ITEMS) {
                    break;
                }
                if (st != ERROR_SUCCESS || (val_type != REG_SZ && val_type != REG_EXPAND_SZ)) {
                    continue;
                }
                const std::string name_lo = ToLower(WideToUtf8(std::wstring_view(val_name, val_name_len)));
                if (name_lo == "dlldirectory" || name_lo == "dlldirectory32") {
                    continue;
                }
                size_t wchar_cnt = val_data_bytes / sizeof(wchar_t);
                while (wchar_cnt > 0 && val_data[wchar_cnt - 1] == L'\0') {
                    --wchar_cnt;
                }
                const std::string dll_u8 = WideToUtf8(std::wstring_view(val_data, wchar_cnt));
                const std::string norm = NormalizeKnownDllBasename(dll_u8);
                if (!norm.empty()) {
                    set.insert(norm);
                }
            }
            ::RegCloseKey(hkey);
        }
#endif
        return set;
    }();
    return s_known;
}

bool FileExistsInDirW(std::wstring_view dir, std::wstring_view filename, std::wstring& out_full) {
    if (dir.empty() || filename.empty()) {
        return false;
    }
    std::wstring candidate(dir);
    while (candidate.size() > 3 && (candidate.back() == L'\\' || candidate.back() == L'/')) {
        candidate.pop_back();
    }
    if (!candidate.empty() && candidate.back() != L'\\') {
        candidate.push_back(L'\\');
    }
    candidate.append(filename);
#if defined(_WIN32)
    DWORD attrs = ::GetFileAttributesW(candidate.c_str());
    if (attrs != INVALID_FILE_ATTRIBUTES && (attrs & FILE_ATTRIBUTE_DIRECTORY) == 0) {
        out_full = std::move(candidate);
        return true;
    }
    return false;
#else
    std::ifstream ifs(WideToUtf8(candidate));
    if (ifs.good()) {
        out_full = std::move(candidate);
        return true;
    }
    return false;
#endif
}

std::string ReadEnvVarA(const char* name) {
#if defined(_WIN32)
    DWORD needed = ::GetEnvironmentVariableA(name, nullptr, 0);
    if (needed == 0) {
        return {};
    }
    std::string out(needed, '\0');
    DWORD written = ::GetEnvironmentVariableA(name, out.data(), needed);
    if (written == 0 || written >= needed) {
        return {};
    }
    out.resize(written);
    return out;
#else
    (void)name;
    return {};
#endif
}

bool ParsePolicyToken(std::string_view token, DllRoutePolicy& out_policy) noexcept {
    const std::string lo = ToLower(TrimAscii(token));
    if (lo == "shim") {
        out_policy = DllRoutePolicy::Shim;
        return true;
    }
    if (lo == "guest" || lo == "native" || lo == "nativeguest" || lo == "nativeguestdll") {
        out_policy = DllRoutePolicy::NativeGuestDll;
        return true;
    }
    if (lo == "windows" || lo == "win" || lo == "system" || lo == "os" || lo == "passthrough") {
        out_policy = DllRoutePolicy::Windows;
        return true;
    }
    return false;
}

bool StripLeadingVersionDot(std::string_view& rest) noexcept {
    size_t i = 0;
    while (i < rest.size() && rest[i] >= '0' && rest[i] <= '9') {
        ++i;
    }
    if (i > 0 && i < rest.size() && rest[i] == '.') {
        rest.remove_prefix(i + 1);
        return true;
    }
    return false;
}

#if defined(_WIN32)
bool ReadMappedPeHeaders64(const void* module_base,
                           const uint8_t*& out_base,
                           const IMAGE_NT_HEADERS64*& out_nt,
                           uint32_t& out_image_size) noexcept {
    if (!module_base) {
        return false;
    }
    const auto* base = static_cast<const uint8_t*>(module_base);
    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew <= 0 || dos->e_lfanew > 0x100000) {
        return false;
    }
    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE ||
        nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        return false;
    }
    out_base = base;
    out_nt = nt;
    out_image_size = nt->OptionalHeader.SizeOfImage;
    return out_image_size >= static_cast<uint32_t>(dos->e_lfanew) + sizeof(IMAGE_NT_HEADERS64);
}

bool MappedVaToRva(uint64_t va,
                   uintptr_t actual_base,
                   uint64_t preferred_base,
                   uint32_t image_size,
                   uint32_t& out_rva) noexcept {
    if (va >= static_cast<uint64_t>(actual_base) &&
        va - static_cast<uint64_t>(actual_base) < image_size) {
        out_rva = static_cast<uint32_t>(va - static_cast<uint64_t>(actual_base));
        return true;
    }
    if (va >= preferred_base && va - preferred_base < image_size) {
        out_rva = static_cast<uint32_t>(va - preferred_base);
        return true;
    }
    return false;
}
#endif

}  // namespace

const char* DllCategoryName(DllCategory category) noexcept {
    switch (category) {
        case DllCategory::WindowsNative: return "WindowsNative";
        case DllCategory::ConsoleExclusive: return "ConsoleExclusive";
        case DllCategory::GdkRuntime: return "GdkRuntime";
        case DllCategory::Middleware: return "Middleware";
        case DllCategory::Other: return "Other";
    }
    return "Other";
}

const char* DllRoutePolicyName(DllRoutePolicy policy) noexcept {
    switch (policy) {
        case DllRoutePolicy::Shim: return "Shim";
        case DllRoutePolicy::NativeGuestDll: return "NativeGuestDll";
        case DllRoutePolicy::Windows: return "Windows";
    }
    return "Windows";
}

bool ResolveShimAlias(std::string_view dll_name, std::string& out_canonical_shim) {
    out_canonical_shim.clear();
    std::string trimmed = TrimAscii(dll_name);
    if (trimmed.empty()) {
        return false;
    }
    const size_t slash = trimmed.find_last_of("\\/");
    if (slash != std::string::npos) {
        trimmed = trimmed.substr(slash + 1);
    }
    if (trimmed.empty()) {
        return false;
    }
    std::string lo = ToLower(trimmed);
    if (lo.size() >= 4 && lo.compare(lo.size() - 4, 4, ".dll") == 0) {
        lo.resize(lo.size() - 4);
    }
    if (lo.empty()) {
        return false;
    }

    // 1. Exact short aliases
    if (lo == "xsapi") {
        out_canonical_shim = "Microsoft.Xbox.Services.GDK.C.dll";
        return true;
    }

    // 2. Versioned / thunk XSAPI DLLs:
    //    Microsoft.Xbox.Services.<ver>.GDK.C(.Thunks)?.dll -> Microsoft.Xbox.Services.GDK.C.dll
    //    Microsoft.Xbox.Services.GDK.C.Thunks.dll          -> Microsoft.Xbox.Services.GDK.C.dll
    constexpr std::string_view kXsapiPrefix = "microsoft.xbox.services.";
    if (lo.size() > kXsapiPrefix.size() && lo.compare(0, kXsapiPrefix.size(), kXsapiPrefix) == 0) {
        std::string_view rest = std::string_view(lo).substr(kXsapiPrefix.size());
        const bool has_ver = StripLeadingVersionDot(rest);
        if (rest == "gdk.c.thunks" || rest == "gdk.thunks" || (has_ver && rest == "gdk.c")) {
            out_canonical_shim = "Microsoft.Xbox.Services.GDK.C.dll";
            return true;
        }
        return false;
    }

    // 3. Versioned / thunk libHttpClient GDK DLLs:
    //    libHttpClient.<ver>.GDK(.C)?(.Thunks)?.dll -> libHttpClient.GDK.dll
    //    libHttpClient.GDK.C(.Thunks)?.dll          -> libHttpClient.GDK.dll
    constexpr std::string_view kHttpPrefix = "libhttpclient.";
    if (lo.size() > kHttpPrefix.size() && lo.compare(0, kHttpPrefix.size(), kHttpPrefix) == 0) {
        std::string_view rest = std::string_view(lo).substr(kHttpPrefix.size());
        const bool has_ver = StripLeadingVersionDot(rest);
        if (rest == "gdk.c" || rest == "gdk.thunks" || rest == "gdk.c.thunks" ||
            (has_ver && rest == "gdk")) {
            out_canonical_shim = "libHttpClient.GDK.dll";
            return true;
        }
        return false;
    }

    return false;
}

DllCategory ClassifyImportDll(const std::string& dll_name) {
    std::string trimmed = TrimAscii(dll_name);
    const size_t slash = trimmed.find_last_of("\\/");
    if (slash != std::string::npos) {
        trimmed = trimmed.substr(slash + 1);
    }
    const std::string lo = ToLower(trimmed);
    if (lo == "d3d12_xs.dll" || lo == "d3d12_x.dll" || lo == "xg_xs.dll" || lo == "xg.dll" ||
        lo == "acphal.dll" || lo == "kernelx.dll" || lo == "xmem.dll" || lo == "dstorage_xs.dll" ||
        lo == "dxcompiler_xs.dll" ||
        lo == "xboxbvhbuilder.dll" || lo == "chad.dll" || lo == "xapu.dll" || lo == "xcrdapi.dll" ||
        lo == "pixevt.dll" ||
        lo == "mfplat_xs.dll" || lo == "advapi32legacy.dll" ||
        lo == "kerneltracecontrol.dll" || lo == "hix_xs.dll" || lo == "xbtp.dll" ||
        lo == "mflnmhelp.dll" || lo == "mfhevcdec.dll" || lo == "gamecoreclient.dll" ||
        lo == "minuserx.dll" || lo == "xtfpix.dll" || lo == "xtfdebugmonitor.dll") {
        return DllCategory::ConsoleExclusive;
    }
    if (lo == "xgameruntime.dll" || lo == "xgamingruntimethunks.dll" ||
        lo == "gameinput.dll" || lo == "dstorage.dll" ||
        lo == "xaudio2_9.dll" || lo == "libhttpclient.gdk.dll" || lo == "xcurl.dll" ||
        lo == "microsoft.xbox.services.gdk.c.dll" || lo == "xsapi.dll" || lo == "winrt_xs.dll") {
        return DllCategory::GdkRuntime;
    }
    std::string alias_target;
    if (ResolveShimAlias(lo, alias_target)) {
        return ClassifyImportDll(alias_target);
    }
    if (lo.find("bink2") != std::string::npos || lo.find("fidelityfx") != std::string::npos ||
        lo.find("fsr") != std::string::npos || lo.find("wwise") != std::string::npos ||
        lo.find("fmod") != std::string::npos) {
        return DllCategory::Middleware;
    }
    if (lo.rfind("api-ms-win-", 0) == 0 || lo.rfind("ext-ms-win-", 0) == 0 ||
        lo == "kernel32.dll" || lo == "kernelbase.dll" || lo == "ntdll.dll" || lo == "user32.dll" ||
        lo == "gdi32.dll" || lo == "advapi32.dll" || lo == "ole32.dll" || lo == "combase.dll" ||
        lo == "shell32.dll" || lo == "ws2_32.dll" || lo == "bcrypt.dll" || lo == "crypt32.dll" ||
        lo == "ucrtbase.dll" || lo == "vcruntime140.dll" || lo == "vcruntime140_1.dll" ||
        lo == "msvcp140.dll" || lo == "d3d12.dll" || lo == "dxgi.dll" || lo == "rpcrt4.dll" ||
        lo == "winmm.dll" || lo == "dbghelp.dll" || lo == "shlwapi.dll" || lo == "imm32.dll" ||
        lo == "mfplat.dll") {
        return DllCategory::WindowsNative;
    }
    return DllCategory::Other;
}

bool IsWindowsKnownDll(std::string_view dll_name) {
    const std::string key = NormalizeKnownDllBasename(dll_name);
    if (key.empty()) {
        return false;
    }
    const auto& known = KnownDllSet();
    return known.find(key) != known.end();
}

bool ResolveKnownDllSystem32PathW(std::wstring_view dll_name, std::wstring& out_system32_path) {
    out_system32_path.clear();
    const std::string key = NormalizeKnownDllBasename(WideToUtf8(dll_name));
    if (key.empty() || !IsWindowsKnownDll(key)) {
        return false;
    }
#if defined(_WIN32)
    wchar_t sys_dir[MAX_PATH]{};
    const UINT len = ::GetSystemDirectoryW(sys_dir, MAX_PATH);
    if (len == 0u || len >= MAX_PATH) {
        return false;
    }
    std::wstring path(sys_dir, len);
    while (!path.empty() && (path.back() == L'\\' || path.back() == L'/')) {
        path.pop_back();
    }
    path.push_back(L'\\');
    path.append(Utf8ToWide(key));
    const DWORD attrs = ::GetFileAttributesW(path.c_str());
    if (attrs != INVALID_FILE_ATTRIBUTES && (attrs & FILE_ATTRIBUTE_DIRECTORY) == 0u) {
        out_system32_path = std::move(path);
        return true;
    }
    // Even if a KnownDLL entry is a virtual/redirected name not directly on disk,
    // return the System32 candidate path so callers never shadow it from a package directory.
    out_system32_path = std::move(path);
    return true;
#else
    out_system32_path = L"C:\\Windows\\System32\\" + Utf8ToWide(key);
    return true;
#endif
}

std::vector<std::string> GetWindowsKnownDllList() {
    const auto& known = KnownDllSet();
    std::vector<std::string> out(known.begin(), known.end());
    std::sort(out.begin(), out.end());
    return out;
}

// ---------------------------------------------------------------------------
// Data-Driven Per-DLL Routing Table
// ---------------------------------------------------------------------------
std::string DllRoutingTable::NormalizeCanonicalName(std::string_view raw_name) {
    std::string trimmed = TrimAscii(raw_name);
    if (trimmed.empty()) {
        return {};
    }
    size_t slash = trimmed.find_last_of("\\/");
    if (slash != std::string::npos) {
        trimmed = trimmed.substr(slash + 1);
    }
    if (trimmed.empty()) {
        return {};
    }
    const std::string lo = ToLower(trimmed);
    if (lo.size() < 4 || lo.compare(lo.size() - 4, 4, ".dll") != 0) {
        trimmed.append(".dll");
    }
    return trimmed;
}

std::string DllRoutingTable::NormalizeDllKey(std::string_view raw_name) {
    return ToLower(NormalizeCanonicalName(raw_name));
}

DllRoutingTable::DllRoutingTable() {
    struct BuiltinShimSpec {
        const char* canonical_name;
        int priority;
        bool is_extended;
        bool is_fixed_stub;
    };
    // 21 core Xbox/GDK shims (incl. chad.dll) + 5 diagnostic/media shims (mfplat_xs,
    // advapi32legacy, KernelTraceControl, hix_xs, xbtp) = 26 ListAllRules(), plus
    // 6 Sprint 7 fixed-return stub shims = 32 ListCompleteRules() total.
    static constexpr BuiltinShimSpec kBuiltinShims[] = {
        // Priority 0: base shims
        {"kernelx.dll", 0, false, false},
        {"xgameruntime.dll", 0, false, false},
        {"GameInput.dll", 0, false, false},
        {"XAudio2_9.dll", 0, false, false},
        // Priority 1: core shims
        {"d3d12_xs.dll", 1, false, false},
        {"xg_xs.dll", 1, false, false},
        {"AcpHal.dll", 1, false, false},
        {"xapu.dll", 1, false, false},
        {"chad.dll", 1, false, false},
        {"dstorage_xs.dll", 1, false, false},
        {"winrt_xs.dll", 1, false, false},
        {"xmem.dll", 1, false, false},
        {"pixevt.dll", 1, false, false},
        {"xcrdapi.dll", 1, false, false},
        {"libHttpClient.GDK.dll", 1, false, false},
        {"XCurl.dll", 1, false, false},
        {"Bink2Scarlett.dll", 1, false, false},
        {"amd_fidelityfx_upscaler_xbox.dll", 1, false, false},
        {"XboxBvhBuilder.dll", 1, false, false},
        // Priority 2: dependent shims
        {"Microsoft.Xbox.Services.GDK.C.dll", 2, false, false},
        {"amd_fidelityfx_loader_xbox.dll", 2, false, false},
        // Extended diagnostic & media shims (5 -> 24 total)
        {"mfplat_xs.dll", 1, true, false},
        {"advapi32legacy.dll", 1, true, false},
        {"KernelTraceControl.dll", 1, true, false},
        {"hix_xs.dll", 1, true, false},
        {"xbtp.dll", 1, true, false},
        // Sprint 7 fixed-return stub shims (6 -> 30 total)
        {"mflnmhelp.dll", 1, true, true},
        {"mfhevcdec.dll", 1, true, true},
        {"gamecoreclient.dll", 1, true, true},
        {"minuserx.dll", 1, true, true},
        {"xtfpix.dll", 1, true, true},
        {"xtfdebugmonitor.dll", 1, true, true},
    };
    for (const auto& spec : kBuiltinShims) {
        const std::string key = NormalizeDllKey(spec.canonical_name);
        rules_[key] = Entry{
            DllRouteRule{spec.canonical_name, DllRoutePolicy::Shim, spec.priority},
            false,
            spec.is_extended,
            spec.is_fixed_stub,
        };
    }
}

DllRoutingTable DllRoutingTable::CreateWithEnvOverrides() {
    DllRoutingTable table;
    const std::string net_routing = ToLower(TrimAscii(ReadEnvVarA("OPENSCARLETT_NET_ROUTING")));
    if (!net_routing.empty()) {
        DllRoutePolicy net_policy = DllRoutePolicy::Shim;
        if (net_routing == "guest" || net_routing == "native" || net_routing == "nativeguest" ||
            net_routing == "nativeguestdll") {
            net_policy = DllRoutePolicy::NativeGuestDll;
            table.SetRule("XCurl.dll", net_policy, 5);
            table.SetRule("libHttpClient.GDK.dll", net_policy, 5);
        } else if (net_routing == "shim") {
            net_policy = DllRoutePolicy::Shim;
            table.SetRule("XCurl.dll", net_policy, 1);
            table.SetRule("libHttpClient.GDK.dll", net_policy, 1);
        }
    }
    const std::string env_spec = ReadEnvVarA("OPENSCARLETT_DLL_ROUTING");
    if (!env_spec.empty()) {
        table.ApplyOverrides(env_spec);
    }
    return table;
}

void DllRoutingTable::SetRule(std::string_view dll_name, DllRoutePolicy policy, int load_priority) {
    const std::string canonical = NormalizeCanonicalName(dll_name);
    if (canonical.empty()) {
        return;
    }
    const std::string key = ToLower(canonical);
    aliases_.erase(key);
    auto it = rules_.find(key);
    if (it != rules_.end()) {
        it->second.rule.policy = policy;
        if (policy != DllRoutePolicy::Shim) {
            it->second.rule.load_priority = (policy == DllRoutePolicy::NativeGuestDll) ? 5 : 10;
        } else if (load_priority >= 0) {
            it->second.rule.load_priority = load_priority;
        }
        it->second.from_override = true;
    } else {
        const int prio = (policy == DllRoutePolicy::Shim)
                             ? load_priority
                             : ((policy == DllRoutePolicy::NativeGuestDll) ? 5 : 10);
        rules_[key] = Entry{DllRouteRule{canonical, policy, prio}, true, false, false};
    }
}

void DllRoutingTable::SetAlias(std::string_view source_dll, std::string_view target_dll) {
    const std::string src_canon = NormalizeCanonicalName(source_dll);
    const std::string dst_canon = NormalizeCanonicalName(target_dll);
    if (src_canon.empty() || dst_canon.empty()) {
        return;
    }
    const std::string src_key = ToLower(src_canon);
    const std::string dst_key = ToLower(dst_canon);
    if (src_key == dst_key) {
        aliases_.erase(src_key);
        return;
    }
    rules_.erase(src_key);
    aliases_[src_key] = dst_canon;
}

void DllRoutingTable::ApplyOverrides(std::string_view override_spec) {
    size_t pos = 0;
    while (pos < override_spec.size()) {
        size_t next = override_spec.find_first_of(";,", pos);
        if (next == std::string_view::npos) {
            next = override_spec.size();
        }
        std::string_view item = override_spec.substr(pos, next - pos);
        pos = next + 1;

        size_t eq = item.find('=');
        if (eq == std::string_view::npos) {
            continue;
        }
        std::string_view name_part = item.substr(0, eq);
        std::string_view policy_part = item.substr(eq + 1);
        DllRoutePolicy policy = DllRoutePolicy::Windows;
        if (ParsePolicyToken(policy_part, policy)) {
            const std::string key = NormalizeDllKey(name_part);
            auto it = rules_.find(key);
            const int prio = (it != rules_.end() && policy == DllRoutePolicy::Shim)
                                 ? it->second.rule.load_priority
                                 : 1;
            SetRule(name_part, policy, prio);
            continue;
        }

        // Otherwise support "source.dll=target.dll" alias overrides.
        const std::string target_trimmed = TrimAscii(policy_part);
        const std::string target_lo = ToLower(target_trimmed);
        if (target_lo.size() > 4 && target_lo.compare(target_lo.size() - 4, 4, ".dll") == 0) {
            SetAlias(name_part, target_trimmed);
        }
    }
}

const DllRouteRule* DllRoutingTable::FindRule(std::string_view dll_name) const {
    const std::string key = NormalizeDllKey(dll_name);
    if (key.empty()) {
        return nullptr;
    }
    auto it = rules_.find(key);
    if (it != rules_.end()) {
        return &it->second.rule;
    }
    auto alias_it = aliases_.find(key);
    if (alias_it != aliases_.end()) {
        auto target_it = rules_.find(ToLower(alias_it->second));
        if (target_it != rules_.end()) {
            return &target_it->second.rule;
        }
    }
    std::string builtin_target;
    if (ResolveShimAlias(key, builtin_target)) {
        auto target_it = rules_.find(ToLower(builtin_target));
        if (target_it != rules_.end()) {
            return &target_it->second.rule;
        }
    }
    if (key == "xgamingruntimethunks.dll") {
        auto target_it = rules_.find("xgameruntime.dll");
        if (target_it != rules_.end()) {
            return &target_it->second.rule;
        }
    }
    if (key == "dxcompiler_xs.dll") {
        static const DllRouteRule kDxcompilerXsRule{
            "dxcompiler_xs.dll",
            DllRoutePolicy::Shim,
            1,
        };
        return &kDxcompilerXsRule;
    }
    return nullptr;
}

DllRouteDecision DllRoutingTable::ResolveRoute(std::string_view dll_name,
                                               std::wstring_view shim_dir,
                                               std::wstring_view guest_dir,
                                               bool xbox_import_context) const {
    DllRouteDecision out{};
    const std::string canonical_in = NormalizeCanonicalName(dll_name);
    if (canonical_in.empty()) {
        return out;
    }
    const std::string key = ToLower(canonical_in);
    out.requested_name = canonical_in;
    out.canonical_name = canonical_in;

    auto resolve_entry = [&](const Entry& entry, bool aliased, bool override_flag) -> DllRouteDecision {
        out.canonical_name = entry.rule.canonical_name;
        out.load_priority = entry.rule.load_priority;
        out.from_override = override_flag || entry.from_override;
        out.aliased = aliased;

        if (entry.rule.policy == DllRoutePolicy::Windows) {
            out.policy = DllRoutePolicy::Windows;
            return out;
        }
        if (entry.rule.policy == DllRoutePolicy::NativeGuestDll) {
            out.policy = DllRoutePolicy::NativeGuestDll;
            const std::wstring req_w = Utf8ToWide(out.requested_name);
            const std::wstring canon_w = Utf8ToWide(out.canonical_name);
            if (!FileExistsInDirW(guest_dir, req_w, out.resolved_path)) {
                FileExistsInDirW(guest_dir, canon_w, out.resolved_path);
            }
            return out;
        }

        // Smart middleware routing: when no explicit override was set and the guest ships
        // its own Bink2Scarlett.dll in guest_dir, prefer the native guest Bink2 DLL while
        // keeping OpenScarlett's Bink2Scarlett.dll shim as automatic fallback when absent.
        if (key == "bink2scarlett.dll" && !out.from_override && !guest_dir.empty()) {
            const std::wstring canon_w = Utf8ToWide(out.canonical_name);
            if (FileExistsInDirW(guest_dir, canon_w, out.resolved_path)) {
                out.policy = DllRoutePolicy::NativeGuestDll;
                out.load_priority = 5;
                out.aliased = false;
                return out;
            }
        }

        // entry.rule.policy == DllRoutePolicy::Shim
        const std::wstring canon_w = Utf8ToWide(out.canonical_name);
        if (FileExistsInDirW(shim_dir, canon_w, out.resolved_path)) {
            out.policy = DllRoutePolicy::Shim;
            return out;
        }
        // If mfplat.dll was explicitly forced to '=shim', fall back to mfplat_xs.dll in shim_dir.
        if (key == "mfplat.dll" && !shim_dir.empty() &&
            FileExistsInDirW(shim_dir, L"mfplat_xs.dll", out.resolved_path)) {
            out.canonical_name = "mfplat_xs.dll";
            out.aliased = true;
            out.policy = DllRoutePolicy::Shim;
            return out;
        }
        // If shim_dir was provided and shim DLL is not present there, fall back to NativeGuestDll if present.
        if (!shim_dir.empty() && !guest_dir.empty()) {
            const std::wstring req_w = Utf8ToWide(out.requested_name);
            if (FileExistsInDirW(guest_dir, req_w, out.resolved_path) ||
                FileExistsInDirW(guest_dir, canon_w, out.resolved_path)) {
                out.policy = DllRoutePolicy::NativeGuestDll;
                out.load_priority = 5;
                out.aliased = false;
                return out;
            }
        }
        out.policy = DllRoutePolicy::Shim;
        return out;
    };

    // 1. Explicit rule (built-in canonical shims OR env overrides including '=passthrough')
    auto it = rules_.find(key);
    if (it != rules_.end()) {
        return resolve_entry(it->second, false, it->second.from_override);
    }

    // 2. Explicit custom alias override ("source.dll=target.dll")
    auto alias_it = aliases_.find(key);
    if (alias_it != aliases_.end()) {
        const std::string& target_canon = alias_it->second;
        const std::string target_key = ToLower(target_canon);
        auto target_it = rules_.find(target_key);
        if (target_it != rules_.end()) {
            return resolve_entry(target_it->second, true, true);
        }
        out.canonical_name = target_canon;
        out.from_override = true;
        out.aliased = true;
        const std::wstring target_w = Utf8ToWide(target_canon);
        if (FileExistsInDirW(shim_dir, target_w, out.resolved_path)) {
            out.policy = DllRoutePolicy::Shim;
            out.load_priority = 1;
            return out;
        }
        if (FileExistsInDirW(guest_dir, target_w, out.resolved_path)) {
            out.policy = DllRoutePolicy::NativeGuestDll;
            out.load_priority = 5;
            return out;
        }
        out.policy = DllRoutePolicy::Shim;
        out.load_priority = 1;
        return out;
    }

    // 3. Built-in versioned / thunk GDK DLL alias resolution
    std::string builtin_target;
    if (ResolveShimAlias(canonical_in, builtin_target)) {
        const std::string target_key = ToLower(builtin_target);
        auto target_it = rules_.find(target_key);
        if (target_it != rules_.end()) {
            return resolve_entry(target_it->second, true, target_it->second.from_override);
        }
    }

    // 3b. Built-in XGamingRuntimeThunks.dll -> xgameruntime.dll alias routing:
    //     If the guest ships its own XGamingRuntimeThunks.dll in guest_dir (and no explicit
    //     OPENSCARLETT_DLL_ROUTING override was set), preserve NativeGuestDll so the guest's
    //     thunk loader can call LoadLibrary("xgameruntime.dll"). Otherwise alias directly to
    //     OpenScarlett's xgameruntime.dll shim.
    if (key == "xgamingruntimethunks.dll") {
        const std::wstring req_w = Utf8ToWide(canonical_in);
        if (!guest_dir.empty() && FileExistsInDirW(guest_dir, req_w, out.resolved_path)) {
            out.policy = DllRoutePolicy::NativeGuestDll;
            out.load_priority = 5;
            out.aliased = false;
            return out;
        }
        auto xgr_it = rules_.find("xgameruntime.dll");
        if (xgr_it != rules_.end()) {
            return resolve_entry(xgr_it->second, true, xgr_it->second.from_override);
        }
    }

    // 3c. Xbox-imported mfplat.dll -> mfplat_xs.dll routing:
    //     Only active when xbox_import_context is true (a PE module that imports Xbox
    //     console-exclusive DLLs) AND mfplat_xs.dll is available in shim_dir (or shim_dir is
    //     empty for symbolic resolution), so desktop Win32 processes always get System32\mfplat.dll.
    if (key == "mfplat.dll" && xbox_import_context) {
        auto mf_it = rules_.find("mfplat_xs.dll");
        if (mf_it != rules_.end() && mf_it->second.rule.policy == DllRoutePolicy::Shim) {
            std::wstring probe_path;
            if (shim_dir.empty() || FileExistsInDirW(shim_dir, L"mfplat_xs.dll", probe_path)) {
                return resolve_entry(mf_it->second, true, mf_it->second.from_override);
            }
        }
    }

    // 3d. Scarlett DXC shader compiler shim (dxcompiler_xs.dll):
    //     Routes to OpenScarlett's dxcompiler_xs.dll shim while keeping legacy
    //     ListRules()/ListAllRules()/ListCompleteRules() counts unchanged unless overridden.
    if (key == "dxcompiler_xs.dll") {
        static const Entry kDxcompilerXsEntry{
            DllRouteRule{"dxcompiler_xs.dll", DllRoutePolicy::Shim, 1},
            false,
            true,
            false,
        };
        return resolve_entry(kDxcompilerXsEntry, false, false);
    }

    // 4. No explicit rule or alias: KnownDLLs and WindowsNative ALWAYS resolve to Windows
    //    (System32 first, never shadowed by package-local images).
    if (IsWindowsKnownDll(canonical_in) || ClassifyImportDll(canonical_in) == DllCategory::WindowsNative) {
        out.policy = DllRoutePolicy::Windows;
        out.load_priority = 10;
        return out;
    }

    const std::wstring canon_w = Utf8ToWide(canonical_in);
    if (!guest_dir.empty() && FileExistsInDirW(guest_dir, canon_w, out.resolved_path)) {
        out.policy = DllRoutePolicy::NativeGuestDll;
        out.load_priority = 5;
        return out;
    }

    out.policy = DllRoutePolicy::Windows;
    out.load_priority = 10;
    return out;
}

DllRouteDecision DllRoutingTable::ResolveRouteW(std::wstring_view dll_name,
                                                std::wstring_view shim_dir,
                                                std::wstring_view guest_dir,
                                                bool xbox_import_context) const {
    return ResolveRoute(WideToUtf8(dll_name), shim_dir, guest_dir, xbox_import_context);
}

std::vector<DllRouteRule> DllRoutingTable::ListRules() const {
    std::vector<DllRouteRule> out;
    out.reserve(rules_.size());
    for (const auto& kv : rules_) {
        if ((!kv.second.is_extended && !kv.second.is_fixed_stub) || kv.second.from_override) {
            out.push_back(kv.second.rule);
        }
    }
    std::sort(out.begin(), out.end(), [](const DllRouteRule& a, const DllRouteRule& b) {
        if (a.load_priority != b.load_priority) {
            return a.load_priority < b.load_priority;
        }
        return ToLower(a.canonical_name) < ToLower(b.canonical_name);
    });
    return out;
}

std::vector<DllRouteRule> DllRoutingTable::ListAllRules() const {
    std::vector<DllRouteRule> out;
    out.reserve(rules_.size());
    for (const auto& kv : rules_) {
        if (!kv.second.is_fixed_stub || kv.second.from_override) {
            out.push_back(kv.second.rule);
        }
    }
    std::sort(out.begin(), out.end(), [](const DllRouteRule& a, const DllRouteRule& b) {
        if (a.load_priority != b.load_priority) {
            return a.load_priority < b.load_priority;
        }
        return ToLower(a.canonical_name) < ToLower(b.canonical_name);
    });
    return out;
}

std::vector<DllRouteRule> DllRoutingTable::ListCompleteRules() const {
    std::vector<DllRouteRule> out;
    out.reserve(rules_.size());
    for (const auto& kv : rules_) {
        out.push_back(kv.second.rule);
    }
    std::sort(out.begin(), out.end(), [](const DllRouteRule& a, const DllRouteRule& b) {
        if (a.load_priority != b.load_priority) {
            return a.load_priority < b.load_priority;
        }
        return ToLower(a.canonical_name) < ToLower(b.canonical_name);
    });
    return out;
}

// ---------------------------------------------------------------------------
// PE32+ Inspector (Imports, Exports & Forwarders, TLS Callbacks, .pdata SEH)
// ---------------------------------------------------------------------------
Status InspectPeBytes(const std::vector<uint8_t>& bytes,
                      const std::string& label,
                      PeInspectionReport& out_report) {
    out_report = {};
    out_report.file_path = label;

    if (bytes.size() < 0x100) {
        return Status::Error(StatusCode::ParseError, "File too small to be a valid PE image");
    }
    uint16_t mz = 0;
    uint32_t pe_off = 0;
    if (!ReadPod(bytes, 0, mz) || mz != 0x5A4Du || !ReadPod(bytes, 0x3C, pe_off)) {
        return Status::Error(StatusCode::ParseError, "Missing DOS MZ header");
    }
    uint32_t pe_sig = 0;
    if (!ReadPod(bytes, pe_off, pe_sig) || pe_sig != 0x00004550u) {
        return Status::Error(StatusCode::ParseError, "Missing PE\\0\\0 signature");
    }

    const size_t coff_off = static_cast<size_t>(pe_off) + 4;
    uint16_t num_sections = 0;
    uint16_t opt_size = 0;
    uint16_t characteristics = 0;
    if (!ReadPod(bytes, coff_off + 0, out_report.machine) ||
        !ReadPod(bytes, coff_off + 2, num_sections) ||
        !ReadPod(bytes, coff_off + 16, opt_size) ||
        !ReadPod(bytes, coff_off + 18, characteristics)) {
        return Status::Error(StatusCode::ParseError, "Truncated COFF header");
    }
    out_report.section_count = num_sections;
    out_report.is_dll = (characteristics & 0x2000u) != 0;
    const bool relocs_stripped_flag = (characteristics & 0x0001u) != 0;
    out_report.has_relocations = false;

    const size_t opt_off = coff_off + 20;
    uint16_t opt_magic = 0;
    if (opt_size < 0x70 || !ReadPod(bytes, opt_off, opt_magic)) {
        return Status::Error(StatusCode::ParseError, "Truncated PE optional header");
    }
    if (opt_magic != 0x020Bu) {
        return Status::Error(StatusCode::UnsupportedFormat, "Not a PE32+ (64-bit) image");
    }
    out_report.is_pe64 = true;

    uint32_t num_rva_and_sizes = 0;
    if (!ReadPod(bytes, opt_off + 16, out_report.entry_point_rva) ||
        !ReadPod(bytes, opt_off + 24, out_report.image_base) ||
        !ReadPod(bytes, opt_off + 56, out_report.image_size) ||
        !ReadPod(bytes, opt_off + 68, out_report.subsystem) ||
        !ReadPod(bytes, opt_off + 108, num_rva_and_sizes)) {
        return Status::Error(StatusCode::ParseError, "Truncated PE32+ fields");
    }

    const size_t dd_off = opt_off + 112;
    auto read_dir = [&](uint32_t idx, uint32_t& rva, uint32_t& sz) -> bool {
        if (idx >= num_rva_and_sizes) return false;
        return ReadPod(bytes, dd_off + static_cast<size_t>(idx) * 8, rva) &&
               ReadPod(bytes, dd_off + static_cast<size_t>(idx) * 8 + 4, sz);
    };

    const size_t sec_off = opt_off + opt_size;
    std::vector<SectionRange> sections;
    sections.reserve(num_sections);
    for (uint16_t i = 0; i < num_sections; ++i) {
        const size_t base = sec_off + static_cast<size_t>(i) * 40;
        SectionRange sr{};
        if (!ReadPod(bytes, base + 8, sr.vsize) ||
            !ReadPod(bytes, base + 12, sr.vaddr) ||
            !ReadPod(bytes, base + 16, sr.raw_size) ||
            !ReadPod(bytes, base + 20, sr.raw_ptr) ||
            !ReadPod(bytes, base + 36, sr.characteristics)) {
            return Status::Error(StatusCode::ParseError, "Truncated section table");
        }
        // Validate section raw file range against EOF to prevent OOB reads on truncated PEs.
        if (sr.raw_size > 0u) {
            const uint64_t raw_end =
                static_cast<uint64_t>(sr.raw_ptr) + static_cast<uint64_t>(sr.raw_size);
            if (raw_end > static_cast<uint64_t>(bytes.size())) {
                return Status::Error(StatusCode::ParseError,
                                     "PE section raw data exceeds file size (EOF)");
            }
        }
        sections.push_back(sr);
    }

    // 1. Export Directory (index 0) including forwarder strings
    uint32_t exp_rva = 0, exp_sz = 0;
    if (read_dir(0, exp_rva, exp_sz) && exp_rva != 0 && exp_sz >= 40u) {
        out_report.export_dir_rva = exp_rva;
        out_report.export_dir_size = exp_sz;
        size_t exp_off = 0;
        if (RvaToFileOffset(sections, exp_rva, bytes.size(), exp_off)) {
            uint32_t ordinal_base = 0;
            uint32_t num_funcs = 0;
            uint32_t num_names = 0;
            uint32_t addr_funcs_rva = 0;
            uint32_t addr_names_rva = 0;
            uint32_t addr_ords_rva = 0;
            if (ReadPod(bytes, exp_off + 16, ordinal_base) &&
                ReadPod(bytes, exp_off + 20, num_funcs) &&
                ReadPod(bytes, exp_off + 24, num_names) &&
                ReadPod(bytes, exp_off + 28, addr_funcs_rva) &&
                ReadPod(bytes, exp_off + 32, addr_names_rva) &&
                ReadPod(bytes, exp_off + 36, addr_ords_rva)) {
                out_report.export_ordinal_base = ordinal_base;
                const uint32_t capped_funcs = std::min<uint32_t>(num_funcs, 65536u);
                const uint32_t capped_names = std::min<uint32_t>(num_names, 65536u);

                std::unordered_map<uint32_t, std::string> index_to_name;
                size_t names_off = 0;
                size_t names_avail = 0;
                size_t ords_off = 0;
                size_t ords_avail = 0;
                if (capped_names > 0 &&
                    addr_names_rva != 0 &&
                    addr_ords_rva != 0 &&
                    RvaToSectionSlice(sections, addr_names_rva, bytes.size(), names_off, names_avail) &&
                    RvaToSectionSlice(sections, addr_ords_rva, bytes.size(), ords_off, ords_avail)) {
                    index_to_name.reserve(capped_names);
                    for (uint32_t i = 0; i < capped_names; ++i) {
                        const size_t name_entry_rel = static_cast<size_t>(i) * 4u;
                        const size_t ord_entry_rel = static_cast<size_t>(i) * 2u;
                        if (name_entry_rel + 4u > names_avail || ord_entry_rel + 2u > ords_avail) {
                            ++out_report.malformed_export_names;
                            break;
                        }
                        uint32_t name_rva = 0;
                        uint16_t func_idx = 0;
                        if (!ReadPod(bytes, names_off + name_entry_rel, name_rva) ||
                            !ReadPod(bytes, ords_off + ord_entry_rel, func_idx)) {
                            ++out_report.malformed_export_names;
                            break;
                        }
                        if (func_idx >= capped_funcs || name_rva == 0) {
                            ++out_report.malformed_export_names;
                            continue;
                        }
                        size_t str_off = 0;
                        size_t str_avail = 0;
                        std::string sym_name;
                        if (RvaToSectionSlice(sections, name_rva, bytes.size(), str_off, str_avail) &&
                            ReadExportNameString(bytes, str_off, str_avail, 512u, sym_name)) {
                            index_to_name.emplace(static_cast<uint32_t>(func_idx), std::move(sym_name));
                        } else {
                            ++out_report.malformed_export_names;
                        }
                    }
                }

                size_t funcs_off = 0;
                size_t funcs_avail = 0;
                if (capped_funcs > 0 &&
                    addr_funcs_rva != 0 &&
                    RvaToSectionSlice(sections, addr_funcs_rva, bytes.size(), funcs_off, funcs_avail)) {
                    out_report.exports.reserve(capped_funcs);
                    const uint64_t exp_end_64 = static_cast<uint64_t>(exp_rva) + static_cast<uint64_t>(exp_sz);
                    for (uint32_t i = 0; i < capped_funcs; ++i) {
                        const size_t fn_entry_rel = static_cast<size_t>(i) * 4u;
                        if (fn_entry_rel + 4u > funcs_avail) {
                            break;
                        }
                        uint32_t fn_rva = 0;
                        if (!ReadPod(bytes, funcs_off + fn_entry_rel, fn_rva)) {
                            break;
                        }
                        if (fn_rva == 0) {
                            continue;
                        }
                        PeExportSymbol sym{};
                        sym.ordinal = ordinal_base + i;
                        sym.rva = fn_rva;
                        auto name_it = index_to_name.find(i);
                        if (name_it != index_to_name.end()) {
                            sym.name = name_it->second;
                        }
                        if (static_cast<uint64_t>(fn_rva) >= static_cast<uint64_t>(exp_rva) &&
                            static_cast<uint64_t>(fn_rva) < exp_end_64) {
                            sym.is_forwarded = true;
                            size_t fwd_off = 0;
                            size_t fwd_avail = 0;
                            if (RvaToSectionSlice(sections, fn_rva, bytes.size(), fwd_off, fwd_avail)) {
                                const size_t dir_rem = static_cast<size_t>(exp_end_64 - fn_rva);
                                const size_t max_fwd = std::min<size_t>({512u, dir_rem, fwd_avail});
                                ReadExportNameString(bytes, fwd_off, max_fwd, 512u, sym.forwarder);
                            }
                        }
                        out_report.exports.push_back(std::move(sym));
                    }
                }
            }
        }
    }

    // 1b. Base Relocation Directory (index 5):
    //     Strictly treat VirtualAddress == 0 OR Size == 0 (or IMAGE_FILE_RELOCS_STRIPPED)
    //     as absent, never attempting to read offset 0 as relocation blocks.
    uint32_t reloc_rva = 0, reloc_sz = 0;
    if (!relocs_stripped_flag && read_dir(5, reloc_rva, reloc_sz) &&
        reloc_rva != 0u && reloc_sz >= 8u) {
        size_t reloc_off = 0;
        size_t reloc_avail = 0;
        if (RvaToSectionSlice(sections, reloc_rva, bytes.size(), reloc_off, reloc_avail)) {
            out_report.has_relocations = true;
            out_report.reloc_dir_rva = reloc_rva;
            out_report.reloc_dir_size = reloc_sz;
            const size_t walk_limit = std::min<size_t>(static_cast<size_t>(reloc_sz), reloc_avail);
            size_t cursor = 0u;
            uint32_t block_guard = 0u;
            while (cursor + 8u <= walk_limit && block_guard < 65536u) {
                uint32_t page_rva = 0;
                uint32_t block_size = 0;
                if (!ReadPod(bytes, reloc_off + cursor, page_rva) ||
                    !ReadPod(bytes, reloc_off + cursor + 4u, block_size)) {
                    break;
                }
                if (block_size == 0u) {
                    break;
                }
                if (block_size < 8u || (block_size & 1u) != 0u || block_size > walk_limit - cursor) {
                    break;
                }
                (void)page_rva;
                ++out_report.reloc_block_count;
                out_report.reloc_entry_count += (block_size - 8u) / 2u;
                cursor += block_size;
                ++block_guard;
            }
        }
    }

    // 2. Exception Directory / x64 .pdata (index 3) & .xdata unwind validation
    uint32_t exc_rva = 0, exc_sz = 0;
    if (read_dir(3, exc_rva, exc_sz) && exc_rva != 0 && exc_sz != 0) {
        out_report.exception_dir_rva = exc_rva;
        out_report.exception_dir_size = exc_sz;
        out_report.exception_entry_count = exc_sz / 12u;  // sizeof(RUNTIME_FUNCTION) == 12 on x64
        PeXdataValidationResult xdata_res{};
        if (ValidatePeXdataUnwind(bytes, xdata_res).ok()) {
            out_report.xdata_valid_entries = xdata_res.valid_entries;
            out_report.xdata_invalid_entries = xdata_res.invalid_entries;
            out_report.xdata_alloc_large_entries = xdata_res.alloc_large_entries;
            out_report.xdata_epilog_entries = xdata_res.epilog_code_entries;
            out_report.xdata_chained_entries = xdata_res.chained_entries;
        }
    }

    // 3. TLS Directory & Callback RVAs (index 9)
    uint32_t tls_rva = 0, tls_sz = 0;
    if (read_dir(9, tls_rva, tls_sz) && tls_rva != 0 && tls_sz != 0) {
        out_report.has_tls = true;
        out_report.tls_dir_rva = tls_rva;
        out_report.tls_dir_size = tls_sz;

        size_t tls_off = 0;
        if (RvaToFileOffset(sections, tls_rva, bytes.size(), tls_off)) {
            // Validate TLS AddressOfIndex (offset 16 in IMAGE_TLS_DIRECTORY64):
            // The OS loader writes the allocated TLS index DWORD to *AddressOfIndex, so it
            // must point inside a writable (IMAGE_SCN_MEM_WRITE) mapped section.
            uint64_t addr_of_index_va = 0;
            if (ReadPod(bytes, tls_off + 16, addr_of_index_va) && addr_of_index_va != 0) {
                constexpr uint32_t kImageScnMemWrite = 0x80000000u;
                if (addr_of_index_va < out_report.image_base) {
                    return Status::Error(StatusCode::ParseError,
                                         "PE TLS AddressOfIndex is below ImageBase");
                }
                const uint64_t idx_rva_64 = addr_of_index_va - out_report.image_base;
                if (idx_rva_64 + 4ull > static_cast<uint64_t>(out_report.image_size)) {
                    return Status::Error(StatusCode::ParseError,
                                         "PE TLS AddressOfIndex is outside image bounds");
                }
                const uint32_t idx_rva = static_cast<uint32_t>(idx_rva_64);
                bool in_writable_section = false;
                for (const auto& s : sections) {
                    const uint32_t span = std::max(s.vsize, s.raw_size);
                    if (idx_rva >= s.vaddr && (idx_rva - s.vaddr) < span &&
                        (span - (idx_rva - s.vaddr)) >= 4u) {
                        if ((s.characteristics & kImageScnMemWrite) != 0u) {
                            in_writable_section = true;
                        }
                        break;
                    }
                }
                if (!in_writable_section) {
                    return Status::Error(StatusCode::ParseError,
                                         "PE TLS AddressOfIndex points to unwritable or unmapped section");
                }
            }

            uint64_t addr_of_callbacks_va = 0;
            if (ReadPod(bytes, tls_off + 24, addr_of_callbacks_va) &&
                addr_of_callbacks_va >= out_report.image_base) {
                const uint64_t cb_rva_64 = addr_of_callbacks_va - out_report.image_base;
                if (cb_rva_64 < out_report.image_size) {
                    size_t cb_off = 0;
                    if (RvaToFileOffset(sections, static_cast<uint32_t>(cb_rva_64), bytes.size(), cb_off)) {
                        for (size_t i = 0; i < 256; ++i) {
                            uint64_t fn_va = 0;
                            if (!ReadPod(bytes, cb_off + i * 8, fn_va) || fn_va == 0) {
                                break;
                            }
                            if (fn_va >= out_report.image_base &&
                                fn_va - out_report.image_base < out_report.image_size) {
                                out_report.tls_callback_rvas.push_back(
                                    static_cast<uint32_t>(fn_va - out_report.image_base));
                            }
                        }
                    }
                }
            }
        }
    }

    // 4. Import & Delay-Load Directories (index 1 & 13)
    std::unordered_map<std::string, size_t> mod_index;
    auto add_module = [&](const std::string& dll_name) -> PeImportModule& {
        std::string lo = ToLower(dll_name);
        auto it = mod_index.find(lo);
        if (it != mod_index.end()) return out_report.imports[it->second];
        PeImportModule m{};
        m.dll_name = dll_name;
        m.category = ClassifyImportDll(dll_name);
        mod_index[lo] = out_report.imports.size();
        out_report.imports.push_back(std::move(m));
        return out_report.imports.back();
    };

    auto parse_thunk_list = [&](uint32_t thunk_rva, bool delay_loaded, PeImportModule& mod) {
        size_t off = 0;
        if (!RvaToFileOffset(sections, thunk_rva, bytes.size(), off)) return;
        for (size_t guard = 0; guard < 16384; ++guard) {
            uint64_t val = 0;
            if (!ReadPod(bytes, off + guard * 8, val) || val == 0) break;
            PeImportSymbol sym{};
            sym.delay_loaded = delay_loaded;
            if ((val & (1ull << 63)) != 0) {
                sym.by_ordinal = true;
                sym.ordinal = static_cast<uint16_t>(val & 0xFFFFu);
            } else {
                size_t hint_off = 0;
                if (RvaToFileOffset(sections, static_cast<uint32_t>(val & 0x7FFFFFFFu), bytes.size(), hint_off)) {
                    ReadPod(bytes, hint_off, sym.ordinal);
                    ReadCString(bytes, hint_off + 2, 512, sym.name);
                }
            }
            mod.symbols.push_back(std::move(sym));
            ++out_report.total_imports;
            if (delay_loaded) ++out_report.delay_load_imports;
            if (mod.category == DllCategory::ConsoleExclusive) ++out_report.console_imports;
            if (mod.category == DllCategory::GdkRuntime) ++out_report.gdk_imports;
        }
    };

    uint32_t imp_rva = 0, imp_sz = 0;
    if (read_dir(1, imp_rva, imp_sz) && imp_rva != 0) {
        size_t off = 0;
        if (RvaToFileOffset(sections, imp_rva, bytes.size(), off)) {
            for (size_t idx = 0; idx < 2048; ++idx) {
                uint32_t oft = 0, name_rva = 0, ft = 0;
                if (!ReadPod(bytes, off + idx * 20 + 0, oft) ||
                    !ReadPod(bytes, off + idx * 20 + 12, name_rva) ||
                    !ReadPod(bytes, off + idx * 20 + 16, ft)) {
                    break;
                }
                if (oft == 0 && name_rva == 0 && ft == 0) break;
                size_t name_off = 0;
                std::string dll;
                if (!RvaToFileOffset(sections, name_rva, bytes.size(), name_off) ||
                    !ReadCString(bytes, name_off, 260, dll)) {
                    continue;
                }
                auto& mod = add_module(dll);
                parse_thunk_list(oft != 0 ? oft : ft, false, mod);
            }
        }
    }

    uint32_t dly_rva = 0, dly_sz = 0;
    if (read_dir(13, dly_rva, dly_sz) && dly_rva != 0) {
        size_t off = 0;
        if (RvaToFileOffset(sections, dly_rva, bytes.size(), off)) {
            for (size_t idx = 0; idx < 1024; ++idx) {
                uint32_t attrs = 0, name_rva = 0, int_rva = 0;
                if (!ReadPod(bytes, off + idx * 32 + 0, attrs) ||
                    !ReadPod(bytes, off + idx * 32 + 4, name_rva) ||
                    !ReadPod(bytes, off + idx * 32 + 16, int_rva)) {
                    break;
                }
                if (name_rva == 0 && int_rva == 0) break;
                if ((attrs & 1u) == 0) continue;
                size_t name_off = 0;
                std::string dll;
                if (!RvaToFileOffset(sections, name_rva, bytes.size(), name_off) ||
                    !ReadCString(bytes, name_off, 260, dll)) {
                    continue;
                }
                auto& mod = add_module(dll);
                parse_thunk_list(int_rva, true, mod);
            }
        }
    }

    return Status::Ok();
}

Status InspectPeFile(const std::string& file_path, PeInspectionReport& out_report) {
    std::ifstream ifs(file_path, std::ios::binary | std::ios::ate);
    if (!ifs) {
        return Status::Error(StatusCode::NotFound, "Cannot open PE file: " + file_path);
    }
    const auto sz = ifs.tellg();
    if (sz <= 0) {
        return Status::Error(StatusCode::ParseError, "Empty PE file: " + file_path);
    }
    ifs.seekg(0);
    std::vector<uint8_t> buf(static_cast<size_t>(sz));
    if (!ifs.read(reinterpret_cast<char*>(buf.data()), sz)) {
        return Status::Error(StatusCode::IoError, "Failed reading PE file: " + file_path);
    }
    return InspectPeBytes(buf, file_path, out_report);
}

// ---------------------------------------------------------------------------
// Export-Forwarder Parsing & Chain Resolution
// ---------------------------------------------------------------------------
bool ParseExportForwarder(std::string_view forwarder, PeForwarderTarget& out_target) {
    out_target = {};
    const size_t dot = forwarder.rfind('.');
    if (dot == std::string_view::npos || dot == 0 || dot + 1 >= forwarder.size()) {
        return false;
    }

    std::string dll(forwarder.substr(0, dot));
    std::string_view sym = forwarder.substr(dot + 1);
    if (dll.empty() || sym.empty()) {
        return false;
    }

    const std::string dll_lo = ToLower(dll);
    if (dll_lo.size() < 4 || dll_lo.compare(dll_lo.size() - 4, 4, ".dll") != 0) {
        dll.append(".dll");
    }
    out_target.dll_name = std::move(dll);

    if (sym[0] == '#') {
        if (sym.size() < 2) {
            return false;
        }
        uint32_t ord = 0;
        for (size_t i = 1; i < sym.size(); ++i) {
            if (sym[i] < '0' || sym[i] > '9') {
                return false;
            }
            ord = ord * 10u + static_cast<uint32_t>(sym[i] - '0');
            if (ord > 0xFFFFu) {
                return false;
            }
        }
        out_target.by_ordinal = true;
        out_target.ordinal = static_cast<uint16_t>(ord);
        return true;
    }

    out_target.by_ordinal = false;
    out_target.symbol_name.assign(sym);
    return true;
}

Status ResolveExportForwarderChain(const std::string& start_dll,
                                   const std::string& start_symbol,
                                   uint16_t start_ordinal,
                                   bool by_ordinal,
                                   const PeModuleBytesResolver& resolver,
                                   PeForwarderResolution& out_resolution,
                                   uint32_t max_depth) {
    out_resolution = {};
    if (!resolver) {
        return Status::Error(StatusCode::InvalidArgument, "Module resolver callback is null");
    }
    if (start_dll.empty() || (!by_ordinal && start_symbol.empty())) {
        return Status::Error(StatusCode::InvalidArgument, "Empty start DLL or export symbol");
    }

    std::unordered_map<std::string, PeInspectionReport> parsed_cache;
    std::unordered_set<std::string> visited;

    std::string cur_dll = start_dll;
    std::string cur_sym = start_symbol;
    uint16_t cur_ord = start_ordinal;
    bool cur_by_ord = by_ordinal;

    for (uint32_t depth = 0; depth <= max_depth; ++depth) {
        std::string norm_dll = cur_dll;
        {
            std::string lo = ToLower(norm_dll);
            if (lo.size() < 4 || lo.compare(lo.size() - 4, 4, ".dll") != 0) {
                norm_dll.append(".dll");
            }
        }
        const std::string dll_key = ToLower(norm_dll);
        const std::string sym_label = cur_by_ord ? ("#" + std::to_string(cur_ord)) : cur_sym;
        const std::string visit_key = dll_key + "!" + sym_label;

        if (!visited.insert(visit_key).second) {
            return Status::Error(StatusCode::ParseError,
                                 "Export forwarder cycle detected at " + norm_dll + "!" + sym_label);
        }
        out_resolution.chain.push_back(norm_dll + "!" + sym_label);

        auto cache_it = parsed_cache.find(dll_key);
        if (cache_it == parsed_cache.end()) {
            std::vector<uint8_t> raw_bytes;
            auto load_st = resolver(norm_dll, raw_bytes);
            if (!load_st.ok()) {
                return load_st;
            }
            PeInspectionReport rep;
            auto parse_st = InspectPeBytes(raw_bytes, norm_dll, rep);
            if (!parse_st.ok()) {
                return parse_st;
            }
            cache_it = parsed_cache.emplace(dll_key, std::move(rep)).first;
        }

        const PeInspectionReport& rep = cache_it->second;
        const PeExportSymbol* found = nullptr;
        for (const auto& exp : rep.exports) {
            if (cur_by_ord) {
                if (exp.ordinal == cur_ord) {
                    found = &exp;
                    break;
                }
            } else {
                if (exp.name == cur_sym) {
                    found = &exp;
                    break;
                }
            }
        }
        if (!found) {
            return Status::Error(StatusCode::NotFound,
                                 "Export not found: " + norm_dll + "!" + sym_label);
        }

        if (!found->is_forwarded) {
            out_resolution.final_dll = norm_dll;
            out_resolution.final_symbol = found->name;
            out_resolution.final_ordinal = static_cast<uint16_t>(found->ordinal & 0xFFFFu);
            out_resolution.by_ordinal = cur_by_ord;
            out_resolution.final_rva = found->rva;
            return Status::Ok();
        }

        if (depth == max_depth) {
            return Status::Error(StatusCode::ParseError,
                                 "Export forwarder chain exceeded max depth (" +
                                     std::to_string(max_depth) + ")");
        }

        PeForwarderTarget next{};
        if (!ParseExportForwarder(found->forwarder, next)) {
            return Status::Error(StatusCode::ParseError,
                                 "Malformed export forwarder string: " + found->forwarder);
        }
        cur_dll = std::move(next.dll_name);
        cur_sym = std::move(next.symbol_name);
        cur_ord = next.ordinal;
        cur_by_ord = next.by_ordinal;
    }

    return Status::Error(StatusCode::ParseError, "Export forwarder chain did not terminate");
}

bool LookupMappedPeExportForwarder(const void* module_base,
                                   const char* proc_name_or_ordinal,
                                   PeForwarderTarget& out_target,
                                   std::string* out_raw_forwarder) {
    out_target = {};
    if (out_raw_forwarder) {
        out_raw_forwarder->clear();
    }
#if !defined(_WIN32)
    (void)module_base;
    (void)proc_name_or_ordinal;
    return false;
#else
    if (!module_base || !proc_name_or_ordinal) {
        return false;
    }
    const uint8_t* base = nullptr;
    const IMAGE_NT_HEADERS64* nt = nullptr;
    uint32_t image_size = 0;
    if (!ReadMappedPeHeaders64(module_base, base, nt, image_size)) {
        return false;
    }

    const auto& exp_dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (exp_dir.VirtualAddress == 0 || exp_dir.Size < sizeof(IMAGE_EXPORT_DIRECTORY) ||
        exp_dir.VirtualAddress >= image_size ||
        exp_dir.Size > image_size - exp_dir.VirtualAddress) {
        return false;
    }

    const auto* exp = reinterpret_cast<const IMAGE_EXPORT_DIRECTORY*>(base + exp_dir.VirtualAddress);
    if (exp->NumberOfFunctions == 0 || exp->AddressOfFunctions == 0 ||
        exp->AddressOfFunctions >= image_size ||
        static_cast<uint64_t>(exp->NumberOfFunctions) * sizeof(uint32_t) >
            image_size - exp->AddressOfFunctions) {
        return false;
    }

    const auto* funcs = reinterpret_cast<const uint32_t*>(base + exp->AddressOfFunctions);
    uint32_t func_index = UINT32_MAX;

    if (reinterpret_cast<uintptr_t>(proc_name_or_ordinal) <= 0xFFFFu) {
        const uint32_t ord = static_cast<uint32_t>(reinterpret_cast<uintptr_t>(proc_name_or_ordinal));
        if (ord < exp->Base || ord - exp->Base >= exp->NumberOfFunctions) {
            return false;
        }
        func_index = ord - exp->Base;
    } else {
        if (exp->NumberOfNames == 0 || exp->AddressOfNames == 0 || exp->AddressOfNameOrdinals == 0 ||
            exp->AddressOfNames >= image_size || exp->AddressOfNameOrdinals >= image_size ||
            static_cast<uint64_t>(exp->NumberOfNames) * sizeof(uint32_t) >
                image_size - exp->AddressOfNames ||
            static_cast<uint64_t>(exp->NumberOfNames) * sizeof(uint16_t) >
                image_size - exp->AddressOfNameOrdinals) {
            return false;
        }

        const auto* names = reinterpret_cast<const uint32_t*>(base + exp->AddressOfNames);
        const auto* ords = reinterpret_cast<const uint16_t*>(base + exp->AddressOfNameOrdinals);

        auto bounded_cmp = [&](uint32_t name_rva, int& out_cmp) -> bool {
            if (name_rva == 0u || name_rva >= image_size) {
                return false;
            }
            const char* cur_name = reinterpret_cast<const char*>(base + name_rva);
            const size_t max_n = static_cast<size_t>(image_size - name_rva);
            size_t len = 0u;
            while (len < max_n && cur_name[len] != '\0') {
                ++len;
            }
            if (len >= max_n) {
                return false;  // Unterminated export name inside mapped image bounds
            }
            out_cmp = std::strcmp(proc_name_or_ordinal, cur_name);
            return true;
        };

        // O(log N) binary search per PE/COFF sorted name table specification.
        uint32_t lo = 0;
        uint32_t hi = exp->NumberOfNames;
        while (lo < hi) {
            const uint32_t mid = lo + (hi - lo) / 2u;
            int cmp = 0;
            if (!bounded_cmp(names[mid], cmp)) {
                break;
            }
            if (cmp == 0) {
                func_index = ords[mid];
                break;
            }
            if (cmp < 0) {
                hi = mid;
            } else {
                lo = mid + 1u;
            }
        }

        // Linear fallback for hand-crafted PE images with unsorted export name tables.
        if (func_index == UINT32_MAX) {
            for (uint32_t i = 0; i < exp->NumberOfNames; ++i) {
                int cmp = 0;
                if (bounded_cmp(names[i], cmp) && cmp == 0) {
                    func_index = ords[i];
                    break;
                }
            }
        }
    }

    if (func_index >= exp->NumberOfFunctions) {
        return false;
    }

    const uint32_t fn_rva = funcs[func_index];
    if (fn_rva < exp_dir.VirtualAddress || fn_rva >= exp_dir.VirtualAddress + exp_dir.Size) {
        return false;
    }

    const size_t max_len = static_cast<size_t>(exp_dir.VirtualAddress + exp_dir.Size - fn_rva);
    const char* fwd_ptr = reinterpret_cast<const char*>(base + fn_rva);
    size_t fwd_len = 0;
    while (fwd_len < max_len && fwd_ptr[fwd_len] != '\0') {
        ++fwd_len;
    }
    if (fwd_len == 0 || fwd_len == max_len) {
        return false;
    }

    const std::string_view fwd_view(fwd_ptr, fwd_len);
    if (!ParseExportForwarder(fwd_view, out_target)) {
        return false;
    }
    if (out_raw_forwarder) {
        out_raw_forwarder->assign(fwd_view);
    }
    return true;
#endif
}

// ---------------------------------------------------------------------------
// TLS Callbacks & x64 .pdata SEH Registration Helpers
// ---------------------------------------------------------------------------
bool ReadMappedPeTlsCallbackRvas(const void* module_base,
                                 std::vector<uint32_t>& out_callback_rvas) {
    out_callback_rvas.clear();
#if !defined(_WIN32)
    (void)module_base;
    return false;
#else
    const uint8_t* base = nullptr;
    const IMAGE_NT_HEADERS64* nt = nullptr;
    uint32_t image_size = 0;
    if (!ReadMappedPeHeaders64(module_base, base, nt, image_size)) {
        return false;
    }

    const auto& tls_dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
    if (tls_dir.VirtualAddress == 0 || tls_dir.Size < sizeof(IMAGE_TLS_DIRECTORY64) ||
        tls_dir.VirtualAddress >= image_size ||
        sizeof(IMAGE_TLS_DIRECTORY64) > image_size - tls_dir.VirtualAddress) {
        return false;
    }

    const auto* tls = reinterpret_cast<const IMAGE_TLS_DIRECTORY64*>(base + tls_dir.VirtualAddress);
    if (tls->AddressOfCallBacks == 0) {
        return true;
    }

    uint32_t cb_array_rva = 0;
    if (!MappedVaToRva(tls->AddressOfCallBacks,
                       reinterpret_cast<uintptr_t>(base),
                       nt->OptionalHeader.ImageBase,
                       image_size,
                       cb_array_rva)) {
        return false;
    }

    for (size_t i = 0; i < 256; ++i) {
        if (cb_array_rva + (i + 1) * sizeof(uint64_t) > image_size) {
            break;
        }
        uint64_t fn_va = 0;
        std::memcpy(&fn_va, base + cb_array_rva + i * sizeof(uint64_t), sizeof(fn_va));
        if (fn_va == 0) {
            break;
        }
        uint32_t fn_rva = 0;
        if (MappedVaToRva(fn_va,
                          reinterpret_cast<uintptr_t>(base),
                          nt->OptionalHeader.ImageBase,
                          image_size,
                          fn_rva)) {
            out_callback_rvas.push_back(fn_rva);
        }
    }
    return true;
#endif
}

uint32_t InvokePeTlsCallbacks(void* module_base, uint32_t reason, void* reserved) {
#if !defined(_WIN32)
    (void)module_base;
    (void)reason;
    (void)reserved;
    return 0;
#else
    if (!module_base) {
        return 0;
    }
    const uint8_t* base = nullptr;
    const IMAGE_NT_HEADERS64* nt = nullptr;
    uint32_t image_size = 0;
    if (!ReadMappedPeHeaders64(module_base, base, nt, image_size)) {
        return 0;
    }

    const auto& tls_dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
    if (tls_dir.VirtualAddress == 0 || tls_dir.Size < sizeof(IMAGE_TLS_DIRECTORY64) ||
        tls_dir.VirtualAddress >= image_size ||
        sizeof(IMAGE_TLS_DIRECTORY64) > image_size - tls_dir.VirtualAddress) {
        return 0;
    }

    const auto* tls = reinterpret_cast<const IMAGE_TLS_DIRECTORY64*>(base + tls_dir.VirtualAddress);
    if (tls->AddressOfCallBacks == 0) {
        return 0;
    }

    // Locate the null-terminated callback pointer table (either inside the mapped image or relocated).
    const uint64_t* cb_table = nullptr;
    uint32_t cb_array_rva = 0;
    size_t max_slots = 256;
    if (MappedVaToRva(tls->AddressOfCallBacks,
                      reinterpret_cast<uintptr_t>(base),
                      nt->OptionalHeader.ImageBase,
                      image_size,
                      cb_array_rva)) {
        cb_table = reinterpret_cast<const uint64_t*>(base + cb_array_rva);
        max_slots = std::min<size_t>(256u, (image_size - cb_array_rva) / sizeof(uint64_t));
    } else {
        cb_table = reinterpret_cast<const uint64_t*>(static_cast<uintptr_t>(tls->AddressOfCallBacks));
    }

    uint32_t invoked = 0;
    for (size_t i = 0; i < max_slots; ++i) {
        const uint64_t fn_va = cb_table[i];
        if (fn_va == 0) {
            break;
        }
        PIMAGE_TLS_CALLBACK fn = nullptr;
        uint32_t fn_rva = 0;
        if (MappedVaToRva(fn_va,
                          reinterpret_cast<uintptr_t>(base),
                          nt->OptionalHeader.ImageBase,
                          image_size,
                          fn_rva)) {
            fn = reinterpret_cast<PIMAGE_TLS_CALLBACK>(
                static_cast<uint8_t*>(module_base) + fn_rva);
        } else {
            // Allow direct absolute function pointer (useful for custom/synthetic host-memory harnesses).
            fn = reinterpret_cast<PIMAGE_TLS_CALLBACK>(static_cast<uintptr_t>(fn_va));
        }
        if (fn != nullptr) {
            fn(module_base, static_cast<DWORD>(reason), reserved);
            ++invoked;
        }
    }
    return invoked;
#endif
}

bool RegisterPeExceptionTable(void* module_base, uint32_t pdata_rva, uint32_t pdata_size) {
#if defined(_WIN32) && (defined(_M_X64) || defined(__x86_64__))
    if (!module_base || pdata_rva == 0 || pdata_size < sizeof(RUNTIME_FUNCTION)) {
        return false;
    }
    auto* table = reinterpret_cast<PRUNTIME_FUNCTION>(
        static_cast<uint8_t*>(module_base) + pdata_rva);
    const DWORD entry_count = pdata_size / static_cast<DWORD>(sizeof(RUNTIME_FUNCTION));
    if (entry_count == 0) {
        return false;
    }
    return ::RtlAddFunctionTable(table,
                                 entry_count,
                                 reinterpret_cast<DWORD64>(module_base)) != FALSE;
#else
    (void)module_base;
    (void)pdata_rva;
    (void)pdata_size;
    return false;
#endif
}

bool RegisterPeExceptionTableFromImage(void* module_base, uint32_t* out_entry_count) {
    if (out_entry_count) {
        *out_entry_count = 0;
    }
#if defined(_WIN32) && (defined(_M_X64) || defined(__x86_64__))
    const uint8_t* base = nullptr;
    const IMAGE_NT_HEADERS64* nt = nullptr;
    uint32_t image_size = 0;
    if (!ReadMappedPeHeaders64(module_base, base, nt, image_size)) {
        return false;
    }
    const auto& exc_dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
    if (exc_dir.VirtualAddress == 0 || exc_dir.Size < sizeof(RUNTIME_FUNCTION) ||
        exc_dir.VirtualAddress >= image_size ||
        exc_dir.Size > image_size - exc_dir.VirtualAddress) {
        return false;
    }
    const uint32_t count = exc_dir.Size / static_cast<uint32_t>(sizeof(RUNTIME_FUNCTION));
    if (!RegisterPeExceptionTable(module_base, exc_dir.VirtualAddress, exc_dir.Size)) {
        return false;
    }
    if (out_entry_count) {
        *out_entry_count = count;
    }
    return true;
#else
    (void)module_base;
    return false;
#endif
}

bool UnregisterPeExceptionTable(void* module_base, uint32_t pdata_rva) {
#if defined(_WIN32) && (defined(_M_X64) || defined(__x86_64__))
    if (!module_base || pdata_rva == 0) {
        return false;
    }
    auto* table = reinterpret_cast<PRUNTIME_FUNCTION>(
        static_cast<uint8_t*>(module_base) + pdata_rva);
    return ::RtlDeleteFunctionTable(table) != FALSE;
#else
    (void)module_base;
    (void)pdata_rva;
    return false;
#endif
}

// ---------------------------------------------------------------------------
// Base Relocation Validation (RVA 0 / Size 0 Safe)
// ---------------------------------------------------------------------------
Status ValidatePeBaseRelocations(const std::vector<uint8_t>& bytes,
                                 bool& out_has_relocations,
                                 uint32_t& out_block_count,
                                 uint32_t& out_entry_count) {
    out_has_relocations = false;
    out_block_count = 0u;
    out_entry_count = 0u;

    PeInspectionReport rep{};
    Status st = InspectPeBytes(bytes, "<reloc_check>", rep);
    if (!st.ok()) {
        return st;
    }
    out_has_relocations = rep.has_relocations;
    out_block_count = rep.reloc_block_count;
    out_entry_count = rep.reloc_entry_count;
    return Status::Ok();
}

// ---------------------------------------------------------------------------
// x64 .pdata / .xdata Unwind Metadata Validator
//   - Validates UNWIND_INFO v1, v2, v3 headers and flags
//   - Validates UWOP_ALLOC_LARGE (info=0 scaled*8, info=1 unscaled 32-bit, alignment & bounds)
//   - Validates v2/v3 UWOP_EPILOG unwind codes
//   - Validates UNW_FLAG_CHAININFO trailing RUNTIME_FUNCTION with cycle detection
// ---------------------------------------------------------------------------
Status ValidatePeXdataUnwind(const std::vector<uint8_t>& bytes,
                             PeXdataValidationResult& out_result) {
    out_result = {};
    if (bytes.size() < 0x100u) {
        return Status::Error(StatusCode::ParseError, "Image too small for PE headers");
    }
    uint16_t mz = 0u;
    uint32_t pe_off = 0u;
    if (!ReadPod(bytes, 0u, mz) || mz != 0x5A4Du || !ReadPod(bytes, 0x3Cu, pe_off)) {
        return Status::Error(StatusCode::ParseError, "Missing DOS MZ header");
    }
    uint32_t pe_sig = 0u;
    if (!ReadPod(bytes, pe_off, pe_sig) || pe_sig != 0x00004550u) {
        return Status::Error(StatusCode::ParseError, "Missing PE signature");
    }

    const size_t coff_off = static_cast<size_t>(pe_off) + 4u;
    uint16_t num_sections = 0u;
    uint16_t opt_size = 0u;
    if (!ReadPod(bytes, coff_off + 2u, num_sections) ||
        !ReadPod(bytes, coff_off + 16u, opt_size)) {
        return Status::Error(StatusCode::ParseError, "Truncated COFF header");
    }
    const size_t opt_off = coff_off + 20u;
    uint16_t opt_magic = 0u;
    uint32_t image_size = 0u;
    uint32_t num_rva_and_sizes = 0u;
    if (opt_size < 0x70u || !ReadPod(bytes, opt_off, opt_magic) || opt_magic != 0x020Bu ||
        !ReadPod(bytes, opt_off + 56u, image_size) ||
        !ReadPod(bytes, opt_off + 108u, num_rva_and_sizes)) {
        return Status::Error(StatusCode::UnsupportedFormat, "Not a valid PE32+ image");
    }

    const size_t dd_off = opt_off + 112u;
    if (num_rva_and_sizes <= 3u) {
        return Status::Ok();
    }
    uint32_t exc_rva = 0u;
    uint32_t exc_sz = 0u;
    if (!ReadPod(bytes, dd_off + 3u * 8u, exc_rva) ||
        !ReadPod(bytes, dd_off + 3u * 8u + 4u, exc_sz)) {
        return Status::Error(StatusCode::ParseError, "Truncated exception data directory");
    }
    if (exc_rva == 0u || exc_sz == 0u) {
        return Status::Ok();
    }

    const size_t sec_off = opt_off + opt_size;
    std::vector<SectionRange> sections;
    sections.reserve(num_sections);
    for (uint16_t i = 0; i < num_sections; ++i) {
        const size_t base = sec_off + static_cast<size_t>(i) * 40u;
        SectionRange sr{};
        if (!ReadPod(bytes, base + 8u, sr.vsize) ||
            !ReadPod(bytes, base + 12u, sr.vaddr) ||
            !ReadPod(bytes, base + 16u, sr.raw_size) ||
            !ReadPod(bytes, base + 20u, sr.raw_ptr)) {
            return Status::Error(StatusCode::ParseError, "Truncated section table");
        }
        sections.push_back(sr);
    }

    size_t pdata_off = 0u;
    size_t pdata_avail = 0u;
    if (!RvaToSectionSlice(sections, exc_rva, bytes.size(), pdata_off, pdata_avail)) {
        ++out_result.bounds_errors;
        out_result.errors.push_back("Exception directory RVA outside raw section data");
        return Status::Ok();
    }

    constexpr uint8_t kUnwFlagEhandler = 0x01u;
    constexpr uint8_t kUnwFlagUhandler = 0x02u;
    constexpr uint8_t kUnwFlagChainInfo = 0x04u;

    auto record_error = [&](const std::string& msg) {
        if (out_result.errors.size() < 64u) {
            out_result.errors.push_back(msg);
        }
    };

    // Helper: validates a single UNWIND_INFO at `unwind_rva` plus any chained targets.
    auto validate_unwind_chain = [&](uint32_t start_unwind_rva,
                                     bool& out_had_alloc_large,
                                     bool& out_had_epilog,
                                     bool& out_had_chain,
                                     uint8_t& out_primary_version) -> bool {
        out_had_alloc_large = false;
        out_had_epilog = false;
        out_had_chain = false;
        out_primary_version = 0u;

        std::unordered_set<uint32_t> visited_rvas;
        uint32_t cur_rva = start_unwind_rva;
        for (uint32_t depth = 0u; depth < 32u; ++depth) {
            // Follow odd indirect RUNTIME_FUNCTION pointer (bit 0 set in x64 .pdata ABI).
            uint32_t indirection_guard = 0u;
            while ((cur_rva & 1u) != 0u && indirection_guard < 8u) {
                const uint32_t rf_rva = cur_rva & ~1u;
                if (!visited_rvas.insert(rf_rva | 1u).second) {
                    ++out_result.cycle_errors;
                    record_error("Cyclic indirect RUNTIME_FUNCTION in .pdata");
                    return false;
                }
                size_t rf_off = 0u, rf_avail = 0u;
                uint32_t r_begin = 0u, r_end = 0u, r_next_unwind = 0u;
                if (!RvaToSectionSlice(sections, rf_rva, bytes.size(), rf_off, rf_avail) ||
                    rf_avail < 12u ||
                    !ReadPod(bytes, rf_off, r_begin) ||
                    !ReadPod(bytes, rf_off + 4u, r_end) ||
                    !ReadPod(bytes, rf_off + 8u, r_next_unwind) ||
                    r_begin >= r_end) {
                    ++out_result.bounds_errors;
                    record_error("Invalid indirect RUNTIME_FUNCTION target");
                    return false;
                }
                cur_rva = r_next_unwind;
                out_had_chain = true;
                ++indirection_guard;
            }
            if ((cur_rva & 1u) != 0u) {
                ++out_result.cycle_errors;
                record_error("Excessive indirect RUNTIME_FUNCTION depth");
                return false;
            }

            if ((cur_rva & 3u) != 0u) {
                ++out_result.alignment_errors;
                record_error("UNWIND_INFO RVA is not 4-byte aligned");
                return false;
            }
            if (cur_rva == 0u || cur_rva >= image_size) {
                ++out_result.bounds_errors;
                record_error("UNWIND_INFO RVA out of image bounds");
                return false;
            }
            if (!visited_rvas.insert(cur_rva).second) {
                ++out_result.cycle_errors;
                record_error("Cycle detected in chained .xdata UNWIND_INFO");
                return false;
            }

            size_t ui_off = 0u;
            size_t ui_avail = 0u;
            if (!RvaToSectionSlice(sections, cur_rva, bytes.size(), ui_off, ui_avail) || ui_avail < 4u) {
                ++out_result.bounds_errors;
                record_error("UNWIND_INFO header out of section bounds");
                return false;
            }

            const uint8_t b0 = bytes[ui_off + 0u];
            const uint8_t size_of_prolog = bytes[ui_off + 1u];
            const uint8_t count_of_codes = bytes[ui_off + 2u];
            const uint8_t b3 = bytes[ui_off + 3u];
            (void)size_of_prolog;
            (void)b3;

            const uint8_t version = b0 & 0x07u;
            const uint8_t flags = static_cast<uint8_t>((b0 >> 3u) & 0x1Fu);
            if (version < 1u || version > 3u) {
                ++out_result.bounds_errors;
                record_error("Unsupported UNWIND_INFO version");
                return false;
            }
            if ((flags & ~static_cast<uint8_t>(kUnwFlagEhandler | kUnwFlagUhandler | kUnwFlagChainInfo)) != 0u) {
                ++out_result.bounds_errors;
                record_error("Unknown UNWIND_INFO flags");
                return false;
            }
            if ((flags & kUnwFlagChainInfo) != 0u &&
                (flags & (kUnwFlagEhandler | kUnwFlagUhandler)) != 0u) {
                ++out_result.bounds_errors;
                record_error("UNW_FLAG_CHAININFO cannot combine with exception/unwind handler flags");
                return false;
            }
            if (depth == 0u) {
                out_primary_version = version;
            }

            const uint32_t padded_codes = (static_cast<uint32_t>(count_of_codes) + 1u) & ~1u;
            const size_t codes_bytes = static_cast<size_t>(padded_codes) * 2u;
            if (4u + codes_bytes > ui_avail) {
                ++out_result.bounds_errors;
                record_error("UNWIND_CODE array truncated past section bounds");
                return false;
            }

            uint32_t slot = 0u;
            while (slot < count_of_codes) {
                const size_t code_off = ui_off + 4u + static_cast<size_t>(slot) * 2u;
                const uint8_t op_byte = bytes[code_off + 1u];
                const uint8_t unwind_op = op_byte & 0x0Fu;
                const uint8_t op_info = static_cast<uint8_t>((op_byte >> 4u) & 0x0Fu);

                switch (unwind_op) {
                    case 0u:  // UWOP_PUSH_NONVOL
                        slot += 1u;
                        break;
                    case 1u: {  // UWOP_ALLOC_LARGE
                        out_had_alloc_large = true;
                        if (op_info == 0u) {
                            if (slot + 1u >= count_of_codes) {
                                ++out_result.bounds_errors;
                                record_error("UWOP_ALLOC_LARGE (info=0) missing scaled size slot");
                                return false;
                            }
                            uint16_t scaled = 0u;
                            ReadPod(bytes, code_off + 2u, scaled);
                            const uint32_t alloc_bytes = static_cast<uint32_t>(scaled) * 8u;
                            if (alloc_bytes == 0u) {
                                ++out_result.alignment_errors;
                                record_error("UWOP_ALLOC_LARGE (info=0) has zero allocation size");
                                return false;
                            }
                            slot += 2u;
                        } else if (op_info == 1u) {
                            if (slot + 2u >= count_of_codes) {
                                ++out_result.bounds_errors;
                                record_error("UWOP_ALLOC_LARGE (info=1) missing 32-bit size slots");
                                return false;
                            }
                            uint32_t unscaled = 0u;
                            ReadPod(bytes, code_off + 2u, unscaled);
                            if (unscaled == 0u || (unscaled & 7u) != 0u) {
                                ++out_result.alignment_errors;
                                record_error("UWOP_ALLOC_LARGE (info=1) size is zero or not 8-byte stack-slot aligned");
                                return false;
                            }
                            slot += 3u;
                        } else {
                            ++out_result.bounds_errors;
                            record_error("UWOP_ALLOC_LARGE has invalid OpInfo (>1)");
                            return false;
                        }
                        break;
                    }
                    case 2u:  // UWOP_ALLOC_SMALL
                    case 3u:  // UWOP_SET_FPREG
                        slot += 1u;
                        break;
                    case 4u:  // UWOP_SAVE_NONVOL (2 slots)
                        if (slot + 1u >= count_of_codes) {
                            ++out_result.bounds_errors;
                            record_error("UWOP_SAVE_NONVOL truncated");
                            return false;
                        }
                        slot += 2u;
                        break;
                    case 5u:  // UWOP_SAVE_NONVOL_FAR (3 slots)
                        if (slot + 2u >= count_of_codes) {
                            ++out_result.bounds_errors;
                            record_error("UWOP_SAVE_NONVOL_FAR truncated");
                            return false;
                        }
                        slot += 3u;
                        break;
                    case 6u:  // UWOP_EPILOG (valid in v2/v3 only)
                        if (version < 2u) {
                            ++out_result.bounds_errors;
                            record_error("UWOP_EPILOG encountered in UNWIND_INFO v1");
                            return false;
                        }
                        out_had_epilog = true;
                        slot += 1u;
                        break;
                    case 7u:  // UWOP_SPARE_CODE (v1 legacy 2-slot)
                        if (version >= 2u || slot + 1u >= count_of_codes) {
                            ++out_result.bounds_errors;
                            record_error("Invalid UWOP_SPARE_CODE in UNWIND_INFO");
                            return false;
                        }
                        slot += 2u;
                        break;
                    case 8u:  // UWOP_SAVE_XMM128 (2 slots)
                        if (slot + 1u >= count_of_codes) {
                            ++out_result.bounds_errors;
                            record_error("UWOP_SAVE_XMM128 truncated");
                            return false;
                        }
                        slot += 2u;
                        break;
                    case 9u:  // UWOP_SAVE_XMM128_FAR (3 slots)
                        if (slot + 2u >= count_of_codes) {
                            ++out_result.bounds_errors;
                            record_error("UWOP_SAVE_XMM128_FAR truncated");
                            return false;
                        }
                        slot += 3u;
                        break;
                    case 10u:  // UWOP_PUSH_MACHFRAME (1 slot, op_info 0 or 1)
                        if (op_info > 1u) {
                            ++out_result.bounds_errors;
                            record_error("UWOP_PUSH_MACHFRAME invalid OpInfo");
                            return false;
                        }
                        slot += 1u;
                        break;
                    default:
                        ++out_result.bounds_errors;
                        record_error("Unknown x64 UNWIND_CODE opcode");
                        return false;
                }
            }

            const size_t tail_off = ui_off + 4u + codes_bytes;
            const size_t tail_avail = ui_avail - (4u + codes_bytes);
            if ((flags & kUnwFlagChainInfo) != 0u) {
                out_had_chain = true;
                if (tail_avail < 12u) {
                    ++out_result.bounds_errors;
                    record_error("Chained RUNTIME_FUNCTION truncated after UNWIND_CODE array");
                    return false;
                }
                uint32_t ch_begin = 0u, ch_end = 0u, ch_unwind = 0u;
                ReadPod(bytes, tail_off + 0u, ch_begin);
                ReadPod(bytes, tail_off + 4u, ch_end);
                ReadPod(bytes, tail_off + 8u, ch_unwind);
                if (ch_begin >= ch_end || ch_end > image_size || ch_unwind == 0u) {
                    ++out_result.bounds_errors;
                    record_error("Chained RUNTIME_FUNCTION has invalid range or unwind RVA");
                    return false;
                }
                cur_rva = ch_unwind;
                continue;
            }

            if ((flags & (kUnwFlagEhandler | kUnwFlagUhandler)) != 0u) {
                if (tail_avail < 4u) {
                    ++out_result.bounds_errors;
                    record_error("Exception handler RVA truncated after UNWIND_CODE array");
                    return false;
                }
                uint32_t handler_rva = 0u;
                ReadPod(bytes, tail_off, handler_rva);
                if (handler_rva == 0u || handler_rva >= image_size) {
                    ++out_result.bounds_errors;
                    record_error("Exception handler RVA out of image bounds");
                    return false;
                }
            }

            return true;
        }

        ++out_result.cycle_errors;
        record_error("Chained UNWIND_INFO depth exceeded maximum limit (32)");
        return false;
    };

    const uint32_t capped_entries = std::min<uint32_t>(
        exc_sz / 12u,
        static_cast<uint32_t>(pdata_avail / 12u));
    out_result.runtime_function_count = capped_entries;

    for (uint32_t i = 0u; i < capped_entries; ++i) {
        const size_t rf_off = pdata_off + static_cast<size_t>(i) * 12u;
        uint32_t begin_rva = 0u, end_rva = 0u, unwind_rva = 0u;
        if (!ReadPod(bytes, rf_off + 0u, begin_rva) ||
            !ReadPod(bytes, rf_off + 4u, end_rva) ||
            !ReadPod(bytes, rf_off + 8u, unwind_rva)) {
            ++out_result.invalid_entries;
            ++out_result.bounds_errors;
            break;
        }
        if (begin_rva == 0u && end_rva == 0u && unwind_rva == 0u) {
            break;
        }
        if (begin_rva >= end_rva || end_rva > image_size) {
            ++out_result.invalid_entries;
            ++out_result.bounds_errors;
            record_error("RUNTIME_FUNCTION BeginAddress/EndAddress invalid");
            continue;
        }

        bool had_alloc_large = false;
        bool had_epilog = false;
        bool had_chain = false;
        uint8_t primary_ver = 0u;
        if (validate_unwind_chain(unwind_rva, had_alloc_large, had_epilog, had_chain, primary_ver)) {
            ++out_result.valid_entries;
            if (primary_ver == 1u) ++out_result.v1_entries;
            else if (primary_ver == 2u) ++out_result.v2_entries;
            else if (primary_ver == 3u) ++out_result.v3_entries;
            if (had_alloc_large) ++out_result.alloc_large_entries;
            if (had_epilog) ++out_result.epilog_code_entries;
            if (had_chain) ++out_result.chained_entries;
        } else {
            ++out_result.invalid_entries;
        }
    }

    return Status::Ok();
}

// ---------------------------------------------------------------------------
// Fault-Free PE Section Protection Transitions
// ---------------------------------------------------------------------------
uint32_t ComputePeSectionProtection(uint32_t section_characteristics) noexcept {
    constexpr uint32_t kScnNotCached = 0x04000000u;
    constexpr uint32_t kScnExecute = 0x20000000u;
    constexpr uint32_t kScnRead = 0x40000000u;
    constexpr uint32_t kScnWrite = 0x80000000u;

    const bool r = (section_characteristics & kScnRead) != 0u;
    const bool w = (section_characteristics & kScnWrite) != 0u;
    const bool x = (section_characteristics & kScnExecute) != 0u;

    uint32_t prot = 0x01u;  // PAGE_NOACCESS
    if (x) {
        if (w) {
            prot = 0x40u;  // PAGE_EXECUTE_READWRITE
        } else if (r) {
            prot = 0x20u;  // PAGE_EXECUTE_READ
        } else {
            prot = 0x10u;  // PAGE_EXECUTE
        }
    } else {
        if (w) {
            prot = 0x04u;  // PAGE_READWRITE
        } else if (r) {
            prot = 0x02u;  // PAGE_READONLY
        } else {
            prot = 0x01u;  // PAGE_NOACCESS
        }
    }
    if ((section_characteristics & kScnNotCached) != 0u && prot != 0x01u) {
        prot |= 0x200u;  // PAGE_NOCACHE
    }
    return prot;
}

Status ApplyPeSectionProtections(void* module_base,
                                 PeSectionProtectionSummary* out_summary) {
    PeSectionProtectionSummary summary{};
    if (out_summary) {
        *out_summary = summary;
    }
    if (!module_base) {
        return Status::Error(StatusCode::InvalidArgument, "Null PE module base");
    }
#if !defined(_WIN32)
    return Status::Error(StatusCode::NotImplemented, "ApplyPeSectionProtections requires Windows");
#else
    // Validate that the DOS header page is committed before touching memory.
    MEMORY_BASIC_INFORMATION hdr_mbi{};
    if (::VirtualQuery(module_base, &hdr_mbi, sizeof(hdr_mbi)) == 0u ||
        hdr_mbi.State != MEM_COMMIT ||
        (hdr_mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)) != 0u) {
        return Status::Error(StatusCode::InvalidArgument, "PE header page is not committed/readable");
    }

    const uint8_t* base = nullptr;
    const IMAGE_NT_HEADERS64* nt = nullptr;
    uint32_t image_size = 0u;
    if (!ReadMappedPeHeaders64(module_base, base, nt, image_size)) {
        return Status::Error(StatusCode::ParseError, "Invalid mapped PE32+ headers");
    }

    SYSTEM_INFO si{};
    ::GetSystemInfo(&si);
    const size_t page_size = (si.dwPageSize != 0u) ? static_cast<size_t>(si.dwPageSize) : 4096u;

    const IMAGE_SECTION_HEADER* secs = IMAGE_FIRST_SECTION(nt);
    const uint16_t num_sections = nt->FileHeader.NumberOfSections;
    summary.total_sections = num_sections;

    const uintptr_t img_start = reinterpret_cast<uintptr_t>(module_base);
    const uintptr_t img_end = img_start + static_cast<uintptr_t>(image_size);

    for (uint16_t i = 0u; i < num_sections; ++i) {
        const auto& sec = secs[i];
        const uint32_t raw_span = std::max<uint32_t>(
            static_cast<uint32_t>(sec.Misc.VirtualSize),
            static_cast<uint32_t>(sec.SizeOfRawData));
        if (sec.VirtualAddress == 0u || raw_span == 0u || sec.VirtualAddress >= image_size) {
            ++summary.skipped_sections;
            continue;
        }

        const uint32_t clamped_span = std::min<uint32_t>(
            raw_span, image_size - static_cast<uint32_t>(sec.VirtualAddress));
        const uintptr_t sec_raw_start = img_start + static_cast<uintptr_t>(sec.VirtualAddress);
        const uintptr_t sec_raw_end = sec_raw_start + static_cast<uintptr_t>(clamped_span);

        const uintptr_t aligned_start = std::max(img_start, sec_raw_start & ~(page_size - 1u));
        const uintptr_t aligned_end = std::min(img_end, (sec_raw_end + page_size - 1u) & ~(page_size - 1u));
        if (aligned_end <= aligned_start) {
            ++summary.skipped_sections;
            continue;
        }

        const DWORD new_prot = static_cast<DWORD>(ComputePeSectionProtection(sec.Characteristics));
        bool any_committed = false;
        bool any_failed = false;

        uintptr_t cursor = aligned_start;
        while (cursor < aligned_end) {
            MEMORY_BASIC_INFORMATION mbi{};
            if (::VirtualQuery(reinterpret_cast<const void*>(cursor), &mbi, sizeof(mbi)) == 0u ||
                mbi.RegionSize == 0u) {
                break;
            }
            const uintptr_t reg_start = reinterpret_cast<uintptr_t>(mbi.BaseAddress);
            const uintptr_t reg_end = reg_start + mbi.RegionSize;
            const uintptr_t step_end = std::min(aligned_end, reg_end);
            if (step_end <= cursor) {
                break;
            }
            if (mbi.State == MEM_COMMIT) {
                any_committed = true;
                DWORD old_prot = 0u;
                if (!::VirtualProtect(reinterpret_cast<void*>(cursor),
                                      static_cast<SIZE_T>(step_end - cursor),
                                      new_prot,
                                      &old_prot)) {
                    any_failed = true;
                }
            }
            cursor = step_end;
        }

        if (!any_committed) {
            ++summary.skipped_sections;
        } else if (any_failed) {
            ++summary.failed_sections;
        } else {
            ++summary.protected_sections;
        }
    }

    if (out_summary) {
        *out_summary = summary;
    }
    return summary.failed_sections == 0u
               ? Status::Ok()
               : Status::Error(StatusCode::DeviceError, "One or more PE sections failed VirtualProtect");
#endif
}

}  // namespace openscarlett
