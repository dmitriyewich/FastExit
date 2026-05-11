#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <MinHook.h>
#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <limits>

static_assert(sizeof(void*) == 4, "FastExit.asi must be built for Win32.");

namespace {
constexpr DWORD kGtaLoadStateAddress = 0x00C8D4C0;
constexpr DWORD kMaxWaitForSampMs = 300000;
constexpr char kIniFileName[] = "FastExit.ini";
constexpr char kConfigSection[] = "Settings";
constexpr char kConfigKeyExitMode[] = "Exit mode";
constexpr std::uint32_t kGta10UsTextStartCompact = 0x53EC8B55u;
constexpr std::uint32_t kGta10UsTextStartHoodlum = 0x16197BE9u;
/** RVA `CGame::Shutdown` (1.0 US / Hoodlum): VA 0x0053C900 − ImageBase 0x00400000. */
constexpr std::uint32_t kCGameShutdownRva = 0x0013C900;
struct SampVersionInfo {
    DWORD entryPointRva;
    const char* name;
    /** RVA вызова GetTickCount на пути выгрузки после /quit; 0 — нет (напр. R2). */
    std::uint32_t sampUnloadGetTickCountCallRva;
};
struct Config {
    int exitMode = 0;
    char path[MAX_PATH]{};
};
constexpr std::array<SampVersionInfo, 8> kSupportedVersions{{
    { 0x031DF13, "R1", 0x000B28DE },
    { 0x03195DD, "R2", 0x00000000 },
    { 0x00CC490, "R3", 0x000C46EB },
    { 0x00CC4D0, "R3-1", 0x000C472B },
    { 0x00CBCB0, "R4", 0x000C3EBB },
    { 0x00CBCD0, "R4-2", 0x000C3EEA },
    { 0x00CBC90, "R5-1", 0x000C3EAA },
    { 0x00FDB60, "DL-R1", 0x000C557B },
}};
#pragma pack(push, 1)
struct RelativeCallPatch {
    std::uint8_t opcode;
    std::int32_t relative;
};
struct IndirectCallPatch {
    std::uint8_t opcode0;
    std::uint8_t opcode1;
    std::uint32_t targetPointerAddress;
};
#pragma pack(pop)
HMODULE g_module = nullptr;
Config g_config;
std::uint32_t g_indirectThunkTarget = 0;
using CGameShutdown_t = bool(__cdecl*)();
static CGameShutdown_t g_origCGameShutdown = nullptr;
const IMAGE_NT_HEADERS32* GetPe32NtHeaders(HMODULE module) {
    if (!module) {
        return nullptr;
    }
    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(module);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        return nullptr;
    }
    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS32*>(
        reinterpret_cast<const std::uint8_t*>(module) + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) {
        return nullptr;
    }
    return nt;
}
void BuildConfigPath(char out[MAX_PATH]) {
    if (GetModuleFileNameA(g_module, out, MAX_PATH) == 0) {
        strcpy_s(out, MAX_PATH, kIniFileName);
        return;
    }
    char* slash = nullptr;
    for (char* p = out; *p; ++p) {
        if (*p == '\\' || *p == '/') {
            slash = p;
        }
    }
    if (slash) {
        slash[1] = '\0';
        strcat_s(out, MAX_PATH, kIniFileName);
    } else {
        strcpy_s(out, MAX_PATH, kIniFileName);
    }
}
bool WriteDefaultIniIfNotExists(const char* path) {
    if (GetFileAttributesA(path) != INVALID_FILE_ATTRIBUTES) {
        return false;
    }
    static const char kBody[] =
        "[Settings]\r\n"
        "; 0 — как без плагина; 1 — ExitProcess; 2 — TerminateProcess.\r\n"
        "; «Выйти» (CGame::Shutdown, gta_sa 1.0 US) и выгрузка samp после /q и /quit (одна подмена call; R2 — без RVA).\r\n"
        "Exit mode=0\r\n";
    const HANDLE h = CreateFileA(path, GENERIC_WRITE, FILE_SHARE_READ, nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        return false;
    }
    DWORD written = 0;
    const DWORD n = static_cast<DWORD>(std::strlen(kBody));
    const BOOL ok = WriteFile(h, kBody, n, &written, nullptr);
    CloseHandle(h);
    return ok && written == n;
}
int LoadIniIntClamped(
    const char* key, const char* defaultStr, int minV, int maxV, int fallback, const char* iniPath) {
    char rawBuf[64] = {};
    (void)GetPrivateProfileStringA(kConfigSection, key, defaultStr, rawBuf, static_cast<DWORD>(sizeof(rawBuf)), iniPath);
    const char* rawStr = rawBuf[0] ? rawBuf : defaultStr;
    char* end = nullptr;
    const long parsed = std::strtol(rawStr, &end, 10);
    int v = fallback;
    if (end != rawStr && !*end) {
        v = static_cast<int>(std::clamp(parsed, static_cast<long>(minV), static_cast<long>(maxV)));
    }
    char normalizedValue[32] = {};
    _snprintf_s(normalizedValue, _TRUNCATE, "%d", v);
    (void)WritePrivateProfileStringA(kConfigSection, key, normalizedValue, iniPath);
    return v;
}
Config LoadConfig() {
    Config cfg;
    BuildConfigPath(cfg.path);
    (void)WriteDefaultIniIfNotExists(cfg.path);
    cfg.exitMode = LoadIniIntClamped(kConfigKeyExitMode, "0", 0, 2, 0, cfg.path);
    return cfg;
}
bool IsGtaSa10UsExecutable(HMODULE exeModule) {
    const auto* nt = GetPe32NtHeaders(exeModule);
    if (!nt) {
        return false;
    }
    const DWORD imageBase = nt->OptionalHeader.ImageBase;
    const std::uintptr_t base = reinterpret_cast<std::uintptr_t>(exeModule);
    if (base != imageBase) {
        return false;
    }
    const auto w = *reinterpret_cast<const std::uint32_t*>(base + 0x1000);
    return w == kGta10UsTextStartCompact || w == kGta10UsTextStartHoodlum;
}
bool WriteBytes(void* address, const void* data, std::size_t size) {
    DWORD oldProtect = 0;
    if (!VirtualProtect(address, size, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        return false;
    }
    std::memcpy(address, data, size);
    FlushInstructionCache(GetCurrentProcess(), address, size);
    DWORD restore = 0;
    VirtualProtect(address, size, oldProtect, &restore);
    return true;
}
const SampVersionInfo* DetectSampVersion(HMODULE sampModule) {
    const auto* nt = GetPe32NtHeaders(sampModule);
    if (!nt) {
        return nullptr;
    }
    const DWORD ep = nt->OptionalHeader.AddressOfEntryPoint;
    for (const auto& v : kSupportedVersions) {
        if (v.entryPointRva == ep) {
            return &v;
        }
    }
    return nullptr;
}
void HardExitIfEnabled() {
    switch (g_config.exitMode) {
    case 1:
        ExitProcess(0);
        break;
    case 2:
        TerminateProcess(GetCurrentProcess(), 0);
        break;
    default:
        break;
    }
}
DWORD WINAPI HookSampUnloadGetTickCount() {
    HardExitIfEnabled();
    return GetTickCount();
}
bool __cdecl HookedCGameShutdown() {
    HardExitIfEnabled();
    return g_origCGameShutdown ? g_origCGameShutdown() : false;
}
/** Подмена `E8 rel` или `FF 15 imm32` на вызов `hookFn` (для FF 15 в `g_indirectThunkTarget` кладётся адрес хука). */
bool PatchCallToHook(std::uintptr_t callSite, void* hookFn) {
    std::uint8_t op[2] = {};
    std::memcpy(op, reinterpret_cast<const void*>(callSite), sizeof(op));
    const auto hookAddr = reinterpret_cast<std::uintptr_t>(hookFn);
    if (op[0] == 0xE8) {
        const long long rel = static_cast<long long>(hookAddr)
            - static_cast<long long>(callSite + sizeof(RelativeCallPatch));
        if (rel < std::numeric_limits<std::int32_t>::min() || rel > std::numeric_limits<std::int32_t>::max()) {
            return false;
        }
        const RelativeCallPatch patch{ 0xE8, static_cast<std::int32_t>(rel) };
        return WriteBytes(reinterpret_cast<void*>(callSite), &patch, sizeof(patch));
    }
    if (op[0] == 0xFF && op[1] == 0x15) {
        g_indirectThunkTarget = static_cast<std::uint32_t>(hookAddr);
        const IndirectCallPatch patch{ 0xFF, 0x15, reinterpret_cast<std::uint32_t>(&g_indirectThunkTarget) };
        return WriteBytes(reinterpret_cast<void*>(callSite), &patch, sizeof(patch));
    }
    return false;
}
bool ApplySampUnloadHook(HMODULE sampModule, const SampVersionInfo& version) {
    if (g_config.exitMode != 1 && g_config.exitMode != 2) {
        return true;
    }
    if (!version.sampUnloadGetTickCountCallRva) {
        return true;
    }
    const std::uintptr_t base = reinterpret_cast<std::uintptr_t>(sampModule);
    return PatchCallToHook(base + version.sampUnloadGetTickCountCallRva, reinterpret_cast<void*>(&HookSampUnloadGetTickCount));
}
bool InstallGtaShutdownHook() {
    if (!g_config.exitMode) {
        return true;
    }
    HMODULE exe = GetModuleHandleA(nullptr);
    if (!IsGtaSa10UsExecutable(exe)) {
        return false;
    }
    const MH_STATUS st = MH_Initialize();
    if (st != MH_OK && st != MH_ERROR_ALREADY_INITIALIZED) {
        return false;
    }
    void* const shutdownAddr = reinterpret_cast<void*>(reinterpret_cast<std::uintptr_t>(exe) + kCGameShutdownRva);
    if (MH_CreateHook(shutdownAddr, &HookedCGameShutdown, reinterpret_cast<void**>(&g_origCGameShutdown)) != MH_OK) {
        MH_Uninitialize();
        return false;
    }
    if (MH_EnableHook(MH_ALL_HOOKS) != MH_OK) {
        MH_DisableHook(MH_ALL_HOOKS);
        MH_RemoveHook(shutdownAddr);
        MH_Uninitialize();
        return false;
    }
    return true;
}
void WaitUntilGtaLoaded() {
    const auto* loadState = reinterpret_cast<volatile DWORD*>(kGtaLoadStateAddress);
    while (*loadState < 9) {
        Sleep(10);
    }
}
void WaitForSampAndApplyHook() {
    const DWORD t0 = GetTickCount();
    for (;;) {
        HMODULE samp = GetModuleHandleA("samp.dll");
        if (samp) {
            if (const auto* ver = DetectSampVersion(samp)) {
                (void)ApplySampUnloadHook(samp, *ver);
            }
            return;
        }
        if (GetTickCount() - t0 >= kMaxWaitForSampMs) {
            return;
        }
        Sleep(100);
    }
}
DWORD WINAPI InitializePlugin(void*) {
    WaitUntilGtaLoaded();
    g_config = LoadConfig();
    WaitForSampAndApplyHook();
    (void)InstallGtaShutdownHook();
    return 0;
}
}  // namespace

BOOL APIENTRY DllMain(HMODULE module, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        g_module = module;
        DisableThreadLibraryCalls(module);
        if (HANDLE th = CreateThread(nullptr, 0, &InitializePlugin, nullptr, 0, nullptr)) {
            CloseHandle(th);
        }
    }
    return TRUE;
}
