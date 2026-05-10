#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#include <MinHook.h>

#include <array>
#include <atomic>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <limits>

static_assert(sizeof(void*) == 4, "FastExit.asi must be built for Win32.");

namespace {

// Состояние загрузки GTA (не HWND): см. plugin-sdk / общие гайды по Maestro state; <9 — ещё загрузка.
constexpr DWORD kGtaLoadStateAddress = 0x00C8D4C0;
constexpr char kIniFileName[] = "FastExit.ini";
constexpr char kConfigSection[] = "Settings";
constexpr char kConfigKey[] = "Time in milliseconds";
constexpr char kConfigKeyCgameShutdownExit[] = "CGame shutdown exit";
constexpr char kConfigKeySampUnloadExit[] = "SAMP unload exit";
constexpr int kDefaultTimeMs = 1000;

// plugin-sdk shared/GameVersion.cpp (GTASA): dword @ image+0x1000 (VA 0x401000 при ImageBase 0x400000)
constexpr std::uint32_t kGta10UsTextStartCompact = 0x53EC8B55u;
constexpr std::uint32_t kGta10UsTextStartHoodlum = 0x16197BE9u;
// plugin_sa/game_sa/meta/meta.CGame.h — CGame::Shutdown, одинаков для 10US compact / hoodlum
constexpr std::uint32_t kCGameShutdownRva = 0x00053C900;

struct SampVersionInfo {
    DWORD entryPointRva;
    const char* name;
    std::uint32_t timeOperandOffset;
    /** 0 = не ставить хук GetTickCount (нет подходящего `E8`/`FF 15` в этой сборке). */
    std::uint32_t getTickCountCallOffset;
    /** RVA imm32 сразу после `push` (0x68) в цепочке выхода по чат-команде (типично `Commands::Quit`: /quit и /q). 0 = не патчить. */
    std::uint32_t quitDelayImm32Rva;
};

struct Config {
    int timeMs = kDefaultTimeMs;
    /** 0 — штатно (в т.ч. ограничение Sleep при shutdown); 1 — при входе в CGame::Shutdown вызвать ExitProcess; 2 — TerminateProcess. */
    int cgameShutdownExit = 0;
    /** 0 — штатно; 1/2 — при первом вызове перехваченного GetTickCount в цепочке выгрузки samp. На R2 смещения GTC нет — ключ не сработает. */
    int sampUnloadExit = 0;
    char path[MAX_PATH]{};
};

// Смещения: Rizin на samp.dll (ImageBase 0x10000000). R5-2 / DL-R1-2 — те же entry point, что R5-1 / DL-R1.
// Порядок полей в строке таблицы (как в struct SampVersionInfo):
//   1 AddressOfEntryPoint (RVA, детект) | 2 метка сборки | 3 imm32 таймера выгрузки samp
//   4 RVA вызова GetTickCount при выгрузке | 5 imm32 задержки /quit (после opcode push)
constexpr std::array<SampVersionInfo, 8> kSupportedVersions{{
    { 0x031DF13, "R1", 0x0009ED79, 0x000B28DE, 0x000B28CD },
    { 0x03195DD, "R2", 0x0009EEA9, 0x00000000, 0x000B2A9A },
    { 0x00CC490, "R3", 0x000A3339, 0x000C46EB, 0x000C46DA },
    { 0x00CC4D0, "R3-1", 0x000A3379, 0x000C472B, 0x000C471A },
    { 0x00CBCB0, "R4", 0x000A3AB9, 0x000C3EBB, 0x000C3EAA },
    { 0x00CBCD0, "R4-2", 0x000A3AE9, 0x000C3EEA, 0x000C3ED9 },
    { 0x00CBC90, "R5-1", 0x000A3AA9, 0x000C3EAA, 0x000C3E99 },
    { 0x00FDB60, "DL-R1", 0x000A3809, 0x000C557B, 0x000C556A },
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
std::uint32_t g_hookTargetAddress = 0;

std::atomic<bool> g_inGtaShutdown{ false };
using CGameShutdown_t = bool(__cdecl*)();
static CGameShutdown_t g_origCGameShutdown = nullptr;
static void(WINAPI* g_origSleep)(DWORD) = nullptr;

/** Возвращает PE32 NT-заголовок модуля или nullptr при ошибке (общая проверка для samp и gta_sa). */
const IMAGE_NT_HEADERS32* GetPe32NtHeaders(HMODULE module) {
    if (module == nullptr) {
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

/** Заполняет `out` полным путём к FastExit.ini рядом с загруженным ASI. */
void BuildConfigPath(char out[MAX_PATH]) {
    if (GetModuleFileNameA(g_module, out, MAX_PATH) == 0) {
        strcpy_s(out, MAX_PATH, kIniFileName);
        return;
    }
    char* slash = nullptr;
    for (char* p = out; *p != '\0'; ++p) {
        if (*p == '\\' || *p == '/') {
            slash = p;
        }
    }
    if (slash != nullptr) {
        slash[1] = '\0';
        strcat_s(out, MAX_PATH, kIniFileName);
    } else {
        strcpy_s(out, MAX_PATH, kIniFileName);
    }
}

/** Если FastExit.ini ещё нет — записывает UTF-8 шаблон с комментариями (;) и значениями по умолчанию. */
bool WriteDefaultIniIfNotExists(const char* path) {
    if (GetFileAttributesA(path) != INVALID_FILE_ATTRIBUTES) {
        return false;
    }
    static const char kBody[] =
        "[Settings]\r\n"
        "; Сколько миллисекунд ждать при выходе (SA:MP и выход из GTA 1.0). Не ставьте 0 без нужды. -1 или -2 — сразу вырубить игру (старый вариант).\r\n"
        "Time in milliseconds=1000\r\n"
        "\r\n"
        "; «Выйти» в меню GTA: 0 — нормально; 1 или 2 — сразу выключить игру.\r\n"
        "CGame shutdown exit=0\r\n"
        "\r\n"
        "; При выходе из SA:MP: 0 — как обычно, 1 или 2 — сразу закрыть игру. На клиенте R2 не действует.\r\n"
        "SAMP unload exit=0\r\n";
    const HANDLE h = CreateFileA(path, GENERIC_WRITE, FILE_SHARE_READ, nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        return false;
    }
    DWORD written = 0;
    const DWORD n = static_cast<DWORD>(std::strlen(kBody));
    const BOOL ok = WriteFile(h, kBody, n, &written, nullptr);
    CloseHandle(h);
    return ok != FALSE && written == n;
}

/** Читает целое из INI, приводит к [minV,maxV], пишет обратно нормализованную строку. */
int LoadIniIntClamped(
    const char* key, const char* defaultStr, int minV, int maxV, int fallback, const char* iniPath) {
    char rawBuf[64] = {};
    (void)GetPrivateProfileStringA(kConfigSection, key, defaultStr, rawBuf, static_cast<DWORD>(sizeof(rawBuf)), iniPath);
    const char* rawStr = rawBuf[0] != '\0' ? rawBuf : defaultStr;
    char* end = nullptr;
    const long parsed = std::strtol(rawStr, &end, 10);
    int v = fallback;
    if (end != rawStr && *end == '\0') {
        if (parsed < minV) {
            v = minV;
        } else if (parsed > maxV) {
            v = maxV;
        } else {
            v = static_cast<int>(parsed);
        }
    }
    char normalizedValue[32] = {};
    _snprintf_s(normalizedValue, _TRUNCATE, "%d", v);
    (void)WritePrivateProfileStringA(kConfigSection, key, normalizedValue, iniPath);
    return v;
}

/** Читает INI рядом с ASI (`kernel32!GetPrivateProfileString`), парсит число, записывает нормализованное значение (`WritePrivateProfileString`). */
Config LoadConfig() {
    Config config;
    BuildConfigPath(config.path);
    (void)WriteDefaultIniIfNotExists(config.path);

    char rawBuf[64] = {};
    (void)GetPrivateProfileStringA(
        kConfigSection, kConfigKey, "1000", rawBuf, static_cast<DWORD>(sizeof(rawBuf)), config.path);
    const char* rawStr = rawBuf[0] != '\0' ? rawBuf : "1000";

    char* end = nullptr;
    const long parsed = std::strtol(rawStr, &end, 10);
    if (end == rawStr || *end != '\0' || parsed < std::numeric_limits<int>::min()
        || parsed > std::numeric_limits<int>::max()) {
        config.timeMs = kDefaultTimeMs;
    } else {
        config.timeMs = static_cast<int>(parsed);
    }

    char normalizedValue[32] = {};
    _snprintf_s(normalizedValue, _TRUNCATE, "%d", config.timeMs);
    (void)WritePrivateProfileStringA(kConfigSection, kConfigKey, normalizedValue, config.path);

    config.cgameShutdownExit = LoadIniIntClamped(kConfigKeyCgameShutdownExit, "0", 0, 2, 0, config.path);
    config.sampUnloadExit = LoadIniIntClamped(kConfigKeySampUnloadExit, "0", 0, 2, 0, config.path);

    return config;
}

/** true, если exe — GTA SA 1.0 US (compact или Hoodlum) по dword @ 0x401000 и совпадению ImageBase. */
bool IsGtaSa10UsExecutable(HMODULE exeModule) {
    const auto* nt = GetPe32NtHeaders(exeModule);
    if (nt == nullptr) {
        return false;
    }
    const DWORD imageBase = nt->OptionalHeader.ImageBase;
    const std::uintptr_t base = reinterpret_cast<std::uintptr_t>(exeModule);
    if (base != imageBase) {
        return false;
    }
    const auto* marker = reinterpret_cast<const std::uint32_t*>(base + 0x1000);
    const std::uint32_t w = *marker;
    return w == kGta10UsTextStartCompact || w == kGta10UsTextStartHoodlum;
}

/** Снимает защиту, копирует байты, восстанавливает защиту страницы. */
bool WriteBytes(void* address, const void* data, std::size_t size) {
    DWORD oldProtect = 0;
    if (!VirtualProtect(address, size, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        return false;
    }
    std::memcpy(address, data, size);
    FlushInstructionCache(GetCurrentProcess(), address, size);
    DWORD restoreProtect = 0;
    VirtualProtect(address, size, oldProtect, &restoreProtect);
    return true;
}

/** Ищет строку таблицы по AddressOfEntryPoint samp.dll. */
const SampVersionInfo* DetectSampVersion(HMODULE sampModule) {
    const auto* nt = GetPe32NtHeaders(sampModule);
    if (nt == nullptr) {
        return nullptr;
    }
    const DWORD entryPoint = nt->OptionalHeader.AddressOfEntryPoint;
    for (const auto& version : kSupportedVersions) {
        if (version.entryPointRva == entryPoint) {
            return &version;
        }
    }
    return nullptr;
}

/** Жёсткий выход по ключам `CGame shutdown exit` и устаревшему `Time in milliseconds` -1/-2. */
void CheckCgameShutdownHardExit() {
    if (g_config.cgameShutdownExit == 1 || g_config.timeMs == -1) {
        ExitProcess(0);
    }
    if (g_config.cgameShutdownExit == 2 || g_config.timeMs == -2) {
        TerminateProcess(GetCurrentProcess(), 0);
    }
}

/** Жёсткий выход по ключам `SAMP unload exit` и устаревшему `Time in milliseconds` -1/-2. */
void CheckSampUnloadHardExit() {
    if (g_config.sampUnloadExit == 1 || g_config.timeMs == -1) {
        ExitProcess(0);
    }
    if (g_config.sampUnloadExit == 2 || g_config.timeMs == -2) {
        TerminateProcess(GetCurrentProcess(), 0);
    }
}

DWORD WINAPI HookGetTickCount() {
    CheckSampUnloadHardExit();
    return ::GetTickCount();
}

bool __cdecl HookedCGameShutdown() {
    CheckCgameShutdownHardExit();
    g_inGtaShutdown.store(true, std::memory_order_release);
    const bool result = g_origCGameShutdown != nullptr ? g_origCGameShutdown() : false;
    g_inGtaShutdown.store(false, std::memory_order_release);
    return result;
}

void WINAPI HookedSleep(DWORD ms) {
    if (g_origSleep == nullptr) {
        ::Sleep(ms);
        return;
    }
    if (!g_inGtaShutdown.load(std::memory_order_acquire)) {
        g_origSleep(ms);
        return;
    }
    const int t = g_config.timeMs;
    if (t < 0) {
        g_origSleep(ms);
        return;
    }
    if (t == 0) {
        g_origSleep(0);
        return;
    }
    const DWORD cap = static_cast<DWORD>(t);
    if (ms == 0) {
        g_origSleep(0);
        return;
    }
    g_origSleep(ms < cap ? ms : cap);
}

/** MinHook: CGame::Shutdown и kernel32!Sleep для ограничения Sleep при выходе (только 10 US exe). */
bool InstallGtaShutdownHooks() {
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
    void* sleepTarget = nullptr;
    if (MH_CreateHookApiEx(L"kernel32.dll", "Sleep", &HookedSleep, reinterpret_cast<void**>(&g_origSleep), &sleepTarget)
        != MH_OK) {
        MH_RemoveHook(shutdownAddr);
        MH_Uninitialize();
        return false;
    }
    if (MH_EnableHook(MH_ALL_HOOKS) != MH_OK) {
        MH_DisableHook(MH_ALL_HOOKS);
        MH_RemoveHook(shutdownAddr);
        if (sleepTarget != nullptr) {
            MH_RemoveHook(sleepTarget);
        }
        MH_Uninitialize();
        return false;
    }
    return true;
}

/** Перехват GTC в samp нужен только для `SAMP unload exit` и устаревшего `Time in milliseconds` -1/-2 на пути samp; иначе хук ломает штатный выход (меню «Выйти» → CGame::Shutdown). */
bool NeedSampGetTickCountHook() {
    return g_config.sampUnloadExit != 0 || g_config.timeMs == -1 || g_config.timeMs == -2;
}

/** Патчит вызов GetTickCount на относительный call или indirect call к g_hookTargetAddress. */
bool InstallGetTickCountHook(std::uintptr_t callAddress) {
    std::uint8_t op[2] = {};
    std::memcpy(op, reinterpret_cast<const void*>(callAddress), sizeof(op));
    if (op[0] == 0xE8) {
        const auto hookAddress = reinterpret_cast<std::uintptr_t>(&HookGetTickCount);
        const long long rel = static_cast<long long>(hookAddress)
            - static_cast<long long>(callAddress + sizeof(RelativeCallPatch));
        if (rel < std::numeric_limits<std::int32_t>::min() || rel > std::numeric_limits<std::int32_t>::max()) {
            return false;
        }
        const RelativeCallPatch patch{ 0xE8, static_cast<std::int32_t>(rel) };
        return WriteBytes(reinterpret_cast<void*>(callAddress), &patch, sizeof(patch));
    }
    if (op[0] == 0xFF && op[1] == 0x15) {
        const IndirectCallPatch patch{ 0xFF, 0x15, reinterpret_cast<std::uint32_t>(&g_hookTargetAddress) };
        return WriteBytes(reinterpret_cast<void*>(callAddress), &patch, sizeof(patch));
    }
    return false;
}

/** Патчи таймера выгрузки, задержки /quit и при необходимости хук GetTickCount. */
bool ApplyPatches(HMODULE sampModule, const SampVersionInfo& version) {
    const std::uintptr_t base = reinterpret_cast<std::uintptr_t>(sampModule);
    // При жёстком выходе через GTC не трогаем imm32 таймеров — иначе возможны краши в цепочке /quit до вызова GTC.
    const bool patchSampDelays = (g_config.sampUnloadExit == 0);
    if (patchSampDelays) {
        const std::uint32_t delay = g_config.timeMs >= 0 ? static_cast<std::uint32_t>(g_config.timeMs) : 0u;
        if (!WriteBytes(reinterpret_cast<void*>(base + version.timeOperandOffset), &delay, sizeof(delay))) {
            return false;
        }
        if (version.quitDelayImm32Rva != 0) {
            const auto* pushOpcode = reinterpret_cast<const std::uint8_t*>(base + version.quitDelayImm32Rva - 1);
            if (*pushOpcode == 0x68) {
                (void)WriteBytes(reinterpret_cast<void*>(base + version.quitDelayImm32Rva), &delay, sizeof(delay));
            }
        }
    }
    if (version.getTickCountCallOffset == 0) {
        return true;
    }
    if (!NeedSampGetTickCountHook()) {
        return true;
    }
    return InstallGetTickCountHook(base + version.getTickCountCallOffset);
}

/** Ждёт загрузки GTA, читает конфиг, ставит хуки GTA (1.0 US), при SA:MP — патчи только к известной `samp.dll`. В одиночной игре `samp.dll` не загружается — SA:MP-правки не вызываются. */
DWORD WINAPI InitializePlugin(void*) {
    const auto* gtaLoadState = reinterpret_cast<volatile DWORD*>(kGtaLoadStateAddress);
    while (*gtaLoadState < 9) {
        Sleep(10);
    }
    g_config = LoadConfig();
    g_hookTargetAddress = reinterpret_cast<std::uint32_t>(&HookGetTickCount);
    (void)InstallGtaShutdownHooks();

    // Одиночная игра: `samp.dll` в процессе не появляется — выходим из потока после таймаута (SA:MP обычно уже подгрузил dll к этому моменту).
    constexpr DWORD kMaxWaitForSampMs = 300000;
    const DWORD waitStart = GetTickCount();
    for (;;) {
        HMODULE sampModule = GetModuleHandleA("samp.dll");
        if (sampModule != nullptr) {
            const auto* version = DetectSampVersion(sampModule);
            if (version != nullptr) {
                (void)ApplyPatches(sampModule, *version);
            }
            return 0;
        }
        if (GetTickCount() - waitStart >= kMaxWaitForSampMs) {
            return 0;
        }
        Sleep(100);
    }
}

}  // namespace

BOOL APIENTRY DllMain(HMODULE module, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        g_module = module;
        DisableThreadLibraryCalls(module);
        HANDLE thread = CreateThread(nullptr, 0, &InitializePlugin, nullptr, 0, nullptr);
        if (thread != nullptr) {
            CloseHandle(thread);
        }
    }
    return TRUE;
}
