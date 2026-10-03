#include <windows.h>
#include <algorithm>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

// Dynamic function pointers for process suspension/resuming
typedef LONG(NTAPI* pfnNtSuspendProcess)(HANDLE ProcessHandle);
typedef LONG(NTAPI* pfnNtResumeProcess)(HANDLE ProcessHandle);

// Console Color Helper
namespace Colors {
    const std::string RESET   = "\033[0m";
    const std::string BOLD    = "\033[1m";
    const std::string RED     = "\033[31m";
    const std::string GREEN   = "\033[32m";
    const std::string YELLOW  = "\033[33m";
    const std::string BLUE    = "\033[34m";
    const std::string CYAN    = "\033[36m";
    const std::string GRAY    = "\033[90m";
}

// Enable ANSI escape sequence support in Windows Console
void enableVTMode() {
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    if (hOut == INVALID_HANDLE_VALUE) return;
    DWORD dwMode = 0;
    if (!GetConsoleMode(hOut, &dwMode)) return;
    dwMode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
    SetConsoleMode(hOut, dwMode);
}

// ============================================================
// Memory Editor Engine
// ============================================================

class Editor
{
private:
    HANDLE process = nullptr;
    DWORD processId = 0;
    bool frozen = false;

public:
    ~Editor()
    {
        close();
    }

    bool open(DWORD pid)
    {
        close();

        // PROCESS_SUSPEND_RESUME is required for NtSuspendProcess / NtResumeProcess
        process = OpenProcess(
            PROCESS_VM_READ |
            PROCESS_VM_WRITE |
            PROCESS_VM_OPERATION |
            PROCESS_QUERY_INFORMATION |
            PROCESS_SUSPEND_RESUME,
            FALSE,
            pid
        );

        if (process)
        {
            processId = pid;
            frozen = false;
            return true;
        }

        return false;
    }

    void close()
    {
        if (process)
        {
            if (frozen)
            {
                unfreeze();
            }
            CloseHandle(process);
            process = nullptr;
            processId = 0;
            frozen = false;
        }
    }

    bool valid() const
    {
        return process != nullptr;
    }

    DWORD getPid() const
    {
        return processId;
    }

    bool isFrozen() const
    {
        return frozen;
    }

    bool freeze()
    {
        if (!valid() || frozen) return false;

        HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
        if (!hNtdll) return false;

        auto NtSuspendProcess = (pfnNtSuspendProcess)GetProcAddress(hNtdll, "NtSuspendProcess");
        if (NtSuspendProcess && NtSuspendProcess(process) == 0)
        {
            frozen = true;
            return true;
        }
        return false;
    }

    bool unfreeze()
    {
        if (!valid() || !frozen) return false;

        HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
        if (!hNtdll) return false;

        auto NtResumeProcess = (pfnNtResumeProcess)GetProcAddress(hNtdll, "NtResumeProcess");
        if (NtResumeProcess && NtResumeProcess(process) == 0)
        {
            frozen = false;
            return true;
        }
        return false;
    }

    template<typename T>
    bool read(uintptr_t address, T& value)
    {
        if (!valid()) return false;
        SIZE_T bytesRead = 0;

        return ReadProcessMemory(
            process,
            reinterpret_cast<LPCVOID>(address),
            &value,
            sizeof(T),
            &bytesRead
        ) && bytesRead == sizeof(T);
    }

    template<typename T>
    bool write(uintptr_t address, const T& value)
    {
        if (!valid()) return false;
        SIZE_T bytesWritten = 0;

        return WriteProcessMemory(
            process,
            reinterpret_cast<LPVOID>(address),
            &value,
            sizeof(T),
            &bytesWritten
        ) && bytesWritten == sizeof(T);
    }

    template<typename T>
    std::vector<uintptr_t> scan(T target)
    {
        std::vector<uintptr_t> results;
        if (!valid()) return results;

        SYSTEM_INFO systemInfo{};
        GetSystemInfo(&systemInfo);

        uintptr_t address = reinterpret_cast<uintptr_t>(systemInfo.lpMinimumApplicationAddress);
        uintptr_t maxAddress = reinterpret_cast<uintptr_t>(systemInfo.lpMaximumApplicationAddress);

        while (address < maxAddress)
        {
            MEMORY_BASIC_INFORMATION mbi{};

            if (VirtualQueryEx(
                    process,
                    reinterpret_cast<LPCVOID>(address),
                    &mbi,
                    sizeof(mbi)
                ) != sizeof(mbi))
            {
                break;
            }

            bool readable =
                mbi.State == MEM_COMMIT &&
                !(mbi.Protect & PAGE_GUARD) &&
                !(mbi.Protect & PAGE_NOACCESS);

            if (readable)
            {
                const size_t regionSize = mbi.RegionSize;
                std::vector<std::byte> buffer(regionSize);
                SIZE_T bytesRead = 0;

                if (ReadProcessMemory(
                        process,
                        mbi.BaseAddress,
                        buffer.data(),
                        regionSize,
                        &bytesRead
                    ))
                {
                    for (size_t i = 0; i + sizeof(T) <= bytesRead; ++i)
                    {
                        T value{};
                        std::memcpy(&value, buffer.data() + i, sizeof(T));

                        if (value == target)
                        {
                            uintptr_t found = reinterpret_cast<uintptr_t>(mbi.BaseAddress) + i;
                            results.push_back(found);
                        }
                    }
                }
            }

            address = reinterpret_cast<uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
        }

        return results;
    }
};

// ============================================================
// Scanner State
// ============================================================

enum class ValueType
{
    None,
    Int,
    Float,
    Double
};

struct Candidate
{
    uintptr_t address;
    int intValue{};
    float floatValue{};
    double doubleValue{};
};

struct Scanner
{
    ValueType type = ValueType::None;
    std::vector<Candidate> candidates;

    bool hasScan() const
    {
        return !candidates.empty() || type != ValueType::None;
    }

    void clear()
    {
        candidates.clear();
        type = ValueType::None;
    }
};

struct Context
{
    Editor editor;
    Scanner scanner;
    bool running = true;
};

Context g_context;

// ============================================================
// Helpers
// ============================================================

uintptr_t parseAddress(const std::string& text)
{
    try {
        return std::stoull(text, nullptr, 16);
    } catch (...) {
        return 0;
    }
}

std::string formatAddress(uintptr_t address)
{
    std::stringstream ss;
    ss << "0x" << std::uppercase << std::hex << std::setw(sizeof(uintptr_t) * 2) << std::setfill('0') << address;
    return ss.str();
}

std::string getTypeString(ValueType type)
{
    switch (type)
    {
        case ValueType::Int: return "INT";
        case ValueType::Float: return "FLOAT";
        case ValueType::Double: return "DOUBLE";
        default: return "NONE";
    }
}

// ============================================================
// Help & Interface Displays
// ============================================================

void help()
{
    std::cout << Colors::CYAN << Colors::BOLD
              << "\n============================================================\n"
              << "                    MEMORY EDITOR COMMANDS                  \n"
              << "============================================================\n" << Colors::RESET;

    std::cout << Colors::YELLOW << "Process Management:\n" << Colors::RESET
              << "  attach <pid>                 Attach to process by PID\n"
              << "  freeze / suspend             Freeze process threads\n"
              << "  unfreeze / resume            Resume process threads\n"
              << "  status                       View process & memory scan status\n\n";

    std::cout << Colors::YELLOW << "Initial Scan:\n" << Colors::RESET
              << "  scan int <value>             Scan memory for integer value\n"
              << "  scan float <value>           Scan memory for float value\n"
              << "  scan double <value>          Scan memory for double value\n\n";

    std::cout << Colors::YELLOW << "Next Scan (Filter Candidates):\n" << Colors::RESET
              << "  next <number>                Filter candidates equal to number\n"
              << "  next int|float|double <val>  Filter candidates by type and value\n"
              << "  next exact <value>           Filter candidates matching exact value\n"
              << "  next increased               Filter values that have increased\n"
              << "  next decreased               Filter values that have decreased\n"
              << "  next changed                 Filter values that have changed\n"
              << "  next unchanged               Filter values that remained unchanged\n\n";

    std::cout << Colors::YELLOW << "Read / Write Memory:\n" << Colors::RESET
              << "  read int|float|double <addr>         Read value at hex address\n"
              << "  write int|float|double <addr> <val>  Write value to hex address\n\n";

    std::cout << Colors::YELLOW << "General:\n" << Colors::RESET
              << "  results                      Display candidate list\n"
              << "  clear                        Clear active scan session\n"
              << "  help                         Display this help menu\n"
              << "  exit                         Exit memory editor\n"
              << Colors::CYAN << "============================================================\n\n" << Colors::RESET;
}

void showResults()
{
    auto& candidates = g_context.scanner.candidates;

    std::cout << "\n" << Colors::BOLD << "Found " << candidates.size() << " candidate(s)" << Colors::RESET << "\n";

    if (candidates.empty()) return;

    size_t displayCount = std::min<size_t>(candidates.size(), 50);

    std::cout << Colors::GRAY << "------------------------------------------------------------\n" << Colors::RESET;
    std::cout << Colors::BOLD << std::left 
              << std::setw(8)  << "INDEX" 
              << std::setw(20) << "ADDRESS" 
              << std::setw(15) << "LAST VALUE" 
              << std::setw(15) << "LIVE VALUE" 
              << Colors::RESET << "\n";
    std::cout << Colors::GRAY << "------------------------------------------------------------\n" << Colors::RESET;

    for (size_t i = 0; i < displayCount; ++i)
    {
        std::cout << "[" << std::setw(5) << i << "] "
                  << Colors::CYAN << std::setw(18) << formatAddress(candidates[i].address) << Colors::RESET << " ";

        // Display Last and Live Values
        switch (g_context.scanner.type)
        {
            case ValueType::Int:
            {
                int liveVal = 0;
                bool success = g_context.editor.read(candidates[i].address, liveVal);
                std::cout << std::setw(15) << candidates[i].intValue;
                if (success)
                    std::cout << Colors::GREEN << std::setw(15) << liveVal << Colors::RESET;
                else
                    std::cout << Colors::RED << std::setw(15) << "??? (Error)" << Colors::RESET;
                break;
            }
            case ValueType::Float:
            {
                float liveVal = 0.0f;
                bool success = g_context.editor.read(candidates[i].address, liveVal);
                std::cout << std::setw(15) << candidates[i].floatValue;
                if (success)
                    std::cout << Colors::GREEN << std::setw(15) << liveVal << Colors::RESET;
                else
                    std::cout << Colors::RED << std::setw(15) << "??? (Error)" << Colors::RESET;
                break;
            }
            case ValueType::Double:
            {
                double liveVal = 0.0;
                bool success = g_context.editor.read(candidates[i].address, liveVal);
                std::cout << std::setw(15) << candidates[i].doubleValue;
                if (success)
                    std::cout << Colors::GREEN << std::setw(15) << liveVal << Colors::RESET;
                else
                    std::cout << Colors::RED << std::setw(15) << "??? (Error)" << Colors::RESET;
                break;
            }
            default:
                break;
        }

        std::cout << "\n";
    }

    if (candidates.size() > displayCount)
    {
        std::cout << Colors::GRAY << "... " << (candidates.size() - displayCount) << " more results hidden\n" << Colors::RESET;
    }
    std::cout << Colors::GRAY << "------------------------------------------------------------\n\n" << Colors::RESET;
}

void showStatus()
{
    std::cout << Colors::CYAN << Colors::BOLD << "\n================ PROCESS & SCAN STATUS ================\n" << Colors::RESET;
    
    // Process Status
    std::cout << Colors::BOLD << "Process Connection: " << Colors::RESET;
    if (g_context.editor.valid())
    {
        std::cout << Colors::GREEN << "ATTACHED (PID: " << g_context.editor.getPid() << ")" << Colors::RESET;
        if (g_context.editor.isFrozen())
        {
            std::cout << Colors::YELLOW << " [FROZEN / PAUSED]" << Colors::RESET;
        }
        else
        {
            std::cout << Colors::GRAY << " [RUNNING]" << Colors::RESET;
        }
        std::cout << "\n";
    }
    else
    {
        std::cout << Colors::RED << "NOT ATTACHED" << Colors::RESET << "\n";
    }

    // Scanner Status
    std::cout << Colors::BOLD << "Active Scan Type  : " << Colors::RESET 
              << Colors::YELLOW << getTypeString(g_context.scanner.type) << Colors::RESET << "\n";
    std::cout << Colors::BOLD << "Candidate Count   : " << Colors::RESET 
              << Colors::GREEN << g_context.scanner.candidates.size() << Colors::RESET << "\n";

    if (g_context.scanner.hasScan() && !g_context.scanner.candidates.empty())
    {
        showResults();
    }
    else
    {
        std::cout << Colors::CYAN << "=======================================================\n\n" << Colors::RESET;
    }
}

// ============================================================
// Scans Implementation
// ============================================================

void scanInt(int target)
{
    std::cout << Colors::YELLOW << "Scanning INT: " << target << "..." << Colors::RESET << "\n";
    auto addresses = g_context.editor.scan(target);

    g_context.scanner.clear();
    g_context.scanner.type = ValueType::Int;

    for (uintptr_t address : addresses)
    {
        Candidate candidate;
        candidate.address = address;
        candidate.intValue = target;
        g_context.scanner.candidates.push_back(candidate);
    }

    showResults();
}

void scanFloat(float target)
{
    std::cout << Colors::YELLOW << "Scanning FLOAT: " << target << "..." << Colors::RESET << "\n";
    auto addresses = g_context.editor.scan(target);

    g_context.scanner.clear();
    g_context.scanner.type = ValueType::Float;

    for (uintptr_t address : addresses)
    {
        Candidate candidate;
        candidate.address = address;
        candidate.floatValue = target;
        g_context.scanner.candidates.push_back(candidate);
    }

    showResults();
}

void scanDouble(double target)
{
    std::cout << Colors::YELLOW << "Scanning DOUBLE: " << target << "..." << Colors::RESET << "\n";
    auto addresses = g_context.editor.scan(target);

    g_context.scanner.clear();
    g_context.scanner.type = ValueType::Double;

    for (uintptr_t address : addresses)
    {
        Candidate candidate;
        candidate.address = address;
        candidate.doubleValue = target;
        g_context.scanner.candidates.push_back(candidate);
    }

    showResults();
}

// Filter Next Scan by Exact Target Value
template<typename T>
void nextExactScan(T targetVal)
{
    auto& candidates = g_context.scanner.candidates;
    size_t oldCount = candidates.size();

    candidates.erase(
        std::remove_if(
            candidates.begin(),
            candidates.end(),
            [&](Candidate& candidate)
            {
                T current{};
                if (!g_context.editor.read(candidate.address, current))
                {
                    return true; // remove unreadable
                }

                bool keep = (current == targetVal);

                if constexpr (std::is_same_v<T, int>) candidate.intValue = current;
                else if constexpr (std::is_same_v<T, float>) candidate.floatValue = current;
                else if constexpr (std::is_same_v<T, double>) candidate.doubleValue = current;

                return !keep;
            }
        ),
        candidates.end()
    );

    std::cout << Colors::YELLOW << "\nNext scan (exact = " << targetVal << "): " << Colors::RESET
              << oldCount << " -> " << Colors::GREEN << candidates.size() << Colors::RESET << " candidates\n";

    showResults();
}

// Filter Next Scan by Relative Operations (increased/decreased/changed/unchanged)
void nextRelativeScan(const std::string& operation)
{
    auto& candidates = g_context.scanner.candidates;
    size_t oldCount = candidates.size();

    candidates.erase(
        std::remove_if(
            candidates.begin(),
            candidates.end(),
            [&](Candidate& candidate)
            {
                bool keep = false;

                if (g_context.scanner.type == ValueType::Int)
                {
                    int current;
                    if (!g_context.editor.read(candidate.address, current)) return true;
                    int previous = candidate.intValue;

                    if (operation == "increased") keep = current > previous;
                    else if (operation == "decreased") keep = current < previous;
                    else if (operation == "changed") keep = current != previous;
                    else if (operation == "unchanged") keep = current == previous;

                    candidate.intValue = current;
                }
                else if (g_context.scanner.type == ValueType::Float)
                {
                    float current;
                    if (!g_context.editor.read(candidate.address, current)) return true;
                    float previous = candidate.floatValue;

                    if (operation == "increased") keep = current > previous;
                    else if (operation == "decreased") keep = current < previous;
                    else if (operation == "changed") keep = current != previous;
                    else if (operation == "unchanged") keep = current == previous;

                    candidate.floatValue = current;
                }
                else if (g_context.scanner.type == ValueType::Double)
                {
                    double current;
                    if (!g_context.editor.read(candidate.address, current)) return true;
                    double previous = candidate.doubleValue;

                    if (operation == "increased") keep = current > previous;
                    else if (operation == "decreased") keep = current < previous;
                    else if (operation == "changed") keep = current != previous;
                    else if (operation == "unchanged") keep = current == previous;

                    candidate.doubleValue = current;
                }

                return !keep;
            }
        ),
        candidates.end()
    );

    std::cout << Colors::YELLOW << "\nNext scan (" << operation << "): " << Colors::RESET
              << oldCount << " -> " << Colors::GREEN << candidates.size() << Colors::RESET << " candidates\n";

    showResults();
}

// ============================================================
// Memory Operations
// ============================================================

void readMemory(const std::string& type, uintptr_t address)
{
    if (type == "int")
    {
        int value;
        if (g_context.editor.read(address, value))
            std::cout << Colors::GREEN << "INT @ " << formatAddress(address) << " = " << value << Colors::RESET << "\n";
        else
            std::cout << Colors::RED << "Failed to read memory.\n" << Colors::RESET;
    }
    else if (type == "float")
    {
        float value;
        if (g_context.editor.read(address, value))
            std::cout << Colors::GREEN << "FLOAT @ " << formatAddress(address) << " = " << value << Colors::RESET << "\n";
        else
            std::cout << Colors::RED << "Failed to read memory.\n" << Colors::RESET;
    }
    else if (type == "double")
    {
        double value;
        if (g_context.editor.read(address, value))
            std::cout << Colors::GREEN << "DOUBLE @ " << formatAddress(address) << " = " << value << Colors::RESET << "\n";
        else
            std::cout << Colors::RED << "Failed to read memory.\n" << Colors::RESET;
    }
    else
    {
        std::cout << Colors::RED << "Unknown data type: " << type << Colors::RESET << "\n";
    }
}

void writeMemory(const std::string& type, uintptr_t address, const std::string& valueText)
{
    try {
        if (type == "int")
        {
            int value = std::stoi(valueText);
            if (g_context.editor.write(address, value))
                std::cout << Colors::GREEN << "INT written successfully to " << formatAddress(address) << Colors::RESET << "\n";
            else
                std::cout << Colors::RED << "Failed to write memory.\n" << Colors::RESET;
        }
        else if (type == "float")
        {
            float value = std::stof(valueText);
            if (g_context.editor.write(address, value))
                std::cout << Colors::GREEN << "FLOAT written successfully to " << formatAddress(address) << Colors::RESET << "\n";
            else
                std::cout << Colors::RED << "Failed to write memory.\n" << Colors::RESET;
        }
        else if (type == "double")
        {
            double value = std::stod(valueText);
            if (g_context.editor.write(address, value))
                std::cout << Colors::GREEN << "DOUBLE written successfully to " << formatAddress(address) << Colors::RESET << "\n";
            else
                std::cout << Colors::RED << "Failed to write memory.\n" << Colors::RESET;
        }
        else
        {
            std::cout << Colors::RED << "Unknown data type: " << type << Colors::RESET << "\n";
        }
    } catch (...) {
        std::cout << Colors::RED << "Invalid value format for type " << type << Colors::RESET << "\n";
    }
}

// ============================================================
// Command Processor
// ============================================================

void executeCommand(const std::vector<std::string>& args)
{
    if (args.empty()) return;

    const std::string& command = args[0];

    // Help
    if (command == "help")
    {
        help();
    }
    // Status
    else if (command == "status")
    {
        showStatus();
    }
    // Attach
    else if (command == "attach")
    {
        if (args.size() < 2)
        {
            std::cout << Colors::YELLOW << "Usage: attach <pid>\n" << Colors::RESET;
            return;
        }

        DWORD pid = static_cast<DWORD>(std::stoul(args[1]));

        if (g_context.editor.open(pid))
        {
            std::cout << Colors::GREEN << "Successfully attached to PID " << pid << Colors::RESET << "\n";
        }
        else
        {
            std::cout << Colors::RED << "Failed to attach. Win32 Error: " << GetLastError() << Colors::RESET << "\n";
        }
    }
    // Freeze / Suspend Process
    else if (command == "freeze" || command == "suspend")
    {
        if (!g_context.editor.valid())
        {
            std::cout << Colors::RED << "Not attached to any process.\n" << Colors::RESET;
            return;
        }
        if (g_context.editor.freeze())
        {
            std::cout << Colors::GREEN << "Process suspended/frozen successfully.\n" << Colors::RESET;
        }
        else
        {
            std::cout << Colors::RED << "Failed to freeze process or process already frozen.\n" << Colors::RESET;
        }
    }
    // Unfreeze / Resume Process
    else if (command == "unfreeze" || command == "resume")
    {
        if (!g_context.editor.valid())
        {
            std::cout << Colors::RED << "Not attached to any process.\n" << Colors::RESET;
            return;
        }
        if (g_context.editor.unfreeze())
        {
            std::cout << Colors::GREEN << "Process resumed/unfrozen successfully.\n" << Colors::RESET;
        }
        else
        {
            std::cout << Colors::RED << "Failed to unfreeze process or process is not frozen.\n" << Colors::RESET;
        }
    }
    // Initial Scan
    else if (command == "scan")
    {
        if (!g_context.editor.valid())
        {
            std::cout << Colors::RED << "Please attach to a process first (attach <pid>)\n" << Colors::RESET;
            return;
        }

        if (args.size() < 3)
        {
            std::cout << Colors::YELLOW << "Usage: scan int|float|double <value>\n" << Colors::RESET;
            return;
        }

        const std::string& type = args[1];

        try {
            if (type == "int") scanInt(std::stoi(args[2]));
            else if (type == "float") scanFloat(std::stof(args[2]));
            else if (type == "double") scanDouble(std::stod(args[2]));
            else std::cout << Colors::RED << "Unknown data type.\n" << Colors::RESET;
        } catch (...) {
            std::cout << Colors::RED << "Invalid scan value.\n" << Colors::RESET;
        }
    }
    // Next Scan
    else if (command == "next")
    {
        if (!g_context.scanner.hasScan())
        {
            std::cout << Colors::RED << "No active scan found. Run an initial scan first.\n" << Colors::RESET;
            return;
        }

        if (args.size() < 2)
        {
            std::cout << Colors::YELLOW
                      << "Usage:\n"
                      << "  next <number>\n"
                      << "  next exact <number>\n"
                      << "  next int|float|double <number>\n"
                      << "  next increased|decreased|changed|unchanged\n"
                      << Colors::RESET;
            return;
        }

        std::string op = args[1];

        // 1. Check if relative operations
        if (op == "increased" || op == "decreased" || op == "changed" || op == "unchanged")
        {
            nextRelativeScan(op);
            return;
        }

        // 2. Syntax: "next exact <value>"
        if (op == "exact" && args.size() >= 3)
        {
            op = args[2];
        }

        // 3. Syntax: "next int <value>" / "next float <value>"
        if ((op == "int" || op == "float" || op == "double") && args.size() >= 3)
        {
            op = args[2];
        }

        // Parse exact value according to active scan type
        try {
            switch (g_context.scanner.type)
            {
                case ValueType::Int:
                    nextExactScan<int>(std::stoi(op));
                    break;
                case ValueType::Float:
                    nextExactScan<float>(std::stof(op));
                    break;
                case ValueType::Double:
                    nextExactScan<double>(std::stod(op));
                    break;
                default:
                    break;
            }
        } catch (...) {
            std::cout << Colors::RED << "Invalid target value format for next scan.\n" << Colors::RESET;
        }
    }
    // Results
    else if (command == "results")
    {
        showResults();
    }
    // Clear
    else if (command == "clear")
    {
        g_context.scanner.clear();
        std::cout << Colors::GREEN << "Active scan session cleared.\n" << Colors::RESET;
    }
    // Read
    else if (command == "read")
    {
        if (args.size() < 3)
        {
            std::cout << Colors::YELLOW << "Usage: read int|float|double <address>\n" << Colors::RESET;
            return;
        }
        readMemory(args[1], parseAddress(args[2]));
    }
    // Write
    else if (command == "write")
    {
        if (args.size() < 4)
        {
            std::cout << Colors::YELLOW << "Usage: write int|float|double <address> <value>\n" << Colors::RESET;
            return;
        }
        writeMemory(args[1], parseAddress(args[2]), args[3]);
    }
    // Exit
    else if (command == "exit")
    {
        g_context.running = false;
    }
    else
    {
        std::cout << Colors::RED << "Unknown command: " << command << ". Type 'help' for options.\n" << Colors::RESET;
    }
}

// ============================================================
// Main Application Loop
// ============================================================

int main()
{
    enableVTMode();

    std::cout << Colors::CYAN << Colors::BOLD
              << "============================================================\n"
              << "                 ADVANCED C++ MEMORY EDITOR                 \n"
              << "============================================================\n"
              << Colors::RESET;
    std::cout << "Type '" << Colors::YELLOW << "help" << Colors::RESET << "' for available commands.\n\n";

    std::string line;

    while (g_context.running)
    {
        std::cout << Colors::BOLD << Colors::GREEN << "> " << Colors::RESET;

        if (!std::getline(std::cin, line))
            break;

        if (line.empty())
            continue;

        std::stringstream stream(line);
        std::vector<std::string> args;
        std::string arg;

        while (stream >> arg)
            args.push_back(arg);

        executeCommand(args);
    }

    return EXIT_SUCCESS;
}