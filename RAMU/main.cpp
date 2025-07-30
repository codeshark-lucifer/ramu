#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>

#include <iostream>
#include <vector>
#include <string>
#include <sstream>
#include <iomanip>
#include <algorithm>

#include <cctype>
#include <climits>
#include <thread>
#include <atomic>
#include <mutex>
#include <chrono>
#include <unordered_map>

// -------------------------
// Cheat Engine–Style Memory Editor with freeze and type switching
// -------------------------

// Console colors
enum ConsoleColor
{
    DEFAULT = 7,
    GREEN = 10,
    RED = 12,
    YELLOW = 14,
    CYAN = 11,
    MAGENTA = 13
};
void setColor(ConsoleColor c) { SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), c); }

// Supported data types for scan and write
enum class DataType
{
    INT32,
    // Future: FLOAT, DOUBLE etc.
};

// Structure to track each matching address and its last known value (int only currently)
struct AddressInfo
{
    uintptr_t addr;
    int lastValue;
};

HANDLE hProcess = nullptr;
std::vector<AddressInfo> tracked;
bool initialScanDone = false;
DataType currentDataType = DataType::INT32;

// Freeze data: address -> freeze value
std::unordered_map<uintptr_t, int> freezeMap;
std::mutex freezeMutex;
std::atomic<bool> freezeRunning{ false };
std::thread freezeThread;

// Case-insensitive comparison
bool iequals(const std::string& a, const std::string& b)
{
    return _stricmp(a.c_str(), b.c_str()) == 0;
}

void showProcesses()
{
    setColor(CYAN);
    std::cout << "\nRunning Processes:\n";
    setColor(YELLOW);
    std::cout << " PID     Name\n";
    setColor(DEFAULT);

    HANDLE hs = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32W pe = { sizeof(pe) };

    if (Process32FirstW(hs, &pe))
    {
        do
        {
            char narrowName[MAX_PATH];
            WideCharToMultiByte(CP_UTF8, 0, pe.szExeFile, -1, narrowName, MAX_PATH, nullptr, nullptr);
            std::string name(narrowName);

            std::string low = name;
            std::transform(low.begin(), low.end(), low.begin(), ::tolower);

            // Skip some system processes
            if (low == "explorer.exe" || low == "svchost.exe" || low == "services.exe" ||
                low == "lsass.exe" || low == "wininit.exe" || low == "csrss.exe" || low == "smss.exe")
                continue;

            setColor(GREEN);
            std::cout << std::setw(7) << pe.th32ProcessID;
            setColor(CYAN);
            std::cout << " " << name << "\n";

        } while (Process32NextW(hs, &pe));
    }

    CloseHandle(hs);
    setColor(DEFAULT);
}

// Attach to process by name (case insensitive)
bool attachProc(const std::string& name)
{
    DWORD pid = 0;
    HANDLE hs = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32W pe = { sizeof(pe) };

    if (Process32FirstW(hs, &pe))
    {
        do
        {
            char narrowName[MAX_PATH];
            WideCharToMultiByte(CP_UTF8, 0, pe.szExeFile, -1, narrowName, MAX_PATH, nullptr, nullptr);
            std::string processName(narrowName);

            if (iequals(name, processName))
            {
                pid = pe.th32ProcessID;
                break;
            }
        } while (Process32NextW(hs, &pe));
    }
    CloseHandle(hs);
    if (!pid)
        return false;

    hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION, FALSE, pid);
    return hProcess != nullptr;
}

// Read integer at address
bool readInt(uintptr_t addr, int& out)
{
    SIZE_T rd;
    return ReadProcessMemory(hProcess, (LPCVOID)addr, &out, sizeof(out), &rd) && rd == sizeof(out);
}

// Write integer to address
bool writeInt(uintptr_t addr, int v)
{
    SIZE_T wr;
    return WriteProcessMemory(hProcess, (LPVOID)addr, &v, sizeof(v), &wr) && wr == sizeof(v);
}

// Initial full scan for int value
void scanValue(int target)
{
    if (initialScanDone)
    {
        std::cout << "Initial scan already done. Use 'refine <value>' to filter addresses, or 'reset' to start over.\n";
        return;
    }
    if (currentDataType != DataType::INT32)
    {
        std::cout << "Currently only int32 scan is supported.\n";
        return;
    }

    tracked.clear();
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    uintptr_t a = (uintptr_t)si.lpMinimumApplicationAddress, e = (uintptr_t)si.lpMaximumApplicationAddress;
    MEMORY_BASIC_INFORMATION mbi;
    while (a < e && VirtualQueryEx(hProcess, (LPCVOID)a, &mbi, sizeof(mbi)))
    {
        if (mbi.State == MEM_COMMIT && (mbi.Protect & PAGE_READWRITE))
        {
            std::vector<BYTE> buf(mbi.RegionSize);
            SIZE_T rd;
            if (ReadProcessMemory(hProcess, mbi.BaseAddress, buf.data(), mbi.RegionSize, &rd))
            {
                for (size_t i = 0; i + sizeof(int) <= rd; i++)
                {
                    int v;
                    memcpy(&v, &buf[i], sizeof(v));
                    if (v == target)
                        tracked.push_back({ (uintptr_t)mbi.BaseAddress + i, v });
                }
            }
        }
        a = (uintptr_t)mbi.BaseAddress + mbi.RegionSize;
    }
    initialScanDone = true;

    setColor(CYAN);
    std::cout << "Found " << tracked.size() << " addresses = " << target << "\n";
    setColor(YELLOW);
    for (auto& x : tracked)
    {
        int curVal;
        if (readInt(x.addr, curVal))
            std::cout << " - 0x" << std::hex << x.addr << std::dec << " : " << curVal << "\n";
        else
            std::cout << " - 0x" << std::hex << x.addr << std::dec << " : null\n";
    }
    setColor(DEFAULT);
}

// Refine existing tracked addresses to new value by comparing delta changes
void refineValue(int newTargetValue)
{
    if (!initialScanDone)
    {
        setColor(RED);
        std::cout << "No initial scan found. Run 'scan <value>' first.\n";
        setColor(DEFAULT);
        return;
    }
    if (currentDataType != DataType::INT32)
    {
        std::cout << "Currently only int32 refine is supported.\n";
        return;
    }

    std::vector<AddressInfo> refined;

    for (auto& x : tracked)
    {
        int currentVal;
        if (readInt(x.addr, currentVal))
        {
            int delta = currentVal - x.lastValue;
            int expectedDelta = newTargetValue - x.lastValue;

            if (delta == expectedDelta)
            {
                refined.push_back({ x.addr, currentVal }); // Update lastValue to currentVal
            }
        }
    }

    tracked.swap(refined);

    setColor(CYAN);
    std::cout << "Refined to " << tracked.size() << " addresses matching value " << newTargetValue << "\n";
    setColor(YELLOW);
    for (auto& x : tracked)
    {
        std::cout << " - 0x" << std::hex << x.addr << std::dec << " : " << x.lastValue << "\n";
    }
    setColor(DEFAULT);
}

// Check changes of each tracked address and update lastValue after reading current
void checkChanges()
{
    if (tracked.empty())
    {
        setColor(RED);
        std::cerr << "No tracked addresses. Run 'scan' first.\n";
        setColor(DEFAULT);
        return;
    }
    if (currentDataType != DataType::INT32)
    {
        std::cout << "Currently only int32 check is supported.\n";
        return;
    }

    setColor(CYAN);
    std::cout << "Addr\t\tLast\tCurrent\tDelta\n";
    setColor(YELLOW);
    for (auto& x : tracked)
    {
        int cur;
        if (readInt(x.addr, cur))
        {
            int d = cur - x.lastValue;
            std::cout << "0x" << std::hex << x.addr << std::dec << "\t" << x.lastValue << "\t" << cur << "\t" << d << "\n";
            x.lastValue = cur; // update lastValue to current value for next refine/check
        }
    }
    setColor(DEFAULT);
}

// Write integer to address (parse from string)
void writeToAddress(const std::string& addrStr, const std::string& valStr)
{
    try
    {
        uintptr_t addr = 0;
        if (addrStr.size() > 2 && addrStr[0] == '0' && (addrStr[1] == 'x' || addrStr[1] == 'X'))
            addr = std::stoull(addrStr, nullptr, 16);
        else
            addr = std::stoull(addrStr, nullptr, 10);

        int v = std::stoi(valStr);

        if (writeInt(addr, v))
        {
            setColor(GREEN);
            std::cout << "Wrote " << v << " to address 0x" << std::hex << addr << "\n";
            setColor(DEFAULT);
        }
        else
        {
            setColor(RED);
            std::cout << "Failed to write to 0x" << std::hex << addr << "\n";
            setColor(DEFAULT);
        }
    }
    catch (const std::exception& e)
    {
        setColor(RED);
        std::cout << "Invalid address or value input: " << e.what() << "\n";
        setColor(DEFAULT);
    }
}

// Reset tracked addresses and state
void resetScan()
{
    tracked.clear();
    initialScanDone = false;
    std::lock_guard<std::mutex> lock(freezeMutex);
    freezeMap.clear();
    std::cout << "Scan reset. You can now run 'scan <value>' to start a new scan.\n";
}

// Freeze thread function: periodically write frozen values
void freezeWorker()
{
    while (freezeRunning)
    {
        {
            std::lock_guard<std::mutex> lock(freezeMutex);
            for (auto& kv : freezeMap)
            {
                writeInt(kv.first, kv.second);
            }
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
}

// Start freeze thread if not running
void startFreezeThread()
{
    if (!freezeRunning)
    {
        freezeRunning = true;
        freezeThread = std::thread(freezeWorker);
    }
}

// Stop freeze thread if running
void stopFreezeThread()
{
    if (freezeRunning)
    {
        freezeRunning = false;
        if (freezeThread.joinable())
            freezeThread.join();
    }
}

// Add or update freeze on address
void freezeAddress(const std::string& addrStr, const std::string& valStr)
{
    try
    {
        uintptr_t addr = 0;
        if (addrStr.size() > 2 && addrStr[0] == '0' && (addrStr[1] == 'x' || addrStr[1] == 'X'))
            addr = std::stoull(addrStr, nullptr, 16);
        else
            addr = std::stoull(addrStr, nullptr, 10);

        int v = std::stoi(valStr);

        {
            std::lock_guard<std::mutex> lock(freezeMutex);
            freezeMap[addr] = v;
        }
        startFreezeThread();

        setColor(GREEN);
        std::cout << "Freezing address 0x" << std::hex << addr << " to value " << std::dec << v << "\n";
        setColor(DEFAULT);
    }
    catch (const std::exception& e)
    {
        setColor(RED);
        std::cout << "Invalid freeze command input: " << e.what() << "\n";
        setColor(DEFAULT);
    }
}

// Remove freeze on address
void unfreezeAddress(const std::string& addrStr)
{
    try
    {
        uintptr_t addr = 0;
        if (addrStr.size() > 2 && addrStr[0] == '0' && (addrStr[1] == 'x' || addrStr[1] == 'X'))
            addr = std::stoull(addrStr, nullptr, 16);
        else
            addr = std::stoull(addrStr, nullptr, 10);

        bool removed = false;
        {
            std::lock_guard<std::mutex> lock(freezeMutex);
            removed = freezeMap.erase(addr) > 0;
        }

        if (removed)
        {
            setColor(GREEN);
            std::cout << "Unfroze address 0x" << std::hex << addr << "\n";
            setColor(DEFAULT);
        }
        else
        {
            setColor(YELLOW);
            std::cout << "Address 0x" << std::hex << addr << " was not frozen.\n";
            setColor(DEFAULT);
        }

        // Stop freeze thread if no frozen addresses left
        {
            std::lock_guard<std::mutex> lock(freezeMutex);
            if (freezeMap.empty())
                stopFreezeThread();
        }
    }
    catch (const std::exception& e)
    {
        setColor(RED);
        std::cout << "Invalid unfreeze command input: " << e.what() << "\n";
        setColor(DEFAULT);
    }
}

// Switch scan data type (only int supported now)
void setType(const std::string& typeStr)
{
    std::string low = typeStr;
    std::transform(low.begin(), low.end(), low.begin(), ::tolower);
    if (low == "int")
    {
        currentDataType = DataType::INT32;
        std::cout << "Scan data type set to int32.\n";
    }
    else
    {
        std::cout << "Unsupported type '" << typeStr << "'. Supported types: int\n";
    }
}

void showBanner()
{
    setColor(MAGENTA);
    std::cout << R"(
                ,---.    .--.          .-. .-. 
                | .-.\  / /\ \ |\    /|| | | | 
                | `-'/ / /__\ \|(\  / || | | | 
                |   (  |  __  |(_)\/  || | | | 
                | |\ \ | |  |)|| \  / || `-')| 
                |_| \)\|_|  (_)| |\/| |`---(_) 
                    (__)       '-'  '-'     
                                                                
       MADE BY: 3XYU-SHADOW | Cheat Engine–Style Scanner

    )" << "\n";
    setColor(DEFAULT);
}

// Print help
void printHelp()
{
    setColor(CYAN);
    std::cout << "\nCommands:\n";
    setColor(YELLOW);
    std::cout << "  showprocs             List running processes\n";
    std::cout << "  attach <exe>          Attach to process\n";
    std::cout << "  scan <value>          Initial full scan for value\n";
    std::cout << "  refine <value>        Filter tracked addresses by new value\n";
    std::cout << "  check                 Show change for each tracked address\n";
    std::cout << "  write <addr> <val>    Write value to address\n";
    std::cout << "  reset                 Reset scan data (start fresh)\n";
    std::cout << "  settype <type>        Switch scan data type (only 'int' supported now)\n";
    std::cout << "  freeze <addr> <val>   Constantly overwrite address with value\n";
    std::cout << "  unfreeze <addr>       Stop freezing address\n";
    std::cout << "  help                  Show this help\n";
    std::cout << "  exit                  Quit\n";
    setColor(DEFAULT);
}

int main()
{
    SetConsoleTitleA("RAMU | Memory Scanner by 3XYU-SHADOW");
    //system("chcp 65001");  // Set code page to UTF-8

    showBanner();
    printHelp();
    std::string line;
    while (true)
    {
        setColor(MAGENTA);
        std::cout << "> ";
        setColor(DEFAULT);
        if (!std::getline(std::cin, line))
            break;
        std::stringstream ss(line);
        std::string cmd;
        ss >> cmd;
        std::transform(cmd.begin(), cmd.end(), cmd.begin(), ::tolower);

        if (cmd == "exit")
            break;
        else if (cmd == "help")
            printHelp();
        else if (cmd == "showprocs")
            showProcesses();
        else if (cmd == "attach")
        {
            std::string exe;
            ss >> exe;
            if (attachProc(exe))
                setColor(GREEN), std::cout << "Attached to " << exe << "\n", setColor(DEFAULT);
            else
                setColor(RED), std::cout << "Attach failed\n", setColor(DEFAULT);
        }
        else if (cmd == "scan")
        {
            int v;
            if (ss >> v)
                scanValue(v);
            else
            {
                std::cout << "Enter value: ";
                std::cin >> v;
                std::cin.ignore();
                scanValue(v);
            }
        }
        else if (cmd == "refine")
        {
            int v;
            if (ss >> v)
                refineValue(v);
            else
            {
                std::cout << "Enter value: ";
                std::cin >> v;
                std::cin.ignore();
                refineValue(v);
            }
        }
        else if (cmd == "check")
            checkChanges();
        else if (cmd == "write")
        {
            std::string arg1, arg2;
            ss >> arg1 >> arg2;

            if (!arg1.empty() && !arg2.empty())
            {
                writeToAddress(arg1, arg2);
            }
            else
            {
                std::string addrStr, valStr;
                std::cout << "Enter address (hex or decimal, e.g. 0x1234ABCD): ";
                std::cin >> addrStr;
                std::cout << "Enter value (int): ";
                std::cin >> valStr;
                std::cin.ignore();
                writeToAddress(addrStr, valStr);
            }
        }
        else if (cmd == "reset")
            resetScan();
        else if (cmd == "settype")
        {
            std::string typeStr;
            ss >> typeStr;
            if (!typeStr.empty())
                setType(typeStr);
            else
                std::cout << "Usage: settype <type>\n";
        }
        else if (cmd == "freeze")
        {
            std::string addrStr, valStr;
            ss >> addrStr >> valStr;
            if (!addrStr.empty() && !valStr.empty())
                freezeAddress(addrStr, valStr);
            else
                std::cout << "Usage: freeze <addr> <value>\n";
        }
        else if (cmd == "unfreeze")
        {
            std::string addrStr;
            ss >> addrStr;
            if (!addrStr.empty())
                unfreezeAddress(addrStr);
            else
                std::cout << "Usage: unfreeze <addr>\n";
        }
        else
        {
            std::cout << "Unknown command. Type 'help' for list of commands.\n";
        }
    }

    stopFreezeThread();
    if (hProcess)
        CloseHandle(hProcess);

    return 0;
}
