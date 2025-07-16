import pefile
import psutil
import argparse
import os
import subprocess
import shutil
import sys

build_dir = os.path.dirname(
    os.path.abspath(__file__)
)

LOGGING_TEMPLATE = """
#include <windows.h>
#include <stdio.h>
#include <time.h>
#include <string.h>
#include <lmcons.h>
#include <tlhelp32.h>

volatile LONG logEntryCounter = 0;
HMODULE realDll = NULL;

DWORD GetParentProcessIdForDLL() {
    HANDLE hSnapshot;
    PROCESSENTRY32 pe32;
    DWORD ppid = 0;
    DWORD currentPid = GetCurrentProcessId();

    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return 0;

    pe32.dwSize = sizeof(PROCESSENTRY32);
    if (!Process32First(hSnapshot, &pe32)) {
        CloseHandle(hSnapshot);
        return 0;
    }

    do {
        if (pe32.th32ProcessID == currentPid) {
            ppid = pe32.th32ParentProcessID;
            break;
        }
    } while (Process32Next(hSnapshot, &pe32));

    CloseHandle(hSnapshot);
    return ppid;
}

void logging(const char* funcName) {
    char logFilePath[MAX_PATH];
    char userName[UNLEN + 1];
    DWORD userNameLen = UNLEN + 1;
    char timestampStr[80];
    DWORD currentPid = GetCurrentProcessId();
    DWORD parentPid = GetParentProcessIdForDLL();
    time_t rawtime;
    struct tm* timeinfo;
    char tempPath[MAX_PATH];
    const char* logFileName = "[yoginder_kumar].log";

    long currentLogId = InterlockedIncrement(&logEntryCounter);

    time(&rawtime);
    timeinfo = localtime(&rawtime);
    strftime(timestampStr, sizeof(timestampStr), "%Y-%m-%d %H:%M:%S", timeinfo);
    GetUserNameA(userName, &userNameLen);

    if (GetTempPathA(MAX_PATH, tempPath)) {
        snprintf(logFilePath, MAX_PATH, "%s%s", tempPath, logFileName);
    } else {
        snprintf(logFilePath, MAX_PATH, "C:\\%s", logFileName);
    }

    FILE* file = fopen(logFilePath, "a+");
    if (file) {
        fprintf(file, "\\n--- Proxy DLL Log Entry ---\\n");
        fprintf(file, "Log ID: %ld\\n", currentLogId);
        fprintf(file, "Function: %s\\n", funcName);
        fprintf(file, "User: %s\\n", userName);
        fprintf(file, "PID: %lu\\n", currentPid);
        fprintf(file, "PPID: %lu\\n", parentPid);
        fprintf(file, "Time: %s\\n", timestampStr);
        fprintf(file, "---------------------------\\n");
        fclose(file);
    }
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved) {
    if (fdwReason == DLL_PROCESS_ATTACH) {
        char path[MAX_PATH];
        GetSystemDirectoryA(path, MAX_PATH);
        strcat(path, "\\\RealDll.dll");
        realDll = LoadLibraryA(path);
        logging("DllMain");
    }
    return TRUE;
}
"""

def infer_function_signature(name):
    candidates = [
        ("Get", "void*", "(void)", "return real_func ? real_func() : NULL;"),
        ("Set", "void", "(int a)", "if (real_func) real_func(a);"),
        ("Init", "BOOL", "(void)", "return real_func ? real_func() : FALSE;"),
        ("Start", "BOOL", "(void)", "return real_func ? real_func() : FALSE;"),
    ]
    for prefix, ret_type, args, body in candidates:
        if prefix.lower() in name.lower():
            return f"__declspec(dllexport) {ret_type} {name}{args} {{\n    logging(\"{name}\");\n    static {ret_type} (*real_func){args} = NULL;\n    if (!real_func && realDll) real_func = ({ret_type} (*){args})GetProcAddress(realDll, \"{name}\");\n    {body}\n}}"
    # Default fallback
    return f"__declspec(dllexport) int {name}(int a, int b) {{\n    logging(\"{name}\");\n    static int (*real_func)(int, int) = NULL;\n    if (!real_func && realDll) real_func = (int (*)(int, int))GetProcAddress(realDll, \"{name}\");\n    return real_func ? real_func(a, b) : -1;\n}}"


def extract_exports(dll_path):
    pe = pefile.PE(dll_path)
    exports = []
    try:
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            if exp.name:
                name = exp.name.decode('utf-8')
                exports.append((exp.ordinal, name))
            else:
                exports.append((exp.ordinal, None))
    except AttributeError:
        print("❌ No exports found.")
    return exports

def generate_def_file(exports, def_path, dll_name):
    with open(def_path, 'w') as f:
        f.write(f"LIBRARY {dll_name}\nEXPORTS\n")
        for ordinal, name in exports:
            if name:
                f.write(f"    {name}\n")
            else:
                f.write(f"    #{ordinal}\n")

def generate_stub_c(file_path, exports):
    with open(file_path, 'w') as f:
        f.write(LOGGING_TEMPLATE + "\n")
        for _, name in exports:
            if name:
                f.write(infer_function_signature(name) + "\n\n")
    # pass

def compile_dll(c_file, def_file, output_path):
    output_dll = output_path if output_path.endswith(".dll") else output_path + ".dll"
    cmd = [
        "gcc",
        c_file,
        "-shared",
        "-o", output_dll,
        "-lkernel32",
        "-Wl,--output-def=" + f'"{def_file}"'
    ]
    print("⚙️  Compiling with:\n", ' '.join(cmd),"\n")
    result = subprocess.run(' '.join(cmd), shell=True, capture_output=True, text=True)
    if result.returncode != 0:
        print("❌ Compilation failed:\n", result.stderr)
        sys.exit(1)
    print("✅ DLL compiled successfully at:", output_dll)

def find_processes_using_file(file_path):
    """Return a list of process info dicts using the specified file."""
    using_procs = []
    for proc in psutil.process_iter(['pid', 'name', 'open_files']):
        try:
            files = proc.info['open_files']
            if files:
                for f in files:
                    if os.path.abspath(f.path).lower() == os.path.abspath(file_path).lower():
                        using_procs.append(proc.info)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return using_procs

def swap_dlls(original_dll_path, proxy_dll_path):
    print(f"🧪 Installing proxy DLL into system directory...")
    
    if not os.path.exists(original_dll_path):
        print("❌ Original DLL not found.")
        return
    
    proxy_dll_path = proxy_dll_path if proxy_dll_path.endswith(".dll") else proxy_dll_path + ".dll"

    # Determine system directory
    system_dir = os.path.join(os.environ.get("WINDIR", "C:\\Windows"), "System32")
    dll_name = os.path.basename(original_dll_path)
    system_dll_path = os.path.join(system_dir, dll_name)

    # Copy original DLL into system32
    if not os.path.isfile(system_dll_path):
        shutil.copy2(original_dll_path, system_dll_path)
    print(f"✅ Original DLL copied to: {system_dll_path}")

    # Detect if the file is in use
    in_use = find_processes_using_file(original_dll_path)
    if in_use:
        print(f"⚠️ File is in use by the following processes:")
        for proc in in_use:
            print(f"  - PID {proc['pid']}: {proc['name']}")
        print("❌ Cannot rename the file while it is in use. Please terminate these processes and try again.")
        return

    # Rename original DLL with underscore in original path
    renamed_path = os.path.join(os.path.dirname(original_dll_path), "_" + dll_name)
    if not os.path.isfile(renamed_path):
        shutil.move(original_dll_path, renamed_path)
    print(f"🔁 Renamed original DLL to: {renamed_path}")

    # Copy proxy DLL in original path
    shutil.move(proxy_dll_path, original_dll_path)
    print(f"✅ Proxy DLL copied to: {original_dll_path}")

def main():
    parser = argparse.ArgumentParser(description="🧪 Proxy DLL Generator with per-export stub generation")
    parser.add_argument("--source", required=True, help="Source/original DLL to proxy")
    parser.add_argument("--dest", required=True, help="Output proxy DLL path")
    parser.add_argument("--swap", action='store_true', help="Replace original DLL with proxy (with backup)")
    args = parser.parse_args()

    source_dll = os.path.abspath(args.source)
    dest_dll = os.path.abspath(args.dest)
    # build_dir = os.path.dirname(dest_dll)
    os.makedirs(build_dir, exist_ok=True)

    base_name = os.path.splitext(os.path.basename(source_dll))[0]
    def_path = os.path.join(build_dir, f"{base_name}.def")
    c_stub_path = os.path.join(build_dir, f"{base_name}_stub.c")

    print("📦 Extracting exports...")
    exports = extract_exports(source_dll)

    print(f"📝 Writing DEF file: {def_path}")
    generate_def_file(exports, def_path, base_name)

    print(f"🧱 Writing C stub with function exports: {c_stub_path}")
    generate_stub_c(c_stub_path, exports)

    dest_dll = os.path.join(
        build_dir,
        base_name
    )

    print(f"🔨 Building proxy DLL: {dest_dll}")
    compile_dll(c_stub_path, def_path, dest_dll)

    if args.swap:
        print("♻️  Swapping real DLL with proxy...")
        swap_dlls(source_dll, dest_dll)

if __name__ == "__main__":
    main()