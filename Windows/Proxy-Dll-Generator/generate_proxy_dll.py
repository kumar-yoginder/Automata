import pefile
import argparse
import os
import subprocess
import shutil
import sys

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
                f.write(f"    {name}=Proxy_{name}\n")
            else:
                f.write(f"    #{ordinal}\n")

def compile_dll(c_file, def_file, output_path):
    cmd = [
        "gcc",
        "-shared",
        "-o", output_path,
        c_file,
        "-Wl,--output-def," + def_file
    ]
    print("⚙️  Compiling with:", ' '.join(cmd))
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print("❌ Compilation failed:\n", result.stderr)
        sys.exit(1)
    print("✅ DLL compiled successfully at:", output_path)

def swap_dlls(original_dll_path, proxy_dll_path):
    backup_path = original_dll_path + ".backup"
    print(f"🧪 Swapping DLL:\n- Original: {original_dll_path}\n- Proxy: {proxy_dll_path}")
    if not os.path.exists(original_dll_path):
        print("❌ Original DLL not found.")
        return
    shutil.move(original_dll_path, backup_path)
    shutil.copy2(proxy_dll_path, original_dll_path)
    print(f"✅ Swap complete. Original backed up as: {backup_path}")

def main():
    parser = argparse.ArgumentParser(description="🧪 Proxy DLL Generator")
    parser.add_argument("--source", required=True, help="Source/original DLL to proxy")
    parser.add_argument("--dest", required=True, help="Output proxy DLL path")
    parser.add_argument("--swap", action='store_true', help="Replace original DLL with proxy (with backup)")

    args = parser.parse_args()
    source_dll = os.path.abspath(args.source)
    dest_dll = os.path.abspath(args.dest)
    build_dir = os.path.dirname(dest_dll)
    os.makedirs(build_dir, exist_ok=True)

    base_name = os.path.splitext(os.path.basename(source_dll))[0]
    def_path = os.path.join(build_dir, f"{base_name}.def")
    c_stub_path = os.path.join(build_dir, f"{base_name}_stub.c")

    print("📦 Extracting exports...")
    exports = extract_exports(source_dll)

    print(f"📝 Writing DEF file: {def_path}")
    generate_def_file(exports, def_path, base_name)

    print(f"🔨 Building proxy DLL: {dest_dll}")
    compile_dll(c_stub_path, def_path, dest_dll)

    if args.swap:
        print("♻️  Swapping real DLL with proxy...")
        swap_dlls(source_dll, dest_dll)

if __name__ == "__main__":
    main()
