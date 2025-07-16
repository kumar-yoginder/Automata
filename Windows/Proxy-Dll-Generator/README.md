# Proxy DLL Generator

## Purpose

This script automates the creation of proxy DLLs for Windows. It extracts all exported functions from a target DLL, generates C stubs that log calls to each export, and builds a new DLL that proxies calls to the original. Optionally, it can swap the original DLL with the proxy, backing up the original.

## Requirements

- Python packages:  
  - `pefile`
  - `psutil`
- Windows build tools:  
  - `gcc` (MinGW or similar, available in PATH)

Install Python dependencies with:
```
pip install pefile psutil
```

## Usage

```
python generate_proxy_dll.py --source <original.dll> --dest <proxy.dll> [--swap]
```

- `--source`: Path to the original DLL to proxy.
- `--dest`: Output path for the generated proxy DLL.
- `--swap`: (Optional) Replace the original DLL with the proxy and back up the original.

**Example:**
```
python generate_proxy_dll.py --source C:\Windows\System32\example.dll --dest C:\temp\example_proxy.dll --swap
```

## Workflow

1. Extracts all exported functions from the source DLL.
2. Generates a C file with logging stubs for each export.
3. Writes a module definition (`.def`) file for exports.
4. Compiles the proxy DLL using `gcc`.
5. (Optional) Swaps the original DLL with the proxy, backing up the original.

---

**Note:**  
- This script is intended for research and educational purposes.  
- Administrative privileges may be required for DLL operations.