# 🥪 Dynamic Proxy DLL Generator

This tool automates the creation of **proxy DLLs** that intercept and forward calls to an original DLL while performing custom logging. It's ideal for reverse engineering, red teaming, security testing, or instrumentation of native Windows DLLs.

Built with:

* `pefile` (Python) for PE export parsing
* `gcc` (MinGW) for compiling the proxy
* PowerShell and Python for automation

---

## ⚙️ Features

* ✅ Parses all exported functions from the original DLL (by name and ordinal)
* ✅ Automatically generates a `.def` file for forwarding
* ✅ Creates a proxy stub with malicious-style logging
* ✅ Compiles a working proxy DLL using GCC (MinGW)
* ✅ Optionally replaces the original DLL with the proxy (backup created)
* ✅ Fully scriptable via `argparse` interface

---

## 📦 Requirements

* Python 3.7+
* MinGW with `gcc` in `PATH`
* Python dependencies:

```bash
pip install -r requirements.txt
```

---

## 🚀 Usage

```bash
python generate_proxy_dll.py --source <original.dll> --dest <output\ProxyDll.dll> [--swap]
```

### 🔧 Arguments

| Flag       | Description                                  |
| ---------- | -------------------------------------------- |
| `--source` | Path to the original DLL to proxy            |
| `--dest`   | Path where the proxy DLL will be generated   |
| `--swap`   | (Optional) If set, replaces the original DLL |

---

## 🧪 Example

### ✅ Generate a proxy DLL

```bash
python generate_proxy_dll.py --source examples/RealDll.dll --dest build/ProxyDll.dll
```

### ↺ Generate and swap with original

```bash
python generate_proxy_dll.py --source C:\MyApp\RealDll.dll --dest build\ProxyDll.dll --swap
```

This will:

* Backup `RealDll.dll` to `RealDll.dll.backup`
* Replace it with `ProxyDll.dll`

---

## 📂 Project Structure

```
proxy-dll-generator/
├── generate_proxy_dll.py      # Main automation script
├── requirements.txt           # Python dependencies
├── templates/
│   └── stub_template.c        # C logging stub template (optional)
├── build/                     # Output: .dll, .def, .c files
├── examples/
│   └── RealDll.dll            # Test DLL (you provide)
└── README.md
```
---

## 📜 Logging Behavior

The proxy logs the following to a temp file:

* User name
* Current working directory
* Process ID and Parent PID
* Timestamp
* Custom log ID per call

📋 Log file: `%TEMP%\[yoginder_kumar].log`

---

## ⚠️ Disclaimer

This tool is intended for **educational, security research, and authorized testing purposes** only.
**Do not use** this tool in environments or systems without proper legal authorization.

---