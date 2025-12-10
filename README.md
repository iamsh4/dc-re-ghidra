# dc-re-ghidra
This is a small script/data for easing the reverse engineering of Dreamcast software
using Ghidra. `DreamcastRE.java` is a script that can be run in the Ghidra Script Manager
or modified via Eclipse. It does several things, and all are done best-effort so that
if any step fails (e.g. because things are already defined) the script will continue.

# Features
1. Define named SH4 MMIO registers and address space. This will cause things like `TCNT0`
and `CCR` to appear as proper volatile registers in the decompiler.
2. Similarly, define named Holly/PVR registers and address space.
3. All referenced data which is only read from is marked as constant. This is crucial
since nearly all function invocations and constant addresses are referenced through a
pointer following code. Without this, the decompiler will not be able to assume that
a function pointer is constant, so it will show as a much less readable pointer dereference
and call. By marking all data as constant, the decompiler can use that information
to decompile into simple function calls.
4. Apply SDK symbol naming to functions. This is done by comparing all functions found
during auto-analysis to all symbols in a text file, also included in this repository.
Each symbol is defined as a crc32 of the function contents, the length in bytes of the
function, the SDK release version, library name, and symbol name. If a match is found,
the function is renamed to the symbol name. This is useful for understanding what
SDK functions are being called.
    - Note, the current SDK symbols are for the GNU libraries included from R9, R10.1, and R11.
    - SDK Symbols for functions <30 bytes are not renamed as the smaller a function is, the more likely it is to be a common pattern/ambiguous.

# Usage
1. Clone this repo, or just download the files `DreamcastRE.java` and `sdk-symbols.txt` into the same folder.
2. Open Ghidra and load a 16 MiB ram binary as superh little-endian to 0x8c000000.
3. Open the program and let the auto-analysis run.
4. Install the script: in the Ghidra CodeBrowser, open Window → Script Manager → Manage Script Directories → ➕ → select the folder with the script files.
5. Run the script: in the Script Manager window, select and run `DreamcastRE.java`.

# TODO:
1. Name SDK symbols by their plane name instead of the "fully-qualified" names.
2. Make it easy for others to include SDK headers (types, function signatures) to the Ghidra project.