# TraceIt
---

- Python 3 lib we can use to trace API call from a binary.
- I wanted something light, easy to use, and that work's with 64bit and python 3
- Probably bugged just a "learn" project.

## How to : 

- There is a documented example in the file `main.py`.

## Comes with two classes : 

- PycoDBG : Ultra minimal debugger :
	+ Start/Attach to a process in debug mode
	+ Break on entrypoint easily by getting base address during first event CREATE\_PROCESS
	+ Define breakpoints and use specific handler for thoses breakpoints
	+ Define breakpoints on API by resolving address with `ModuleSnapshot`
	+ Dump register

- APITracer : Tracer class utility
	+ Easy to use class to setup trace simply
	
## Example

### GetProcAddress tracing on a meterpreter : 

```
[BREAKPOINT] - HIT : GetProcAddress

        [EXE]     [FUNC]         [ARGNUM] [VALUE]            [TOINT]    [TOSTR]
        meter.exe GetProcAddress [1]      0x7ffc401b0000     0x401b0000 b'MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00\xb8\x00\x00\x00\x00\x00\x00\x00@\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
        meter.exe GetProcAddress [2]      0x89d352           0x89d352   b'DeleteFileA\x00\x9f\x00CreateNamedPipeA\x00\x00\xab\x02GetVer'
        meter.exe GetProcAddress [3]      0xc6               0xc6       False
        meter.exe GetProcAddress [4]      0xc6               0xc6       False
[BREAKPOINT] - HIT : GetProcAddress

        [EXE]     [FUNC]         [ARGNUM] [VALUE]            [TOINT]    [TOSTR]
        meter.exe GetProcAddress [1]      0x7ffc401b0000     0x401b0000 b'MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00\xb8\x00\x00\x00\x00\x00\x00\x00@\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
        meter.exe GetProcAddress [2]      0x89d360           0x89d360   b'CreateNamedPipeA\x00\x00\xab\x02GetVersionExA\x00\xd3\x02Heap'
        meter.exe GetProcAddress [3]      0x116              0x116      False
        meter.exe GetProcAddress [4]      0x116              0x116      False
[BREAKPOINT] - HIT : GetProcAddress

        [EXE]     [FUNC]         [ARGNUM] [VALUE]            [TOINT]    [TOSTR]
        meter.exe GetProcAddress [1]      0x7ffc401b0000     0x401b0000 b'MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00\xb8\x00\x00\x00\x00\x00\x00\x00@\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
        meter.exe GetProcAddress [2]      0x89d374           0x89d374   b'GetVersionExA\x00\xd3\x02HeapAlloc\x00\xd7\x02HeapFree\x00\x00Q\x02'
        meter.exe GetProcAddress [3]      0xde               0xde       False
        meter.exe GetProcAddress [4]      0xde               0xde       False
[BREAKPOINT] - HIT : GetProcAddress

        [EXE]     [FUNC]         [ARGNUM] [VALUE]            [TOINT]    [TOSTR]
        meter.exe GetProcAddress [1]      0x7ffc401b0000     0x401b0000 b'MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00\xb8\x00\x00\x00\x00\x00\x00\x00@\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
        meter.exe GetProcAddress [2]      0x89d384           0x89d384   b'HeapAlloc\x00\xd7\x02HeapFree\x00\x00Q\x02GetProcessHeap\x00\x00'
        meter.exe GetProcAddress [3]      0x326              0x326      False
        meter.exe GetProcAddress [4]      0x326              0x326      False
[BREAKPOINT] - HIT : GetProcAddress

        [EXE]     [FUNC]         [ARGNUM] [VALUE]            [TOINT]    [TOSTR]
        meter.exe GetProcAddress [1]      0x7ffc401b0000     0x401b0000 b'MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00\xb8\x00\x00\x00\x00\x00\x00\x00@\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
        meter.exe GetProcAddress [2]      0x89d26c           0x89d26c   b'GetCurrentThread\x00\x00\xe7\x01GetExitCodeThread\x00\x01\x04'
        meter.exe GetProcAddress [3]      0x2d3              0x2d3      False
        meter.exe GetProcAddress [4]      0x2d3              0x2d3      False
[BREAKPOINT] - HIT : GetProcAddress

        [EXE]     [FUNC]         [ARGNUM] [VALUE]            [TOINT]    [TOSTR]
        meter.exe GetProcAddress [1]      0x7ffc401b0000     0x401b0000 b'MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00\xb8\x00\x00\x00\x00\x00\x00\x00@\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
        meter.exe GetProcAddress [2]      0x89d39c           0x89d39c   b'GetProcessHeap\x00\x00\x82\x03OpenProcess\x00\xc6\x01GetCurre'
        meter.exe GetProcAddress [3]      0x224              0x224      False
        meter.exe GetProcAddress [4]      0x224              0x224      False
[BREAKPOINT] - HIT : GetProcAddress

        [EXE]     [FUNC]         [ARGNUM] [VALUE]            [TOINT]    [TOSTR]
        meter.exe GetProcAddress [1]      0x7ffc401b0000     0x401b0000 b'MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00\xb8\x00\x00\x00\x00\x00\x00\x00@\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
        meter.exe GetProcAddress [2]      0x89d3ae           0x89d3ae   b'OpenProcess\x00\xc6\x01GetCurrentProcess\x00\xec\x00Duplic'
        meter.exe GetProcAddress [3]      0x2be              0x2be      False
        meter.exe GetProcAddress [4]      0x2be              0x2be      False
```
