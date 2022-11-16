# Main class of the debugger.
# TODO :
#   Add possibility to trace executable function (not winapi by giving offsets?)
#   Add possibility to dump return value.
# thx   :
#       - https://github.com/MarioVilas/winappdbg
#       - https://github.com/OpenRCE/pydbg
#       - https://www.codeproject.com/Articles/132742/Writing-Windows-Debugger-Part-2

from ctypes import *
from ctypes.wintypes import HMODULE, LPCSTR
from .defines import *
from .context import *
from .breakpoints import *
import logging
import sys
import win32api
import win32process

kernel32 = WinDLL('kernel32', use_last_error=True)
kernel32.GetProcAddress.restype = c_void_p
kernel32.GetProcAddress.argtypes = (HMODULE, c_char_p)
kernel32.LoadLibraryA.restype = HMODULE

class PycoDBG:
    """
    PycoDBG class : Main class used for the pico debugger.
    This debugger does not implement all debug event but only
    those needed for WinAPI tracing.
        hProcess = Handle to debugged process
        hThread = Handle to current debugged thread
        pid = Debugged process PID
        isActive = Boolean used to know when to stop GetDebugEvent loop.
        context = parameter containing CONTEXT structure (used for *ThreadContext)
        entrypoint = Value containing lpStartAddress set upon debugged starting
        breakpoints = dict of Breakpoints class used to manage breakpoint
    """
    def __init__(self, loglevel=25):
        self.hProcess = None
        self.hThread = None
        self.pid = None
        self.isActive = False
        self.context = None
        self.entrypoint = None
        self.breakpoints = {}
        self.lastBp = {}
        self.initLogger(loglevel)        

    def initLogger(self, loglevel):
        # colorama init()
        # init()
        logging.BREAKPOINT = 26
        logging.addLevelName(logging.BREAKPOINT, 'BREAKPOINT') # rename existing
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(loglevel)
        ch = logging.StreamHandler()
        formatter = logging.Formatter('[%(levelname)s] - %(message)s')
        ch.setFormatter(formatter)
        self.logger.addHandler(ch)
        self.logger.breakpoint = lambda msg, *args: self.logger._log(logging.BREAKPOINT, msg, args)


    def Load(self, execPath):
        """
        Load method :
            Start process given by execPath in DEBUG_PROCESS mode.
        """
        creation_flags = DEBUG_PROCESS

        si = STARTUPINFO()
        pi = PROCESS_INFORMATION()

        si.dwFlags = 0x1
        si.wShowWindow = 0x5
        si.cb = sizeof(si)

        self.logger.info("Loading file : {}".format(execPath))
        if kernel32.CreateProcessA(None,
                c_char_p(execPath.encode('utf-8')),
                                    None,
                                    None,
                                    False,
                                    DEBUG_PROCESS,
                                    None,
                                    None,
                                    byref(si),
                                    byref(pi)):
            self.logger.info("Process {} started. pid : {}".format(execPath, pi.dwProcessId))
            self.isActive = True
            self.pid = pi.dwProcessId
            self.hProcess = pi.hProcess
        
        else:
            self.logger.error("CreateProcessA : Error 0x{:08x}".format(kernel32.GetLastError()))
            sys.exit(-1)
    
    def OpenProcess(self,pid):
        """
        OpenProcess method :
            Wrapper around OpenProcess winapi.
        """ 
        # PROCESS_ALL_ACCESS = 0x0x001F0FFF
        h_process = kernel32.OpenProcess(PROCESS_ALL_ACCESS,False,pid) 
        
        return h_process

    def Attach(self,pid):
        """
        Attach method :
            Wrapper to attach and debug an already running process.
            Not used for this moment
        """
        self.hProcess = self.OpenProcess(pid)
        
        # We attempt to attach to the process
        # if this fails we exit the call
        if kernel32.DebugActiveProcess(pid):
            self.pid             = int(pid)
        else:
            self.logger.error("Unable to attach to the process.")
        

    def Run(self):
        """
        Run method:
            Start debugging.
        """
        while self.isActive == True:
            self.GetDebugEvent()

    def ReadProcessMemory(self, addr, length):
        """
        ReadProcessMemory method :
            Wrapper around ReadProcesMemory winapi.
        """
        data = b""
        buf = create_string_buffer(length)
        cnt = c_ulong(0)

        if not kernel32.ReadProcessMemory(self.hProcess,
                                          c_void_p(addr),
                                          buf,
                                          length,
                                          byref(cnt)):
            return False
        else:
            data += buf.raw
            return data

    def WriteProcessMemory(self, addr, data):
        """
        WriteProcessMemory method :
            Wrapper around WriteProcessMemory winapi.
        """
        count = c_ulong(0)
        length = len(data)

        c_data = c_char_p(data[count.value:])

        if not kernel32.WriteProcessMemory(self.hProcess,
                                          c_void_p(addr),
                                          c_data,
                                          length,
                                          byref(count)):
            return False
        else:
            return True
        

    def SetBp(self,address, handler, name=None):
        """
        SetBp method:
            Used to set breakpoint.
            Will write `int 3` (`\xCC`) after having saved the old byte.
            Register the breakpoint into self.breakpoint dict.
        """
        self.logger.debug("Setting breakpoint at: 0x{:016x} [{}]".format(address, name))
        if address not in self.breakpoints.keys():
            # store the original byte
            old_protect = c_ulong(0)
            if not kernel32.VirtualProtectEx(self.hProcess, c_void_p(address), 1, PAGE_EXECUTE_READWRITE, byref(old_protect)):
                self.logger.error("VirtualProtectEx : 0x{:08x}".format(kernel32.GetLastError()))

            original_byte = self.ReadProcessMemory(address, 1)
            if original_byte != False:
                
                # write the INT3 opcode
                if self.WriteProcessMemory(address, b"\xCC"):

                    # register the breakpoint in our internal list
                    self.breakpoints[address] = Breakpoints(address, original_byte, handler, name)
                    return True
                else:
                    self.logger.error("WriteProcessMemory : 0x{:08x}".format(kernel32.GetLastError()))
            else:
                self.logger.error("ReadProcessMemory : 0x{:08x}".format(kernel32.GetLastError()))
                return False

    def GetModulesBaseAddr(self, moduleName):
        """
        GetModuleBaseAddr method :
            Wrapper use to retrieve a loaded module base address.
        """
        hSnapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, self.pid)
        if hSnapshot:
            me = MODULEENTRY32()
            me.dwSize = sizeof(MODULEENTRY32)
            success = kernel32.Module32First(hSnapshot, byref(me))
            if success:
                while success:
                    lpBaseAddress = me.modBaseAddr
                    fileName = me.szModule
                    #self.logger.debug("[*] File : {} ".format(fileName))#
                    #self.logger.debug("[*] addr : 0x{:08x}".format(lpBaseAddress))
                    if moduleName.lower() == fileName.decode('utf-8').lower():
                        #print("[*] Found : {}".format(moduleName))
                        return lpBaseAddress
                    success = kernel32.Module32Next(hSnapshot, byref(me))
            else:
                self.logger.error("Module32First : 0x{:08x}".format(kernel32.GetLastError()))

        else:
            self.logger.error("CreateToolhelp32Snapshot : 0x{:08x}".format(kernel32.GetLastError()))
        return False

    def GetDebugEvent(self):
        """
        GetDebugEvent method :
            Main debug loop. 
            Threat exception code.
            When EXCEPTION_BREAKPOINT pass control flow to breakpoint handler.
            During CREATE_PROCESS_DEBUG_EVENT it will retrieve lpStartAddress
            and set all breakpoints.
        """
        debugEvent = DEBUG_EVENT()
        continueStatus = DBG_CONTINUE

        if kernel32.WaitForDebugEvent(byref(debugEvent), INFINITE):
            self.hThread = self.OpenThread(debugEvent.dwThreadId)
            self.context = self.GetThreadContext(self.hThread)
            
            if debugEvent.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT:
                self.logger.info("Process exited !")
                self.isActive = False

            if debugEvent.dwDebugEventCode == CREATE_PROCESS_DEBUG_EVENT:
                if not self.entrypoint:
                    self.entrypoint = debugEvent.u.CreateProcessInfo.lpStartAddress
                    if self.entryBp:
                        self.SetBp(debugEvent.u.CreateProcessInfo.lpStartAddress, self.entryBpHandler, "entrypoint")
                
            if debugEvent.dwDebugEventCode == EXCEPTION_DEBUG_EVENT:
                self.exception = debugEvent.u.Exception.ExceptionRecord.ExceptionCode
                self.exceptionAddr = debugEvent.u.Exception.ExceptionRecord.ExceptionAddress

                #hanlders for exception type
                if self.exception == EXCEPTION_ACCESS_VIOLATION:
                    self.logger.debug("Exception access violation")
                if self.exception == EXCEPTION_BREAKPOINT:
                    self.logger.debug("Exception BP")
                    continueStatus = self.ExceptionHandlerBreakpoint()
                if self.exception == EXCEPTION_GUARD_PAGE:
                    self.logger.debug("Exception guard page")
                if self.exception == EXCEPTION_SINGLE_STEP:
                    self.logger.debug("Exception single step")
                    continueStatus = self.ExceptionSingleStepHandler()
                if self.exception == LOAD_DLL_DEBUG_EVENT:
                    self.logger.debug("Exception load DLL")
            kernel32.CloseHandle(self.hThread)
            kernel32.ContinueDebugEvent(debugEvent.dwProcessId,
                                        debugEvent.dwThreadId,
                                        continueStatus)


    def ResolveApi(self, dllName, functName):
        """
        ResolveApi method :
            Wrapper around LoadLibraryA/GetProcAddress to retrieve an function address
            from the dll name and the function name.
        """
        self.logger.debug("ResolveApi : {} - {}".format(dllName, functName.encode('utf8')))
        dllHandle = kernel32.LoadLibraryA(c_char_p(dllName.encode('utf8')))
        if dllHandle:
            addr = kernel32.GetProcAddress(dllHandle, functName.encode('utf8'))
            if addr:
                self.logger.debug("Found addr {:08x} for : {}".format(addr, functName))
                return addr
            else:
                self.logger.error("GetProcAddress : 0x{:08x}".format(kernel32.GetLastError()))
        else:
            self.logger.error("LoadLibrary : 0x{:08x}".format(kernel32.GetLastError()))

        self.logger.debug("Can't find {} is either incorrect or not imported"
            .format(dllName))
        return False

    def SetBpAPI(self, dllName, functName, handler):
        """
        SetBpAPI method :
            Set a breakpoint on an windows api from the dll name and function name.
            handler will get called when the breakpoint is hit.
        """
        # Resolve addr
        dllAddr = self.ResolveApi(dllName, functName)
        if dllAddr:
            self.SetBp(dllAddr, handler, functName)
            self.logger.debug("API set on for {}".format(functName))

    def SetBpOnEntrypoint(self, handler):
        """
        SetBpOnEntrypoint method :
            Set a breakpoint on the entrypoint.
            handler would be called when breakpoint is hit.
        """
        self.entryBp = True
        self.entryBpHandler = handler

    def ExceptionSingleStepHandler(self):
        """
        ExceptionSingleStepHandler method :
            Single step execption handler
            Allow us to replace a breakpoint to make it repeatable
            As we trigg en EXCEPTION_SINGLE_STEP after a breakpoint
        """
        self.logger.debug("self.lastBp : {:08x}".format(self.lastBp))
        if self.lastBp not in self.breakpoints.keys():
            return DBG_CONTINUE

        address = self.lastBp 
        self.logger.debug("Re-writing breakpoint for : {:08x}".format(address))
        if not self.WriteProcessMemory(address, b"\xCC"):
            self.logger.error("Can't re-write breakpoint for : {:08x}".format(address))
        
        return DBG_CONTINUE


    def ExceptionHandlerBreakpoint(self):
        """
        ExceptionHandlerBreakpoint method :
            Main breakpoint handler.
            If the exceptionAddr is not our breakpoints we continue
            Else It will execute the breakpoint handler and
            Continue execution.
        """
        if self.exceptionAddr not in self.breakpoints.keys():
            return DBG_CONTINUE
        
        if self.breakpoints[self.exceptionAddr].name != None:
            self.logger.breakpoint("HIT : {}".format(self.breakpoints[self.exceptionAddr].name))

        self.logger.debug("exceptionAddr : {:08x}".format(self.exceptionAddr))
        self.breakpoints[self.exceptionAddr].handler()
        if not self.WriteProcessMemory(self.exceptionAddr, self.breakpoints[self.exceptionAddr].original_byte):
            self.logger.error("Can't set bp adress to it's original value : 0x{:08x}".format(kernel32.GetLastError()))
       
        # we set last bp to be able to restore it after the exception_single_step
        self.lastBp = self.exceptionAddr
        self.context = self.GetThreadContext(self.hThread)
        self.context.Rip -= 1
        # Used to trig an SINGLE_STEP_EXEPTION that we can handle to re-write the breakpoint.
        self.context.EFlags |= 0x100
        if not kernel32.SetThreadContext(self.hThread, byref(self.context)):
            self.logger.error("SetThreadContext : 0x{:08x}".format(kernel32.GetLastError()))
        return DBG_CONTINUE

    def OpenThread(self, thread_id):
        """
        OpenThread method :
            Wrapper around OpenThread winapi.
        """
        h_thread = kernel32.OpenThread(THREAD_ALL_ACCESS, None, thread_id)
        if h_thread is not None:
            return h_thread
        else:
            self.logger.error("Could not obtain a valid thread handle.")
        return False

    def GetThreadContext (self, hThread):
        """
        GetThreadContext method :
            Wrapper around GetThreadContext winapi.
        """
        context = CONTEXT()
        context.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS
        # Obtain a handle to the thread
        if kernel32.GetThreadContext(hThread, byref(context)):
            return context
        else:
            self.logger.error("GetThreadContext : 0x{:08x}".format(kernel32.GetLastError()))
            return False

    def EnumThreads(self):
        """
        EnumThreads method :
            Helper function to retrieve thread list.
        """
        thread_entry = THREADENTRY32()
        thread_list = []
        snapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, self.pid)
        if snapshot is not None:
        # You have to set the size of the struct
        # or the call will fail
            thread_entry.dwSize = sizeof(thread_entry)
            success = kernel32.Thread32First(snapshot, byref(thread_entry))
            while success:
                if thread_entry.th32OwnerProcessID == self.pid:
                    thread_list.append(thread_entry.th32ThreadID)
                
                success = kernel32.Thread32Next(snapshot, byref(thread_entry))
            kernel32.CloseHandle(snapshot)
            return thread_list
        else:
            return False
