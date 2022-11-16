#https://securityxploded.com/api-call-tracing-with-pefile-pydbg-and-idapython.php

import pefile
from .PycoDBG import PycoDBG
import logging
from ctypes import *
import os

class APITracer():
    """
    APITracer class : Main class used to manage the breakpoint setting to the debugger.
        file = executable file path
        pe = pefile.PE object used to retrieve import by example.
        toTrace = Array of tuple in format [("dllname.dll", "functionname"),] that will be traced.
        dbg = PycoDBG object.
        exeName = contains the name of the executable.
    """
    def __init__(self, filePath, loglevel=15):
        self.file = filePath
        self.pe = pefile.PE(self.file)
        self.toTrace = []
        self.dbg = PycoDBG(loglevel=loglevel)
        self.initLogger(loglevel)
        self.exeName = os.path.basename(filePath)

    def initLogger(self, loglevel):
        logging.TRACER = 25
        logging.addLevelName(logging.TRACER, 'TRACER') # rename existing
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(loglevel)
        ch = logging.StreamHandler()
        formatter = logging.Formatter('[%(levelname)s] - %(message)s')
        ch.setFormatter(formatter)
        self.logger.addHandler(ch)
        self.logger.tracer = lambda msg, *args: self.logger._log(logging.TRACER, msg, args)
        
    def HandlerAPISetupBp(self):
        """
        HandlerAPISetupBp method :
            Will create breakpoint for the method we want to trace.
        """
        self.logger.info("Creating BP to setup trace")
        for api in self.toTrace:
            if api["handler"]:
                self.dbg.SetBpAPI(api["dllName"], api["functName"], api["handler"])
            else:
                self.dbg.SetBpAPI(api["dllName"], api["functName"], self.HandlerDefaultAPI)
                

    def AddToTracer(self, dllName, functName, handler=None):
        """
        AddToTracer method :
            Add function to trace.
        """
        self.toTrace.append({"dllName":dllName, "functName": functName, "handler":handler})
        self.dbg.SetBpOnEntrypoint(self.HandlerAPISetupBp)

    def TraceDLL(self, dllList, handler=None):
        """
        TraceDLL method :
            Will trace all the function in a specified dll.
        """
        for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
            dllName = entry.dll
            print(dllName.decode('utf-8'))
            print(dllList)
            for dll in dllList:
                if dllName.decode('utf-8').casefold() == dll.casefold():
                    self.logger.debug("entry : {}".format(dllName))
                    for imp in entry.imports:
                        functName = imp.name
                        if functName:
                            self.logger.debug("functname : {}".format(functName))
                            self.AddToTracer(dllName.decode('utf-8'), functName.decode('utf-8'), handler)

    def TraceAll(self, traceNtdll=False, handler=None):
        """
        TraceAll method :
            Will trace all the import dll and the ntdll functions
            if traceNtdll is true.
        """
        for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
            dllName = entry.dll
            self.logger.debug("entry : {}".format(dllName))
            for imp in entry.imports:
                functName = imp.name
                if functName:
                    self.logger.debug("functname : {}".format(functName))
                    self.AddToTracer(dllName.decode('utf-8'), functName.decode('utf-8'), handler)
        if traceNtdll == True:
            ntdll = pefile.PE("C:\\Windows\\System32\\ntdll.dll")
            self.logger.debug("entry : {}".format("ntdll.dll"))
            for imp in ntdll.DIRECTORY_ENTRY_EXPORT.symbols:
                if imp.name:
                    self.logger.debug("functName : {}".format(imp.name))
                    self.AddToTracer("ntdll.dll", imp.name.decode('utf-8'), handler)


    def toStr(self, b):
        if not b:
            return "Can't read"
        try:
            res = b.decode('utf-8')
        except UnicodeDecodeError:
            res = "no utf-8"
        return res

    # func1(int a, int b, int c, int d, int e, int f);
    # a in RCX, b in RDX, c in R8, d in R9, f then e pushed on stack
    def HandlerDefaultAPI(self):
        """
        HandlerDefaultAPI method :
            Default handler that will be called when a breakpoint is hit.
            It print register and try to print the content at the address by reading debugged memory.
        """
        context = self.dbg.GetThreadContext(self.dbg.hThread)
        functName = "{}".format(self.dbg.breakpoints[self.dbg.exceptionAddr].name)
        stringrpz = self.dbg.ReadProcessMemory(context.Rcx, 32)
        intrpz = context.Rcx
        alignFunc = len(functName)
        if alignFunc < len("[FUNC]"):
            alignFunc = len("[FUNC]")
        alignExe = len(self.exeName)
        if alignExe < len("[EXE]"):
            alignExe = len("[EXE]")
        print("")
        print("\t{} {} {:8s} {:18s} {:10s} {}".format("[EXE]".ljust(alignExe), "[FUNC]".ljust(alignFunc), "[ARGNUM]", "[VALUE]", "[TOINT]", "[TOSTR]"))
        print("\t{} {} {:8s} {:<#18x} {:<#10x} {}".format(self.exeName.ljust(alignExe), functName.ljust(alignFunc), "[1]", context.Rcx, context.Rcx & 0xFFFFFFFF, self.dbg.ReadProcessMemory(context.Rcx, 40)))
        print("\t{} {} {:8s} {:<#18x} {:<#10x} {}".format(self.exeName.ljust(alignExe), functName.ljust(alignFunc), "[2]", context.Rdx, context.Rdx & 0xFFFFFFFF, self.dbg.ReadProcessMemory(context.Rdx, 40)))
        print("\t{} {} {:8s} {:<#18x} {:<#10x} {}".format(self.exeName.ljust(alignExe), functName.ljust(alignFunc), "[3]", context.R8, context.R8 & 0xFFFFFFFF, self.dbg.ReadProcessMemory(context.R8, 40)))
        print("\t{} {} {:8s} {:<#18x} {:<#10x} {}".format(self.exeName.ljust(alignExe), functName.ljust(alignFunc), "[4]", context.R9, context.R9 & 0xFFFFFFFF, self.dbg.ReadProcessMemory(context.R9, 40)))

    def Run(self):
        self.dbg.Load(self.file)
        self.dbg.Run()

