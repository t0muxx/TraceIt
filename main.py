from APITracer import *
import logging
import sys
from multiprocessing import Process 
import os

TO_TRACE = [
    ("kernel32.dll", "LoadLibraryA"),
    ("kernel32.dll", "LoadLibraryW"),
    ("kernel32.dll", "GetProcAddress"),
    ]

# You can either create your own handler or use default one
#def myHandler():
#    APITRACE.logger.tracer("---> CUSTOM HANDLER <----")
#
# To set it
#    APITRACE.AddToTracer("kernel32.dll", "GetProcAddress", handler=myHandler)
#    APITRACE.TraceAll(handler=myHandler)
#   APITRACE.TraceDLL(["adVaPi32.dll"], handler=myHandler)


def runTrace(filename):
    APITRACE = APITracer(filename, loglevel=logging.INFO)
    for api in TO_TRACE:
        APITRACE.AddToTracer(api[0], api[1])
    #APITRACE.TraceAll()
    #APITRACE.TraceAll(traceNtdll=True)
    #APITRACE.TraceDLL(["adVaPi32.dll"])
    APITRACE.Run()
    #os.system(filename)

def main():
        runTrace("")
        print("############################################")

if __name__ == '__main__':
	main()
