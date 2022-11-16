from ctypes import *
from .defines import *

# The old CONTEXT structure for 32bit which holds all of the
# register values after a GetThreadContext() call
class CONTEXT32(Structure):
    _fields_ = [
    
        ("ContextFlags", DWORD),
        ("Dr0", DWORD),
        ("Dr1", DWORD),
        ("Dr2", DWORD),
        ("Dr3", DWORD),
        ("Dr6", DWORD),
        ("Dr7", DWORD),
        ("FloatSave", FLOATING_SAVE_AREA),
        ("SegGs", DWORD),
        ("SegFs", DWORD),
        ("SegEs", DWORD),
        ("SegDs", DWORD),
        ("Edi", DWORD),
        ("Esi", DWORD),
        ("Ebx", DWORD),
        ("Edx", DWORD),
        ("Ecx", DWORD),
        ("Eax", DWORD),
        ("Ebp", DWORD),
        ("Eip", DWORD),
        ("SegCs", DWORD),
        ("EFlags", DWORD),
        ("Esp", DWORD),
        ("SegSs", DWORD),
        ("ExtendedRegisters", BYTE * 512),
]

#typedef struct _M128A {
#    ULONG64	Low;
#    ULONG64	High;	
#} M128A;

class M128A(Structure):
    _fields_ = [
        ("Low", ULONG64),
        ("High", ULONG64),
    ]

#typedef struct _NEON128
#{
#    ULONGLONG Low;
#    LONGLONG High;
#} NEON128, *PNEON128;

class NEON128(Structure):
    _fields_ = [
        ("Low", ULONGLONG),
        ("High", LONGLONG),
    ]

#
# typedef struct XMM_SAVE_AREA32 {
#	UINT16       ControlWord;                                             
#	UINT16       StatusWord;                                              
#	UINT8        TagWord;                                                 
#	UINT8        Reserved1;                                               
#	UINT16       ErrorOpcode;                                             
#	ULONG32      ErrorOffset;                                             
#	UINT16       ErrorSelector;                                           
#	UINT16       Reserved2;                                               
#	ULONG32      DataOffset;                                              
#	UINT16       DataSelector;                                            
#	UINT16       Reserved3;                                               
#	ULONG32      MxCsr;                                                   
#	ULONG32      MxCsr_Mask;                                              
#	struct _M128A FloatRegisters[8];                                      
#	struct _M128A XmmRegisters[16];                                       
#	UINT8        Reserved4[96];                                           
#}XMM_SAVE_AREA32, *PXMM_SAVE_AREA32;

class XMM_SAVE_AREA32(Structure):
    _fields_ = [
        ("ControlWord", UINT16),
        ("StatusWord", UINT16),
        ("TagWord", UINT8),
        ("Reserved1", UINT8),
        ("ErrorOpcode", UINT16),
        ("ErrorOffset", ULONG32),
        ("ErrorSelector", UINT16),
        ("Reserved2", UINT16),
        ("DataOffset", ULONG32),
        ("DataSelector", UINT16),
        ("Reserved3", UINT16),
        ("MxCsr", ULONG32),
        ("MxCsr_Mask", ULONG32),
        ("FloatRegisters", M128A * 8),
        ("XmmRegisters", M128A * 16),
        ("Reserved4", UINT8 * 96),
    ]
    

class _CONTEXT_FLTSAVE_STRUCT(Structure):
    _fields_ = [
        ('Header',                  M128A * 2),
        ('Legacy',                  M128A * 8),
        ('Xmm0',                    M128A),
        ('Xmm1',                    M128A),
        ('Xmm2',                    M128A),
        ('Xmm3',                    M128A),
        ('Xmm4',                    M128A),
        ('Xmm5',                    M128A),
        ('Xmm6',                    M128A),
        ('Xmm7',                    M128A),
        ('Xmm8',                    M128A),
        ('Xmm9',                    M128A),
        ('Xmm10',                   M128A),
        ('Xmm11',                   M128A),
        ('Xmm12',                   M128A),
        ('Xmm13',                   M128A),
        ('Xmm14',                   M128A),
        ('Xmm15',                   M128A),
    ]

class _CONTEXT_FLTSAVE_UNION(Union):
    _fields_ = [
        ('flt',                     XMM_SAVE_AREA32),
        ('xmm',                     _CONTEXT_FLTSAVE_STRUCT),
    ]

# https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-context
# CONTEXT class for 64bits
# thx : https://github.com/MarioVilas/winappdbg/blob/master/winappdbg/win32/context_amd64.py
class CONTEXT(Structure):
    _pack_ = 16
    _fields_ = [

        # Register parameter home addresses.
        ('P1Home',                  DWORD64),
        ('P2Home',                  DWORD64),
        ('P3Home',                  DWORD64),
        ('P4Home',                  DWORD64),
        ('P5Home',                  DWORD64),
        ('P6Home',                  DWORD64),

        # Control flags.
        ('ContextFlags',            DWORD),
        ('MxCsr',                   DWORD),

        # Segment Registers and processor flags.
        ('SegCs',                   WORD),
        ('SegDs',                   WORD),
        ('SegEs',                   WORD),
        ('SegFs',                   WORD),
        ('SegGs',                   WORD),
        ('SegSs',                   WORD),
        ('EFlags',                  DWORD),

        # Debug registers.
        ('Dr0',                     DWORD64),
        ('Dr1',                     DWORD64),
        ('Dr2',                     DWORD64),
        ('Dr3',                     DWORD64),
        ('Dr6',                     DWORD64),
        ('Dr7',                     DWORD64),

        # Integer registers.
        ('Rax',                     DWORD64),
        ('Rcx',                     DWORD64),
        ('Rdx',                     DWORD64),
        ('Rbx',                     DWORD64),
        ('Rsp',                     DWORD64),
        ('Rbp',                     DWORD64),
        ('Rsi',                     DWORD64),
        ('Rdi',                     DWORD64),
        ('R8',                      DWORD64),
        ('R9',                      DWORD64),
        ('R10',                     DWORD64),
        ('R11',                     DWORD64),
        ('R12',                     DWORD64),
        ('R13',                     DWORD64),
        ('R14',                     DWORD64),
        ('R15',                     DWORD64),

        # Program counter.
        ('Rip',                     DWORD64),

        # Floating point state.
        ('FltSave',                 _CONTEXT_FLTSAVE_UNION),

        # Vector registers.
        ('VectorRegister',          M128A * 26),
        ('VectorControl',           DWORD64),

        # Special debug control registers.
        ('DebugControl',            DWORD64),
        ('LastBranchToRip',         DWORD64),
        ('LastBranchFromRip',       DWORD64),
        ('LastExceptionToRip',      DWORD64),
        ('LastExceptionFromRip',    DWORD64),
    ]

    _others = ('P1Home', 'P2Home', 'P3Home', 'P4Home', 'P5Home', 'P6Home', \
               'MxCsr', 'VectorRegister', 'VectorControl')
    _control = ('SegSs', 'Rsp', 'SegCs', 'Rip', 'EFlags')
    _integer = ('Rax', 'Rcx', 'Rdx', 'Rbx', 'Rsp', 'Rbp', 'Rsi', 'Rdi', \
                'R8', 'R9', 'R10', 'R11', 'R12', 'R13', 'R14', 'R15')
    _segments = ('SegDs', 'SegEs', 'SegFs', 'SegGs')
    _debug = ('Dr0', 'Dr1', 'Dr2', 'Dr3', 'Dr6', 'Dr7', \
              'DebugControl', 'LastBranchToRip', 'LastBranchFromRip', \
              'LastExceptionToRip', 'LastExceptionFromRip')
    _mmx = ('Xmm0', 'Xmm1', 'Xmm2', 'Xmm3', 'Xmm4', 'Xmm5', 'Xmm6', 'Xmm7', \
          'Xmm8', 'Xmm9', 'Xmm10', 'Xmm11', 'Xmm12', 'Xmm13', 'Xmm14', 'Xmm15')
