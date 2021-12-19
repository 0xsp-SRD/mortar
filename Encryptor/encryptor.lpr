{
===========================================
                  MIT License
Copyright (c) 2021 0xsp security research and development
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


program encryptor;

{$mode objfpc}{$H+}

uses
  {$IFDEF UNIX}
  cthreads,
  {$ENDIF}
  Classes, SysUtils,base64,blowfish, CustApp
  { you can add units after this };

type

  { TMortar }

  TMortar = class(TCustomApplication)
  protected
    procedure DoRun; override;
  public
    constructor Create(TheOwner: TComponent); override;
    destructor Destroy; override;
    procedure WriteHelp; virtual;
    procedure encrypt; virtual;
  end;

{ TMortar }

procedure TMortar.DoRun;
var
  ErrorMsg: String;
begin
  // quick check parameters
  ErrorMsg:=CheckOptions('h f o', 'help filename ouput');
  if ErrorMsg<>'' then begin
    ShowException(Exception.Create(ErrorMsg));
    Terminate;
    Exit;
  end;

  // parse parameters
  if HasOption('h', 'help') then begin
    WriteHelp;
    Terminate;
    Exit;
  end;

    encrypt;
  Terminate;
end;

function FileToBase64(const AFile: String; var Base64: String): Boolean;
var
  MS: TMemoryStream;
  Str: String;
begin
  Result := False;
  if not FileExists(AFile) then
    Exit;
  MS := TMemoryStream.Create;
  try
    MS.LoadFromFile(AFile);
    if MS.Size > 0 then
    begin
      SetLength(Str, MS.Size div SizeOf(Char));
      MS.ReadBuffer(Str[1], MS.Size div SizeOf(Char));
      Base64 := EncodeStringBase64(Str);
      Result := True;
    end;
  finally
    MS.Free;
  end;
end;


function blowfish_encryption(value:rawbytestring;output:string):string;
var
  en :TBlowFishEncryptStream;
  de : TBlowFishDeCryptStream;
  s1,s2:Tstringstream;
  key,temp:string;
  i:integer;
  vstrm :TFileStream;

  begin
  vStrm := TFileStream.Create(output,fmCreate);

  key :='zuxiamhere';  // encryption + decryption key

  s1 := Tstringstream.Create('');
  writeln('[+] Encrypting the binary ...');
  en := TBlowFishEncryptStream.Create(key,s1);  // this will create blowfish encryption stream .
  en.Write(value[1],length(value));
  vStrm.Write(s1.DataString[1], Length(s1.DataString));
  en.free;
  vstrm.Free;
  end;



constructor TMortar.Create(TheOwner: TComponent);
begin
  inherited Create(TheOwner);
  StopOnException:=True;
end;

destructor TMortar.Destroy;
begin
  inherited Destroy;
end;

procedure TMortar.encrypt;
var
  filename,output,b64_encoded:string;
begin

   writeln('{!} Mortar Evasion Technique - Encryptor Tool');
   writeln('[+] 0xsp.com @zux0x3a');
   writeln(' ');

  filename := getoptionvalue('f');
  output := getoptionvalue('o');

  if not filetobase64(filename,b64_encoded) then
begin
  writeln('[+] Error While Dealing with file,Make sure to select valid filename or you have access permission ');
  exit;
  end;
  blowfish_encryption(b64_encoded,output);
  writeln('[!] content is written to '+output);
end;


procedure TMortar.WriteHelp;
begin
  { add your help code here }
  writeln('Usage: ', ExeName, ' -h');
  writeln('-f','--select valid executable');
  writeln('-o','--output path');

end;

var
  Application: TMortar;
begin
  Application:=TMortar.Create(nil);
  Application.Title:='Encryptor';
  Application.Run;
  Application.Free;
end.

