# AV Evasion: Shellcode

# **AV Evasion: Shellcode**

Learn shellcode encoding, packing, binders, and crypters.

LINKS:
[https://tryhackme.com/r/room/avevasionshellcode](https://tryhackme.com/r/room/avevasionshellcode)
[https://tryhackme.com/room/windowsinternals](https://tryhackme.com/room/windowsinternals)

[https://docs.microsoft.com/en-us/windows/win32/debug/pe-format](https://docs.microsoft.com/en-us/windows/win32/debug/pe-format)
[https://www.notion.so/EICAR-cfe6a8066a6a4ab995f86ac9af78be10?pvs=4](https://www.notion.so/EICAR-cfe6a8066a6a4ab995f86ac9af78be10?pvs=21)

[https://blog.rchapman.org/posts/Linux_System_Call_Table_for_x86_64/](https://blog.rchapman.org/posts/Linux_System_Call_Table_for_x86_64/)

[https://github.com/mvelazc0/defcon27_csharp_workshop/blob/master/Labs/lab2/2.cs](https://github.com/mvelazc0/defcon27_csharp_workshop/blob/master/Labs/lab2/2.cs)

[https://github.com/mkaring/ConfuserEx/releases/tag/v1.6.0](https://github.com/mkaring/ConfuserEx/releases/tag/v1.6.0)

[https://tryhackme.com/room/runtimedetectionevasion](https://tryhackme.com/room/runtimedetectionevasion)

CHAT GPT:

[Index](AV%20Evasion%20Shellcode%20bb784cc3a59d463f856a403c318a4650/Index%20417b7e4db615496bae5809fba7d01f19.md)

[Task 1: Intro](AV%20Evasion%20Shellcode%20bb784cc3a59d463f856a403c318a4650/Task%201%20Intro%20ef7cf3761c944851b267f6611ef0dfb3.md)

[Task 2 Challenge](AV%20Evasion%20Shellcode%20bb784cc3a59d463f856a403c318a4650/Task%202%20Challenge%20188a94696da94f81877feeda2489126c.md)

[Task 3 PE Structure](AV%20Evasion%20Shellcode%20bb784cc3a59d463f856a403c318a4650/Task%203%20PE%20Structure%20084a1663511f460bb9d83a5414e7aead.md)

[Task 4 Intro Shellcode](AV%20Evasion%20Shellcode%20bb784cc3a59d463f856a403c318a4650/Task%204%20Intro%20Shellcode%2044d5184c583546d09ae60380a51fdaab.md)

[Task 5 Generate Shellcode](AV%20Evasion%20Shellcode%20bb784cc3a59d463f856a403c318a4650/Task%205%20Generate%20Shellcode%206f2a6ccab0b54d839c88c2fece7ca93a.md)

[Task 6 Staged Payloads](AV%20Evasion%20Shellcode%20bb784cc3a59d463f856a403c318a4650/Task%206%20Staged%20Payloads%204dd48ff43a2b4d5b9bb1267eb3bed0b0.md)

[Task 7 Introduction to Encoding and Encryption](AV%20Evasion%20Shellcode%20bb784cc3a59d463f856a403c318a4650/Task%207%20Introduction%20to%20Encoding%20and%20Encryption%20c61f6f80be5248d7869b8588134d5783.md)

[Task 8 Shellcode Encoding and Encryption](AV%20Evasion%20Shellcode%20bb784cc3a59d463f856a403c318a4650/Task%208%20Shellcode%20Encoding%20and%20Encryption%20644f125c98ce41c9ad3a1a295c03edc5.md)

[Task 9 Packers](AV%20Evasion%20Shellcode%20bb784cc3a59d463f856a403c318a4650/Task%209%20Packers%2064e073a4ec524de1b4750bc0fcf281b1.md)

[Task 10 Binders](AV%20Evasion%20Shellcode%20bb784cc3a59d463f856a403c318a4650/Task%2010%20Binders%2099b67f6c90b84d20b0f2e512933a089b.md)

[Task 11 Conclusion](AV%20Evasion%20Shellcode%20bb784cc3a59d463f856a403c318a4650/Task%2011%20Conclusion%20a23eb871e11b41169c5bc3c871be7b20.md)

[Answers](AV%20Evasion%20Shellcode%20bb784cc3a59d463f856a403c318a4650/Answers%20812307b5aa874e4399207fe4b4bd5c6a.md)

[Main Take Aways](AV%20Evasion%20Shellcode%20bb784cc3a59d463f856a403c318a4650/Main%20Take%20Aways%2053eb0a1918b2483eb3623b8eb5db7c82.md)

root@ip-10-10-75-113:~# md5sum ted
abf766d3dc25eeac73e3dc9d0ad40e6e  ted
root@ip-10-10-75-113:~# md5sum ted.asm
0387265c30efa8ffca059d2ccfd36601  ted.asm
root@ip-10-10-75-113:~# md5sum ted.c
19c14ac23a32a9dfbacd152afccc978c  ted.c
root@ip-10-10-75-113:~# md5sum ted.o
f806c50401b76822ff43e7bd396170da  ted.o
root@ip-10-10-75-113:~# md5sum ted.text
4eed7e6a2689ac26d5a28e29118c9a5d  ted.text

md5sum tedx
022e0f8dd805ff5d7bd8da0129d18012  tedx

root@ip-10-10-75-113:~# md5sum eicar
49cd3e752d8c8ee267113bf88a606081  eicar
root@ip-10-10-75-113:~# md5sum eicar.asm
4308ec7669a0e192f0b5ff8f4d70b9cc  eicar.asm
root@ip-10-10-75-113:~# md5sum eicar.c
c7a6432fcbe6e7b093670422c7a68b95  eicar.c
root@ip-10-10-75-113:~# md5sum eicar.o
fb8ec642f8dcfd7a40e8e3a6db232045  eicar.o
root@ip-10-10-75-113:~# md5sum eicar.text
7c5d63293f6a2eb6ba3024bed2b2a7fa  eicar.text
root@ip-10-10-75-113:~# md5sum eicarx
ac00021083c43a64432cd3439f8bb03b  eicarx

root@ip-10-10-75-113:~# md5sum calc.c
a4b79d55944c9c7e1a7e688fdc6d3b88  calc.c
root@ip-10-10-75-113:~# md5sum calc-MSF.exe
6bffb2b25cf3cc3c72bbca2b2269e8e2  calc-MSF.exe
root@ip-10-10-75-113:~# md5sum injector_template
cf392160516c6d8b5259144d87b92ce5  injector_template
root@ip-10-10-75-113:~# md5sum injector_template_windows
e471531524c78f9bd7cc52caf85830b3  injector_template_windows

encXFER.tar.gz.aes

xfer2_enc_tar.gz.aes :: md5 hash:  13c466b5a55afbdc9392b84552d953a8  -

```bash
find xfer2 -type f -exec md5sum {} + | md5sum
13c466b5a55afbdc9392b84552d953a8  -

```

[Combiner](AV%20Evasion%20Shellcode%20bb784cc3a59d463f856a403c318a4650/Combiner%20c7c917282eb646bc841842b4a74239d4.md)