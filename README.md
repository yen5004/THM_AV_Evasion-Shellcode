# THM_AV_Evasion-Shellcode
TryHackMe tutorial on AV Evasion with shellcode

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

# Task 1: Intro

Task 1 Introduction

In this room, we'll explore how to build and deliver payloads, focusing on avoiding detection by common AV engines. We'll look at different techniques available to us as attackers and discuss the pros and cons of every one of them.

# Objectives

- Learn how shellcodes are made.
- Explore the pros and cons of staged payloads.
- Create stealthy shellcodes to avoid AV detection.

# Prerequisites

It is recommended to have some prior knowledge of [how antivirus software works](https://tryhackme.com/room/introtoav) and a basic understanding of encryption and encoding. While not strictly required, some knowledge of basic assembly language can also be helpful. Also, we recommend having a basic understanding of reading code and understanding functions (C, C#).

Answer the questions below
Click and continue learning!
NAN


# Task 2 Challenge

Task 2 Challenge

Start Machine

In this challenge, we prepared a Windows machine with a web application to let you upload your payloads. Once uploaded, the payloads will be checked by an AV and executed if found to be clean of malware. The main goal of this challenge is to evade Antivirus software installed on the VM and capture the flag in the file system. Feel free to try all of the techniques discussed throughout the room by uploading them to **`http://MACHINE_IP/`**.

Points to remember:

- Try to combine the techniques discussed in this room.
- The website supports EXE files only.
- Once the AV scans the uploaded file and no malicious code is detected, the file gets executed. Thus, if everything is put together correctly, then you should receive a reverse shell.

![https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/7a5c9d8d5501eaed9d0b677d94266414.png](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/7a5c9d8d5501eaed9d0b677d94266414.png)

You can ignore the questions for this task for now, but be sure to come back to them once you have successfully bypassed the AV and gained a shell.

Deploy the attached VM to follow up with the content of the room before continuing to the next section! The VM will deploy in-browser and should appear automatically in the Split View. In case the VM is not visible, use the blue Show Split View button at the top-right of the page. If you prefer connecting via RDP, you can do so with the following credentials:

![https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/94fe3c0f556877a2721ca9e0744ad026.png](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/94fe3c0f556877a2721ca9e0744ad026.png)

| Username | thm |
| --- | --- |
| Password | Password321 |

You will also need the AttackBox for some tasks, so this is also a good moment to start it.

Answer the questions below:

Which Antivirus software is running on the VM?
Submit

What is the name of the user account to which you have access?
Submit

Establish a working shell on the victim machine and read the file on the user's desktop. What is the flag?
Submit

[Answer](Task%202%20Challenge%20188a94696da94f81877feeda2489126c/Answer%2062b2c0072170444dada14972fa81576e.md)


# Task 3 PE Structure

This task highlights some of the high-level essential elements of PE data structure for Windows binaries.

# What is PE?

Windows Executable file format, aka PE (Portable Executable), is a data structure that holds information necessary for files. It is a way to organize executable file code on a disk. Windows operating system components, such as Windows and DOS loaders, can load it into memory and execute it based on the parsed file information found in the PE.

In general, the default file structure of Windows binaries, such as EXE, DLL, and Object code files, has the same PE structure and works in the Windows operating system for both (x86 and x64) CPU architecture.

A PE structure contains various sections that hold information about the binary, such as metadata and links to a memory address of external libraries. One of these sections is the **PE Header**, which contains metadata information, pointers, and links to address sections in memory. Another section is the **Data section**, which includes ****containers that include the information required for the Windows loader to run a program, such as the executable code, resources, links to libraries, data variables, etc.

![https://tryhackme-images.s3.amazonaws.com/user-uploads/5d617515c8cd8348d0b4e68f/room-content/ad61ff4aa1d4f649c02348dfa32eb613.png](https://tryhackme-images.s3.amazonaws.com/user-uploads/5d617515c8cd8348d0b4e68f/room-content/ad61ff4aa1d4f649c02348dfa32eb613.png)

There are different types of data containers in the PE structure, each holding different data.

1. **.text** stores the actual code of the program
2. **.data** holds the initialized and defined variables
3. **.bss** holds the uninitialized data (declared variables with no assigned values)
4. **.rdata** contains the read-only data
5. **.edata**: contains exportable objects and related table information
6. **.idata** imported objects and related table information
7. **.reloc** image relocation information
8. **.rsrc** links external resources used by the program such as images, icons, embedded binaries, and manifest file, which has all information about program versions, authors, company, and copyright!

The PE structure is a vast and complicated topic, and we are not going to go into too much detail regarding the headers and data sections. This task provides a high-level overview of the PE structure. If you are interested in gaining more information on the topic, we suggest checking the following THM rooms where the topic is explained in greater detail:

- [Windows Internals](https://tryhackme.com/room/windowsinternals): [https://tryhackme.com/room/windowsinternals](https://tryhackme.com/room/windowsinternals)
- Dissecting PE Headers

You can also get more in-depth details about PE if you check the [Windows PE format](https://docs.microsoft.com/en-us/windows/win32/debug/pe-format)'s Docs website. [https://docs.microsoft.com/en-us/windows/win32/debug/pe-format](https://docs.microsoft.com/en-us/windows/win32/debug/pe-format)

When looking at the PE contents, we'll see it contains a bunch of bytes that aren't human-readable. However, it includes all the details the loader needs to run the file. The following are the example steps in which the Windows loader reads an executable binary and runs it as a process.

1. Header sections: DOS, Windows, and optional headers are parsed to provide information about the EXE file. For example,
    - The magic number starts with "MZ," which tells the loader that this is an EXE file.
    - File Signatures
    - Whether the file is compiled for x86 or x64 CPU architecture.
    - Creation timestamp.
2. Parsing the section table details, such as
    - Number of Sections the file contains.
3. Mapping the file contents into memory based on
    - The EntryPoint address and the offset of the ImageBase.
    - RVA: Relative Virtual Address, Addresses related to Imagebase.
4. Imports, DLLs, and other objects are loaded into the memory.
5. The EntryPoint address is located and the main execution function runs.

# Why do we need to know about PE?

There are a couple of reasons why we need to learn about it. First, since we are dealing with packing and unpacking topics, the technique requires details about the PE structure.

The other reason is that AV software and malware analysts analyze EXE files based on the information in the PE Header and other PE sections. Thus, to create or modify malware with AV evasion capability targeting a Windows machine, we need to understand the structure of Windows Portable Executable files and where the malicious shellcode can be stored.

We can control in which Data section to store our shellcode by how we define and initialize the shellcode variable. The following are some examples that show how we can store the shellcode in PE:

1. Defining the shellcode as a local variable within the main function will store it in the **.TEXT** PE section.
2. Defining the shellcode as a global variable will store it in the **.Data** section.
3. Another technique involves storing the shellcode as a raw binary in an icon image and linking it within the code, so in this case, it shows up in the **.rsrc** Data section.
4. We can add a custom data section to store the shellcode.

# PE-Bear

The attached VM is a Windows development machine that has the tools needed to parse EXE files and read the details we discussed. For your convenience, we have provided a copy of the PE-Bear software on the Desktop, which helps to check the PE structure: Headers, Sections, etc. PE-Bear provides a graphic user interface to show all relevant EXE details. To load an EXE file for analysis, select **File** -> **Load PEs** (Ctrl + O).

![https://tryhackme-images.s3.amazonaws.com/user-uploads/5d617515c8cd8348d0b4e68f/room-content/c51856efd63b36680857498bac814469.png](https://tryhackme-images.s3.amazonaws.com/user-uploads/5d617515c8cd8348d0b4e68f/room-content/c51856efd63b36680857498bac814469.png)

Once a file is loaded, we can see all PE details. The following screenshot shows PE details of the loaded file, including the headers and sections we discussed earlier in this task.

![https://tryhackme-images.s3.amazonaws.com/user-uploads/5d617515c8cd8348d0b4e68f/room-content/78dca06d1d1e4249f25734af8082b8be.png](https://tryhackme-images.s3.amazonaws.com/user-uploads/5d617515c8cd8348d0b4e68f/room-content/78dca06d1d1e4249f25734af8082b8be.png)

Now it is time to try it out! Load the **thm-intro2PE.exe** file to answer the questions below. The file is located in the following location: **`c:\Tools\PE files\thm-intro2PE.exe`**.

Answer the questions below

What is the last 6 digits of the MD5 hash value of the **thm-intro2PE.exe** file?

530949

hint: Check the General tab and look for the MD5 value

What is the Magic number value of the thm-intro2PE.exe file (in Hex)?
5a4d

What is the Entry Point value of the thm-intro2PE.exe file?
12e4
Hint: Check the Optional Header tab and look for the Entry Point value.

How many Sections does the thm-intro2PE.exe file have?
7
Hint: Check the File Header section (Section Count) or count them manually.

A custom section could be used to store extra data. Malware developers use this technique to create a new section that contains their malicious code and hijack the flow of the program to jump and execute the content of the new section. What is the name of the extra section?
.flag

Check the content of the extra section. What is the flag?
THM{PE-N3w-s3ction!}

Hint: Select the Raw Address or Virtual Address value.
go to Section Hdrs, .flag, click on virtual address, look at ascii filed on top right.
