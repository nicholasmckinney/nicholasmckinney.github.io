---
layout: post
title: "HackTheBox - Nest Writeup"
published: false
---

![Nest Infopage](../images/Nest/31_nest_page.png)
Nest is an "Easy" (hard for me!) machine on HackTheBox.


To begin, I started with a common port scan, discovering any common (< port 1000) ports that were open. I discovered that SMB was running on TCP 445. I tried to run some Metasploit scanners for SMB to check for any known vulnerabilities like some of the semi-recent NSA exploits that were leaked. The machine was patched against those vulnerabilities so there was no easy initial access via an out of the box exploit.

![port scan](../images/Nest/0_port_scan.png)

Knowing that SMB is a file-sharing protocol, I attempted to enumerate further using Metasploit's modules, discovering some shares on the machine.

![smb enum](../images/Nest/1_smb_enumshare.png)

Without any credentials, I used `smbclient` and attempted to see what I could read as an unauthenticated user. As an unauthenticated user, I couldn't read any files from the `Users` share, but I did gain some information on usernames. Access to the `ADMIN$` and `C$` shares was denied. Nothing could be enumerated as an anonymous user on the `Secure$` or `Users` drives.

![access denied](../images/Nest/2_AccessDenied_users_share.png)

However, on the `Data` share I found a file containing the credentials of `TempUser`.

![file discovery](../images/Nest/3_smb_file.png)
![welcome email](../images/Nest/4_WelcomeEmail.png)

Using those credentials, I was able to authenticate and enumerate the `IT` directory on the `Data` share. There, I found configuration files related to IT. 

![auth data](../images/Nest/5_authenticated_datashare_as_tempuser.png)
![npp files](../images/Nest/6_notepadplusplus_listfiles.png)
![disclosure](../images/Nest/7_notepadplusplus_filedisclosure.png)


The NotepadPlusPlus `config.xml` file provided me a file history of recently edited files. Seeing the entry for the `Carl` directory on the `Secure$` share under `IT` allowed me to change to that directory as the `TempUser` despite the fact that I was not permitted to run `ls` from `Secure$\\IT`.

![hidden dir](../images/Nest/8_ls_hidden_carldir.png)

In Carl's directory, I was able to find a work-in-progress (WIP) project named `RU Scanner`. I read through the code and found a reference to `RU_Config.xml`. Back on the `Data` share where I found IT configs, there was a directory named `RU Scanner`. I pulled the `RU_config.xml` file from there.

![config](../images/Nest/9_config_ref.png)
![config](../images/Nest/10_RU_config.png)

In that file I found credentials related to C.Smith, one of the usernames enumerated earlier.

![csmith creds](../images/Nest/11_c_smith_creds.png)

It looked like it might have been simple Base64 encoding, but it was not. I referred back to the code Carl had written and found a string decryption routine. It was using AES-256-CBC encryption with a RFC2898 key (aka PBKDF2). All the parameters for the algorithms (salt, password, password iteration, IV) were hard-coded, so I pulled them out and emulated the decryption routine using [CyberChef](https://gchq.github.io/CyberChef).

![decryption code](../images/Nest/12_decryption_code.png)
![key extraction](../images/Nest/13_key_extraction.png)
![aes decryption](../images/Nest/14_aes_decryption_csmith_pass.png)

With C.Smith's password, I used his credentials and logged back into the `Users` share and found the `user.txt` hash under the `C.Smith` directory!

![user.txt](../images/Nest/user_own.png)

In C.Smith's directory, I also found files relating to a service named `HQK Reporting`. I ran `strings` on the executable and found it to be a .NET binary. I also found a reference to port `4386` which wasn't initially discovered by my nmap scan (since I only scanned for common ports).

![csmith files](../images/Nest/15_get_csmith_files.png)
![hqk strings](../images/Nest/16_strings_hqk_ldap.png)
![4386](../images/Nest/17_service_open_port_4386.png)

I also found a file named `Debug Mode Password.txt`. Although the file initially looked empty, I was able to get a password from an NTFS alternate data stream.

![debug pwd](../images/Nest/18_debug_mode_password_alternate_data_stream.png)
![get stream](../images/Nest/19_get_stream.png)
![debug pwd](../images/Nest/20_debug_pwd.png)

I connected to the service on 4386 using `telnet`, and then interacted with it, elevating privileges using debug mode and then discovering that I could read files using the `showquery` command (so long as the file wasn't too big), change directory using `setdir`, and see my place on the filesystem using `session`.

![hqk reporting](../images/Nest/21_hqk_reporting_service_4386.png)
![iteracting](../images/Nest/22_interacting_service.png)
![debug session](../images/Nest/24_service_session_commands.png)

With that information, I was able to find and read a file containing what looks like LDAP credentials.

![admin pwd](../images/Nest/25_got_admin_pwd.png)

Knowing that the HQK binary discovered earlier was a .NET executable, I decompiled it using ILSpy and found that it used a similar routine as that found in the Visual Basic code earlier. There were different parameters with minor changes to the code such as first base64-decoding the input.

![.net decryption code](../images/Nest/30_got_decryption_params.png)

I once again used CyberChef to help derive the key and decrypt with AES.

![aes key hex](../images/Nest/26_aes_key_hex.png)
![b64 decode](../images/Nest/28_admin_pw_from_b64.png)
![decrypt](..images/Nest/27_admin_pwd.png)

With the Administrator password, I was then able to access the `ADMIN$` share and get the `root.txt` flag.

![root.txt](../images/Nest/29_root.png)
