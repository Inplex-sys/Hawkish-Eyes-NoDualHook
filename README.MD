

<h1 align="center">
  Hawkish-Eyes without Dual Hook
</h1>

# Proofs that Sordeal Stealer is a Dual Hook :
An investigation has uncovered that the `main.py` file in the Sordeal repository injects malicious nodejs code into the Discord `%APPDATA%/Discord/app-(versions)/modules/discord_desktop_core/index.js` module. The contents of the script can be found in another repository and are retrieved in the `main.py` file 
(see [link](https://github.com/Hawkish-Eyes/Hawkish-Eyes/blob/main/main.py#L102)).

The `index.js` file, which is executed by the main thread of Electron (Discord), is responsible for stealing the Discord session token and collecting various information about the victim. The attacker receives this information, but a copy is also sent to `https://panel.sordeal.com:3000/` using a `POST` method (see [link](https://github.com/Hawkish-Eyes/Hawkish-Inject/blob/main/index.js#L24)).

A review of the code [link](https://github.com/Hawkish-Eyes/Hawkish-Inject/blob/main/index.js#L262) reveals that we send the same HTTP request 2 times,
one time for `config.webhook` and one time for `config.Placed` who is the dualhook url.

# Hawkish-Eyes
Just a simple Ethical Hacking Tool | Contain: Tokens Grabber Discord, Browsers Passwords &amp; Cookies Stealer, Discord Injection JS, Chrome Injection JS, Roblox Session Stealer, Window Info Stealer, Data Files Sniper, Wallet Stealer, Minecraft Account Stealer, Bypass Firewall &amp; Antivirus.
