# FatalRAT Unpacking with Unicorn Engine

[`@LittleRedBean2`](https://twitter.com/LittleRedBean2) posted about a malware they were sent on Telegram.

It's an executable that has an embedded ZIP encrypted archive, it will extract it and load that DLL into memory and execute an exported function and pass it's encrypted configuration to it.

The malware is actually a fully featured RAT and not just a stealer.

This `karton-unpacker` module will unpack the second stage DLL.

**References:**
- https://twitter.com/LittleRedBean2/status/1391012054228742148
