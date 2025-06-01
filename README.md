# tclctl
Access SMS services on the TCL Linkport IK511 5G dongle from the command line.

This may work on other devices, such as the EE HH70VB, which [has been documented](https://jamesmacwhite.medium.com/hidden-firmware-features-on-the-4gee-home-router-17cb5d7060ba) by [@jamesmacwhite](https://github.com/jamesmacwhite) to use the same `_TclRequestVerificationKey` header. However, assuming that this is in fact the exact same software, it has since been updated to obfuscate all API calls via encryption with trivially sniffable keys. This presented a slight reverse engineering challenge but has no actual security benefit whatsoever.

## Why
I got tired of logging in every time the "unread SMS" light started blinking. Also, the web interface is annoying and logs you out after a few seconds idle.

## Usage
```
$ TCL_PASSWORD=YOUR_PASSWORD ./sms.py
```
This was written with Python 3.11.2. There are no requirements other than an openssl binary in $PATH.
