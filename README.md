# Info
This is a macOS cli tool that uses KextRW (https://github.com/alfiecg24/KextRW) to disable sandboxes of specific processes.
Tested on `macbook pro m3 pro` `macOS 26.2`

# Requirements
Disabling SIP.
Installing KextRW (https://github.com/alfiecg24/KextRW) kext.

# Usage
`suspender <pid>`

# Library dependencies
Statically linked against libkextrw and libSimplePatchFinder (https://github.com/doraorak/simplePatchFinder).
Dynamically linked against cpp standard library.

# How it works
Its calling `_sandbox_suspend symbol` from the kernel.

# Limitations
Unfortunately when the sandbox of an app is disabled and you close the app, next time you open it, it will not launch and instead get stuck on the bouncing animation. This issue is fixed after rebooting. Alternatively launching the app from the terminal is a workaround.
