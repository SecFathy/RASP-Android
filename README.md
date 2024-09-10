# Android Security Check

![Kotlin](https://img.shields.io/badge/Kotlin-1.8.10-blue.svg)
![Android](https://img.shields.io/badge/Android-API%209%2B-green.svg)

## Overview

**Android Security Check** is a robust Kotlin library designed to enhance the security of Android applications by detecting and mitigating common threats such as Frida injection and ADB (Android Debug Bridge) debugging. By integrating this library into your Android project, you can proactively monitor and protect your app against reverse engineering, debugging, and tampering attempts.

## Features

- **ADB Debugging Detection**
  - Checks if ADB debugging is enabled (USB or WiFi).
  - Detects if ADB is listening on default ports (e.g., 5555 for WiFi).

- **Frida Injection Detection**
  - Scans process memory for Frida-related signatures.
  - Detects open ports commonly used by Frida (`27042`, `27043`).
  - Identifies the presence of Frida binaries in common directories.
  - Checks for Frida-related packages installed on the device.
  - Detects injected Frida libraries within the app’s memory.

- **Comprehensive Monitoring**
  - Periodically checks for security threats every 5 seconds.
  - Terminates the application if any suspicious activity is detected.

