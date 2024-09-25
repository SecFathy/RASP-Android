package com.example.security

import android.content.Context
import android.content.pm.PackageManager
import android.os.Debug
import android.os.Handler
import android.os.Looper
import android.provider.Settings
import android.widget.Toast
import android.util.Base64
import java.io.File
import java.io.InputStreamReader
import java.net.InetSocketAddress
import java.net.Socket

class SecurityCheck(private val context: Context) {

    // Base64-encoded Frida-related strings
    private val suspiciousFridaStrings = listOf(
        "ZnJpZGE=", // "frida"
        "Z2FkZ2V0", // "gadget"
        "c3Bhd24=", // "spawn"
        "cmVwbA==", // "repl"
        "SW50ZXJjZXB0aW9u", // "Interception"
        "ZnJpZGEtYWdlbnQ=", // "frida-agent"
        "ZnJpZGEtc2VydmVy"  // "frida-server"
    ).map { decodeBase64(it) }

    // Frida-related packages (Base64 encoded)
    private val fridaPackages = listOf(
        "Y29tLmZyaWRhLnNlcnZlcg==", // "com.frida.server"
        "Y29tLmZyaWRhLmdhZGdldA==", // "com.frida.gadget"
        "Y29tLmZyaWRhLmFnZW50" // "com.frida.agent"
    ).map { decodeBase64(it) }

    private val fridaPorts = listOf(27042, 27043)

    private val fridaBinaries = listOf(
        "/data/local/tmp/frida-server",
        "/data/local/tmp/gadget.so",
        "/data/local/tmp/libfrida-gadget.so",
        "/system/xbin/frida-server",
        "/system/bin/frida-server"
    )

    // BusyBox and other common root binaries
    private val busyboxBinaries = listOf(
        "/system/xbin/busybox",
        "/system/bin/busybox",
        "/sbin/busybox",
        "/system/bin/.ext/.su",
        "/system/usr/we-need-root/su-backup",
        "/system/xbin/daemonsu",
        "/system/app/Superuser.apk"
    )

    // Starts periodic security checks
    fun monitorSecurityThreats() {
        Handler(Looper.getMainLooper()).apply {
            post(object : Runnable {
                override fun run() {
                    if (isSecurityThreatDetected()) {
                        handleSecurityThreat()
                    } else {
                        postDelayed(this, 5000)
                    }
                }
            })
        }
    }

    // Consolidated method to check for security threats
    private fun isSecurityThreatDetected(): Boolean {
        return isPackageTampered() || isRunningInEmulator() ||
                isAdbEnabled() || isAdbOverWifiEnabled() || detectFrida() ||
                isFridaPackageInstalled() || isDeviceRooted() || isDebuggerAttached() || detectBusyBox()
    }

    // Detect Frida-related activities (memory, binaries, ports, processes)
    private fun detectFrida(): Boolean {
        return detectFridaInMemory() || detectFridaBinaries() || isFridaPortOpen() || isFridaProcessRunning()
    }

    // Check if ADB is enabled
    private fun isAdbEnabled(): Boolean = getSecureSetting(Settings.Secure.ADB_ENABLED) == 1

    // Check if ADB over WiFi is enabled by detecting if port 5555 is open
    private fun isAdbOverWifiEnabled(): Boolean = isPortOpen(5555)

    // Check if a specific port is open
    private fun isPortOpen(port: Int): Boolean {
        return try {
            Socket().use { socket ->
                socket.connect(InetSocketAddress("localhost", port), 1000)
                true
            }
        } catch (e: Exception) {
            false
        }
    }

    // Detect Frida-related strings in process memory
    private fun detectFridaInMemory(): Boolean {
        return try {
            val process = Runtime.getRuntime().exec("cat /proc/self/maps")
            InputStreamReader(process.inputStream).buffered().useLines { lines ->
                lines.any { line -> suspiciousFridaStrings.any { fridaString -> line.contains(fridaString) } }
            }
        } catch (e: Exception) {
            false
        }
    }

    // Check for the presence of Frida binaries in the filesystem
    private fun detectFridaBinaries(): Boolean = fridaBinaries.any { File(it).exists() }

    // Check if Frida's communication ports are open
    private fun isFridaPortOpen(): Boolean = fridaPorts.any { isPortOpen(it) }

    // Check if a Frida process is running
    private fun isFridaProcessRunning(): Boolean {
        return try {
            val process = Runtime.getRuntime().exec("ps -A")
            InputStreamReader(process.inputStream).buffered().useLines { lines ->
                lines.any { line -> line.contains("frida") }
            }
        } catch (e: Exception) {
            false
        }
    }

    // Check if Frida-related packages are installed on the device
    private fun isFridaPackageInstalled(): Boolean {
        val pm: PackageManager = context.packageManager
        return fridaPackages.any { packageName ->
            try {
                pm.getPackageInfo(packageName, 0)
                true // Package found
            } catch (e: PackageManager.NameNotFoundException) {
                false
            }
        }
    }

    // Check if the device is rooted by checking for common root binaries
    private fun isDeviceRooted(): Boolean {
        val rootPaths = listOf(
            "/system/app/Superuser.apk",
            "/system/xbin/su",
            "/system/bin/su",
            "/system/xbin/daemonsu",
            "/system/etc/init.d/99SuperSUDaemon"
        )
        return rootPaths.any { File(it).exists() }
    }

    // Check for BusyBox binaries commonly associated with rooted devices
    private fun detectBusyBox(): Boolean = busyboxBinaries.any { File(it).exists() }

    // Check if a debugger is attached to the app
    private fun isDebuggerAttached(): Boolean = Debug.isDebuggerConnected()

    // Check if the app is running on an emulator
    private fun isRunningInEmulator(): Boolean {
        val model = android.os.Build.MODEL.lowercase()
        return android.os.Build.FINGERPRINT.startsWith("generic") ||
               model.contains("emulator") || model.contains("google_sdk")
    }

    // Check if the APK has been tampered with by comparing its signature
    private fun isPackageTampered(): Boolean {
        val packageInfo = context.packageManager.getPackageInfo(context.packageName, PackageManager.GET_SIGNATURES)
        val currentSignature = packageInfo.signatures.firstOrNull()?.toByteArray()
        val knownSignature = byteArrayOf(/* Your known APK signature byte array here */)
        return currentSignature?.let { !it.contentEquals(knownSignature) } ?: true
    }

    // Retrieve a secure setting value
    private fun getSecureSetting(settingName: String): Int {
        return try {
            Settings.Secure.getInt(context.contentResolver, settingName, 0)
        } catch (e: Settings.SettingNotFoundException) {
            0
        }
    }

    // Base64 decoding for obfuscated strings
    private fun decodeBase64(encodedString: String): String = String(Base64.decode(encodedString, Base64.DEFAULT))

    // Handle detected security threats
    private fun handleSecurityThreat() {
        showToastAndTerminateApp()
        selfDestructAppData() // Optional: Self-destruct if tampering detected
    }

    // Show an alert to the user and terminate the app
    private fun showToastAndTerminateApp() {
        Toast.makeText(context, "Security threat detected! The app will be terminated.", Toast.LENGTH_LONG).show()
        Handler(Looper.getMainLooper()).postDelayed({
            android.os.Process.killProcess(android.os.Process.myPid())
        }, 3000) // 3-second delay to show toast before terminating
    }

    // Self-destruct the app's data (optional, can be risky)
    private fun selfDestructAppData() {
        val appDir = File(context.filesDir.absolutePath)
        appDir.deleteRecursively()
    }
}
