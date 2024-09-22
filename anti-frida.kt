package com.example.security

import android.content.Context
import android.content.pm.PackageManager
import android.os.Debug
import android.os.Handler
import android.os.Looper
import android.provider.Settings
import android.widget.Toast
import java.io.BufferedReader
import java.io.File
import java.io.InputStreamReader
import java.net.InetSocketAddress
import java.net.Socket

class SecurityCheck(private val context: Context) {

    // List of suspicious strings commonly associated with Frida
    private val suspiciousFridaStrings = listOf(
        "frida", "gadget", "spawn", "repl", "Interception", "frida-agent", "frida-server"
    )

    // Ports used by Frida for communication
    private val fridaPorts = listOf(27042, 27043)

    // List of Frida-related packages that should not be installed
    private val fridaPackageNames = listOf(
        "com.frida.server",
        "com.frida.gadget",
        "com.frida.agent"
    )

    // List of possible Frida binaries
    private val suspiciousFridaFiles = listOf(
        "/data/local/tmp/frida-server",
        "/data/local/tmp/gadget.so",
        "/data/local/tmp/libfrida-gadget.so",
        "/system/xbin/frida-server",
        "/system/bin/frida-server"
    )

    /**
     * Starts periodic checks for Frida, root, and debugger presence.
     * Terminates the app if any suspicious activity is detected.
     */
    fun monitorSecurityThreats() {
        val handler = Handler(Looper.getMainLooper())
        handler.post(object : Runnable {
            override fun run() {
                if (isAdbEnabled() || isAdbOverWifiEnabled() || detectFrida() || isFridaPackageInstalled() || isDeviceRooted() || isDebuggerAttached()) {
                    alertAndTerminateApp()
                } else {
                    handler.postDelayed(this, 5000)
                }
            }
        })
    }

    /**
     * Check if ADB debugging is enabled on the device.
     */
    private fun isAdbEnabled(): Boolean {
        return getSecureSettingValue(Settings.Secure.ADB_ENABLED) == 1
    }

    /**
     * Check if ADB over WiFi is enabled by detecting if ADB is listening on port 5555.
     */
    private fun isAdbOverWifiEnabled(): Boolean {
        return isPortOpen(5555)
    }

    /**
     * Perform all Frida detection checks: memory scanning, port scanning, file presence, ptrace hooking,
     * and package injection detection.
     */
    private fun detectFrida(): Boolean {
        return detectFridaInMemory() || detectFridaBinaries() || isFridaPortOpen() || isFridaProcessRunning() || isFridaInjectedInLibraries()
    }

    /**
     * Detect Frida-related strings in process memory (scanning `/proc/self/maps`).
     */
    private fun detectFridaInMemory(): Boolean {
        return try {
            val process = Runtime.getRuntime().exec("cat /proc/self/maps")
            process.inputStream.bufferedReader().useLines { lines ->
                lines.any { line -> suspiciousFridaStrings.any { fridaString -> line.contains(fridaString) } }
            }
        } catch (e: Exception) {
            false
        }
    }

    /**
     * Check for the presence of known Frida binaries in common directories.
     */
    private fun detectFridaBinaries(): Boolean {
        return suspiciousFridaFiles.any { File(it).exists() }
    }

    /**
     * Check if Frida's default communication ports (27042, 27043) are open.
     */
    private fun isFridaPortOpen(): Boolean {
        return fridaPorts.any { isPortOpen(it) }
    }

    /**
     * Check if a process named Frida is running (ptrace hooking detection).
     */
    private fun isFridaProcessRunning(): Boolean {
        return try {
            val process = Runtime.getRuntime().exec("ps -A")
            process.inputStream.bufferedReader().useLines { lines ->
                lines.any { line -> line.contains("frida") }
            }
        } catch (e: Exception) {
            false
        }
    }

    /**
     * Check if a specific port is open on localhost.
     */
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

    /**
     * Detect if Frida-related libraries are injected by checking loaded libraries.
     */
    private fun isFridaInjectedInLibraries(): Boolean {
        return try {
            val process = Runtime.getRuntime().exec("cat /proc/self/maps")
            process.inputStream.bufferedReader().useLines { lines ->
                lines.any { line ->
                    suspiciousFridaStrings.any { fridaString ->
                        line.contains(fridaString)
                    }
                }
            }
        } catch (e: Exception) {
            false
        }
    }

    /**
     * Check if Frida-related packages are installed on the device.
     */
    private fun isFridaPackageInstalled(): Boolean {
        val pm: PackageManager = context.packageManager
        return fridaPackageNames.any { packageName ->
            try {
                pm.getPackageInfo(packageName, 0)
                true // Frida package is installed
            } catch (e: PackageManager.NameNotFoundException) {
                false
            }
        }
    }

    /**
     * Check if the device is rooted by checking for the existence of root binaries.
     */
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

    /**
     * Check if a debugger is attached to the app.
     */
    private fun isDebuggerAttached(): Boolean {
        return Debug.isDebuggerConnected()
    }

    /**
     * Retrieve a secure setting's value from the system.
     */
    private fun getSecureSettingValue(settingName: String): Int {
        return try {
            Settings.Secure.getInt(context.contentResolver, settingName, 0)
        } catch (e: Settings.SettingNotFoundException) {
            0
        }
    }

    /**
     * Show an alert and terminate the application when a threat is detected.
     */
    private fun alertAndTerminateApp() {
        Toast.makeText(context, "Security threat detected! The app will be terminated.", Toast.LENGTH_LONG).show()
        Handler(Looper.getMainLooper()).postDelayed({
            android.os.Process.killProcess(android.os.Process.myPid())
        }, 3000) // Delay for 3 seconds to show the toast before killing the app
    }
}
