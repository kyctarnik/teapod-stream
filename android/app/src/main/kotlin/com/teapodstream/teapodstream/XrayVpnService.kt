package com.teapodstream.teapodstream

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.net.TrafficStats
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.system.OsConstants
import androidx.core.app.NotificationCompat
import java.io.File

class XrayVpnService : VpnService() {

    companion object {
        init {
            System.loadLibrary("vpnhelper")
        }

        @JvmStatic external fun nativeStartProcessWithFd(cmd: String, args: Array<String>, envKeys: Array<String>, envVals: Array<String>, keepFd: Int, maxFds: Int): Long
        @JvmStatic external fun nativeKillProcess(pid: Long): Int
        @JvmStatic external fun nativeIsProcessAlive(pid: Long): Int
        @JvmStatic external fun nativeSetMaxFds(maxFds: Int): Int

        const val ACTION_CONNECT = "com.teapodstream.CONNECT"
        const val ACTION_DISCONNECT = "com.teapodstream.DISCONNECT"
        const val EXTRA_XRAY_CONFIG = "xray_config"
        const val EXTRA_SOCKS_PORT = "socks_port"
        const val EXTRA_SOCKS_USER = "socks_user"
        const val EXTRA_SOCKS_PASSWORD = "socks_password"
        const val EXTRA_EXCLUDED_PACKAGES = "excluded_packages"
        const val EXTRA_INCLUDED_PACKAGES = "included_packages"
        const val EXTRA_VPN_MODE = "vpn_mode"
        const val EXTRA_TUN_ADDRESS = "tun_address"
        const val EXTRA_TUN_NETMASK = "tun_netmask"
        const val EXTRA_TUN_MTU = "tun_mtu"
        const val EXTRA_TUN_DNS = "tun_dns"
        const val EXTRA_ENABLE_UDP = "enable_udp"
        const val EXTRA_CONFIG_NAME = "config_name"

        // Единственный источник правды о состоянии VPN
        @Volatile private var currentNativeState: String = "disconnected"
        @JvmStatic fun getNativeState(): String = currentNativeState

        private const val NOTIFICATION_CHANNEL_ID = "vpn_service"
        private const val NOTIFICATION_ID = 1
        private const val HEARTBEAT_INTERVAL_MS = 8000L

        @Volatile private var totalUpload: Long = 0
        @Volatile private var totalDownload: Long = 0
        @Volatile private var lastUploadSpeed: Long = 0
        @Volatile private var lastDownloadSpeed: Long = 0
        @Volatile private var baseUpload: Long = 0
        @Volatile private var baseDownload: Long = 0

        fun getStats(): Map<String, Long> = mapOf(
            "upload" to totalUpload,
            "download" to totalDownload,
            "uploadSpeed" to lastUploadSpeed,
            "downloadSpeed" to lastDownloadSpeed,
        )

        // --- Quick Settings tile: сохранение/загрузка параметров подключения ---

        private const val PREFS_NAME = "vpn_tile_prefs"

        fun saveLastConnectionParams(
            context: android.content.Context,
            xrayConfig: String, socksPort: Int, socksUser: String, socksPassword: String,
            excludedPackages: List<String>, includedPackages: List<String>,
            vpnMode: String, tunAddress: String, tunNetmask: String, tunMtu: Int, tunDns: String,
            configName: String = "",
        ) {
            context.getSharedPreferences(PREFS_NAME, android.content.Context.MODE_PRIVATE).edit()
                .putString("xrayConfig", xrayConfig)
                .putInt("socksPort", socksPort)
                .putString("socksUser", socksUser)
                .putString("socksPassword", socksPassword)
                .putStringSet("excludedPackages", excludedPackages.toSet())
                .putStringSet("includedPackages", includedPackages.toSet())
                .putString("vpnMode", vpnMode)
                .putString("tunAddress", tunAddress)
                .putString("tunNetmask", tunNetmask)
                .putInt("tunMtu", tunMtu)
                .putString("tunDns", tunDns)
                .putString("configName", configName)
                .putBoolean("hasConfig", true)
                .apply()
        }

        fun hasLastConnectionParams(context: android.content.Context): Boolean {
            return context.getSharedPreferences(PREFS_NAME, android.content.Context.MODE_PRIVATE)
                .getBoolean("hasConfig", false)
        }

        fun createConnectIntentFromSaved(context: android.content.Context): Intent? {
            val prefs = context.getSharedPreferences(PREFS_NAME, android.content.Context.MODE_PRIVATE)
            if (!prefs.getBoolean("hasConfig", false)) return null

            return Intent(context, XrayVpnService::class.java).apply {
                action = ACTION_CONNECT
                putExtra(EXTRA_XRAY_CONFIG, prefs.getString("xrayConfig", "") ?: "")
                putExtra(EXTRA_SOCKS_PORT, prefs.getInt("socksPort", 10808))
                putExtra(EXTRA_SOCKS_USER, prefs.getString("socksUser", "") ?: "")
                putExtra(EXTRA_SOCKS_PASSWORD, prefs.getString("socksPassword", "") ?: "")
                putExtra(EXTRA_EXCLUDED_PACKAGES, ArrayList(prefs.getStringSet("excludedPackages", emptySet()) ?: emptySet()))
                putExtra(EXTRA_INCLUDED_PACKAGES, ArrayList(prefs.getStringSet("includedPackages", emptySet()) ?: emptySet()))
                putExtra(EXTRA_VPN_MODE, prefs.getString("vpnMode", "allExcept") ?: "allExcept")
                putExtra(EXTRA_TUN_ADDRESS, prefs.getString("tunAddress", "10.0.0.1") ?: "10.0.0.1")
                putExtra(EXTRA_TUN_NETMASK, prefs.getString("tunNetmask", "255.255.255.0") ?: "255.255.255.0")
                putExtra(EXTRA_TUN_MTU, prefs.getInt("tunMtu", 1500))
                putExtra(EXTRA_TUN_DNS, prefs.getString("tunDns", "1.1.1.1") ?: "1.1.1.1")
                putExtra(EXTRA_CONFIG_NAME, prefs.getString("configName", "") ?: "")
            }
        }

        fun prepareBinaries(context: android.content.Context): Boolean {
            val filesDir = context.filesDir
            val assets = context.assets
            for (name in listOf("geoip.dat", "geosite.dat")) {
                val file = File(filesDir, name)
                if (file.exists()) continue
                try {
                    val input = try { assets.open("binaries/$name") } catch (_: Exception) { assets.open("flutter_assets/assets/binaries/$name") }
                    input.use { i -> file.outputStream().use { o -> i.copyTo(o) } }
                } catch (_: Exception) { }
            }
            return true
        }

        /**
         * Извлекает PID из java.lang.Process через рефлексию.
         * Android использует UNIXProcess / ProcessImpl с полем "pid".
         */
        private fun getProcessPid(process: Process): Long {
            return try {
                val field = process.javaClass.getDeclaredField("pid")
                field.isAccessible = true
                field.getLong(process)
            } catch (_: Exception) {
                -1L
            }
        }
    }

    // --- Ресурсы, управляемые cleanupAll() ---
    private var tunInterface: ParcelFileDescriptor? = null
    private var xrayProcess: Process? = null
    private var xrayPid: Long = -1L
    private var tun2socksPid: Long = -1L
    private var statsThread: Thread? = null
    private var heartbeatThread: Thread? = null
    @Volatile private var isRunning = false
    private var networkCallback: ConnectivityManager.NetworkCallback? = null
    private var lastNetworkUpdate: Long = 0
    private val networkUpdateDebounceMs = 5000L
    private var currentConfigName: String = ""

    // =====================================================================
    // Управление состоянием — единственная точка обновления
    // =====================================================================

    /**
     * Обновляет состояние VPN и уведомляет Flutter.
     * Все обновления currentNativeState должны проходить ТОЛЬКО через эту функцию.
     */
    private fun updateState(newState: String) {
        val old = currentNativeState
        if (old == newState) return
        currentNativeState = newState
        log("info", "State: $old → $newState")
        VpnEventStreamHandler.sendStateEvent(newState)
    }

    // =====================================================================
    // Lifecycle
    // =====================================================================

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        // Устанавливаем appContext для обновления Quick Settings плитки
        // (нужно, если VPN запущен из тайла без открытия приложения)
        if (VpnEventStreamHandler.appContext == null) {
            VpnEventStreamHandler.appContext = applicationContext
        }
        when (intent?.action) {
            ACTION_DISCONNECT -> {
                cleanupAll()
                stopSelf()
                return START_NOT_STICKY
            }
            ACTION_CONNECT -> {
                val configName = intent.getStringExtra(EXTRA_CONFIG_NAME) ?: ""
                currentConfigName = configName
                startForegroundNotification(configName)
                val xrayConfig = intent.getStringExtra(EXTRA_XRAY_CONFIG) ?: ""
                val socksPort = intent.getIntExtra(EXTRA_SOCKS_PORT, 10808)
                val socksUser = intent.getStringExtra(EXTRA_SOCKS_USER) ?: ""
                val socksPassword = intent.getStringExtra(EXTRA_SOCKS_PASSWORD) ?: ""
                val excludedPackages = intent.getStringArrayListExtra(EXTRA_EXCLUDED_PACKAGES) ?: arrayListOf()
                val includedPackages = intent.getStringArrayListExtra(EXTRA_INCLUDED_PACKAGES) ?: arrayListOf()
                val vpnMode = intent.getStringExtra(EXTRA_VPN_MODE) ?: "allExcept"
                val tunAddress = intent.getStringExtra(EXTRA_TUN_ADDRESS) ?: "10.0.0.1"
                val tunNetmask = intent.getStringExtra(EXTRA_TUN_NETMASK) ?: "255.255.255.0"
                val tunMtu = intent.getIntExtra(EXTRA_TUN_MTU, 1500)
                val tunDns = intent.getStringExtra(EXTRA_TUN_DNS) ?: "1.1.1.1"

                saveLastConnectionParams(this, xrayConfig, socksPort, socksUser, socksPassword,
                    excludedPackages, includedPackages, vpnMode, tunAddress, tunNetmask, tunMtu, tunDns,
                    configName)

                startVpn(xrayConfig, socksPort, socksUser, socksPassword,
                    excludedPackages, includedPackages, vpnMode,
                    tunAddress, tunNetmask, tunMtu, tunDns)
                return START_STICKY
            }
            else -> return START_NOT_STICKY
        }
    }

    override fun onRevoke() {
        log("info", "VPN revoked by system")
        cleanupAll()
        stopSelf()
    }

    override fun onDestroy() {
        log("info", "Service onDestroy")
        cleanupAll()
        super.onDestroy()
    }

    // =====================================================================
    // Единая функция очистки всех ресурсов
    // =====================================================================

    /**
     * Останавливает все процессы, закрывает TUN, отменяет потоки и колбэки,
     * обновляет состояние на "disconnected".
     * Безопасна для повторного вызова (idempotent).
     */
    private fun cleanupAll() {
        if (!isRunning && currentNativeState == "disconnected") return
        isRunning = false

        // 1. Остановить heartbeat и stats потоки
        heartbeatThread?.interrupt()
        heartbeatThread = null
        statsThread?.interrupt()
        statsThread = null

        // 2. Отменить network callback
        unregisterNetworkCallback()

        // 3. Убить tun2socks (native PID)
        if (tun2socksPid > 0) {
            log("info", "Killing tun2socks (pid=$tun2socksPid)")
            nativeKillProcess(tun2socksPid)
            tun2socksPid = -1L
        }

        // 4. Убить xray: сначала Java Process, потом native PID как fallback
        xrayProcess?.let { proc ->
            log("info", "Destroying xray process")
            proc.destroy()
            xrayProcess = null
        }
        if (xrayPid > 0) {
            log("info", "Killing xray (pid=$xrayPid)")
            nativeKillProcess(xrayPid)
            xrayPid = -1L
        }

        // 5. Закрыть TUN-интерфейс
        tunInterface?.let { tun ->
            try { tun.close() } catch (_: Exception) {}
            tunInterface = null
        }

        // 6. Сбросить статистику скорости
        lastUploadSpeed = 0
        lastDownloadSpeed = 0

        // 7. Обновить состояние
        updateState("disconnected")
    }

    // =====================================================================
    // Запуск VPN
    // =====================================================================

    private fun startVpn(
        xrayConfig: String,
        socksPort: Int,
        socksUser: String,
        socksPassword: String,
        excludedPackages: List<String>,
        includedPackages: List<String>,
        vpnMode: String,
        tunAddress: String,
        tunNetmask: String,
        tunMtu: Int,
        tunDns: String,
    ) {
        if (isRunning) {
            log("warning", "startVpn called while already running, ignoring")
            return
        }
        isRunning = true
        updateState("connecting")
        log("info", "Starting VPN")

        try {
            val configFile = File(filesDir, "xray_config.json")
            configFile.writeText(xrayConfig)
            prepareBinaries(this)

            // --- Построение TUN-интерфейса ---
            val builder = Builder()
                .setSession("TeapodStream")
                .setMtu(tunMtu)
                .addAddress(tunAddress, subnetMaskToPrefix(tunNetmask))
                .addRoute("0.0.0.0", 0)
                .addDnsServer(tunDns)
                .allowFamily(OsConstants.AF_INET)
                .setBlocking(false)

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                val cm = getSystemService(CONNECTIVITY_SERVICE) as ConnectivityManager
                cm.activeNetwork?.let { network ->
                    builder.setUnderlyingNetworks(arrayOf(network))
                    log("info", "Underlying network set: $network")
                }
            }

            // --- Split tunneling ---
            applySplitTunneling(builder, vpnMode, excludedPackages, includedPackages)

            // Поднять лимит fd
            val fdResult = nativeSetMaxFds(65536)
            log("info", "nativeSetMaxFds result (parent): $fdResult")

            tunInterface = builder.establish()
                ?: throw IllegalStateException("Failed to establish TUN")

            val tunDupPfd = ParcelFileDescriptor.dup(tunInterface!!.fileDescriptor)
            val tunFd = tunDupPfd.fd
            log("info", "TUN established, dup fd=$tunFd")

            // --- 1. Запуск Xray ---
            val xrayBin = File(applicationInfo.nativeLibraryDir, "libxray.so")
            val xrayPb = ProcessBuilder(xrayBin.absolutePath, "run", "-c", configFile.absolutePath)
            xrayPb.environment()["XRAY_LOCATION_ASSET"] = filesDir.absolutePath
            xrayPb.redirectErrorStream(true)
            xrayProcess = xrayPb.start()

            // Извлекаем PID для надёжного мониторинга и kill
            xrayPid = getProcessPid(xrayProcess!!)
            log("info", "xray process started (pid=$xrayPid)")

            // Поток чтения логов xray
            Thread {
                try {
                    xrayProcess?.inputStream?.bufferedReader()?.forEachLine { line ->
                        log("debug", "[xray] $line")
                    }
                } catch (_: Exception) {}
            }.also { it.isDaemon = true; it.name = "xray-log"; it.start() }

            Thread.sleep(800)

            if (!isProcessAlive(xrayProcess)) {
                throw IllegalStateException("xray process died on startup")
            }

            // --- 2. Запуск tun2socks (native fork) ---
            val tun2socksBin = File(applicationInfo.nativeLibraryDir, "libtun2socks.so")
            val proxyUrl = if (socksUser.isNotEmpty()) {
                "socks5://$socksUser:$socksPassword@127.0.0.1:$socksPort"
            } else {
                "socks5://127.0.0.1:$socksPort"
            }
            val t2sArgs = arrayOf(
                tun2socksBin.absolutePath,
                "-device", "fd://$tunFd",
                "-proxy", proxyUrl,
                "-mtu", tunMtu.toString(),
                "-loglevel", "error",
                "-tcp-sndbuf", "524288",
                "-tcp-rcvbuf", "524288",
                "-tcp-auto-tuning",
            )
            log("info", "Starting tun2socks (native): ${t2sArgs.joinToString(" ")}")
            tun2socksPid = nativeStartProcessWithFd(
                tun2socksBin.absolutePath, t2sArgs,
                emptyArray(), emptyArray(), tunFd, 65536
            )
            if (tun2socksPid < 0) {
                throw IllegalStateException("nativeStartProcessWithFd failed: errno=${-tun2socksPid}")
            }

            // Закрываем нашу копию fd — tun2socks уже имеет свою
            tunDupPfd.close()
            Thread.sleep(300)
            log("info", "tun2socks started (pid=$tun2socksPid)")

            // --- Старт мониторинга ---
            startStatsMonitoring()
            startHeartbeat()
            registerNetworkCallback()

            updateState("connected")
            log("info", "VPN connected successfully")
        } catch (e: Exception) {
            log("error", "Start failed: ${e.message}")
            updateState("error")
            cleanupAll()
        }
    }

    // =====================================================================
    // Split tunneling
    // =====================================================================

    private fun applySplitTunneling(
        builder: Builder,
        vpnMode: String,
        excludedPackages: List<String>,
        includedPackages: List<String>,
    ) {
        if (vpnMode == "onlySelected") {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                for (pkg in includedPackages) {
                    try {
                        builder.addAllowedApplication(pkg)
                        log("info", "Allowed: $pkg")
                    } catch (e: Exception) {
                        log("warning", "Failed to allow $pkg: ${e.message}")
                    }
                }
            } else {
                log("warning", "onlySelected mode requires Android 10+, falling back to allExcept")
                applyExcludedPackages(builder, excludedPackages)
            }
        } else {
            applyExcludedPackages(builder, excludedPackages)
        }
    }

    private fun applyExcludedPackages(builder: Builder, excludedPackages: List<String>) {
        for (pkg in excludedPackages) {
            try { builder.addDisallowedApplication(pkg) } catch (_: Exception) {}
        }
        try { builder.addDisallowedApplication(packageName) } catch (_: Exception) {}
    }

    // =====================================================================
    // Мониторинг процессов (heartbeat)
    // =====================================================================

    /** Проверяет живость Java Process через exitValue(). */
    private fun isProcessAlive(p: Process?): Boolean {
        p ?: return false
        return try { p.exitValue(); false } catch (_: IllegalThreadStateException) { true }
    }

    /** Проверяет живость native-процесса по PID (kill(pid, 0)). */
    private fun isNativePidAlive(pid: Long): Boolean {
        if (pid <= 0) return false
        return nativeIsProcessAlive(pid) == 1
    }

    /**
     * Heartbeat-поток: каждые HEARTBEAT_INTERVAL_MS проверяет,
     * живы ли xray и tun2socks. При смерти любого — cleanupAll().
     */
    private fun startHeartbeat() {
        heartbeatThread?.interrupt()
        heartbeatThread = Thread {
            while (isRunning) {
                try {
                    Thread.sleep(HEARTBEAT_INTERVAL_MS)
                    if (!isRunning) break

                    val xrayAlive = isProcessAlive(xrayProcess)
                    val t2sAlive = isNativePidAlive(tun2socksPid)

                    if (!xrayAlive || !t2sAlive) {
                        log("error", "Heartbeat: процесс умер (xray=$xrayAlive, tun2socks=$t2sAlive)")
                        cleanupAll()
                        stopSelf()
                        break
                    }
                } catch (_: InterruptedException) {
                    break
                } catch (e: Exception) {
                    log("warning", "Heartbeat error: ${e.message}")
                }
            }
        }.also { it.isDaemon = true; it.name = "vpn-heartbeat"; it.start() }
    }

    // =====================================================================
    // Статистика трафика
    // =====================================================================

    private fun startStatsMonitoring() {
        baseUpload = TrafficStats.getUidTxBytes(applicationInfo.uid).coerceAtLeast(0)
        baseDownload = TrafficStats.getUidRxBytes(applicationInfo.uid).coerceAtLeast(0)
        totalUpload = 0
        totalDownload = 0
        lastUploadSpeed = 0
        lastDownloadSpeed = 0

        var lastUp = 0L
        var lastDown = 0L
        var lastTime = System.currentTimeMillis()

        statsThread = Thread {
            while (isRunning) {
                try {
                    Thread.sleep(1000)
                    val now = System.currentTimeMillis()
                    val elapsed = (now - lastTime) / 1000.0

                    val rawTx = TrafficStats.getUidTxBytes(applicationInfo.uid).coerceAtLeast(0)
                    val rawRx = TrafficStats.getUidRxBytes(applicationInfo.uid).coerceAtLeast(0)
                    val currentTx = (rawTx - baseUpload).coerceAtLeast(0)
                    val currentRx = (rawRx - baseDownload).coerceAtLeast(0)

                    totalUpload = currentTx
                    totalDownload = currentRx

                    if (elapsed > 0) {
                        lastUploadSpeed = ((currentTx - lastUp) / elapsed).toLong().coerceAtLeast(0)
                        lastDownloadSpeed = ((currentRx - lastDown) / elapsed).toLong().coerceAtLeast(0)
                    }
                    lastUp = totalUpload
                    lastDown = totalDownload
                    lastTime = now
                    VpnEventStreamHandler.sendStatsEvent(totalUpload, totalDownload, lastUploadSpeed, lastDownloadSpeed)
                } catch (_: InterruptedException) { break } catch (_: Exception) {}
            }
        }.also { it.isDaemon = true; it.name = "vpn-stats"; it.start() }
    }

    // =====================================================================
    // Network callback (underlying networks)
    // =====================================================================

    private fun registerNetworkCallback() {
        try {
            val cm = getSystemService(CONNECTIVITY_SERVICE) as ConnectivityManager
            networkCallback = object : ConnectivityManager.NetworkCallback() {
                override fun onAvailable(network: Network) {
                    log("info", "Network available, updating underlying networks")
                    updateUnderlyingNetworks(cm)
                }
                override fun onLost(network: Network) {
                    log("info", "Network lost, updating underlying networks")
                    updateUnderlyingNetworks(cm)
                }
                override fun onCapabilitiesChanged(network: Network, networkCapabilities: NetworkCapabilities) {
                    // Ignored: слишком часто на некоторых устройствах (Huawei),
                    // повторные setUnderlyingNetworks() ломают TCP-соединения xray
                }
            }
            val request = NetworkRequest.Builder()
                .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
                .build()
            cm.registerNetworkCallback(request, networkCallback!!)
        } catch (e: Exception) {
            log("warning", "Failed to register network callback: ${e.message}")
        }
    }

    private fun updateUnderlyingNetworks(cm: ConnectivityManager) {
        val now = System.currentTimeMillis()
        if (now - lastNetworkUpdate < networkUpdateDebounceMs) return
        lastNetworkUpdate = now

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            cm.activeNetwork?.let { network ->
                setUnderlyingNetworks(arrayOf(network))
                log("info", "Updated underlying network")
            }
        }
    }

    private fun unregisterNetworkCallback() {
        try {
            val cm = getSystemService(CONNECTIVITY_SERVICE) as ConnectivityManager
            networkCallback?.let {
                cm.unregisterNetworkCallback(it)
                networkCallback = null
            }
        } catch (_: Exception) {}
    }

    // =====================================================================
    // Foreground notification
    // =====================================================================

    private fun startForegroundNotification(configName: String = "") {
        val manager = getSystemService(NOTIFICATION_SERVICE) as NotificationManager
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(NOTIFICATION_CHANNEL_ID, "VPN Service", NotificationManager.IMPORTANCE_LOW)
            manager.createNotificationChannel(channel)
        }
        val flags = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        } else {
            PendingIntent.FLAG_UPDATE_CURRENT
        }
        val stopIntent = PendingIntent.getService(this, 0,
            Intent(this, XrayVpnService::class.java).apply { action = ACTION_DISCONNECT }, flags)
        val contentText = if (configName.isNotEmpty()) configName else "Защищенное соединение активно"
        val notification = NotificationCompat.Builder(this, NOTIFICATION_CHANNEL_ID)
            .setContentTitle("TeapodStream VPN")
            .setContentText(contentText)
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setOngoing(true)
            .addAction(android.R.drawable.ic_menu_close_clear_cancel, "Отключить", stopIntent)
            .build()
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            startForeground(NOTIFICATION_ID, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
        } else {
            startForeground(NOTIFICATION_ID, notification)
        }
    }

    // =====================================================================
    // Утилиты
    // =====================================================================

    private fun log(level: String, message: String) {
        android.util.Log.i("TeapodVPN", "[$level] $message")
        if (level == "error" || level == "info" || (BuildConfig.DEBUG && level == "debug")) {
            VpnEventStreamHandler.sendLogEvent(level, message)
        }
    }

    private fun subnetMaskToPrefix(mask: String): Int {
        var prefix = 0
        for (part in mask.split(".").map { it.toInt() }) {
            var bits = part
            while (bits != 0) { prefix += bits and 1; bits = bits ushr 1 }
        }
        return prefix
    }
}
