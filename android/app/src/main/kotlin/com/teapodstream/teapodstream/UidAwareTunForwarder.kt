package com.teapodstream.teapodstream

import android.net.ConnectivityManager
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import androidx.annotation.RequiresApi
import kotlinx.coroutines.*
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.net.*
import java.nio.ByteBuffer
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.locks.ReentrantLock
import kotlin.concurrent.withLock

/**
 * UID-aware TUN forwarder — замена tun2socks.
 *
 * Читает сырые IP-пакеты из TUN fd, для каждого TCP/UDP-пакета определяет UID
 * приложения через ConnectivityManager.getConnectionOwnerUid().
 * Пакеты с неизвестным UID (SO_BINDTODEVICE bypass) — дропаются.
 * Разрешённые пакеты проксируются через SOCKS5 в xray.
 *
 * Поддерживает IPv4 + IPv6, TCP + UDP (через SOCKS5 CONNECT / UDP ASSOCIATE).
 */
class UidAwareTunForwarder(
    private val vpnService: VpnService,
    private val tunPfd: ParcelFileDescriptor,
    private val socksHost: String,
    private val socksPort: Int,
    private val socksUser: String,
    private val socksPassword: String,
    private val mtu: Int,
    private val enableUdp: Boolean,
    private val onLog: (level: String, message: String) -> Unit,
) {
    // region Константы

    companion object {
        private const val IP_V4 = 4
        private const val IP_V6 = 6
        private const val PROTO_TCP = 6
        private const val PROTO_UDP = 17

        // TCP флаги
        private const val TCP_FIN = 0x01
        private const val TCP_SYN = 0x02
        private const val TCP_RST = 0x04
        private const val TCP_PSH = 0x08
        private const val TCP_ACK = 0x10

        // TCP состояния
        private const val STATE_SYN_RECEIVED = 1
        private const val STATE_ESTABLISHED = 2
        private const val STATE_CLOSE_WAIT = 3
        private const val STATE_LAST_ACK = 4
        private const val STATE_FIN_WAIT = 5
        private const val STATE_CLOSED = 6

        // Таймауты
        private const val TCP_IDLE_TIMEOUT_MS = 300_000L   // 5 мин
        private const val UDP_IDLE_TIMEOUT_MS = 120_000L   // 2 мин
        private const val CLEANUP_INTERVAL_MS = 30_000L    // 30 сек
        private const val SOCKS_CONNECT_TIMEOUT_MS = 10_000

        private const val UID_INVALID = -1

        // Максимальный размер буфера ожидания данных до подключения SOCKS
        private const val MAX_PENDING_BYTES = 256 * 1024  // 256 КБ
    }

    // endregion

    // region Структуры данных

    /** Ключ TCP/UDP-сессии — полная 5-tuple. */
    data class SessionKey(
        val proto: Int,
        val srcAddr: InetAddress,
        val srcPort: Int,
        val dstAddr: InetAddress,
        val dstPort: Int,
    )

    /** Ключ UDP-сессии — привязка к исходному сокету приложения. */
    data class UdpSessionKey(
        val srcAddr: InetAddress,
        val srcPort: Int,
    )

    /** Распарсенный IP+транспортный заголовок. */
    private class ParsedPacket(
        val ipVersion: Int,
        val protocol: Int,
        val srcAddr: InetAddress,
        val dstAddr: InetAddress,
        val srcPort: Int,
        val dstPort: Int,
        val ipHeaderLen: Int,
        val transportHeaderLen: Int,
        val tcpFlags: Int,
        val tcpSeqNum: Long,
        val tcpAckNum: Long,
        val tcpWindow: Int,
        val payload: ByteArray,
        val rawPacket: ByteArray,
    )

    // endregion

    // region Состояние

    private val running = AtomicBoolean(false)
    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())

    private val tunInput = FileInputStream(tunPfd.fileDescriptor)
    private val tunOutput = FileOutputStream(tunPfd.fileDescriptor)
    private val tunWriteLock = ReentrantLock()

    private val connectivityManager: ConnectivityManager =
        vpnService.getSystemService(VpnService.CONNECTIVITY_SERVICE) as ConnectivityManager

    private val tcpSessions = ConcurrentHashMap<SessionKey, TcpSession>()
    private val udpSessions = ConcurrentHashMap<UdpSessionKey, UdpSession>()

    // Счётчики для логирования
    private val droppedPackets = AtomicLong(0)
    private val forwardedPackets = AtomicLong(0)

    // Генератор ISN (Initial Sequence Number)
    private val isnCounter = AtomicInteger((System.nanoTime() and 0x7FFFFFFF).toInt())

    // endregion

    // region Публичный API

    fun start() {
        if (running.getAndSet(true)) return
        onLog("info", "UidAwareTunForwarder запущен (MTU=$mtu, SOCKS=$socksHost:$socksPort)")
        scope.launch { tunReadLoop() }
        scope.launch { sessionCleanupLoop() }
    }

    fun stop() {
        if (!running.getAndSet(false)) return
        onLog("info", "UidAwareTunForwarder остановлен " +
                "(forwarded=${forwardedPackets.get()}, dropped=${droppedPackets.get()})")
        scope.cancel()
        tcpSessions.values.forEach { it.close() }
        udpSessions.values.forEach { it.close() }
        tcpSessions.clear()
        udpSessions.clear()
    }

    // endregion

    // region Основной цикл чтения TUN

    private suspend fun tunReadLoop() {
        val buffer = ByteArray(mtu + 4)
        while (running.get() && currentCoroutineContext().isActive) {
            val len = try {
                tunInput.read(buffer)
            } catch (e: IOException) {
                if (running.get()) onLog("error", "TUN read error: ${e.message}")
                break
            }
            if (len <= 0) continue
            val raw = buffer.copyOf(len)
            processPacket(raw)
        }
    }

    // endregion

    // region Обработка пакетов и проверка UID

    private fun processPacket(raw: ByteArray) {
        val packet = parsePacket(raw) ?: return

        // Проверяем UID только на API 29+ (Android 10+)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            val uid = queryConnectionOwnerUid(packet)
            if (uid == UID_INVALID) {
                val count = droppedPackets.incrementAndGet()
                if (count <= 5 || count % 500 == 0L) {
                    onLog("warning", "DROP пакет (UID неизвестен): " +
                            "${packet.srcAddr.hostAddress}:${packet.srcPort} → " +
                            "${packet.dstAddr.hostAddress}:${packet.dstPort} " +
                            "proto=${packet.protocol} [всего dropped=$count]")
                }
                return
            }
        }

        forwardedPackets.incrementAndGet()

        when (packet.protocol) {
            PROTO_TCP -> handleTcp(packet)
            PROTO_UDP -> if (enableUdp) handleUdp(packet)
        }
    }

    @RequiresApi(Build.VERSION_CODES.Q)
    private fun queryConnectionOwnerUid(packet: ParsedPacket): Int {
        return try {
            connectivityManager.getConnectionOwnerUid(
                packet.protocol,
                InetSocketAddress(packet.srcAddr, packet.srcPort),
                InetSocketAddress(packet.dstAddr, packet.dstPort),
            )
        } catch (_: SecurityException) {
            UID_INVALID
        } catch (_: IllegalArgumentException) {
            // Может возникнуть для ICMP или некорректных адресов
            UID_INVALID
        } catch (_: Exception) {
            UID_INVALID
        }
    }

    // endregion

    // region TCP: обработка пакетов

    private fun handleTcp(packet: ParsedPacket) {
        val key = SessionKey(
            PROTO_TCP, packet.srcAddr, packet.srcPort, packet.dstAddr, packet.dstPort
        )

        val flags = packet.tcpFlags

        // SYN без ACK — новое подключение
        if (flags and TCP_SYN != 0 && flags and TCP_ACK == 0) {
            handleTcpSyn(key, packet)
            return
        }

        val session = tcpSessions[key] ?: run {
            // Пакет для несуществующей сессии — RST
            if (flags and TCP_RST == 0) {
                sendTcpRst(packet)
            }
            return
        }
        session.lastActivity = System.currentTimeMillis()

        when {
            flags and TCP_RST != 0 -> session.close()
            flags and TCP_FIN != 0 -> handleTcpFin(session, packet)
            flags and TCP_ACK != 0 -> handleTcpAck(session, packet)
        }
    }

    private fun handleTcpSyn(key: SessionKey, packet: ParsedPacket) {
        // Закрываем старую сессию если есть (повторный SYN)
        tcpSessions.remove(key)?.close()

        val session = TcpSession(
            key = key,
            ipVersion = packet.ipVersion,
            deviceInitialSeq = packet.tcpSeqNum,
        )
        tcpSessions[key] = session

        // Отправляем SYN-ACK
        val mss = mtu - if (packet.ipVersion == IP_V4) 40 else 60
        sendTcpPacket(
            srcAddr = packet.dstAddr,
            dstAddr = packet.srcAddr,
            srcPort = packet.dstPort,
            dstPort = packet.srcPort,
            seqNum = session.ourInitialSeq,
            ackNum = session.ourAckNum,
            flags = TCP_SYN or TCP_ACK,
            payload = EMPTY_BYTES,
            ipVersion = packet.ipVersion,
            mssOption = mss,
        )
        // SYN-ACK расходует 1 номер последовательности
        session.ourSeqNum = (session.ourInitialSeq + 1) and SEQ_MASK

        // Подключаемся к SOCKS5 в фоне
        session.connectJob = scope.launch {
            session.connectSocks()
        }
    }

    private fun handleTcpAck(session: TcpSession, packet: ParsedPacket) {
        when (session.state) {
            STATE_SYN_RECEIVED -> {
                // ACK на наш SYN-ACK — соединение установлено
                session.state = STATE_ESTABLISHED
                // Если есть данные в этом пакете
                if (packet.payload.isNotEmpty()) {
                    forwardTcpPayload(session, packet)
                }
            }
            STATE_ESTABLISHED -> {
                if (packet.payload.isNotEmpty()) {
                    forwardTcpPayload(session, packet)
                }
                // Чистый ACK без данных — обновляем окно, ничего не делаем
            }
            STATE_LAST_ACK -> {
                // ACK на наш FIN — закрываем
                session.close()
            }
            STATE_FIN_WAIT -> {
                // Ожидаем FIN от устройства
                if (packet.payload.isNotEmpty()) {
                    forwardTcpPayload(session, packet)
                }
            }
        }
    }

    private fun forwardTcpPayload(session: TcpSession, packet: ParsedPacket) {
        // Обновляем ACK — подтверждаем получение данных от устройства
        session.ourAckNum = (packet.tcpSeqNum + packet.payload.size) and SEQ_MASK

        // Отправляем ACK устройству
        sendTcpPacket(
            srcAddr = session.key.dstAddr,
            dstAddr = session.key.srcAddr,
            srcPort = session.key.dstPort,
            dstPort = session.key.srcPort,
            seqNum = session.ourSeqNum,
            ackNum = session.ourAckNum,
            flags = TCP_ACK,
            payload = EMPTY_BYTES,
            ipVersion = session.ipVersion,
        )

        // Пересылаем данные в SOCKS5
        if (session.socksConnected) {
            try {
                session.socksOutput!!.write(packet.payload)
                session.socksOutput!!.flush()
            } catch (e: IOException) {
                onLog("debug", "SOCKS write failed: ${e.message}")
                session.sendRst()
                session.close()
            }
        } else {
            // SOCKS ещё не подключён — буферизуем
            session.pendingLock.withLock {
                session.pendingBytes += packet.payload.size
                if (session.pendingBytes > MAX_PENDING_BYTES) {
                    onLog("warning", "Pending buffer overflow для ${session.key}")
                    session.sendRst()
                    session.close()
                    return
                }
                session.pendingData.add(packet.payload.clone())
            }
        }
    }

    private fun handleTcpFin(session: TcpSession, packet: ParsedPacket) {
        // Обрабатываем данные, пришедшие вместе с FIN
        val payloadLen = packet.payload.size
        session.ourAckNum = (packet.tcpSeqNum + payloadLen + 1) and SEQ_MASK // +1 за FIN

        if (payloadLen > 0 && session.socksConnected) {
            try {
                session.socksOutput!!.write(packet.payload)
                session.socksOutput!!.flush()
            } catch (_: IOException) { /* закрываем ниже */ }
        }

        // ACK на FIN
        sendTcpPacket(
            srcAddr = session.key.dstAddr,
            dstAddr = session.key.srcAddr,
            srcPort = session.key.dstPort,
            dstPort = session.key.srcPort,
            seqNum = session.ourSeqNum,
            ackNum = session.ourAckNum,
            flags = TCP_ACK,
            payload = EMPTY_BYTES,
            ipVersion = session.ipVersion,
        )

        // Закрываем SOCKS-сторону
        try { session.socksSocket?.shutdownOutput() } catch (_: Exception) {}

        // Отправляем наш FIN
        sendTcpPacket(
            srcAddr = session.key.dstAddr,
            dstAddr = session.key.srcAddr,
            srcPort = session.key.dstPort,
            dstPort = session.key.srcPort,
            seqNum = session.ourSeqNum,
            ackNum = session.ourAckNum,
            flags = TCP_FIN or TCP_ACK,
            payload = EMPTY_BYTES,
            ipVersion = session.ipVersion,
        )
        session.ourSeqNum = (session.ourSeqNum + 1) and SEQ_MASK // FIN расходует 1 seq
        session.state = STATE_LAST_ACK
    }

    /** Отправляет RST на пакет, адресованный несуществующей сессии. */
    private fun sendTcpRst(packet: ParsedPacket) {
        sendTcpPacket(
            srcAddr = packet.dstAddr,
            dstAddr = packet.srcAddr,
            srcPort = packet.dstPort,
            dstPort = packet.srcPort,
            seqNum = packet.tcpAckNum,  // Чтобы RST был валиден
            ackNum = (packet.tcpSeqNum + maxOf(packet.payload.size, 1)) and SEQ_MASK,
            flags = TCP_RST or TCP_ACK,
            payload = EMPTY_BYTES,
            ipVersion = packet.ipVersion,
        )
    }

    // endregion

    // region TCP Session

    /**
     * TCP-сессия: управляет SOCKS5-подключением и перенаправлением данных.
     */
    inner class TcpSession(
        val key: SessionKey,
        val ipVersion: Int,
        deviceInitialSeq: Long,
    ) {
        val ourInitialSeq: Long = (isnCounter.getAndAdd(64000) and 0x7FFFFFFF).toLong()
        var ourSeqNum: Long = ourInitialSeq
        var ourAckNum: Long = (deviceInitialSeq + 1) and SEQ_MASK

        @Volatile var state: Int = STATE_SYN_RECEIVED
        @Volatile var lastActivity: Long = System.currentTimeMillis()
        @Volatile var socksConnected: Boolean = false

        var socksSocket: Socket? = null
        var socksOutput: OutputStream? = null
        var socksInput: InputStream? = null

        val pendingData = mutableListOf<ByteArray>()
        val pendingLock = ReentrantLock()
        var pendingBytes: Int = 0

        var connectJob: Job? = null
        var readJob: Job? = null

        /** Подключение к SOCKS5 и передача управления. */
        suspend fun connectSocks() {
            try {
                val socket = Socket()
                vpnService.protect(socket)
                socket.tcpNoDelay = true
                socket.connect(InetSocketAddress(socksHost, socksPort), SOCKS_CONNECT_TIMEOUT_MS)
                socksSocket = socket
                socksOutput = socket.getOutputStream()
                socksInput = socket.getInputStream()

                performSocks5Handshake(
                    socksOutput!!, socksInput!!,
                    key.dstAddr, key.dstPort,
                )

                socksConnected = true

                // Отправляем буферизованные данные
                pendingLock.withLock {
                    for (chunk in pendingData) {
                        socksOutput!!.write(chunk)
                    }
                    if (pendingData.isNotEmpty()) socksOutput!!.flush()
                    pendingData.clear()
                    pendingBytes = 0
                }

                // Читаем данные от удалённого сервера через SOCKS
                readJob = scope.launch { socksReadLoop() }

            } catch (e: Exception) {
                if (state != STATE_CLOSED) {
                    onLog("debug", "SOCKS5 connect fail [${key.dstAddr.hostAddress}:${key.dstPort}]: ${e.message}")
                    sendRst()
                    close()
                }
            }
        }

        /** Чтение данных от удалённого сервера и отправка устройству через TUN. */
        private suspend fun socksReadLoop() {
            val maxPayload = mtu - if (ipVersion == IP_V4) 40 else 60
            val buffer = ByteArray(maxPayload)
            try {
                while (state != STATE_CLOSED && currentCoroutineContext().isActive) {
                    val len = socksInput!!.read(buffer)
                    if (len <= 0) {
                        // Удалённая сторона закрыла соединение — отправляем FIN устройству
                        sendFinToDevice()
                        break
                    }
                    lastActivity = System.currentTimeMillis()

                    // Разбиваем на сегменты не больше MSS
                    var offset = 0
                    while (offset < len) {
                        val chunkSize = minOf(maxPayload, len - offset)
                        val chunk = buffer.copyOfRange(offset, offset + chunkSize)

                        sendTcpPacket(
                            srcAddr = key.dstAddr,
                            dstAddr = key.srcAddr,
                            srcPort = key.dstPort,
                            dstPort = key.srcPort,
                            seqNum = ourSeqNum,
                            ackNum = ourAckNum,
                            flags = TCP_ACK or TCP_PSH,
                            payload = chunk,
                            ipVersion = ipVersion,
                        )
                        ourSeqNum = (ourSeqNum + chunkSize) and SEQ_MASK
                        offset += chunkSize
                    }
                }
            } catch (e: IOException) {
                if (state != STATE_CLOSED) {
                    sendRst()
                    close()
                }
            }
        }

        /** Отправляет FIN устройству (удалённая сторона закрыла соединение). */
        private fun sendFinToDevice() {
            if (state == STATE_CLOSED) return
            sendTcpPacket(
                srcAddr = key.dstAddr,
                dstAddr = key.srcAddr,
                srcPort = key.dstPort,
                dstPort = key.srcPort,
                seqNum = ourSeqNum,
                ackNum = ourAckNum,
                flags = TCP_FIN or TCP_ACK,
                payload = EMPTY_BYTES,
                ipVersion = ipVersion,
            )
            ourSeqNum = (ourSeqNum + 1) and SEQ_MASK
            state = STATE_FIN_WAIT
        }

        fun sendRst() {
            if (state == STATE_CLOSED) return
            sendTcpPacket(
                srcAddr = key.dstAddr,
                dstAddr = key.srcAddr,
                srcPort = key.dstPort,
                dstPort = key.srcPort,
                seqNum = ourSeqNum,
                ackNum = ourAckNum,
                flags = TCP_RST or TCP_ACK,
                payload = EMPTY_BYTES,
                ipVersion = ipVersion,
            )
        }

        fun close() {
            if (state == STATE_CLOSED) return
            state = STATE_CLOSED
            connectJob?.cancel()
            readJob?.cancel()
            try { socksSocket?.close() } catch (_: Exception) {}
            tcpSessions.remove(key)
        }
    }

    // endregion

    // region UDP: обработка пакетов

    private fun handleUdp(packet: ParsedPacket) {
        val sessionKey = UdpSessionKey(packet.srcAddr, packet.srcPort)

        val session = udpSessions.getOrPut(sessionKey) {
            UdpSession(sessionKey, packet.ipVersion).also {
                scope.launch { it.connect() }
            }
        }
        session.lastActivity = System.currentTimeMillis()

        if (session.connected) {
            session.forward(packet.payload, packet.dstAddr, packet.dstPort)
        } else {
            // SOCKS UDP ASSOCIATE ещё не готов — буферизуем (макс. 5 пакетов)
            session.pendingLock.withLock {
                if (session.pendingPackets.size < 5) {
                    session.pendingPackets.add(
                        Triple(packet.payload.clone(), packet.dstAddr, packet.dstPort)
                    )
                }
            }
        }
    }

    // endregion

    // region UDP Session

    /**
     * UDP-сессия: управляет SOCKS5 UDP ASSOCIATE и пересылкой дейтаграмм.
     */
    inner class UdpSession(
        val key: UdpSessionKey,
        val ipVersion: Int,
    ) {
        // TCP-контрольное соединение для SOCKS5 UDP ASSOCIATE
        var controlSocket: Socket? = null
        var relaySocket: DatagramSocket? = null
        var relayAddress: InetSocketAddress? = null

        @Volatile var connected: Boolean = false
        @Volatile var lastActivity: Long = System.currentTimeMillis()

        val pendingPackets = mutableListOf<Triple<ByteArray, InetAddress, Int>>()
        val pendingLock = ReentrantLock()

        var readJob: Job? = null

        suspend fun connect() {
            try {
                // 1. TCP-соединение для управления SOCKS5
                val ctrl = Socket()
                vpnService.protect(ctrl)
                ctrl.connect(InetSocketAddress(socksHost, socksPort), SOCKS_CONNECT_TIMEOUT_MS)
                controlSocket = ctrl

                val out = ctrl.getOutputStream()
                val inp = ctrl.getInputStream()

                // 2. Аутентификация SOCKS5
                performSocks5Auth(out, inp)

                // 3. UDP ASSOCIATE
                out.write(byteArrayOf(
                    0x05, 0x03, 0x00, 0x01,            // VER=5, CMD=UDP_ASSOCIATE, RSV=0, ATYP=IPv4
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00 // ADDR=0.0.0.0, PORT=0
                ))
                out.flush()

                val resp = ByteArray(4)
                readFully(inp, resp)
                if (resp[1] != 0x00.toByte()) {
                    throw IOException("SOCKS5 UDP ASSOCIATE failed: rep=${resp[1]}")
                }

                // Читаем BND.ADDR:BND.PORT
                val (bndAddr, bndPort) = readSocks5Address(inp, resp[3])
                val actualAddr = if (bndAddr.isAnyLocalAddress)
                    InetAddress.getByName(socksHost) else bndAddr
                relayAddress = InetSocketAddress(actualAddr, bndPort)

                // 4. UDP-сокет для relay
                val relay = DatagramSocket()
                vpnService.protect(relay)
                relaySocket = relay

                connected = true

                // Отправляем буферизованные пакеты
                pendingLock.withLock {
                    for ((data, addr, port) in pendingPackets) {
                        forward(data, addr, port)
                    }
                    pendingPackets.clear()
                }

                // 5. Читаем ответы от relay
                readJob = scope.launch { udpRelayReadLoop() }

            } catch (e: Exception) {
                if (connected || !running.get()) return
                onLog("debug", "UDP ASSOCIATE fail: ${e.message}")
                close()
            }
        }

        /** Пересылает UDP-дейтаграмму через SOCKS5 relay. */
        fun forward(payload: ByteArray, dstAddr: InetAddress, dstPort: Int) {
            val relay = relaySocket ?: return
            val target = relayAddress ?: return

            val addrBytes = dstAddr.address
            val atyp: Byte = if (addrBytes.size == 4) 0x01 else 0x04
            // SOCKS5 UDP header: RSV(2) + FRAG(1) + ATYP(1) + ADDR + PORT(2)
            val headerLen = 4 + addrBytes.size + 2
            val packet = ByteArray(headerLen + payload.size)
            // RSV = 0x0000, FRAG = 0x00
            packet[3] = atyp
            addrBytes.copyInto(packet, 4)
            packet[4 + addrBytes.size] = ((dstPort ushr 8) and 0xFF).toByte()
            packet[4 + addrBytes.size + 1] = (dstPort and 0xFF).toByte()
            payload.copyInto(packet, headerLen)

            try {
                relay.send(DatagramPacket(packet, packet.size, target))
            } catch (e: IOException) {
                onLog("debug", "UDP relay send failed: ${e.message}")
            }
        }

        /** Читает ответные UDP-дейтаграммы из relay и пишет в TUN. */
        private suspend fun udpRelayReadLoop() {
            val buf = ByteArray(65535)
            val dgram = DatagramPacket(buf, buf.size)
            try {
                while (connected && currentCoroutineContext().isActive) {
                    relaySocket!!.receive(dgram)
                    lastActivity = System.currentTimeMillis()

                    val data = dgram.data
                    val len = dgram.length
                    if (len < 4) continue

                    val frag = data[2].toInt() and 0xFF
                    if (frag != 0) continue // Фрагментированные UDP — пропускаем

                    val atyp = data[3].toInt() and 0xFF
                    val fromAddr: InetAddress
                    val fromPort: Int
                    val headerLen: Int

                    when (atyp) {
                        0x01 -> { // IPv4
                            if (len < 10) continue
                            fromAddr = InetAddress.getByAddress(data.copyOfRange(4, 8))
                            fromPort = ((data[8].toInt() and 0xFF) shl 8) or (data[9].toInt() and 0xFF)
                            headerLen = 10
                        }
                        0x04 -> { // IPv6
                            if (len < 22) continue
                            fromAddr = InetAddress.getByAddress(data.copyOfRange(4, 20))
                            fromPort = ((data[20].toInt() and 0xFF) shl 8) or (data[21].toInt() and 0xFF)
                            headerLen = 22
                        }
                        0x03 -> { // Доменное имя (маловероятно от relay)
                            val domLen = data[4].toInt() and 0xFF
                            val minLen = 5 + domLen + 2
                            if (len < minLen) continue
                            val host = String(data, 5, domLen, Charsets.US_ASCII)
                            fromAddr = InetAddress.getByName(host)
                            fromPort = ((data[5 + domLen].toInt() and 0xFF) shl 8) or
                                    (data[5 + domLen + 1].toInt() and 0xFF)
                            headerLen = 5 + domLen + 2
                        }
                        else -> continue
                    }

                    val udpPayload = data.copyOfRange(headerLen, len)

                    // Собираем UDP/IP пакет и пишем в TUN
                    val responsePacket = buildUdpIpPacket(
                        srcAddr = fromAddr,
                        dstAddr = key.srcAddr,
                        srcPort = fromPort,
                        dstPort = key.srcPort,
                        payload = udpPayload,
                        ipVersion = ipVersion,
                    )
                    writeTun(responsePacket)
                }
            } catch (e: IOException) {
                if (connected) {
                    onLog("debug", "UDP relay read ended: ${e.message}")
                }
            }
        }

        fun close() {
            connected = false
            readJob?.cancel()
            try { relaySocket?.close() } catch (_: Exception) {}
            try { controlSocket?.close() } catch (_: Exception) {}
            udpSessions.remove(key)
        }
    }

    // endregion

    // region SOCKS5 Handshake

    /** Полный SOCKS5 handshake: аутентификация + CONNECT к destination. */
    private fun performSocks5Handshake(
        output: OutputStream,
        input: InputStream,
        dstAddr: InetAddress,
        dstPort: Int,
    ) {
        performSocks5Auth(output, input)

        // CONNECT request
        val addrBytes = dstAddr.address
        val atyp: Byte = if (addrBytes.size == 4) 0x01 else 0x04
        val req = ByteArray(4 + addrBytes.size + 2)
        req[0] = 0x05 // VER
        req[1] = 0x01 // CMD=CONNECT
        req[2] = 0x00 // RSV
        req[3] = atyp
        addrBytes.copyInto(req, 4)
        req[4 + addrBytes.size] = ((dstPort ushr 8) and 0xFF).toByte()
        req[4 + addrBytes.size + 1] = (dstPort and 0xFF).toByte()
        output.write(req)
        output.flush()

        // CONNECT response
        val resp = ByteArray(4)
        readFully(input, resp)
        if (resp[0] != 0x05.toByte()) throw IOException("Неверная версия SOCKS: ${resp[0]}")
        if (resp[1] != 0x00.toByte()) throw IOException("SOCKS5 CONNECT отклонён: rep=${resp[1]}")

        // Пропускаем BND.ADDR + BND.PORT
        skipSocks5Address(input, resp[3])
    }

    /** Аутентификация SOCKS5 (username/password или noauth). */
    private fun performSocks5Auth(output: OutputStream, input: InputStream) {
        if (socksUser.isNotEmpty()) {
            output.write(byteArrayOf(0x05, 0x01, 0x02)) // VER=5, NMETHODS=1, METHOD=USER/PASS
        } else {
            output.write(byteArrayOf(0x05, 0x01, 0x00)) // VER=5, NMETHODS=1, METHOD=NOAUTH
        }
        output.flush()

        val methodResp = ByteArray(2)
        readFully(input, methodResp)
        if (methodResp[0] != 0x05.toByte()) throw IOException("Неверная версия SOCKS: ${methodResp[0]}")

        if (methodResp[1] == 0x02.toByte() && socksUser.isNotEmpty()) {
            // RFC 1929: Username/Password authentication
            val userBytes = socksUser.toByteArray(Charsets.UTF_8)
            val passBytes = socksPassword.toByteArray(Charsets.UTF_8)
            val authReq = ByteArray(3 + userBytes.size + passBytes.size)
            authReq[0] = 0x01  // VER
            authReq[1] = userBytes.size.toByte()
            userBytes.copyInto(authReq, 2)
            authReq[2 + userBytes.size] = passBytes.size.toByte()
            passBytes.copyInto(authReq, 3 + userBytes.size)
            output.write(authReq)
            output.flush()

            val authResp = ByteArray(2)
            readFully(input, authResp)
            if (authResp[1] != 0x00.toByte()) throw IOException("SOCKS5 auth failed: status=${authResp[1]}")
        } else if (methodResp[1] == 0xFF.toByte()) {
            throw IOException("SOCKS5: нет подходящего метода аутентификации")
        }
    }

    /** Читает SOCKS5 BND.ADDR + BND.PORT, возвращает (адрес, порт). */
    private fun readSocks5Address(input: InputStream, atyp: Byte): Pair<InetAddress, Int> {
        return when (atyp) {
            0x01.toByte() -> { // IPv4
                val addr = ByteArray(4)
                readFully(input, addr)
                val port = readUint16(input)
                Pair(InetAddress.getByAddress(addr), port)
            }
            0x04.toByte() -> { // IPv6
                val addr = ByteArray(16)
                readFully(input, addr)
                val port = readUint16(input)
                Pair(InetAddress.getByAddress(addr), port)
            }
            0x03.toByte() -> { // Domain
                val domLen = input.read()
                val dom = ByteArray(domLen)
                readFully(input, dom)
                val port = readUint16(input)
                Pair(InetAddress.getByName(String(dom, Charsets.US_ASCII)), port)
            }
            else -> throw IOException("Unknown SOCKS5 ATYP: $atyp")
        }
    }

    /** Пропускает SOCKS5 BND.ADDR + BND.PORT. */
    private fun skipSocks5Address(input: InputStream, atyp: Byte) {
        when (atyp) {
            0x01.toByte() -> readFully(input, ByteArray(4 + 2))   // IPv4 + port
            0x04.toByte() -> readFully(input, ByteArray(16 + 2))  // IPv6 + port
            0x03.toByte() -> {
                val domLen = input.read()
                readFully(input, ByteArray(domLen + 2))            // domain + port
            }
        }
    }

    // endregion

    // region Парсинг IP/TCP/UDP пакетов

    private fun parsePacket(raw: ByteArray): ParsedPacket? {
        if (raw.isEmpty()) return null
        val version = (raw[0].toInt() ushr 4) and 0xF
        return when (version) {
            IP_V4 -> parseIPv4(raw)
            IP_V6 -> parseIPv6(raw)
            else -> null
        }
    }

    private fun parseIPv4(raw: ByteArray): ParsedPacket? {
        if (raw.size < 20) return null
        val ihl = (raw[0].toInt() and 0x0F) * 4
        if (raw.size < ihl) return null

        // Проверяем фрагментацию (biOffset поля Flags+FragmentOffset по смещению 6-7)
        val flagsAndOffset = ((raw[6].toInt() and 0xFF) shl 8) or (raw[7].toInt() and 0xFF)
        val moreFragments = (flagsAndOffset and 0x2000) != 0
        val fragmentOffset = flagsAndOffset and 0x1FFF
        if (moreFragments || fragmentOffset != 0) return null // Фрагменты игнорируем

        val protocol = raw[9].toInt() and 0xFF
        val srcAddr = InetAddress.getByAddress(raw.copyOfRange(12, 16))
        val dstAddr = InetAddress.getByAddress(raw.copyOfRange(16, 20))

        return parseTransport(raw, ihl, protocol, srcAddr, dstAddr, IP_V4)
    }

    private fun parseIPv6(raw: ByteArray): ParsedPacket? {
        if (raw.size < 40) return null
        // Упрощённый парсинг: берём Next Header без обработки extension headers
        val nextHeader = raw[6].toInt() and 0xFF
        val srcAddr = InetAddress.getByAddress(raw.copyOfRange(8, 24))
        val dstAddr = InetAddress.getByAddress(raw.copyOfRange(24, 40))

        return parseTransport(raw, 40, nextHeader, srcAddr, dstAddr, IP_V6)
    }

    private fun parseTransport(
        raw: ByteArray,
        ipHeaderLen: Int,
        protocol: Int,
        srcAddr: InetAddress,
        dstAddr: InetAddress,
        ipVersion: Int,
    ): ParsedPacket? {
        return when (protocol) {
            PROTO_TCP -> parseTcp(raw, ipHeaderLen, srcAddr, dstAddr, ipVersion)
            PROTO_UDP -> parseUdp(raw, ipHeaderLen, srcAddr, dstAddr, ipVersion)
            else -> null // ICMP и прочее — игнорируем
        }
    }

    private fun parseTcp(
        raw: ByteArray,
        ipHeaderLen: Int,
        srcAddr: InetAddress,
        dstAddr: InetAddress,
        ipVersion: Int,
    ): ParsedPacket? {
        val offset = ipHeaderLen
        if (raw.size < offset + 20) return null

        val srcPort = ((raw[offset].toInt() and 0xFF) shl 8) or (raw[offset + 1].toInt() and 0xFF)
        val dstPort = ((raw[offset + 2].toInt() and 0xFF) shl 8) or (raw[offset + 3].toInt() and 0xFF)
        val seqNum = getUint32(raw, offset + 4)
        val ackNum = getUint32(raw, offset + 8)
        val dataOffset = ((raw[offset + 12].toInt() ushr 4) and 0xF) * 4
        val flags = raw[offset + 13].toInt() and 0x3F
        val window = ((raw[offset + 14].toInt() and 0xFF) shl 8) or (raw[offset + 15].toInt() and 0xFF)

        val transportHeaderLen = dataOffset
        val payloadStart = offset + transportHeaderLen
        val payload = if (payloadStart < raw.size) raw.copyOfRange(payloadStart, raw.size) else EMPTY_BYTES

        return ParsedPacket(
            ipVersion = ipVersion,
            protocol = PROTO_TCP,
            srcAddr = srcAddr,
            dstAddr = dstAddr,
            srcPort = srcPort,
            dstPort = dstPort,
            ipHeaderLen = ipHeaderLen,
            transportHeaderLen = transportHeaderLen,
            tcpFlags = flags,
            tcpSeqNum = seqNum,
            tcpAckNum = ackNum,
            tcpWindow = window,
            payload = payload,
            rawPacket = raw,
        )
    }

    private fun parseUdp(
        raw: ByteArray,
        ipHeaderLen: Int,
        srcAddr: InetAddress,
        dstAddr: InetAddress,
        ipVersion: Int,
    ): ParsedPacket? {
        val offset = ipHeaderLen
        if (raw.size < offset + 8) return null

        val srcPort = ((raw[offset].toInt() and 0xFF) shl 8) or (raw[offset + 1].toInt() and 0xFF)
        val dstPort = ((raw[offset + 2].toInt() and 0xFF) shl 8) or (raw[offset + 3].toInt() and 0xFF)

        val payloadStart = offset + 8
        val payload = if (payloadStart < raw.size) raw.copyOfRange(payloadStart, raw.size) else EMPTY_BYTES

        return ParsedPacket(
            ipVersion = ipVersion,
            protocol = PROTO_UDP,
            srcAddr = srcAddr,
            dstAddr = dstAddr,
            srcPort = srcPort,
            dstPort = dstPort,
            ipHeaderLen = ipHeaderLen,
            transportHeaderLen = 8,
            tcpFlags = 0,
            tcpSeqNum = 0,
            tcpAckNum = 0,
            tcpWindow = 0,
            payload = payload,
            rawPacket = raw,
        )
    }

    // endregion

    // region Построение IP/TCP/UDP пакетов

    private val EMPTY_BYTES = byteArrayOf()
    private val SEQ_MASK = 0xFFFFFFFFL
    private val ipIdCounter = AtomicInteger(0)

    /**
     * Собирает TCP-пакет (IP + TCP) и пишет в TUN.
     * @param mssOption если не null, добавляет MSS TCP-опцию (для SYN-ACK).
     */
    private fun sendTcpPacket(
        srcAddr: InetAddress,
        dstAddr: InetAddress,
        srcPort: Int,
        dstPort: Int,
        seqNum: Long,
        ackNum: Long,
        flags: Int,
        payload: ByteArray,
        ipVersion: Int,
        mssOption: Int? = null,
    ) {
        val packet = buildTcpIpPacket(
            srcAddr, dstAddr, srcPort, dstPort,
            seqNum, ackNum, flags, payload, ipVersion, mssOption,
        )
        writeTun(packet)
    }

    private fun buildTcpIpPacket(
        srcAddr: InetAddress,
        dstAddr: InetAddress,
        srcPort: Int,
        dstPort: Int,
        seqNum: Long,
        ackNum: Long,
        flags: Int,
        payload: ByteArray,
        ipVersion: Int,
        mssOption: Int?,
    ): ByteArray {
        // TCP options: MSS (4 байта) + Window Scale (3 байта) + NOP (1 байт) = 8 байт
        val hasOptions = mssOption != null
        val tcpOptionsLen = if (hasOptions) 8 else 0
        val tcpHeaderLen = 20 + tcpOptionsLen
        val tcpDataOffset = tcpHeaderLen / 4

        val ipHeaderLen = if (ipVersion == IP_V4) 20 else 40
        val totalLen = ipHeaderLen + tcpHeaderLen + payload.size
        val packet = ByteArray(totalLen)

        // --- IP Header ---
        if (ipVersion == IP_V4) {
            buildIPv4Header(packet, srcAddr, dstAddr, PROTO_TCP, totalLen)
        } else {
            buildIPv6Header(packet, srcAddr, dstAddr, PROTO_TCP, tcpHeaderLen + payload.size)
        }

        // --- TCP Header ---
        val t = ipHeaderLen
        putUint16(packet, t, srcPort)
        putUint16(packet, t + 2, dstPort)
        putUint32(packet, t + 4, seqNum)
        putUint32(packet, t + 8, ackNum)
        packet[t + 12] = ((tcpDataOffset shl 4) and 0xF0).toByte()
        packet[t + 13] = (flags and 0x3F).toByte()
        putUint16(packet, t + 14, 65535)   // Window
        // Checksum [t+16..t+17] — заполним после
        // Urgent pointer = 0

        // TCP options
        if (hasOptions) {
            // MSS: Kind=2, Len=4, Value=mssOption
            packet[t + 20] = 0x02
            packet[t + 21] = 0x04
            putUint16(packet, t + 22, mssOption!!)
            // Window Scale: Kind=3, Len=3, Value=6
            packet[t + 24] = 0x03
            packet[t + 25] = 0x03
            packet[t + 26] = 0x06
            // NOP padding: Kind=1
            packet[t + 27] = 0x01
        }

        // Payload
        if (payload.isNotEmpty()) {
            payload.copyInto(packet, t + tcpHeaderLen)
        }

        // TCP Checksum (над pseudo-header + TCP segment)
        val tcpChecksum = computeTcpUdpChecksum(
            srcAddr.address, dstAddr.address, PROTO_TCP,
            packet, t, tcpHeaderLen + payload.size, ipVersion,
        )
        putUint16(packet, t + 16, tcpChecksum)

        return packet
    }

    private fun buildUdpIpPacket(
        srcAddr: InetAddress,
        dstAddr: InetAddress,
        srcPort: Int,
        dstPort: Int,
        payload: ByteArray,
        ipVersion: Int,
    ): ByteArray {
        val udpHeaderLen = 8
        val ipHeaderLen = if (ipVersion == IP_V4) 20 else 40
        val totalLen = ipHeaderLen + udpHeaderLen + payload.size
        val packet = ByteArray(totalLen)

        // --- IP Header ---
        if (ipVersion == IP_V4) {
            buildIPv4Header(packet, srcAddr, dstAddr, PROTO_UDP, totalLen)
        } else {
            buildIPv6Header(packet, srcAddr, dstAddr, PROTO_UDP, udpHeaderLen + payload.size)
        }

        // --- UDP Header ---
        val u = ipHeaderLen
        putUint16(packet, u, srcPort)
        putUint16(packet, u + 2, dstPort)
        putUint16(packet, u + 4, udpHeaderLen + payload.size)
        // Checksum [u+6..u+7] — заполним после

        // Payload
        if (payload.isNotEmpty()) {
            payload.copyInto(packet, u + udpHeaderLen)
        }

        // UDP Checksum
        val udpChecksum = computeTcpUdpChecksum(
            srcAddr.address, dstAddr.address, PROTO_UDP,
            packet, u, udpHeaderLen + payload.size, ipVersion,
        )
        putUint16(packet, u + 6, udpChecksum)

        return packet
    }

    private fun buildIPv4Header(
        packet: ByteArray,
        srcAddr: InetAddress,
        dstAddr: InetAddress,
        protocol: Int,
        totalLength: Int,
    ) {
        packet[0] = 0x45.toByte()                        // Version=4, IHL=5
        packet[1] = 0x00                                  // DSCP/ECN
        putUint16(packet, 2, totalLength)                  // Total Length
        putUint16(packet, 4, ipIdCounter.incrementAndGet() and 0xFFFF)  // Identification
        packet[6] = 0x40.toByte()                          // Flags: Don't Fragment
        packet[7] = 0x00                                   // Fragment Offset
        packet[8] = 64                                     // TTL
        packet[9] = protocol.toByte()                      // Protocol
        // Header checksum [10..11] — заполним после
        srcAddr.address.copyInto(packet, 12)
        dstAddr.address.copyInto(packet, 16)

        // IPv4 header checksum
        val headerChecksum = computeIpChecksum(packet, 0, 20)
        putUint16(packet, 10, headerChecksum)
    }

    private fun buildIPv6Header(
        packet: ByteArray,
        srcAddr: InetAddress,
        dstAddr: InetAddress,
        nextHeader: Int,
        payloadLength: Int,
    ) {
        packet[0] = 0x60.toByte()                          // Version=6
        // Traffic Class + Flow Label = 0 (bytes 1-3)
        putUint16(packet, 4, payloadLength)                // Payload Length
        packet[6] = nextHeader.toByte()                    // Next Header
        packet[7] = 64                                     // Hop Limit
        srcAddr.address.copyInto(packet, 8)                // Source (16 bytes)
        dstAddr.address.copyInto(packet, 24)               // Destination (16 bytes)
    }

    // endregion

    // region Контрольные суммы

    /** IPv4 header checksum (RFC 791). */
    private fun computeIpChecksum(data: ByteArray, offset: Int, length: Int): Int {
        var sum = 0L
        var i = offset
        val end = offset + length
        while (i < end - 1) {
            if (i != offset + 10) { // Пропускаем поле checksum
                sum += ((data[i].toInt() and 0xFF) shl 8) or (data[i + 1].toInt() and 0xFF)
            }
            i += 2
        }
        while (sum shr 16 != 0L) sum = (sum and 0xFFFF) + (sum shr 16)
        return sum.toInt().inv() and 0xFFFF
    }

    /**
     * TCP/UDP checksum с pseudo-header (RFC 793, RFC 768).
     * Используется для TCP и UDP поверх IPv4 и IPv6.
     */
    private fun computeTcpUdpChecksum(
        srcAddr: ByteArray,
        dstAddr: ByteArray,
        protocol: Int,
        data: ByteArray,
        transportOffset: Int,
        transportLength: Int,
        ipVersion: Int,
    ): Int {
        var sum = 0L

        // Pseudo-header
        // Адрес источника
        var i = 0
        while (i < srcAddr.size - 1) {
            sum += ((srcAddr[i].toInt() and 0xFF) shl 8) or (srcAddr[i + 1].toInt() and 0xFF)
            i += 2
        }
        // Адрес назначения
        i = 0
        while (i < dstAddr.size - 1) {
            sum += ((dstAddr[i].toInt() and 0xFF) shl 8) or (dstAddr[i + 1].toInt() and 0xFF)
            i += 2
        }

        if (ipVersion == IP_V4) {
            // IPv4 pseudo-header: 0 + protocol (16 bit) + TCP/UDP length (16 bit)
            sum += protocol.toLong()
            sum += transportLength.toLong()
        } else {
            // IPv6 pseudo-header: upper-layer packet length (32 bit) + 0(24 bit) + next header (8 bit)
            sum += (transportLength.toLong() ushr 16)
            sum += (transportLength.toLong() and 0xFFFF)
            sum += protocol.toLong()
        }

        // Данные транспортного уровня (с обнулённым полем checksum)
        val checksumFieldOffset = when (protocol) {
            PROTO_TCP -> transportOffset + 16
            PROTO_UDP -> transportOffset + 6
            else -> -1
        }

        i = transportOffset
        val end = transportOffset + transportLength
        while (i < end - 1) {
            val word = if (i == checksumFieldOffset) {
                0 // Обнуляем поле checksum
            } else {
                ((data[i].toInt() and 0xFF) shl 8) or (data[i + 1].toInt() and 0xFF)
            }
            sum += word
            i += 2
        }
        // Нечётный последний байт
        if (transportLength % 2 != 0) {
            sum += (data[end - 1].toInt() and 0xFF) shl 8
        }

        while (sum shr 16 != 0L) sum = (sum and 0xFFFF) + (sum shr 16)
        val result = sum.toInt().inv() and 0xFFFF
        // Для UDP: checksum 0 означает «не вычислен», заменяем на 0xFFFF
        return if (protocol == PROTO_UDP && result == 0) 0xFFFF else result
    }

    // endregion

    // region Утилиты

    private fun writeTun(packet: ByteArray) {
        tunWriteLock.withLock {
            try {
                tunOutput.write(packet)
            } catch (e: IOException) {
                if (running.get()) onLog("error", "TUN write error: ${e.message}")
            }
        }
    }

    private fun readFully(input: InputStream, buf: ByteArray) {
        var offset = 0
        while (offset < buf.size) {
            val n = input.read(buf, offset, buf.size - offset)
            if (n < 0) throw IOException("Unexpected EOF при чтении SOCKS5")
            offset += n
        }
    }

    private fun readUint16(input: InputStream): Int {
        val hi = input.read()
        val lo = input.read()
        if (hi < 0 || lo < 0) throw IOException("Unexpected EOF")
        return (hi shl 8) or lo
    }

    private fun getUint32(data: ByteArray, offset: Int): Long {
        return ((data[offset].toLong() and 0xFF) shl 24) or
                ((data[offset + 1].toLong() and 0xFF) shl 16) or
                ((data[offset + 2].toLong() and 0xFF) shl 8) or
                (data[offset + 3].toLong() and 0xFF)
    }

    private fun putUint16(data: ByteArray, offset: Int, value: Int) {
        data[offset] = ((value ushr 8) and 0xFF).toByte()
        data[offset + 1] = (value and 0xFF).toByte()
    }

    private fun putUint32(data: ByteArray, offset: Int, value: Long) {
        data[offset] = ((value ushr 24) and 0xFF).toByte()
        data[offset + 1] = ((value ushr 16) and 0xFF).toByte()
        data[offset + 2] = ((value ushr 8) and 0xFF).toByte()
        data[offset + 3] = (value and 0xFF).toByte()
    }

    // endregion

    // region Очистка сессий по таймауту

    private suspend fun sessionCleanupLoop() {
        while (running.get() && currentCoroutineContext().isActive) {
            delay(CLEANUP_INTERVAL_MS)
            val now = System.currentTimeMillis()

            tcpSessions.values.removeAll { session ->
                val expired = now - session.lastActivity > TCP_IDLE_TIMEOUT_MS
                if (expired) {
                    session.sendRst()
                    session.close()
                }
                expired
            }

            udpSessions.values.removeAll { session ->
                val expired = now - session.lastActivity > UDP_IDLE_TIMEOUT_MS
                if (expired) session.close()
                expired
            }
        }
    }

    // endregion
}
