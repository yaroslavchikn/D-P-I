package com.dpibypass.app

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.util.Log
import androidx.core.app.NotificationCompat
import kotlinx.coroutines.*
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.Inet4Address
import java.net.InetAddress
import java.nio.ByteBuffer
import java.nio.ByteOrder

class DpiBypassService : VpnService() {

    private var vpnInterface: ParcelFileDescriptor? = null
    private var vpnInput: FileInputStream? = null
    private var vpnOutput: FileOutputStream? = null
    private val serviceScope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private val TAG = "DpiBypassService"

    companion object {
        const val CHANNEL_ID = "dpi_bypass_vpn"
        const val NOTIFICATION_ID = 1
        const val MTU = 1500
        const val TARGET_PORT = 443
        const val TCP_PROTOCOL = 6
        const val FAKE_TTL = 5
        const val FRAGMENT_THRESHOLD = 1400
    }

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent == null) return START_NOT_STICKY

        // Запуск в режиме foreground с уведомлением
        startForeground(NOTIFICATION_ID, buildNotification())

        // Создаём VPN-интерфейс
        establishVpn()
        // Запускаем обработку пакетов
        serviceScope.launch {
            processPackets()
        }

        return START_STICKY
    }

    override fun onDestroy() {
        super.onDestroy()
        serviceScope.cancel()
        vpnInput?.close()
        vpnOutput?.close()
        vpnInterface?.close()
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                "DPI Bypass VPN",
                NotificationManager.IMPORTANCE_LOW
            )
            val manager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
            manager.createNotificationChannel(channel)
        }
    }

    private fun buildNotification(): Notification {
        val pendingIntent = PendingIntent.getActivity(
            this, 0, Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE
        )
        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("Обход DPI активен")
            .setContentText("Локальный VPN работает")
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setContentIntent(pendingIntent)
            .setOngoing(true)
            .build()
    }

    private fun establishVpn() {
        // Настраиваем TUN-интерфейс
        val builder = Builder()
            .setSession("DPI Bypass")
            .addAddress("10.0.0.2", 32) // Локальный адрес
            .addRoute("0.0.0.0", 0)      // Маршрут по умолчанию
            .addDnsServer("8.8.8.8")     // DNS Google
            .addDnsServer("8.8.4.4")
            .setMtu(MTU)
            .setBlocking(true)           // Блокирующий режим для упрощения потоков

        vpnInterface = builder.establish()
        vpnInput = FileInputStream(vpnInterface!!.fileDescriptor)
        vpnOutput = FileOutputStream(vpnInterface!!.fileDescriptor)
    }

    /**
     * Главный цикл чтения/записи пакетов из TUN.
     * Пакеты, адресованные на TCP/443, модифицируются согласно технике обхода DPI.
     */
    private suspend fun processPackets() = withContext(Dispatchers.IO) {
        val buffer = ByteArray(MTU)
        var length: Int

        while (isActive) {
            try {
                length = vpnInput!!.read(buffer)
                if (length > 0) {
                    val packet = buffer.copyOf(length)
                    val modified = modifyPacketIfNeeded(packet)
                    if (modified != null) {
                        vpnOutput!!.write(modified)
                    } else {
                        // Если пакет не модифицирован, отправляем оригинал
                        vpnOutput!!.write(packet)
                    }
                }
            } catch (e: Exception) {
                Log.e(TAG, "Ошибка при обработке пакета", e)
                break
            }
        }
    }

    /**
     * Проверяет, является ли пакет TCP-сегментом на порт 443,
     * и применяет методы обхода DPI:
     * 1. Установка TTL = 5 (чтобы пакет затух до DPI-фильтров)
     * 2. Добавление IP-опции Timestamp (меняет сигнатуру)
     * 3. Фрагментация пакетов > 1400 байт (запутывает сборку)
     */
    private fun modifyPacketIfNeeded(packet: ByteArray): ByteArray? {
        if (packet.size < 20) return null  // Минимальный размер IP-заголовка

        val buffer = ByteBuffer.wrap(packet).order(ByteOrder.BIG_ENDIAN)
        val versionAndIhl = buffer.get(0).toInt() and 0xFF
        val version = versionAndIhl shr 4
        if (version != 4) return null  // Работаем только с IPv4

        val ihl = versionAndIhl and 0x0F
        val protocol = buffer.get(9).toInt() and 0xFF
        if (protocol != TCP_PROTOCOL) return null

        val totalLength = buffer.getShort(2).toInt() and 0xFFFF
        if (totalLength != packet.size) return null // Несоответствие размера

        val srcPort = buffer.getShort(ihl * 4).toInt() and 0xFFFF
        val dstPort = buffer.getShort(ihl * 4 + 2).toInt() and 0xFFFF
        if (dstPort != TARGET_PORT && srcPort != TARGET_PORT) return null

        Log.d(TAG, "Обнаружен TCP/443 пакет, применяем обход")

        // Шаг 1: модифицируем TTL
        var modified = packet.clone()
        val ttlIndex = 8
        modified[ttlIndex] = FAKE_TTL.toByte()

        // Шаг 2: добавляем IP-опцию Timestamp (тип 68, длина 8, указатель 5, флаг 0, адрес 0.0.0.0)
        modified = insertTimestampOption(modified, ihl)

        // Шаг 3: если размер > порога, фрагментируем
        if (modified.size > FRAGMENT_THRESHOLD) {
            return fragmentPacket(modified)
        }

        // Пересчитываем контрольные суммы после правок
        recalculateIpChecksum(modified)
        recalculateTcpChecksum(modified)
        return modified
    }

    /**
     * Вставка IP-опции Timestamp в заголовок.
     * Опция: [тип=0x44, длина=8, указатель=5, флаги/переполнение=0, адрес=0.0.0.0]
     */
    private fun insertTimestampOption(packet: ByteArray, oldIhl: Int): ByteArray {
        val optionLen = 8
        val newIhl = oldIhl + optionLen / 4  // IHL в 32-битных словах
        if (newIhl > 15) return packet // Нельзя расширить заголовок (максимум 60 байт)

        // Создаём новый массив с дополнительным местом для опции
        val newPacket = ByteArray(packet.size + optionLen)
        val headerLen = oldIhl * 4

        // Копируем начало пакета до места вставки опции (сразу после исходного IP-заголовка)
        System.arraycopy(packet, 0, newPacket, 0, headerLen)
        // Вставляем опцию Timestamp
        newPacket[headerLen] = 0x44.toByte()       // Тип
        newPacket[headerLen + 1] = optionLen.toByte() // Длина
        newPacket[headerLen + 2] = 5               // Указатель на первое свободное место
        newPacket[headerLen + 3] = 0               // Флаги/переполнение
        // Адрес 0.0.0.0
        for (i in 4 until 8) newPacket[headerLen + i] = 0

        // Копируем оставшуюся часть (TCP и данные)
        System.arraycopy(packet, headerLen, newPacket, headerLen + optionLen, packet.size - headerLen)

        // Обновляем IHL и Total Length в новом пакете
        val versionIhl = (4 shl 4) or newIhl
        newPacket[0] = versionIhl.toByte()
        val newTotalLength = newPacket.size
        val totalBuf = ByteBuffer.allocate(2).order(ByteOrder.BIG_ENDIAN).putShort(newTotalLength.toShort())
        System.arraycopy(totalBuf.array(), 0, newPacket, 2, 2)

        return newPacket
    }

    /**
     * Простая IP-фрагментация для пакетов больше порога.
     * Возвращает массив байт с несколькими IP-фрагментами, склеенными последовательно.
     * Вызывающий код должен отправить их по отдельности. В текущей реализации мы
     * возвращаем первый фрагмент, а остальные отправляем прямо здесь (требует доработки).
     * Для упрощения возвращаем только первый фрагмент; остальные будут отправлены асинхронно.
     * Чтобы не усложнять, показываем принцип.
     */
    private fun fragmentPacket(packet: ByteArray): ByteArray? {
        // Здесь должна быть полноценная фрагментация, но для демонстрации вернём оригинал
        // В реальном коде мы бы создали массив фрагментов, записали бы их в vpnOutput.
        // Так как функция должна вернуть один пакет, просто отправим все фрагменты сейчас.
        val fragments = createFragments(packet)
        for (frag in fragments) {
            vpnOutput?.write(frag)
        }
        return null // Указываем, что оригинальный пакет уже отправлен частями
    }

    private fun createFragments(packet: ByteArray): List<ByteArray> {
        val mtu = FRAGMENT_THRESHOLD
        val headerLen = (packet[0].toInt() and 0x0F) * 4
        val totalLen = packet.size
        val identification = ByteBuffer.wrap(packet, 4, 2).short

        val tcpHeaderLen = ((packet[headerLen + 12].toInt() and 0xF0) shr 4) * 4
        val dataOffset = headerLen + tcpHeaderLen
        val dataLen = totalLen - dataOffset

        if (dataLen <= 0) return listOf(packet)

        val fragments = mutableListOf<ByteArray>()

        var offset = 0
        val maxDataPerFragment = mtu - headerLen
        var first = true

        while (offset < dataLen) {
            val chunkSize = minOf(maxDataPerFragment, dataLen - offset)
            val fragmentLen = headerLen + (if (first) tcpHeaderLen + chunkSize else chunkSize)
            val fragment = ByteArray(fragmentLen)

            // IP-заголовок
            System.arraycopy(packet, 0, fragment, 0, headerLen)
            // Поле total length
            val totalLengthBuf = ByteBuffer.allocate(2).order(ByteOrder.BIG_ENDIAN).putShort(fragmentLen.toShort())
            System.arraycopy(totalLengthBuf.array(), 0, fragment, 2, 2)

            // Флаги и смещение
            var flagsAndOffset = 0
            if (!first) {
                flagsAndOffset = offset / 8
            }
            if (offset + chunkSize < dataLen) {
                flagsAndOffset = flagsAndOffset or 0x2000 // MF = more fragments
            }
            val flagsBuf = ByteBuffer.allocate(2).order(ByteOrder.BIG_ENDIAN).putShort(flagsAndOffset.toShort())
            System.arraycopy(flagsBuf.array(), 0, fragment, 6, 2)

            // Идентификатор
            System.arraycopy(packet, 4, fragment, 4, 2)

            // Данные
            if (first) {
                // копируем TCP-заголовок и данные
                System.arraycopy(packet, headerLen, fragment, headerLen, tcpHeaderLen + chunkSize)
            } else {
                // только данные
                System.arraycopy(packet, dataOffset + offset, fragment, headerLen, chunkSize)
            }

            recalculateIpChecksum(fragment)
            fragments.add(fragment)
            offset += chunkSize
            first = false
        }
        return fragments
    }

    /**
     * Пересчёт контрольной суммы IP-заголовка по RFC 1071.
     */
    private fun recalculateIpChecksum(packet: ByteArray) {
        val ihl = packet[0].toInt() and 0x0F
        val headerLen = ihl * 4
        // Обнуляем поле checksum
        packet[10] = 0
        packet[11] = 0

        var sum = 0
        var i = 0
        while (i < headerLen) {
            val word = ((packet[i].toInt() and 0xFF) shl 8) or (packet[i + 1].toInt() and 0xFF)
            sum += word
            i += 2
        }
        while (sum shr 16 > 0) {
            sum = (sum and 0xFFFF) + (sum shr 16)
        }
        val checksum = (sum.inv() and 0xFFFF)
        val checksumBuf = ByteBuffer.allocate(2).order(ByteOrder.BIG_ENDIAN).putShort(checksum.toShort())
        System.arraycopy(checksumBuf.array(), 0, packet, 10, 2)
    }

    /**
     * Пересчёт контрольной суммы TCP с учётом псевдозаголовка.
     */
    private fun recalculateTcpChecksum(packet: ByteArray) {
        val ihl = packet[0].toInt() and 0x0F
        val headerLen = ihl * 4
        val totalLen = packet.size
        val tcpLen = totalLen - headerLen

        val srcAddr = ByteArray(4)
        val dstAddr = ByteArray(4)
        System.arraycopy(packet, 12, srcAddr, 0, 4)
        System.arraycopy(packet, 16, dstAddr, 0, 4)

        // Обнуляем контрольную сумму TCP
        packet[headerLen + 16] = 0
        packet[headerLen + 17] = 0

        var sum = 0
        // Псевдозаголовок
        sum += ((srcAddr[0].toInt() and 0xFF) shl 8) or (srcAddr[1].toInt() and 0xFF)
        sum += ((srcAddr[2].toInt() and 0xFF) shl 8) or (srcAddr[3].toInt() and 0xFF)
        sum += ((dstAddr[0].toInt() and 0xFF) shl 8) or (dstAddr[1].toInt() and 0xFF)
        sum += ((dstAddr[2].toInt() and 0xFF) shl 8) or (dstAddr[3].toInt() and 0xFF)
        sum += 0x0006 // protocol TCP
        sum += tcpLen

        // TCP сегмент
        var i = headerLen
        while (i < totalLen - 1) {
            val word = ((packet[i].toInt() and 0xFF) shl 8) or (packet[i + 1].toInt() and 0xFF)
            sum += word
            i += 2
        }
        if (i < totalLen) {
            // последний байт padding
            sum += (packet[i].toInt() and 0xFF) shl 8
        }

        while (sum shr 16 > 0) {
            sum = (sum and 0xFFFF) + (sum shr 16)
        }
        val checksum = (sum.inv() and 0xFFFF)
        val checksumBuf = ByteBuffer.allocate(2).order(ByteOrder.BIG_ENDIAN).putShort(checksum.toShort())
        System.arraycopy(checksumBuf.array(), 0, packet, headerLen + 16, 2)
    }
}
