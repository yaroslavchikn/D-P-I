package com.dpibypass.app

import android.app.Activity
import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import android.widget.Button
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity

class MainActivity : AppCompatActivity() {

    private lateinit var toggleButton: Button
    private lateinit var statusText: TextView
    private var isRunning = false
    private val VPN_REQUEST_CODE = 42

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        toggleButton = findViewById(R.id.toggleButton)
        statusText = findViewById(R.id.statusText)

        toggleButton.setOnClickListener {
            if (isRunning) {
                stopVpn()
            } else {
                // Запрашиваем разрешение на создание VPN
                val intent = VpnService.prepare(this)
                if (intent != null) {
                    startActivityForResult(intent, VPN_REQUEST_CODE)
                } else {
                    // Разрешение уже выдано
                    startVpn()
                }
            }
        }
    }

    @Deprecated("Deprecated in Java")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == VPN_REQUEST_CODE && resultCode == Activity.RESULT_OK) {
            startVpn()
        }
    }

    private fun startVpn() {
        val intent = Intent(this, DpiBypassService::class.java)
        startService(intent)
        isRunning = true
        updateUi()
    }

    private fun stopVpn() {
        val intent = Intent(this, DpiBypassService::class.java)
        stopService(intent)
        isRunning = false
        updateUi()
    }

    private fun updateUi() {
        if (isRunning) {
            statusText.text = "Статус: VPN запущен"
            toggleButton.text = "Выключить обход DPI"
        } else {
            statusText.text = "Статус: не запущено"
            toggleButton.text = "Включить обход DPI"
        }
    }
}
