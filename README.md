# esp32-c3
### ESP32-C3 SuperMini Board
### Test Led, Button and UART 1, 2, 3.

```
=== Board GPIO ===
	X1:
	1 - GPIO5 / ADC2 / SCL / SPI_MISO
	2 - GPIO6 / SPI_MOSI
	3 - GPIO7 / SPI_SS
	4 - GPIO8 / PWM / SDA
	5 - GPIO8 / BOOT / SCL
	6 - GPIO10
	7 - GPIO20 / U0RXD (Serial0)
	8 - GPIO21 / U0TXD (Serial0)

	X2:
	8 - VBUS (5V)
	7 - GND
	6 - 3.3V
	5 - GPIO4 / ADC1 / SDA / SPI_SCK
	4 - GPIO3
	3 - GPIO2 - R10k - 3.3V
	2 - GPIO1 / U1RXD (Serial1 - No Work)
	1 - GPIO0 / U1TXD (Serial1 - No Work)
  
	GPIO8  - LED (Blue) - R5k1 - 3.3V
	GPIO9  - Button PROG (BOOT) - GND
	GPIO18 - USBD_N (Serial)
	GPIO19 - USBD_P (Serial)

=== platformio.ini ===
	[env:seeed_xiao_esp32c3]
	platform = espressif32
	board = seeed_xiao_esp32c3
	framework = arduino

=== Program ===
	1. Connect to USB.
	2. Press Button [Reset]+[Boot].
	3. Unpress Button [Reset].
	4. Unpress Button [Boot].
	5. PlatformIO: Select COM Port.
	6. PlatformIO: Upload.
```
RAM:   [          ]   4.2% (used 13884 bytes from 327680 bytes)
Flash: [==        ]  19.6% (used 256486 bytes from 1310720 bytes)
