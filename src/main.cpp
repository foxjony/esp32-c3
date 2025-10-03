// ESP32-C3 SuperMini Board (Aliexpress 1$)
// Test Led, Button and UART 1, 2, 3.

/*
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
	2 - GPIO1 / U1RXD (Serial1)
	1 - GPIO0 / U1TXD (Serial1)
  
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

RAM:   [          ]   4.2% (used 13884 bytes from 327680 bytes)
Flash: [==        ]  19.6% (used 256486 bytes from 1310720 bytes)
*/

#include <WiFi.h>

#define LED 8		// Boadr Blue Led (0 => On)
#define BTN 9		// Board Button (Press => 0)

uint32_t tik = 0;
uint32_t tim = 0;

void led_Flash(uint16_t t1, uint16_t t2, uint16_t n) {
	while (n) {
		n--;
		digitalWrite(LED, LOW);
		delay(t1);
		digitalWrite(LED, HIGH);
		delay(t2);
	}
}

void test_Button() {
	while (!digitalRead(BTN)) {
		Serial.println("BTN USB");
		Serial0.println("BTN UART0");
		Serial1.println("BTN UART1");
		led_Flash(10, 100, 1);
	}
	tik = 0;
}

void test_Tim() {
	tim = 0;
	tik++;
	Serial.print("TIK USB: "); Serial.println(tik);
	Serial0.print("TIK UART0: "); Serial0.println(tik);
	Serial1.print("TIK UART1: "); Serial1.println(tik);
	led_Flash(10, 1000, 1);
}

void test_Uart() {
	char data[250];
	uint8_t m;

	// USB
	if (Serial.available()) {
		m = Serial.readBytesUntil('\n', data, sizeof (data)-1);
		data[m] = '\0';
		Serial.println(data);		// Send Eho
		led_Flash(10, 10, 1);
	}

	// UART0
	if (Serial0.available()) {
		m = Serial0.readBytesUntil('\n', data, sizeof (data)-1);
		data[m] = '\0';
		Serial0.println(data);		// Send Eho
		led_Flash(10, 10, 1);
	}

	// UART1
	if (Serial1.available()) {
		m = Serial1.readBytesUntil('\n', data, sizeof (data)-1);
		data[m] = '\0';
		Serial1.println(data);		// Send Eho
		led_Flash(10, 10, 1);
	}
}

void setup() {
	pinMode(BTN, INPUT_PULLUP);
	pinMode(LED, OUTPUT);
	digitalWrite(LED, HIGH);
	delay(100);               					// For start USB

	Serial.begin(115200);						// USB: GP18, GP19
	while(!Serial);
	Serial.println("START USB");

	Serial0.begin(115200);						// RX: GP20, TX: GP21
	while(!Serial0);
	Serial0.println("START UART0");

	Serial1.begin(115200, SERIAL_8N1, 1, 0);	// RX: GP1,  TX: GP0
	while(!Serial1);
	Serial1.println("START UART1");

	led_Flash(10, 100, 3);
}

void loop() {
	if (!digitalRead(BTN)) {test_Button();}
	if (tim >= 1000) {test_Tim();} else {tim++; delay(1);}
	test_Uart();
}
