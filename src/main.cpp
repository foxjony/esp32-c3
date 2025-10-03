// ESP32-C3 SuperMini Board Bitcoin Satoshi Puzzle
// ECDSA secp256k1 + Hash SHA-256 + Hash RIPEMD-160
// E-Paper 2.9" 128x296 (White-Black, White-Black-Red)
// 3.10.2025

// RP2040		100 [6.842 s]	14 keys/s	(x1) 	(2-Core 133 MHz, max 250 MHz)
// ESP32		100 [1.703 s]	58 keys/s	(x4.14) (2-Core 240 MHz)
// ESP32-C3		100 [2.137 s]	47 keys/s	(x3.35) (1-Core 160 MHz)

// Power:
// ESP32		(5.0V, 30 mA, 0.150 W)
// ESP32-C3 	(5.1V, 32 mA, 0.165 W)

/*
=== Board GPIO ===
	X1:										E-Paper:
	1 - GPIO5 / ADC2 / SCL / SPI_MISO
	2 - GPIO6 / SPI_MOSI					SDA		pin6
	3 - GPIO7 / SPI_SS						CS		pin4
	4 - GPIO8 / PWM / SDA					DC		pin3
	5 - GPIO9 / BOOT / SCL
	6 - GPIO10								RES		pin2
	7 - GPIO20 / U0RXD (Serial0)
	8 - GPIO21 / U0TXD (Serial0)

	X2:
	8 - VBUS (5V)
	7 - GND									GND		pin7
	6 - VCC (3.3V)							VCC		pin8
	5 - GPIO4 / ADC1 / SDA / SPI_SCK		SCL		pin5
	4 - GPIO3 (BUZZER_PIN)
	3 - GPIO2 - R10k - 3.3V
	2 - GPIO1 / U1RXD (Serial1)				BUSY	pin1
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

RAM:   [=         ]   7.4% (used 24208 bytes from 327680 bytes)
Flash: [==        ]  20.9% (used 273426 bytes from 1310720 bytes)
*/

#include <Arduino.h>
#include <EEPROM.h>
#include <GxEPD2_3C.h>
#include <Fonts/FreeMonoBold9pt7b.h>
#include "esp_task_wdt.h"

#define   LED_PIN       8		// Boadr Blue Led (0 => On)
#define   BTN_PIN       9		// Board Button (Press => 0)
#define   BUZZER_PIN    3		// BUZZER (1 => On)
#define   ADC_PIN		0		// ADC for True Random
#define   BIGINT_WORDS  8      	// secp256k1

// E-Paper: CS=7, DC=8, RES=10, BUSY=1
GxEPD2_3C<GxEPD2_290_C90c, GxEPD2_290_C90c::HEIGHT> display(GxEPD2_290_C90c(7, 8, 10, 1));

typedef struct {uint32_t data[BIGINT_WORDS];}   BigInt;       // secp256k1
typedef struct {BigInt x, y; bool infinity;}    ECPoint;      // secp256k1
typedef struct {BigInt X, Y, Z; bool infinity;} ECPointJac;   // secp256k1

const BigInt const_p = {
  {0xFFFFFC2F, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF}
};    // secp256k1

const ECPointJac const_g = {
  {{0x16F81798, 0x59F2815B, 0x2DCE28D9, 0x029BFCDB, 0xCE870B07, 0x55A06295, 0xF9DCBBAC, 0x79BE667E}},
  {{0xFB10D4B8, 0x9C47D08F, 0xA6855419, 0xFD17B448, 0x0E1108A8, 0x5DA4FBFC, 0x26A3C465, 0x483ADA77}},
  {{1, 0, 0, 0, 0, 0, 0, 0}}
};    // secp256k1

const BigInt const_n = {
  {0xD0364141, 0xBFD25E8C, 0xAF48A03B, 0xBAAEDCE6, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF}
};    // secp256k1

int t = 0;
const char logo[]  = "Private Key";
const char logo2[] = "Search Key";
char str1[] = "00000000 00000000 00000000";
char str2[] = "00000000 00000000 00000000";
char str3[] = "00000000 00000000";
char str[20];

uint64_t  start, end;
uint64_t  counter = 0;                // Counter
uint8_t   privateKey[32];             // Private Key 8*32
uint8_t   publicKey_Uncompressed[65]; // Uncompressed Public Key
uint8_t   publicKey_Compressed[33];   // Compressed Public Key
uint8_t   keyHash_Uncompressed[32];   // Key Uncompressed Hash SHA-256
uint8_t   keyHash_Compressed[32];     // Key Compressed Hash SHA-256
uint8_t   ripemd_160[20];             // ripemd-160
uint8_t   ripemd_160_u[20];           // ripemd-160 Uncompressed
uint8_t   ripemd_160_c[20];           // ripemd-160 Compressed
uint16_t  keyLen = 0;                 // Key Len
String    strHex;                     // String Hex
uint8_t   i;
String    strRx = "";
char      bufRx[250] = {0};
uint16_t  countRx = 0;
//bool    ledState = 0;

// Puzzle 71: 1PWo3JeB9jrGwfHDNpdGK54CRas7fsVzXU (f6f5431d25bbf7b12e8add9af5e3475c44a0a5b8)
// Puzzle 72: 1JTK7s9YVYywfm5XUH7RNhHJH1LshCaRFR (bf7413e8df4e7a34ce9dc13e2f2648783ec54adb)
// Puzzle 73: 12VVRNPi4SJqUTsp6FmqDqY5sGosDtysn4 (105b7f253f0ebd7843adaebbd805c944bfb863e4)
uint8_t   addr[3][20] = {
  {0xf6, 0xf5, 0x43, 0x1d, 0x25, 0xbb, 0xf7, 0xb1, 0x2e, 0x8a, 0xdd, 0x9a, 0xf5, 0xe3, 0x47, 0x5c, 0x44, 0xa0, 0xa5, 0xb8},   // Puzzle 71
  {0xbf, 0x74, 0x13, 0xe8, 0xdf, 0x4e, 0x7a, 0x34, 0xce, 0x9d, 0xc1, 0x3e, 0x2f, 0x26, 0x48, 0x78, 0x3e, 0xc5, 0x4a, 0xdb},   // Puzzle 72
  {0x10, 0x5b, 0x7f, 0x25, 0x3f, 0x0e, 0xbd, 0x78, 0x43, 0xad, 0xae, 0xbb, 0xd8, 0x05, 0xc9, 0x44, 0xbf, 0xb8, 0x63, 0xe4}    // Puzzle 73
};

void ledFlash(uint16_t t1, uint16_t t2, uint8_t n) {
  while (n) {
	n--;
    digitalWrite(LED_PIN, LOW);    	// LED ON
    delay(t1);
    digitalWrite(LED_PIN, HIGH);  	// LED OFF
    delay(t2);
  }
}

void buzzerFlash() {
  digitalWrite(BUZZER_PIN, HIGH);	// BUZZER ON
  digitalWrite(LED_PIN, LOW);     	// LED    ON
  delay(100);
  digitalWrite(BUZZER_PIN, LOW);  	// BUZZER OFF
  digitalWrite(LED_PIN, HIGH);    	// LED    OFF
}

// === RND ===
// Fast Random 0,375 us (1:3) [random(255) = 1,22 us]

static uint16_t x = 12345, y = 6789, z = 24, w = 1985;

uint16_t xorshift16() {
  uint16_t t = x ^ (x << 5);
  x = y; y = z; z = w;
  w = w ^ (w >> 1) ^ t ^ (t >> 3);
  return w;
}

uint16_t rnd_adc() {
  uint16_t rnd = 0;
  for (i=0; i<16; i++) {
    uint8_t a = 1;
    uint8_t b = 0;
    while (a) {
      a = 0;
      b = analogRead(ADC_PIN);		// GP0
      if (b == 0) {a = 1;}
      if (b == 255) {a = 1;}
    }
    rnd |= (uint16_t)(b&0x0001)<<i;
  }
  return rnd;
}

void init_rnd() {
  x = rnd_adc();   // 12345
  y = rnd_adc();   // 6789
  z = rnd_adc();   // 42
  w = rnd_adc();   // 1729
}
// === RND ===

void printHex(uint8_t *data, size_t len) {
  strHex = "";
  for(uint16_t i=0; i<len; i++) {
		char str[3];
		sprintf(str, "%02x", (uint8_t)data[i]);
    strHex += str;
		Serial.print(str);
	}
  Serial.print("\n");
}

uint8_t hexCharToNibble(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  return 0;   // Incorrect
}

size_t hexStringToBytes(const char* hexStr, uint8_t* outBuf, size_t outBufSize) {
  size_t len = strlen(hexStr);
  if (len % 2 != 0) {return 0;}     // Odd length

  size_t bytesLen = len / 2;
  if (bytesLen > outBufSize) {return 0;}

  for (size_t i = 0; i < bytesLen; i++) {
    uint8_t high = hexCharToNibble(hexStr[2 * i]);
    uint8_t low  = hexCharToNibble(hexStr[2 * i + 1]);
    outBuf[i] = (high << 4) | low;
  }
  return bytesLen;
}

void outEpaper(bool s) {
  display.init();
  display.setRotation(1);
  display.setFont(&FreeMonoBold9pt7b);
  display.fillScreen(GxEPD_WHITE);
  display.setTextColor(GxEPD_BLACK);
  display.firstPage();

  // 1857 ms (black), 21654 ms (red)
  do {
    //display.setTextColor(GxEPD_RED);    // GxEPD_RED / GxEPD_BLACK
    display.setTextSize(2);
    display.setCursor(20, 30);
    display.print(logo);

    if (s) {
      display.setTextSize(1);
      display.setCursor(5, 60);
      display.print(str1);
      display.setCursor(5, 85);
      display.print(str2);
      display.setCursor(5, 110);
      display.print(str3);
    }
  } while (display.nextPage());
}

void printEpaper(bool u) {
  EEPROM.begin(64);
  EEPROM.write(1, 1);
  delay(1);
  for (i=0; i<32; i++) {EEPROM.write(i+10, privateKey[i]); delay(1);}
  EEPROM.commit();
  EEPROM.end();

  sprintf(str1, "%02x%02x%02x%02x %02x%02x%02x%02x %02x%02x%02x%02x",
    privateKey[0], privateKey[1], privateKey[2],  privateKey[3],
    privateKey[4], privateKey[5], privateKey[6],  privateKey[7],
    privateKey[8], privateKey[9], privateKey[10], privateKey[11]
  );

  sprintf(str2, "%02x%02x%02x%02x %02x%02x%02x%02x %02x%02x%02x%02x",
    privateKey[12], privateKey[13], privateKey[14], privateKey[15],
    privateKey[16], privateKey[17], privateKey[18], privateKey[19],
    privateKey[20], privateKey[21], privateKey[22], privateKey[23]
  );

  sprintf(str3, "%02x%02x%02x%02x %02x%02x%02x%02x",
    privateKey[24], privateKey[25], privateKey[26], privateKey[27],
    privateKey[28], privateKey[29], privateKey[30], privateKey[31]
  );

  outEpaper(1);

  if (u) {Serial.println("POWER_OFF"); delay(100);}

  while (1) {
    Serial.print("\n=== Found! ===\n");
    printHex(privateKey, 32);
    printHex(publicKey_Compressed, 33);
    printHex(ripemd_160_c, 20);
    buzzerFlash();
    delay(1000);
  }
}

// === SHA-256 (85 us) ============================================
typedef struct {
  uint8_t data[64];
  uint32_t datalen;
  unsigned long long bitlen;
  uint32_t state[8];
} SHA256_CTX;

#define ROTRIGHT(word, bits) (((word) >> (bits)) | ((word) << (32 - (bits))))
#define CH(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x) (ROTRIGHT(x, 2) ^ ROTRIGHT(x, 13) ^ ROTRIGHT(x, 22))
#define EP1(x) (ROTRIGHT(x, 6) ^ ROTRIGHT(x, 11) ^ ROTRIGHT(x, 25))
#define SIG0(x) (ROTRIGHT(x, 7) ^ ROTRIGHT(x, 18) ^ ((x) >> 3))
#define SIG1(x) (ROTRIGHT(x, 17) ^ ROTRIGHT(x, 19) ^ ((x) >> 10))

const uint32_t k[64] = {
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

void sha256_transform(SHA256_CTX *ctx, const uint8_t data[]) {
  uint32_t a, b, c, d, e, f, g, h, i, j, t1, t2, m[64];

  for (i = 0, j = 0; i < 16; ++i, j += 4) {
    m[i] = (data[j] << 24) | (data[j + 1] << 16) | (data[j + 2] << 8) | (data[j + 3]);
  }

  for (; i < 64; ++i) {
    m[i] = SIG1(m[i - 2]) + m[i - 7] + SIG0(m[i - 15]) + m[i - 16];
  }

  a = ctx->state[0];
  b = ctx->state[1];
  c = ctx->state[2];
  d = ctx->state[3];
  e = ctx->state[4];
  f = ctx->state[5];
  g = ctx->state[6];
  h = ctx->state[7];

  for (i = 0; i < 64; ++i) {
    t1 = h + EP1(e) + CH(e, f, g) + k[i] + m[i];
    t2 = EP0(a) + MAJ(a, b, c);
    h = g; g = f; f = e; e = d + t1;
    d = c; c = b; b = a; a = t1 + t2;
  }

  ctx->state[0] += a;
  ctx->state[1] += b;
  ctx->state[2] += c;
  ctx->state[3] += d;
  ctx->state[4] += e;
  ctx->state[5] += f;
  ctx->state[6] += g;
  ctx->state[7] += h;
}

void sha256_init(SHA256_CTX *ctx) {
  ctx->datalen = 0;
  ctx->bitlen = 0;
  ctx->state[0] = 0x6a09e667;
  ctx->state[1] = 0xbb67ae85;
  ctx->state[2] = 0x3c6ef372;
  ctx->state[3] = 0xa54ff53a;
  ctx->state[4] = 0x510e527f;
  ctx->state[5] = 0x9b05688c;
  ctx->state[6] = 0x1f83d9ab;
  ctx->state[7] = 0x5be0cd19;
}

void sha256_update(SHA256_CTX *ctx, const uint8_t data[], size_t len) {
  for (size_t i = 0; i < len; ++i) {
    ctx->data[ctx->datalen] = data[i];
    ctx->datalen++;
    if (ctx->datalen == 64) {
      sha256_transform(ctx, ctx->data);
      ctx->bitlen += 512;
      ctx->datalen = 0;
    }
  }
}

void sha256_final(SHA256_CTX *ctx, uint8_t hash[]) {
  uint32_t i = ctx->datalen;

  if (ctx->datalen < 56) {
    ctx->data[i++] = 0x80;
    while (i < 56) {ctx->data[i++] = 0x00;}
  } else {
    ctx->data[i++] = 0x80;
    while (i < 64) {ctx->data[i++] = 0x00;}
    sha256_transform(ctx, ctx->data);
    memset(ctx->data, 0, 56);
  }

  ctx->bitlen += ctx->datalen * 8;
  ctx->data[63] = ctx->bitlen;
  ctx->data[62] = ctx->bitlen >> 8;
  ctx->data[61] = ctx->bitlen >> 16;
  ctx->data[60] = ctx->bitlen >> 24;
  ctx->data[59] = ctx->bitlen >> 32;
  ctx->data[58] = ctx->bitlen >> 40;
  ctx->data[57] = ctx->bitlen >> 48;
  ctx->data[56] = ctx->bitlen >> 56;

  sha256_transform(ctx, ctx->data);

  for (i = 0; i < 4; ++i) {
    hash[i] = (ctx->state[0] >> (24 - i * 8)) & 0x000000ff;
    hash[i + 4] = (ctx->state[1] >> (24 - i * 8)) & 0x000000ff;
    hash[i + 8] = (ctx->state[2] >> (24 - i * 8)) & 0x000000ff;
    hash[i + 12] = (ctx->state[3] >> (24 - i * 8)) & 0x000000ff;
    hash[i + 16] = (ctx->state[4] >> (24 - i * 8)) & 0x000000ff;
    hash[i + 20] = (ctx->state[5] >> (24 - i * 8)) & 0x000000ff;
    hash[i + 24] = (ctx->state[6] >> (24 - i * 8)) & 0x000000ff;
    hash[i + 28] = (ctx->state[7] >> (24 - i * 8)) & 0x000000ff;
  }
}

void gcc_sha256(uint8_t *input, const uint16_t len, uint8_t *outputHash) {
  SHA256_CTX ctx;
  sha256_init(&ctx);
  sha256_update(&ctx, (const unsigned char*)input, len);
  sha256_final(&ctx, outputHash);
}
// === SHA-256 (85 us) ============================================

// === RIPEMD-160 (105 us) ============================================
uint32_t ripemd160_initial_digest[5] = {
  0x67452301UL, 0xefcdab89UL, 0x98badcfeUL, 0x10325476UL, 0xc3d2e1f0UL
};

uint8_t ripemd160_rho[16] = {
  0x7, 0x4, 0xd, 0x1, 0xa, 0x6, 0xf, 0x3, 0xc, 0x0, 0x9, 0x5, 0x2, 0xe, 0xb, 0x8
};

uint8_t ripemd160_shifts[80] = {
  11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
  12, 13, 11, 15, 6, 9, 9, 7, 12, 15, 11, 13, 7, 8, 7, 7,
  13, 15, 14, 11, 7, 7, 6, 8, 13, 14, 13, 12, 5, 5, 6, 9,
  14, 11, 12, 14, 8, 6, 5, 5, 15, 12, 15, 14, 9, 9, 8, 6,
  15, 12, 13, 13, 9, 5, 8, 6, 14, 11, 12, 11, 8, 6, 5, 5
};

uint32_t ripemd160_constants_left[5] = {
  0x00000000UL, 0x5a827999UL, 0x6ed9eba1UL, 0x8f1bbcdcUL, 0xa953fd4eUL
};

uint32_t ripemd160_constants_right[5] = {
  0x50a28be6UL, 0x5c4dd124UL, 0x6d703ef3UL, 0x7a6d76e9UL, 0x00000000UL
};

uint8_t ripemd160_fns_left[5]  = {1, 2, 3, 4, 5};
uint8_t ripemd160_fns_right[5] = {5, 4, 3, 2, 1};

#define ROL(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

void ripemd160_compute_line(uint32_t *digest, uint32_t *words, uint32_t *chunk, uint8_t *index, uint8_t *shifts, uint32_t *ks, uint8_t *fns) {
  for (uint8_t i=0; i<5; i++) {words[i] = digest[i];}

  for (uint8_t round=0; ; round++) {    // breaks out mid-loop
    uint32_t k  = ks[round];
    uint8_t  fn = fns[round];
    for (uint8_t i=0; i<16; i++) {
      uint32_t tmp;
      switch (fn) {
        case 1: tmp = words[1] ^ words[2] ^ words[3]; break;
        case 2: tmp = (words[1] & words[2]) | (~words[1] & words[3]); break;
        case 3: tmp = (words[1] | ~words[2]) ^ words[3]; break;
        case 4: tmp = (words[1] & words[3]) | (words[2] & ~words[3]); break;
        case 5: tmp = words[1] ^ (words[2] | ~words[3]); break;
      }
      tmp += words[0] + chunk[index[i]] + k;
      tmp = ROL(tmp, shifts[index[i]]) + words[4];
      words[0] = words[4];
      words[4] = words[3];
      words[3] = ROL(words[2], 10);
      words[2] = words[1];
      words[1] = tmp;
    }
    if (round == 4) {break;}
    shifts += 16;

    uint8_t index_tmp[16];
    for (uint8_t i=0; i<16; i++) {index_tmp[i] = ripemd160_rho[index[i]];}
    for (uint8_t i=0; i<16; i++) {index[i] = index_tmp[i];}
  }
}

void ripemd160_update_digest(uint32_t *digest, uint32_t *chunk) {
  uint8_t index[16];

  // initial permutation for left line is the identity
  for (uint8_t i=0; i<16; i++) {index[i] = i;}
  uint32_t words_left[5];
  ripemd160_compute_line(digest, words_left, chunk, index, ripemd160_shifts, ripemd160_constants_left, ripemd160_fns_left);

  // initial permutation for right line is 5+9i (mod 16)
  index[0] = 5;
  for (uint8_t i=1; i<16; i++) {index[i] = (index[i-1] + 9) & 0x0f;}
  uint32_t words_right[5];
  ripemd160_compute_line(digest, words_right, chunk, index, ripemd160_shifts, ripemd160_constants_right, ripemd160_fns_right);

  // update digest
  digest[0] += words_left[1] + words_right[2];
  digest[1] += words_left[2] + words_right[3];
  digest[2] += words_left[3] + words_right[4];
  digest[3] += words_left[4] + words_right[0];
  digest[4] += words_left[0] + words_right[1];

  // final rotation
  words_left[0] = digest[0];
  digest[0] = digest[1];
  digest[1] = digest[2];
  digest[2] = digest[3];
  digest[3] = digest[4];
  digest[4] = words_left[0];
}

void gcc_ripemd160(const uint8_t *data, uint32_t data_len, uint8_t *digest_bytes) {
  // NB assumes correct endianness
  uint32_t *digest = (uint32_t*)digest_bytes;
  for (uint8_t i=0; i<5; i++) {digest[i] = ripemd160_initial_digest[i];}

  const uint8_t *last_chunk_start = data + (data_len & (~0x3f));
  while (data < last_chunk_start) {
    ripemd160_update_digest(digest, (uint32_t*)data);
    data += 0x40;
  }

  uint8_t last_chunk[0x40];
  uint8_t leftover_size = data_len & 0x3f;
  for (uint8_t i=0; i<leftover_size; i++) {last_chunk[i] = *data++;}

  // append a single 1 bit and then zeroes, leaving 8 bytes for the length at the end
  last_chunk[leftover_size] = 0x80;
  for (uint8_t i=leftover_size+1; i<0x40; i++) {last_chunk[i] = 0;}

  if (leftover_size >= 0x38) {
    // no room for size in this chunk, add another chunk of zeroes
    ripemd160_update_digest(digest, (uint32_t*)last_chunk);
    for (uint8_t i=0; i<0x38; i++) {last_chunk[i] = 0;}
  }

  uint32_t *length_lsw = (uint32_t *)(last_chunk + 0x38);
  *length_lsw = (data_len<<3);
  uint32_t *length_msw = (uint32_t *)(last_chunk + 0x3c);
  *length_msw = (data_len>>29);

  ripemd160_update_digest(digest, (uint32_t*)last_chunk);
}
// === RIPEMD-160 (105 us) ============================================

// === secp256k1 (7331 us) ============================================
// copy big-endian uint32_t[8] => BigInt
void copy_uint8_to_bigint(const uint8_t *key, BigInt *result) {
  for (int i = 0; i < BIGINT_WORDS; i++) {
    result->data[BIGINT_WORDS - 1 - i] =
      ((uint32_t)key[4*i]     << 24) |
      ((uint32_t)key[4*i + 1] << 16) |
      ((uint32_t)key[4*i + 2] << 8)  |
      ((uint32_t)key[4*i + 3]);
  }
}

void point_set_infinity_jac(ECPointJac *P) {
  P->infinity = true;
}

void init_bigint(BigInt *x, uint32_t val) {
  x->data[0] = val;
  for (int i = 1; i < BIGINT_WORDS; i++) {x->data[i] = 0;}
}

void copy_bigint(BigInt *dest, const BigInt *src) {
  for (int i = 0; i < BIGINT_WORDS; i++) {dest->data[i] = src->data[i];}
}

// Порівняння a і b, повертає 1 якщо a>b, 0 якщо a==b, -1 якщо a<b
int compare_bigint(const BigInt *a, const BigInt *b) {
  for (int i = BIGINT_WORDS - 1; i >= 0; i--) {
    if (a->data[i] > b->data[i]) {return 1;}
    if (a->data[i] < b->data[i]) {return -1;}
  }
  return 0;
}

bool is_zero(const BigInt *a) {
  for (int i = 0; i < BIGINT_WORDS; i++) {if (a->data[i]) {return false;}}
  return true;
}

int get_bit(const BigInt *a, int i) {
  int word_idx = i >> 5;                          // i / 32
  int bit_idx = i & 31;                           // i % 32
  if (word_idx >= BIGINT_WORDS) {return 0;}
  return (a->data[word_idx] >> bit_idx) & 1;
}

// Еквівалент CUDA 256-бітне додавання (res = a + b)
void u256Add(BigInt *res, const BigInt *a, const BigInt *b) {
  uint64_t carry = 0;
  for (int i = 0; i < BIGINT_WORDS; i++) {
    uint64_t temp = (uint64_t)a->data[i] + (uint64_t)b->data[i] + carry;
    res->data[i] = (uint32_t)temp;
    carry = temp >> 32; // перенос у наступне слово
  }
}

// Еквівалент CUDA 256-бітне віднімання (res = a - b)
void u256Sub(BigInt *res, const BigInt *a, const BigInt *b) {
  int64_t borrow = 0;
  for (int i = 0; i < BIGINT_WORDS; i++) {
    int64_t temp = (int64_t)a->data[i] - (int64_t)b->data[i] - borrow;
    res->data[i] = (uint32_t)temp;
    borrow = (temp < 0) ? 1 : 0;  // якщо від'ємне, перенос у наступне слово
  }
}

// Додавання по модулю: res = (a + b) % p
void add_mod(BigInt *res, const BigInt *a, const BigInt *b, const BigInt *p) {
  u256Add(res, a, b);
  // якщо є carry або res >= p, віднімаємо p
  if (compare_bigint(res, p) >= 0) {u256Sub(res, res, p);}
}

// Optimized multiply_bigint_by_const with unrolling
void multiply_bigint_by_const(const BigInt *a, uint32_t c, uint32_t result[9]) {
  uint64_t carry = 0;
  #pragma GCC unroll 8
  for (int i = 0; i < BIGINT_WORDS; i++) {
    uint64_t prod = (uint64_t)a->data[i] * c + carry;
    result[i] = (uint32_t)prod;
    carry = prod >> 32;
  }
  result[8] = (uint32_t)carry;
}

// Optimized shift_left_word
void shift_left_word(const BigInt *a, uint32_t result[9]) {
  result[0] = 0;
  #pragma GCC unroll 8
  for (int i = 0; i < BIGINT_WORDS; i++) {result[i+1] = a->data[i];}
}

// Optimized add_9word with unrolling
void add_9word(uint32_t r[9], const uint32_t addend[9]) {
  uint64_t carry = 0;
  #pragma GCC unroll 9
  for (int i = 0; i < 9; i++) {
    uint64_t sum = (uint64_t)r[i] + addend[i] + carry;
    r[i] = (uint32_t)sum;
    carry = sum >> 32;
  }
}

void convert_9word_to_bigint(const uint32_t r[9], BigInt *res) {
  for (int i = 0; i < BIGINT_WORDS; i++) {res->data[i] = r[i];}
}

// Еквівалент CUDA __umulhi(a, b) для ESP32
uint32_t __umulhi(uint32_t a, uint32_t b) {
  uint64_t result = (uint64_t)a * (uint64_t)b;
  return (uint32_t)(result >> 32);              // Старші 32 біти
}

void mul_mod_device(BigInt *res, const BigInt *a, const BigInt *b) {
  uint32_t prod[16] = {0};

  // i = 0
  {
    uint32_t carry = 0;
    uint64_t sum;

    uint32_t low = a->data[0] * b->data[0];
    uint32_t high = __umulhi(a->data[0], b->data[0]);
    sum = (uint64_t)prod[0] + low + carry;
    prod[0] = (uint32_t)sum;
    carry = high + (uint32_t)(sum >> 32);

    low = a->data[0] * b->data[1];
    high = __umulhi(a->data[0], b->data[1]);
    sum = (uint64_t)prod[1] + low + carry;
    prod[1] = (uint32_t)sum;
    carry = high + (uint32_t)(sum >> 32);

    low = a->data[0] * b->data[2];
    high = __umulhi(a->data[0], b->data[2]);
    sum = (uint64_t)prod[2] + low + carry;
    prod[2] = (uint32_t)sum;
    carry = high + (uint32_t)(sum >> 32);

    low = a->data[0] * b->data[3];
    high = __umulhi(a->data[0], b->data[3]);
    sum = (uint64_t)prod[3] + low + carry;
    prod[3] = (uint32_t)sum;
    carry = high + (uint32_t)(sum >> 32);

    low = a->data[0] * b->data[4];
    high = __umulhi(a->data[0], b->data[4]);
    sum = (uint64_t)prod[4] + low + carry;
    prod[4] = (uint32_t)sum;
    carry = high + (uint32_t)(sum >> 32);

    low = a->data[0] * b->data[5];
    high = __umulhi(a->data[0], b->data[5]);
    sum = (uint64_t)prod[5] + low + carry;
    prod[5] = (uint32_t)sum;
    carry = high + (uint32_t)(sum >> 32);

    low = a->data[0] * b->data[6];
    high = __umulhi(a->data[0], b->data[6]);
    sum = (uint64_t)prod[6] + low + carry;
    prod[6] = (uint32_t)sum;
    carry = high + (uint32_t)(sum >> 32);

    low = a->data[0] * b->data[7];
    high = __umulhi(a->data[0], b->data[7]);
    sum = (uint64_t)prod[7] + low + carry;
    prod[7] = (uint32_t)sum;
    carry = high + (uint32_t)(sum >> 32);

    prod[8] += carry;
  }

  // i = 1
  {
    uint32_t carry = 0;
    uint64_t sum;

    uint32_t low = a->data[1] * b->data[0];
    uint32_t high = __umulhi(a->data[1], b->data[0]);
    sum = (uint64_t)prod[1] + low + carry;
    prod[1] = (uint32_t)sum;
    carry = high + (uint32_t)(sum >> 32);

    low = a->data[1] * b->data[1];
    high = __umulhi(a->data[1], b->data[1]);
    sum = (uint64_t)prod[2] + low + carry;
    prod[2] = (uint32_t)sum;
    carry = high + (uint32_t)(sum >> 32);

    low = a->data[1] * b->data[2];
    high = __umulhi(a->data[1], b->data[2]);
    sum = (uint64_t)prod[3] + low + carry;
    prod[3] = (uint32_t)sum;
    carry = high + (uint32_t)(sum >> 32);

    low = a->data[1] * b->data[3];
    high = __umulhi(a->data[1], b->data[3]);
    sum = (uint64_t)prod[4] + low + carry;
    prod[4] = (uint32_t)sum;
    carry = high + (uint32_t)(sum >> 32);

    low = a->data[1] * b->data[4];
    high = __umulhi(a->data[1], b->data[4]);
    sum = (uint64_t)prod[5] + low + carry;
    prod[5] = (uint32_t)sum;
    carry = high + (uint32_t)(sum >> 32);

    low = a->data[1] * b->data[5];
    high = __umulhi(a->data[1], b->data[5]);
    sum = (uint64_t)prod[6] + low + carry;
    prod[6] = (uint32_t)sum;
    carry = high + (uint32_t)(sum >> 32);

    low = a->data[1] * b->data[6];
    high = __umulhi(a->data[1], b->data[6]);
    sum = (uint64_t)prod[7] + low + carry;
    prod[7] = (uint32_t)sum;
    carry = high + (uint32_t)(sum >> 32);

    low = a->data[1] * b->data[7];
    high = __umulhi(a->data[1], b->data[7]);
    sum = (uint64_t)prod[8] + low + carry;
    prod[8] = (uint32_t)sum;
    carry = high + (uint32_t)(sum >> 32);

    prod[9] += carry;
  }

  // i = 2
  {
    uint32_t carry = 0;
    uint64_t sum;

    uint32_t low = a->data[2] * b->data[0];
    uint32_t high = __umulhi(a->data[2], b->data[0]);
    sum = (uint64_t)prod[2] + low + carry;
    prod[2] = (uint32_t)sum;
    carry = high + (uint32_t)(sum >> 32);

    low = a->data[2] * b->data[1];
    high = __umulhi(a->data[2], b->data[1]);
    sum = (uint64_t)prod[3] + low + carry;
    prod[3] = (uint32_t)sum;
    carry = high + (uint32_t)(sum >> 32);

    low = a->data[2] * b->data[2];
    high = __umulhi(a->data[2], b->data[2]);
    sum = (uint64_t)prod[4] + low + carry;
    prod[4] = (uint32_t)sum;
    carry = high + (uint32_t)(sum >> 32);

    low = a->data[2] * b->data[3];
    high = __umulhi(a->data[2], b->data[3]);
    sum = (uint64_t)prod[5] + low + carry;
    prod[5] = (uint32_t)sum;
    carry = high + (uint32_t)(sum >> 32);

    low = a->data[2] * b->data[4];
    high = __umulhi(a->data[2], b->data[4]);
    sum = (uint64_t)prod[6] + low + carry;
    prod[6] = (uint32_t)sum;
    carry = high + (uint32_t)(sum >> 32);

    low = a->data[2] * b->data[5];
    high = __umulhi(a->data[2], b->data[5]);
    sum = (uint64_t)prod[7] + low + carry;
    prod[7] = (uint32_t)sum;
    carry = high + (uint32_t)(sum >> 32);

    low = a->data[2] * b->data[6];
    high = __umulhi(a->data[2], b->data[6]);
    sum = (uint64_t)prod[8] + low + carry;
    prod[8] = (uint32_t)sum;
    carry = high + (uint32_t)(sum >> 32);

    low = a->data[2] * b->data[7];
    high = __umulhi(a->data[2], b->data[7]);
    sum = (uint64_t)prod[9] + low + carry;
    prod[9] = (uint32_t)sum;
    carry = high + (uint32_t)(sum >> 32);

    prod[10] += carry;
  }

  // i = 3
  {
    uint32_t carry = 0;
    uint64_t sum;

    uint32_t low = a->data[3] * b->data[0];
    uint32_t high = __umulhi(a->data[3], b->data[0]);
    sum = (uint64_t)prod[3] + low + carry;
    prod[3] = (uint32_t)sum;
    carry = high + (uint32_t)(sum >> 32);

    low = a->data[3] * b->data[1];
    high = __umulhi(a->data[3], b->data[1]);
    sum = (uint64_t)prod[4] + low + carry;
    prod[4] = (uint32_t)sum;
    carry = high + (uint32_t)(sum >> 32);

    low = a->data[3] * b->data[2];
    high = __umulhi(a->data[3], b->data[2]);
    sum = (uint64_t)prod[5] + low + carry;
    prod[5] = (uint32_t)sum;
    carry = high + (uint32_t)(sum >> 32);

    low = a->data[3] * b->data[3];
    high = __umulhi(a->data[3], b->data[3]);
    sum = (uint64_t)prod[6] + low + carry;
    prod[6] = (uint32_t)sum;
    carry = high + (uint32_t)(sum >> 32);

    low = a->data[3] * b->data[4];
    high = __umulhi(a->data[3], b->data[4]);
    sum = (uint64_t)prod[7] + low + carry;
    prod[7] = (uint32_t)sum;
    carry = high + (uint32_t)(sum >> 32);

    low = a->data[3] * b->data[5];
    high = __umulhi(a->data[3], b->data[5]);
    sum = (uint64_t)prod[8] + low + carry;
    prod[8] = (uint32_t)sum;
    carry = high + (uint32_t)(sum >> 32);

    low = a->data[3] * b->data[6];
    high = __umulhi(a->data[3], b->data[6]);
    sum = (uint64_t)prod[9] + low + carry;
    prod[9] = (uint32_t)sum;
    carry = high + (uint32_t)(sum >> 32);

    low = a->data[3] * b->data[7];
    high = __umulhi(a->data[3], b->data[7]);
    sum = (uint64_t)prod[10] + low + carry;
    prod[10] = (uint32_t)sum;
    carry = high + (uint32_t)(sum >> 32);

    prod[11] += carry;
  }

  // i = 4
  {
    uint32_t carry = 0;
    uint64_t sum;

    uint32_t low = a->data[4] * b->data[0];
    uint32_t high = __umulhi(a->data[4], b->data[0]);
    sum = (uint64_t)prod[4] + low + carry;
    prod[4] = (uint32_t)sum;
    carry = high + (uint32_t)(sum >> 32);

    low = a->data[4] * b->data[1];
    high = __umulhi(a->data[4], b->data[1]);
    sum = (uint64_t)prod[5] + low + carry;
    prod[5] = (uint32_t)sum;
    carry = high + (uint32_t)(sum >> 32);

    low = a->data[4] * b->data[2];
    high = __umulhi(a->data[4], b->data[2]);
    sum = (uint64_t)prod[6] + low + carry;
    prod[6] = (uint32_t)sum;
    carry = high + (uint32_t)(sum >> 32);

    low = a->data[4] * b->data[3];
    high = __umulhi(a->data[4], b->data[3]);
    sum = (uint64_t)prod[7] + low + carry;
    prod[7] = (uint32_t)sum;
    carry = high + (uint32_t)(sum >> 32);

    low = a->data[4] * b->data[4];
    high = __umulhi(a->data[4], b->data[4]);
    sum = (uint64_t)prod[8] + low + carry;
    prod[8] = (uint32_t)sum;
    carry = high + (uint32_t)(sum >> 32);

    low = a->data[4] * b->data[5];
    high = __umulhi(a->data[4], b->data[5]);
    sum = (uint64_t)prod[9] + low + carry;
    prod[9] = (uint32_t)sum;
    carry = high + (uint32_t)(sum >> 32);

    low = a->data[4] * b->data[6];
    high = __umulhi(a->data[4], b->data[6]);
    sum = (uint64_t)prod[10] + low + carry;
    prod[10] = (uint32_t)sum;
    carry = high + (uint32_t)(sum >> 32);

    low = a->data[4] * b->data[7];
    high = __umulhi(a->data[4], b->data[7]);
    sum = (uint64_t)prod[11] + low + carry;
    prod[11] = (uint32_t)sum;
    carry = high + (uint32_t)(sum >> 32);

    prod[12] += carry;
  }

  // i = 5
  {
    uint32_t carry = 0;
    uint64_t sum;

    uint32_t low = a->data[5] * b->data[0];
    uint32_t high = __umulhi(a->data[5], b->data[0]);
    sum = (uint64_t)prod[5] + low + carry;
    prod[5] = (uint32_t)sum;
    carry = high + (uint32_t)(sum >> 32);

    low = a->data[5] * b->data[1];
    high = __umulhi(a->data[5], b->data[1]);
    sum = (uint64_t)prod[6] + low + carry;
    prod[6] = (uint32_t)sum;
    carry = high + (uint32_t)(sum >> 32);

    low = a->data[5] * b->data[2];
    high = __umulhi(a->data[5], b->data[2]);
    sum = (uint64_t)prod[7] + low + carry;
    prod[7] = (uint32_t)sum;
    carry = high + (uint32_t)(sum >> 32);

    low = a->data[5] * b->data[3];
    high = __umulhi(a->data[5], b->data[3]);
    sum = (uint64_t)prod[8] + low + carry;
    prod[8] = (uint32_t)sum;
    carry = high + (uint32_t)(sum >> 32);

    low = a->data[5] * b->data[4];
    high = __umulhi(a->data[5], b->data[4]);
    sum = (uint64_t)prod[9] + low + carry;
    prod[9] = (uint32_t)sum;
    carry = high + (uint32_t)(sum >> 32);

    low = a->data[5] * b->data[5];
    high = __umulhi(a->data[5], b->data[5]);
    sum = (uint64_t)prod[10] + low + carry;
    prod[10] = (uint32_t)sum;
    carry = high + (uint32_t)(sum >> 32);

    low = a->data[5] * b->data[6];
    high = __umulhi(a->data[5], b->data[6]);
    sum = (uint64_t)prod[11] + low + carry;
    prod[11] = (uint32_t)sum;
    carry = high + (uint32_t)(sum >> 32);

    low = a->data[5] * b->data[7];
    high = __umulhi(a->data[5], b->data[7]);
    sum = (uint64_t)prod[12] + low + carry;
    prod[12] = (uint32_t)sum;
    carry = high + (uint32_t)(sum >> 32);

    prod[13] += carry;
  }

  // i = 6
  {
    uint32_t carry = 0;
    uint64_t sum;

    uint32_t low = a->data[6] * b->data[0];
    uint32_t high = __umulhi(a->data[6], b->data[0]);
    sum = (uint64_t)prod[6] + low + carry;
    prod[6] = (uint32_t)sum;
    carry = high + (uint32_t)(sum >> 32);

    low = a->data[6] * b->data[1];
    high = __umulhi(a->data[6], b->data[1]);
    sum = (uint64_t)prod[7] + low + carry;
    prod[7] = (uint32_t)sum;
    carry = high + (uint32_t)(sum >> 32);

    low = a->data[6] * b->data[2];
    high = __umulhi(a->data[6], b->data[2]);
    sum = (uint64_t)prod[8] + low + carry;
    prod[8] = (uint32_t)sum;
    carry = high + (uint32_t)(sum >> 32);

    low = a->data[6] * b->data[3];
    high = __umulhi(a->data[6], b->data[3]);
    sum = (uint64_t)prod[9] + low + carry;
    prod[9] = (uint32_t)sum;
    carry = high + (uint32_t)(sum >> 32);

    low = a->data[6] * b->data[4];
    high = __umulhi(a->data[6], b->data[4]);
    sum = (uint64_t)prod[10] + low + carry;
    prod[10] = (uint32_t)sum;
    carry = high + (uint32_t)(sum >> 32);

    low = a->data[6] * b->data[5];
    high = __umulhi(a->data[6], b->data[5]);
    sum = (uint64_t)prod[11] + low + carry;
    prod[11] = (uint32_t)sum;
    carry = high + (uint32_t)(sum >> 32);

    low = a->data[6] * b->data[6];
    high = __umulhi(a->data[6], b->data[6]);
    sum = (uint64_t)prod[12] + low + carry;
    prod[12] = (uint32_t)sum;
    carry = high + (uint32_t)(sum >> 32);

    low = a->data[6] * b->data[7];
    high = __umulhi(a->data[6], b->data[7]);
    sum = (uint64_t)prod[13] + low + carry;
    prod[13] = (uint32_t)sum;
    carry = high + (uint32_t)(sum >> 32);

    prod[14] += carry;
  }

  // i = 7
  {
    uint32_t carry = 0;
    uint64_t sum;

    uint32_t low = a->data[7] * b->data[0];
    uint32_t high = __umulhi(a->data[7], b->data[0]);
    sum = (uint64_t)prod[7] + low + carry;
    prod[7] = (uint32_t)sum;
    carry = high + (uint32_t)(sum >> 32);

    low = a->data[7] * b->data[1];
    high = __umulhi(a->data[7], b->data[1]);
    sum = (uint64_t)prod[8] + low + carry;
    prod[8] = (uint32_t)sum;
    carry = high + (uint32_t)(sum >> 32);

    low = a->data[7] * b->data[2];
    high = __umulhi(a->data[7], b->data[2]);
    sum = (uint64_t)prod[9] + low + carry;
    prod[9] = (uint32_t)sum;
    carry = high + (uint32_t)(sum >> 32);

    low = a->data[7] * b->data[3];
    high = __umulhi(a->data[7], b->data[3]);
    sum = (uint64_t)prod[10] + low + carry;
    prod[10] = (uint32_t)sum;
    carry = high + (uint32_t)(sum >> 32);

    low = a->data[7] * b->data[4];
    high = __umulhi(a->data[7], b->data[4]);
    sum = (uint64_t)prod[11] + low + carry;
    prod[11] = (uint32_t)sum;
    carry = high + (uint32_t)(sum >> 32);

    low = a->data[7] * b->data[5];
    high = __umulhi(a->data[7], b->data[5]);
    sum = (uint64_t)prod[12] + low + carry;
    prod[12] = (uint32_t)sum;
    carry = high + (uint32_t)(sum >> 32);

    low = a->data[7] * b->data[6];
    high = __umulhi(a->data[7], b->data[6]);
    sum = (uint64_t)prod[13] + low + carry;
    prod[13] = (uint32_t)sum;
    carry = high + (uint32_t)(sum >> 32);

    low = a->data[7] * b->data[7];
    high = __umulhi(a->data[7], b->data[7]);
    sum = (uint64_t)prod[14] + low + carry;
    prod[14] = (uint32_t)sum;
    carry = high + (uint32_t)(sum >> 32);

    prod[15] += carry;
  }

  BigInt L, H;
  #pragma GCC unroll 8
  for (int i = 0; i < BIGINT_WORDS; i++) {
    L.data[i] = prod[i];
    H.data[i] = prod[i + BIGINT_WORDS];
  }

  uint32_t Rext[9] = {0};
  #pragma GCC unroll 8
  for (int i = 0; i < BIGINT_WORDS; i++) {Rext[i] = L.data[i];}
  Rext[8] = 0;

  uint32_t H977[9] = {0};
  multiply_bigint_by_const(&H, 977, H977);
  add_9word(Rext, H977);

  uint32_t Hshift[9] = {0};
  shift_left_word(&H, Hshift);
  add_9word(Rext, Hshift);

  if (Rext[8]) {
    uint32_t extra[9] = {0};
    BigInt extraBI;
    init_bigint(&extraBI, Rext[8]);
    Rext[8] = 0;

    uint32_t extra977[9] = {0}, extraShift[9] = {0};
    multiply_bigint_by_const(&extraBI, 977, extra977);
    shift_left_word(&extraBI, extraShift);

    #pragma GCC unroll 9
    for (int i = 0; i < 9; i++) {extra[i] = extra977[i];}
    add_9word(extra, extraShift);
    add_9word(Rext, extra);
  }

  BigInt R_temp;
  convert_9word_to_bigint(Rext, &R_temp);
  if (Rext[8] || compare_bigint(&R_temp, &const_p) >= 0) {u256Sub(&R_temp, &R_temp, &const_p);}
  if (compare_bigint(&R_temp, &const_p) >= 0) {u256Sub(&R_temp, &R_temp, &const_p);}
  copy_bigint(res, &R_temp);
}

void sub_mod_device(BigInt *res, const BigInt *a, const BigInt *b) {
  BigInt temp;
  if (compare_bigint(a, b) < 0) {
    BigInt sum;
    u256Add(&sum, a, &const_p);
    u256Sub(&temp, &sum, b);
  } else {
    u256Sub(&temp, a, b);
  }
  copy_bigint(res, &temp);
}

void modexp(BigInt *res, const BigInt *base, const BigInt *exp) {
  BigInt result;
  init_bigint(&result, 1);
  BigInt b;
  copy_bigint(&b, base);
  for (int i = 0; i < 256; i++) {
    if (get_bit(exp, i)) {mul_mod_device(&result, &result, &b);}
    mul_mod_device(&b, &b, &b);
  }
  copy_bigint(res, &result);
}

void mod_inverse(BigInt *res, const BigInt *a) {
  BigInt p_minus_2, two;
  init_bigint(&two, 2);
  u256Sub(&p_minus_2, &const_p, &two);
  modexp(res, a, &p_minus_2);
}

void point_copy_jac(ECPointJac *dest, const ECPointJac *src) {
  copy_bigint(&dest->X, &src->X);
  copy_bigint(&dest->Y, &src->Y);
  copy_bigint(&dest->Z, &src->Z);
  dest->infinity = src->infinity;
}

void double_point_jac(ECPointJac *R, const ECPointJac *P) {
  if (P->infinity || is_zero(&P->Y)) {point_set_infinity_jac(R); return;}
  BigInt A, B, C, D, X3, Y3, Z3, temp, temp2;
  mul_mod_device(&A, &P->Y, &P->Y);
  mul_mod_device(&temp, &P->X, &A);
  init_bigint(&temp2, 4);
  mul_mod_device(&B, &temp, &temp2);
  mul_mod_device(&temp, &A, &A);
  init_bigint(&temp2, 8);
  mul_mod_device(&C, &temp, &temp2);
  mul_mod_device(&temp, &P->X, &P->X);
  init_bigint(&temp2, 3);
  mul_mod_device(&D, &temp, &temp2);
  BigInt D2, two, twoB;
  mul_mod_device(&D2, &D, &D);
  init_bigint(&two, 2);
  mul_mod_device(&twoB, &B, &two);
  sub_mod_device(&X3, &D2, &twoB);
  sub_mod_device(&temp, &B, &X3);
  mul_mod_device(&temp, &D, &temp);
  sub_mod_device(&Y3, &temp, &C);
  init_bigint(&temp, 2);
  mul_mod_device(&temp, &temp, &P->Y);
  mul_mod_device(&Z3, &temp, &P->Z);
  copy_bigint(&R->X, &X3);
  copy_bigint(&R->Y, &Y3);
  copy_bigint(&R->Z, &Z3);
  R->infinity = false;
}

void add_point_jac(ECPointJac *R, const ECPointJac *P, const ECPointJac *Q) {
  if (P->infinity) {point_copy_jac(R, Q); return;}
  if (Q->infinity) {point_copy_jac(R, P); return;}

  BigInt Z1Z1, Z2Z2, U1, U2, S1, S2, H, R_big, H2, H3, U1H2, X3, Y3, Z3, temp;
  mul_mod_device(&Z1Z1, &P->Z, &P->Z);
  mul_mod_device(&Z2Z2, &Q->Z, &Q->Z);
  mul_mod_device(&U1, &P->X, &Z2Z2);
  mul_mod_device(&U2, &Q->X, &Z1Z1);
  BigInt Z2_cubed, Z1_cubed;
  mul_mod_device(&temp, &Z2Z2, &Q->Z); copy_bigint(&Z2_cubed, &temp);
  mul_mod_device(&temp, &Z1Z1, &P->Z); copy_bigint(&Z1_cubed, &temp);
  mul_mod_device(&S1, &P->Y, &Z2_cubed);
  mul_mod_device(&S2, &Q->Y, &Z1_cubed);

  if (compare_bigint(&U1, &U2) == 0) {
    if (compare_bigint(&S1, &S2) != 0) {point_set_infinity_jac(R); return;}
    else {double_point_jac(R, P); return;}
  }

  sub_mod_device(&H, &U2, &U1);
  sub_mod_device(&R_big, &S2, &S1);
  mul_mod_device(&H2, &H, &H);
  mul_mod_device(&H3, &H2, &H);
  mul_mod_device(&U1H2, &U1, &H2);
  BigInt R2, two, twoU1H2;
  mul_mod_device(&R2, &R_big, &R_big);
  init_bigint(&two, 2);
  mul_mod_device(&twoU1H2, &U1H2, &two);
  sub_mod_device(&temp, &R2, &H3);
  sub_mod_device(&X3, &temp, &twoU1H2);
  sub_mod_device(&temp, &U1H2, &X3);
  mul_mod_device(&temp, &R_big, &temp);
  mul_mod_device(&Y3, &S1, &H3);
  sub_mod_device(&Y3, &temp, &Y3);
  mul_mod_device(&temp, &P->Z, &Q->Z);
  mul_mod_device(&Z3, &temp, &H);
  copy_bigint(&R->X, &X3);
  copy_bigint(&R->Y, &Y3);
  copy_bigint(&R->Z, &Z3);
  R->infinity = false;
}

void scalar_multiply_jac_device(ECPointJac *result, const ECPointJac *point, const BigInt *scalar) {
  // const ECPointJac point:
  // X: 79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
  // Y: 483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8
  // Z: 0000000000000000000000000000000000000000000000000000000000000001

  // const BigInt scalar
  // 0000000000000000000000000000000000000000000000000000000000556e52

  const int WINDOW_SIZE = 4;
  const int PRECOMP_SIZE = 1 << WINDOW_SIZE;    // PRECOMP_SIZE = 16
  
  // Use shared memory for precomputed points
  ECPointJac shared_precomp[PRECOMP_SIZE];

  // Each thread computes some precomputed points
  for (int i = 0; i < PRECOMP_SIZE; i++) {
    if (i == 0)       {point_set_infinity_jac(&shared_precomp[0]);} 
    else if (i == 1)  {point_copy_jac(&shared_precomp[1], point);} 
    else              {add_point_jac(&shared_precomp[i], &shared_precomp[i-1], point);}
  }
    
  // Find the highest non-zero bit
  int highest_bit = BIGINT_WORDS * 32 - 1;        // 8 * 32 - 1 = 255
  for (; highest_bit >= 0; highest_bit--) {
    if (get_bit(scalar, highest_bit)) {break;}
  }

  // 0x556e52 => 0101 0101 0110 1110 0101 0010 => highest_bit = 22
  
  if (highest_bit < 0) {point_set_infinity_jac(result); return;}
  
  // Initialize result
  ECPointJac res;
  point_set_infinity_jac(&res);
  
  // Process scalar in windows of WINDOW_SIZE bits
  int i = highest_bit;      // highest_bit = 22
  while (i >= 0) {
    // Determine window size for this iteration
    int window_bits = (i >= WINDOW_SIZE - 1) ? WINDOW_SIZE : (i + 1);
    
    // Double 'window_bits' times
    for (int j = 0; j < window_bits; j++) {double_point_jac(&res, &res);}
    
    // Extract window value
    int window_value = 0;
    for (int j = 0; j < window_bits; j++) {
      if (i - j >= 0 && get_bit(scalar, i - j)) {window_value |= (1 << (window_bits - 1 - j));}
    }
    
    // Add precomputed point if window value is non-zero
    if (window_value > 0) {add_point_jac(&res, &res, &shared_precomp[window_value]);}
    
    i -= window_bits;
  }

  point_copy_jac(result, &res);     // result <= res

  // result:
  // X: a2751584ca9449b2b58b1e25d3c8cfc9542753813bae0049f8f1d17dbfe84ab5
  // Y: 3769e016b188d09faaf549ec66c99f6c664696e886a863dfa52b8bd375c100c4
  // Z: 8cce5b2f3fbd6dad02f860356e15300ed5b511a17eb98ae53e0bf6b03614ff7f
}

void jacobian_to_affine(ECPoint *R, const ECPointJac *P) {
  if (P->infinity) {
    R->infinity = true;
    init_bigint(&R->x, 0);
    init_bigint(&R->y, 0);
    return;
  }
  BigInt Zinv, Zinv2, Zinv3;
  mod_inverse(&Zinv, &P->Z);
  mul_mod_device(&Zinv2, &Zinv, &Zinv);
  mul_mod_device(&Zinv3, &Zinv2, &Zinv);
  mul_mod_device(&R->x, &P->X, &Zinv2);
  mul_mod_device(&R->y, &P->Y, &Zinv3);
  R->infinity = false;
}

// Convert to big-endian byte order
uint8_t get_byte(const BigInt *a, int i) {
  int word_index = 7 - (i / 4);         // reverse word order
  int byte_index = 3 - (i % 4);         // reverse byte order within word
  return (a->data[word_index] >> (8 * byte_index)) & 0xFF;
}

void coords_to_compressed_pubkey(const BigInt *x, const BigInt *y, uint8_t *pubkey) {
  // Prefix: 0x02 if y is even, 0x03 if y is odd
  pubkey[0] = (y->data[0] & 1) ? 0x03 : 0x02;

  // Copy x coordinate (32 bytes) with unrolling
  #pragma GCC unroll 32
  for (int i = 0; i < 32; i++) {pubkey[1 + i] = get_byte(x, i);}
}

void gcc_PublicKey_COMPRESSED() {
  BigInt priv;
  ECPointJac result_jac;
  ECPoint public_key;

  // secp256k1 CUDA lib
  copy_uint8_to_bigint(privateKey, &priv);
  scalar_multiply_jac_device(&result_jac, &const_g, &priv);
  jacobian_to_affine(&public_key, &result_jac);
  coords_to_compressed_pubkey(&public_key.x, &public_key.y, publicKey_Compressed);

  /*
  Serial.printf("\npriv:\n");
  for (int i=0; i<32; i++) {Serial.printf("%02x", get_byte(priv, i));}
  Serial.printf("\n");
  Serial.printf("\npublic_key.x:\n");
  for (int i=0; i<32; i++) {Serial.printf("%02x", get_byte(public_key.x, i));}
  Serial.printf("\n");
  Serial.printf("\npublic_key.y:\n");
  for (int i=0; i<32; i++) {Serial.printf("%02x", get_byte(public_key.y, i));}
  Serial.printf("\n");
  */
}
// === secp256k1 (7331 us) ============================================

void setup() {
  pinMode(BTN_PIN, INPUT_PULLUP);  	// BUTTON RESET E-Paper (0 - Press)
  pinMode(BUZZER_PIN, OUTPUT);     	// OUT BUZZER (1 - On)
  pinMode(LED_PIN, OUTPUT);        	// OUT LED    (0 - On)
  digitalWrite(BUZZER_PIN, LOW);   	// BUZZER OFF
  digitalWrite(LED_PIN, HIGH);      // LED    OFF
  delay(1000);               		// Delay for start USB

  // Setting ADC
  analogReadResolution(12);                             // 12 bit (0-4095)
  analogSetAttenuation(ADC_ATTENDB_MAX);                // 4

  setCpuFrequencyMhz(160);                            	// {160, 80}
  uint16_t currentFrequency = getCpuFrequencyMhz();     // 160 MHz
  Serial.begin(115200);
  while(!Serial);
  ledFlash(100, 100, 2);
  Serial.printf("\nMCU: %d MHz\n", currentFrequency);

  uint8_t d = rnd_adc();
  delay(d/2);
  init_rnd();
  Serial.printf("Init RND (x,y,z,w): %d, %d, %d, %d\n", x, y, z, w);
  // Init RND (x,y,z,w): 1454, 31292, 12145, 39236
  // Init RND (x,y,z,w): 19034, 1, 5763, 31751
  // Init RND (x,y,z,w): 3477, 33944, 52943, 62633

  Serial.print("=== TEST SATOSHI PUZZLE 1 ===\n");

  for (uint8_t i=0; i<31; i++) {privateKey[i] = 0;}
  privateKey[31] = 1;

  Serial.print("Private Key:\n");
  printHex(privateKey, 32);
  // 0000000000000000000000000000000000000000000000000000000000000001

  start = micros();
  gcc_PublicKey_COMPRESSED();
  end = micros();

  Serial.printf("secp256k1 Time: %llu\n", end-start);	// secp256k1 Time: 7331 us
  
  Serial.print("Public Key Compressed:\n");
  printHex(publicKey_Compressed, 33);
  // 0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798

  start = micros();
  gcc_sha256(publicKey_Compressed, 33, keyHash_Compressed);
  end = micros();

  Serial.printf("SHA-256 Time: %llu\n", end-start);  	// SHA-256 Time: 85 us
  Serial.print("SHA-256 Hash:\n");
  printHex(keyHash_Compressed, 32);
  // 0f715baf5d4c2ed329785cef29e562f73488c8a2bb9dbc5700b361d54b9b0554

  start = micros();
  gcc_ripemd160(keyHash_Compressed, 32, ripemd_160_c);
  end = micros();

  Serial.printf("RIPEMD-160 Time: %llu\n", end-start);	// RIPEMD-160 Time: 105 us
  Serial.print("RIPEMD-160 Hash:\n");
  printHex(ripemd_160_c, 20);
  // 751e76e8199196d454941c45d1b3a323f1433bd6
  Serial.print("=== END TEST ===\n\n");

  ledFlash(100, 100, 2);
  buzzerFlash();

  EEPROM.begin(64);
  uint8_t s = EEPROM.read(1);
  if (s == 1) {
    for (i=0; i<32; i++) {privateKey[i] = EEPROM.read(10+i); delay(1);}
    EEPROM.end();
    while (1) {
      Serial.print("\n=== Found! ===\n");
      printHex(privateKey, 32);
      buzzerFlash();
      delay(1000);
      if (!digitalRead(BTN_PIN)) {
        delay(100);
        if (!digitalRead(BTN_PIN)) {
          delay(100);
          if (!digitalRead(BTN_PIN)) {
            EEPROM.begin(64);
            EEPROM.write(1, 0);
            delay(1);
            EEPROM.commit();
            EEPROM.end();
            outEpaper(0);
            Serial.print("=== Clear E-Parer ===\n");
			ledFlash(100, 100, 3);
            delay(1000);
            esp_restart();
          }
        }
      }
    }
  }

  outEpaper(0);

  if (!digitalRead(BTN_PIN)) {
    delay(100);
    if (!digitalRead(BTN_PIN)) {
      delay(100);
      if (!digitalRead(BTN_PIN)) {
        EEPROM.begin(64);
        EEPROM.write(1, 0);
        delay(1);
        EEPROM.commit();
        EEPROM.end();
        Serial.print("=== Clear Data ===\n");
		ledFlash(100, 100, 3);
      }
    }
  }

  start = micros();

  // Task Watchdog set 5 s
  esp_task_wdt_init(5, true);
  esp_task_wdt_add(NULL);

  /*
  MCU: 160 MHz
  Init RND (x,y,z,w): 59035, 28723, 12792, 18457
  === TEST SATOSHI PUZZLE 1 ===
  Private Key:
  0000000000000000000000000000000000000000000000000000000000000001
  secp256k1 Time: 7331
  Public Key Compressed:
  0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
  SHA-256 Time: 85
  SHA-256 Hash:
  0f715baf5d4c2ed329785cef29e562f73488c8a2bb9dbc5700b361d54b9b0554
  RIPEMD-160 Time: 105
  RIPEMD-160 Hash:
  751e76e8199196d454941c45d1b3a323f1433bd6
  === END TEST ===
  */
}

void loop() {
  // === Test RND ===
  //uint16_t x1 = rnd_adc(); 		// xorshift16();
  //uint16_t y1 = rnd_adc(); 		// xorshift16();
  //uint16_t z1 = rnd_adc(); 		// xorshift16();
  //uint16_t w1 = rnd_adc(); 		// xorshift16();
  // https://github.com/CieNTi/serial_port_plotter
  //Serial.printf("$%d %d %d %d;\r\n", x1, y1+80000, z1+160000, w1+240000);
  //Serial.printf("$%d %d %d %d;\r\n", x1, y1, z1, w1);
  // https://dot1nt.github.io/webplot/
  //Serial.printf("%d,%d,%d,%d\r\n", x1, y1+80000, z1+160000, w1+240000);
  //Serial.printf("%d,%d,%d,%d\r\n", x1, y1, z1, w1);
  // === Test RND ===

  // === Read UART ===
  if (Serial.available()) {
    while (Serial.available()) {
      bufRx[countRx] = Serial.read();
      strRx += (char)bufRx[countRx];
      countRx++;

      if (strRx.equals("START\r\n")) {
        display.init();
        display.setRotation(1);
        display.setFont(&FreeMonoBold9pt7b);
        display.fillScreen(GxEPD_WHITE);
        display.setTextColor(GxEPD_BLACK);
        display.firstPage();

        do {
          display.setTextSize(2);
          display.setCursor(10, 50);
          display.print("START");
          display.setCursor(10, 90);
          display.print("          ");
        } while (display.nextPage());

        strRx = "";
        bufRx[0] = 0;
        bufRx[64] = 0;
        bufRx[65] = 0;
        countRx = 0;
		Serial.println("=== START ===");
		ledFlash(10, 10, 1);
      }

      if (countRx == 66) {
        if (strRx.endsWith("\r\n")) {
          strRx.replace("\r\n", "");
          countRx = 0;
          bufRx[64] = 0;
          bufRx[65] = 0;
          size_t n = hexStringToBytes(strRx.c_str(), privateKey, sizeof(privateKey));
          if (n) {printEpaper(1);}
          strRx = "";
        }
      }
    }
  } else {countRx = 0; strRx = "";}

  //if (ledState) {ledState = 0;} else {ledState = 1;}
  //digitalWrite(LED_PIN, ledState);          // 21.4 ms => 46 key/s (5.1V, 32 mA, 0.165W)

  counter++;
  if (counter % 100 == 0) {
    end = micros();
    Serial.printf("%llu [%.3f s] -> ", counter, (end-start)/1000000.0); printHex(privateKey, 32);
    esp_task_wdt_reset();
	ledFlash(10, 1, 1);
	start = micros();
    // 100 [2.118 s] -> 0000000000000000000000000000000000000000000000734b0abd8b621c14c3
	// 200 [2.132 s] -> 000000000000000000000000000000000000000000000069bb4af38d9f44ae36
	// 300 [2.137 s] -> 00000000000000000000000000000000000000000000004a9bad9e89acefbb93
  }

  if (counter % 1000 == 0) {
    init_rnd();
    sprintf(str, "%d 000", counter/1000);

    display.init();
    display.setRotation(1);
    display.setFont(&FreeMonoBold9pt7b);
    display.fillScreen(GxEPD_WHITE);
    display.setTextColor(GxEPD_BLACK);
    display.firstPage();

    do {
      display.setTextSize(2);
      display.setCursor(10, 50);
      display.print(logo2);
      display.setCursor(10, 90);
      display.print(str);
    } while (display.nextPage());
  }

  i = 0;
  for (uint8_t j=0; j<23; j++) {privateKey[i] = 0; i++;}

  privateKey[i] = (uint8_t)xorshift16()&0x7f|0x40; i++;

  for (uint8_t j=0; j<4; j++) {
    uint16_t dd = xorshift16();
    privateKey[i] = dd>>8; i++;
    privateKey[i] = dd; i++;
  }
  // 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0040 0000 0000 0000 0000 (64)
  // 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0080 0000 0000 0000 0000 (128)

  //Serial.printf("%d -> ", counter);
  //printHex(privateKey, 32);
  // 0000000000000000000000000000000000000000000000000000000000000001

  gcc_PublicKey_COMPRESSED();
  //printHex(publicKey_Compressed, 33);
  // 0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798

  gcc_sha256(publicKey_Compressed, 33, keyHash_Compressed);
  //printHex(keyHash_Compressed, 32);
  // 0f715baf5d4c2ed329785cef29e562f73488c8a2bb9dbc5700b361d54b9b0554

  gcc_ripemd160(keyHash_Compressed, 32, ripemd_160_c);
  //printHex(ripemd_160_c, 20);
  // 751e76e8199196d454941c45d1b3a323f1433bd6

  // === TEST for COMPARE ===
  //if (counter == 555) {for (i=0; i<20; i++) {ripemd_160_c[i] = addr[0][i];} Serial.print("\nCopy\n");}
  // === TEST for COMPARE ===

  // === COMPARE ===
  for (i=0; i<20; i++) {if (ripemd_160_c[i] != addr[0][i]) {break;}}    // addr[0] => Puzzle 71
  if (i == 20) {
    printEpaper(0);
  }
  // === COMPARE ===
}
