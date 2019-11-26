
#include <SHA256.h>


#include <EEPROM.h>

#include <types.h>
#include <uECC.h>
#include <uECC_vli.h>


static int RNG(uint8_t *dest, unsigned size) {
  // Use the least-significant bits from the ADC for an unconnected pin (or connected to a source of 
  // random noise). This can take a long time to generate random data if the result of analogRead(0) 
  // doesn't change very frequently.
  while (size) {
    uint8_t val = 0;
    for (unsigned i = 0; i < 8; ++i) {
      int init = analogRead(0);
      int count = 0;
      while (analogRead(0) == init) {
        ++count;
      }
      
      if (count == 0) {
         val = (val << 1) | (init & 0x01);
      } else {
         val = (val << 1) | (count & 0x01);
      }
    }
    *dest = val;
    ++dest;
    --size;
  }
  // NOTE: it would be a good idea to hash the resulting random data using SHA-256 or similar.
  return 1;
}

const struct uECC_Curve_t *curve = uECC_secp256k1();
const int PRVBYTES = uECC_curve_private_key_size(curve);
const int PUBBYTES = uECC_curve_public_key_size(curve);
uint8_t *private_key = new uint8_t [PRVBYTES];
uint8_t *public_key = new uint8_t [PUBBYTES];
uint8_t *Peer_pub = new uint8_t [PUBBYTES];

#define BUFF_LEN 256
uint8_t buff[BUFF_LEN];

#define HASH_LEN 32
uint8_t hash[HASH_LEN];
uint8_t signature[64];
SHA256 sha256 = SHA256();

#define MAIN_MENU     1<<0
#define SETTINGS_MENU 1<<1
#define DSA_MENU      1<<2
#define DH_MENU       1<<3
#define HASH_MENU     1<<4
uint8_t menu_state = MAIN_MENU;

bool prompt_setting = true;

#define OUTPUT_RAW 1<<0
#define OUTPUT_HEX 1<<1
uint8_t output_setting = OUTPUT_HEX;

#define HASH_LEN 32

void setup() {
  // put your setup code here, to run once:
  Serial.begin(115200);
  uECC_set_rng(&RNG);
  prompt();
}

uint8_t hex2bin(char c) {
  if ((c >= '0') && (c <='9'))
    return (c - '0');
  if ((c >='a') && (c <= 'f'))
    return (10 + c - 'a');
  if ((c >='A') && (c <= 'F'))
    return (10 + c - 'A');
  return 0;
}

void prompt() {
  if (! prompt_setting) return;
  switch (menu_state) {
    case DSA_MENU:
      Serial.print("ECDSA> ");
      break;
    case DH_MENU:
      Serial.print("ECDH> ");
      break;
    case HASH_MENU:
      Serial.print("SHA-256> ");
      break;
    case SETTINGS_MENU:
      Serial.print("Settings> ");
      break;
    default:
      Serial.print("> ");
  }
}
void loop() {
  // put your main code here, to run repeatedly:
  if(Serial.available()) {
    char c = Serial.read();
    if (prompt_setting) Serial.println(c);
    switch (menu_state) {
      case MAIN_MENU:
        main_menu(c);
        break;
      case HASH_MENU:
        hash_menu(c);
        break;
      case DSA_MENU:
        ecdsa_menu(c);
        break;
      case SETTINGS_MENU:
        settings_menu(c);
        break;
      default:
        if (prompt_setting) Serial.println("Escaped menu system!");
        menu_state = MAIN_MENU;
    }
    prompt();
  }
}

void main_menu(char c) {
  switch (c) {
     case 'h':
      menu_state = HASH_MENU;
      break;
     case 'k':
      menu_state = DSA_MENU;
      break;
     case 's':
      menu_state = SETTINGS_MENU;
      break;
     case '?':
      main_help();
      break;
     default:
      if (prompt_setting) Serial.println("Command not recognised. Send '?' for help.");
  }
}
void main_help() {
  Serial.println("?:\tPrint this help screen");
  Serial.println("k:\tECDSA menu");
  Serial.println("h:\tHash menu");
  Serial.println("s:\tSettings menu");
}

void ecdsa_menu(char c) {
  switch (c) {
    case 'g':
      gen_key(private_key, public_key);
      break;
    case 'p':
      for(int i = 0; i < PUBBYTES; i++)
        printByte(public_key[i]);
      if (prompt_setting) Serial.println();
      break;
    case 'q':
      menu_state = MAIN_MENU;
      break;
    case '?':
      ecdsa_help();
      break;
    default:
      if (prompt_setting) Serial.print("Command unknown. Send '?' for help menu.");
  }
}
void ecdsa_help() {
  Serial.println("?:\tPrint this help screen");
  Serial.println("q:\tReturn to main menu");
  Serial.println("g:\tGenerate ECDSA keypair");
  Serial.println("p:\tPrint public key");
}

void hash_menu(char c) {
  switch (c) {
    case 'd':
      for(int i = 0; i < HASH_LEN; i++) {
        printByte(hash[i]);
      }
      if (prompt_setting) Serial.println();
      break;
    case 'm':
      readBytes(BUFF_LEN);
      sha256_hash(buff, BUFF_LEN);
      break;
    case 'p':
      sha256_hash(public_key, PRVBYTES);
      break;
    case 'P':
      sha256_hash(private_key, PRVBYTES);
      break;
    case '?':
      hash_help();
      break;
    case 'q':
      menu_state = MAIN_MENU;
      break;
  }
}

void hash_help() {
  Serial.println("?:\tPrint this help screen");
  Serial.println("q:\tReturn to main menu");
  Serial.println("d:\tPrint hash");
  Serial.println("m:\tRead into buffer");
  Serial.println("p:\tSHA-256 of public key");
  Serial.println("P:\tSHA-256 of private key");
}

void settings_menu(char c) {
  switch (c) {
    case 'q':
      menu_state = MAIN_MENU;
      break;
    case 'o':
      output_setting = OUTPUT_RAW;
      break;
    case 'O':
      output_setting = OUTPUT_HEX;
      break;
    case 'p':
      prompt_setting = !prompt_setting;
      break;
    case '?':
      settings_help();
      break;
  }
}

void settings_help() {
  Serial.println("?:\tPrint this help screen");
  Serial.println("q:\tReturn to main menu");
  Serial.println("o:\tOutput in raw binary");
  Serial.println("O:\tOutput in ASCII hexidecimal");
  Serial.println("p:\tToggle prompt on and off");
}

void sha256_hash(void *buff, size_t len) {
  sha256.reset();
  sha256.update(buff, len);
  sha256.finalize(hash, HASH_LEN);
  sha256.reset();
}

void printByte(uint8_t c) {
  switch (output_setting) {
    case OUTPUT_RAW:
      Serial.print(c);
      break;
    case OUTPUT_HEX:
      Serial.printf("%02X", c);
      break;
  }
}

void readBytes(size_t len) {
  if (len > BUFF_LEN)
    len = BUFF_LEN;
  switch (output_setting){
    case OUTPUT_RAW:
      for(int i = 0; i < len; i++) {
        while(!Serial.available()){};
        buff[i] = Serial.read();
      }    
      break;
    case OUTPUT_HEX:
      for(int i = 0; i < len; i++) {
        while(!Serial.available()){};
        int a = hex2bin(Serial.read());
        while(!Serial.available()){};
        int b = hex2bin(Serial.read());
        buff[i] = a*16+b;
      }
      break;
  }
}

void gen_key(uint8_t *priv, uint8_t *pub) {
  uECC_make_key(pub, priv, curve);
}
