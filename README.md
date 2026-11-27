# departure-board
Melbourne Public Transport Departure Board using ESP32 and SSD1306

Setup:
1. Parts: ESP32 DevKit, 0.96" SSD1306, four female to female jumper wires or a breadboard, USB-C power source
2. Wiring: SDA to GPIO 21, SCL to GPIO 22, 3V3 to VIN, GND to GND
<img width="286" height="166" alt="image" src="https://github.com/user-attachments/assets/18a072ef-c3fe-4ff9-bedd-f590ec3d67da" />

3. Libraries: Adafruit SSD1306, Adafruit GFX, ArduinoJson v7, ESP32 Arduino core 3.x
4. API: Register for [https://www.vic.gov.au/public-transport-timetable-api](PTV API)
5. Code: Input constants for WIFI_SSID, WIFI_PASSWORD, DEV_ID, API_KEY
6. Flash: Using Arduino IDE, flash the code to the
7. Settings: Use https://ptv.local to input metadata
