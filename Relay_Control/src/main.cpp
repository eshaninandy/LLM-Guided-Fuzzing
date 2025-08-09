#include <Arduino.h>

const int RELAY_PIN = 11;

void setup() {
  Serial.begin(9600);
  pinMode(RELAY_PIN, OUTPUT);

  // Start with Pi OFF
  digitalWrite(RELAY_PIN, LOW); // LOW = Power OFF
}

void loop() {
  if (Serial.available()) {
    String cmd = Serial.readStringUntil('\n');
    cmd.trim(); // Remove any newline or whitespace

    if (cmd == "RESET" or cmd == "OFF1") {
      digitalWrite(RELAY_PIN, LOW);   // Power OFF
      //delay(3000);                    // Wait 3 seconds
      //digitalWrite(RELAY_PIN, HIGH);  // Power ON
    } else if (cmd == "ON1") {
      digitalWrite(RELAY_PIN, HIGH);  // Power ON
    } //else if (cmd == "OFF1") {
      //digitalWrite(RELAY_PIN, LOW);   // Power OFF
    //}
  }
}
