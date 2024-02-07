#include <Wire.h>
#include <Adafruit_GFX.h>
#include <Adafruit_SSD1306.h>

#define SCREEN_WIDTH 128 // OLED display width, in pixels
#define SCREEN_HEIGHT 64 // OLED display height, in pixels

//pins
const int greenLed = 5;
const int orangeLed = 18;
const int redLed = 19;
const int buzzer = 23;
const int pushButton = 17;

unsigned long previousMillis = 0;

const long greenDuration = 5000;
const long orangeDuration = 2000;
const long redDuration = 5000;
const long pedestrianWaitDuration = 2000;
const long pedestrianCrossDuration = 5000;

int readPushbutton = 0;
// Declaration for an SSD1306 display connected to I2C (SDA, SCL pins)
Adafruit_SSD1306 display(SCREEN_WIDTH, SCREEN_HEIGHT, &Wire, -1);

void PlaySound(int buzzer){
  if (digitalRead(redLed) == HIGH) // Check if the GREEN_C is HIGH
    {tone(buzzer,10,10);}}

void setup()
{Serial.begin(115200);
  if(!display.begin(SSD1306_SWITCHCAPVCC, 0x3C)) { // Address 0x3D for 128x64
    Serial.println(F("SSD1306 allocation failed"));
    for(;;);}
  delay(2000);
  display.clearDisplay();
  display.setTextSize(2);
  display.setTextColor(WHITE);
  display.setCursor(0, 0);
  display.display(); 
  delay(100);
  pinMode(greenLed, OUTPUT);
  pinMode(orangeLed, OUTPUT);
  pinMode(redLed, OUTPUT);
  digitalWrite(greenLed, LOW);
  digitalWrite(orangeLed, LOW);
  digitalWrite(redLed, LOW);

  pinMode(pushButton, INPUT);
  //for the serial monitor
  Serial.begin(9600);}
void loop()
{ int readPushbutton = digitalRead(pushButton);
    if (readPushbutton == 0 ) {
    	digitalWrite(greenLed, HIGH);
  		digitalWrite(orangeLed, LOW);
  		digitalWrite(redLed, LOW);  
          Serial.println("PEDESTRIAN WAITING");
      for(int i = 3; i!=0; i--){
        display.setCursor(0, 0);
        display.clearDisplay();
        String output = String(i) + " wait !";
        display.println(output);
        display.display(); 
        delay(1000);}
      display.clearDisplay();
    	// delay(3000);
      digitalWrite(greenLed, LOW);
  		digitalWrite(orangeLed, HIGH);
  		digitalWrite(redLed, LOW);  
      for(int i = 2; i!=0; i--){
                display.setCursor(0, 0);
        display.clearDisplay();
        String output = String(i) + " wait !";
        display.println(output);
        display.display(); 
        delay(1000);}
      display.clearDisplay();
    	// delay(2000);
  		    Serial.println("PEDESTRIAN CROSSING");
      digitalWrite(greenLed, LOW);
  		digitalWrite(orangeLed, LOW);
  		digitalWrite(redLed, HIGH);  
      for(int i = 5; i!=0; i--){
                display.setCursor(0, 0);
                PlaySound(buzzer);
          display.clearDisplay();
        String output = String(i) + " cross !";
        display.println(output);
        display.display(); 
        delay(1000);}
                // PlaySound(buzzer);}
      display.clearDisplay();
      // PlaySound(buzzer);
    	// delay(5000); 	
    }
    else if (readPushbutton == 1){
        readPushbutton = 0;
      	    Serial.println("PEDESTRIAN WAITING");
       	digitalWrite(greenLed,LOW);
  		digitalWrite(orangeLed,HIGH);
      	digitalWrite(redLed, LOW); 
        for(int i = 2; i!=0; i--){display.setCursor(0, 0);
        display.clearDisplay();
        String output = String(i) + " wait !";
        display.println(output);
        display.display(); 
        delay(1000);}
  		// delay(2000);
      display.clearDisplay();
      
      digitalWrite(greenLed,LOW);
   		digitalWrite(orangeLed,LOW);
  		digitalWrite(redLed,HIGH);
  		    Serial.println("PEDESTRIAN CROSSING");
      for(int i = 5; i!=0; i--){
                display.setCursor(0, 0);
                PlaySound(buzzer);
          display.clearDisplay();
        String output = String(i) + " cross !";
        display.println(output);
        display.display(); 
        delay(1000);}
        // PlaySound(buzzer);
  		// delay(5000);
}}

//without OLED variant

///save///
// const int greenLed = 5;
// const int orangeLed = 18;
// const int redLed = 19;
// const int buzzer = 21;
// const int pushButton = 17;

// unsigned long previousMillis = 0;
// const long greenDuration = 5000;
// const long orangeDuration = 2000;
// const long redDuration = 5000;
// const long pedestrianWaitDuration = 2000;
// const long pedestrianCrossDuration = 5000;

// int readPushbutton = 0;

// void PlaySound(int buzzer){
//   if (digitalRead(redLed) == HIGH) // Check if the GREEN_C is HIGH
//     {
//       for (int i = 0; i < 9; i++) // Use a loop for the buzzer
//       {
//         tone(buzzer, 1000, 500);
//         delay(100);
//       }
//   }}

// void setup()
// {
//   pinMode(greenLed, OUTPUT);
//   pinMode(orangeLed, OUTPUT);
//   pinMode(redLed, OUTPUT);
 
//   //Turn the LEDs off
//   digitalWrite(greenLed, LOW);
//   digitalWrite(orangeLed, LOW);
//   digitalWrite(redLed, LOW);
  
//   //setting the buttons to input
//   pinMode(pushButton, INPUT);
  
  
//   //for the serial monitor
//   Serial.begin(9600);
// }
// void OLED_display(){
//   //free code here from python variant
// }
// void loop()
// {

//   int readPushbutton = digitalRead(pushButton);
  
//   if (readPushbutton == 0 ) {
//     	digitalWrite(greenLed, HIGH);
//   		digitalWrite(orangeLed, LOW);
//   		digitalWrite(redLed, LOW);  
//       Serial.println("PEDESTRIAN WAITING");
//     	delay(3000);
//       digitalWrite(greenLed, LOW);
//   		digitalWrite(orangeLed, HIGH);
//   		digitalWrite(redLed, LOW);  
//     	delay(2000);
//   		Serial.println("PEDESTRIAN CROSSING");
//       digitalWrite(greenLed, LOW);
//   		digitalWrite(orangeLed, LOW);
//   		digitalWrite(redLed, HIGH);  
//       PlaySound(buzzer);
//     	delay(5000);
      	
//     }
//     else if (readPushbutton == 1){
//         readPushbutton = 0;
//       	Serial.println("PEDESTRIAN WAITING");
//        	digitalWrite(greenLed,LOW);
//   		digitalWrite(orangeLed,HIGH);
//       	digitalWrite(redLed, LOW); 
//   		delay(2000);
      
//       	digitalWrite(greenLed,LOW);
//    		digitalWrite(orangeLed,LOW);
//   		digitalWrite(redLed,HIGH);
//   		Serial.println("PEDESTRIAN CROSSING");
//       PlaySound(buzzer);
//   		delay(5000);
            
//     }
  
// }