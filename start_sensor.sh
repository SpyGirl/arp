#!/bin/sh

sudo ./gradlew :sensor:clean :sensor:jarAll
sudo java -jar sensor/build/libs/sensor-all-1.0.jar
