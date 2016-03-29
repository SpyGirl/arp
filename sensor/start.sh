#!/bin/sh

.././gradlew clean jarAll
sudo java -jar build/libs/sensor-all-1.0.jar
