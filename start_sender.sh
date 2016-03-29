#!/bin/sh

sudo ./gradlew :sender:clean :sender:jarAll
sudo java -jar sender/build/libs/sender-all-1.0.jar
