# ApkSign library: works on Android Device
This library can sign Android application on an Android device.

## Usage
If you want to test this library, run the follow command.

```
$ cd libsample
$ java -jar ApkSign-0.0.1-SNAPSHOT-jar-with-dependencies.jar
```

If you want to run this library on an Android device, please look MainActivity.java

## Use test Application

ApkSignatureSample.apk is the sample application which signs non-sign apk on the Android device.

```
$ adb install ApkSignatureSample.apk
```

If you start the activity and push the button, the application makes signed apk in /data/data/com.example.apksignaturesample/files/

