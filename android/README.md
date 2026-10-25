# Gommage for Android

Gommage for Android TV and Android phones: one button that connects the whole device to Tor through bridges. It's the Android version of the [Gommage desktop app](../README.md), with the same look. One APK covers both: TVs get a wide layout driven by the remote, phones get the desktop window's upright switch.

## What it does

- **Whole-device VPN.** Every app (YouTube, browsers, streaming apps, Telegram) goes through Tor. DNS goes through Tor too, and IPv6 is captured so it can't leak.
- **Bridges in the same order as the desktop app.** It tries your own bridges and the ones that worked last time first. Then it fetches the public bridge lists from GitHub (or the jsDelivr mirror), tests them in parallel and uses the 15 fastest. After that it tries Tor's built-in obfs4 bridges, and Snowflake last.
- **Exit country**, **New identity** and a connection timer.
- **TV remote:** OK on the switch connects; Up reaches the flags, where left and right change the country.

## Install

Download `Gommage.apk` from [Releases](../../../releases) (the `android-v…` release).

**Phone:** open the APK and install it. Allow installs from unknown sources if Android asks.

**TV:**

1. Copy `Gommage.apk` to a USB stick, or send it with an app like *Send Files to TV*.
2. On the TV, allow installs from unknown sources for your file manager. On Android TV that's Settings → Device Preferences → Security & restrictions → Unknown sources.
3. Open the APK and install it. Gommage then shows up on the home screen.

Press **START**. The first time, Android asks you to allow the VPN.

The TV needs to run **Android TV / Google TV**. Other TV systems (Tizen, webOS, or custom Linux) can't install APKs. The app installs on Android 7 and newer. The tunnel library is built for Android 10, though, so on Android 7–9 the VPN may not start.

## Build

You need JDK 24+ (tor-android ships Java 24 class files) and the Android SDK with platform `android-37.2`. From Iran, Google's SDK servers need a VPN.

```bash
./gradlew assembleDebug
```

The APK is written to `app/build/outputs/apk/debug/app-debug.apk` (ARM only; add `-Pabis=x86_64` for the emulator). Run the bridge-parsing checks with `./gradlew test`.

## Built on

- [tor-android](https://github.com/guardianproject/tor-android) (Tor) and [IPtProxy](https://github.com/tladesignz/IPtProxy) (obfs4, webtunnel, Snowflake), both from the Guardian Project and also used by Orbot
- [hev-socks5-tunnel](https://github.com/heiher/hev-socks5-tunnel), which carries the VPN's traffic into Tor's SOCKS port (prebuilt AAR in `app/libs`)
- Flags from [circle-flags](https://github.com/HatScripts/circle-flags) and the Red Hat Display font, as in the desktop app (licences in `app/src/main/assets`)

Licensed under GPLv3, like the desktop app.
