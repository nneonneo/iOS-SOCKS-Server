# What

A simple HTTP/SOCKS proxy designed to run on Pythonista on iOS, letting you fake-tether your devices to a phone.
It can also run on Android (Termux) with automatic hotspot IP detection.

# Installation

- Install Pythonista from the [App Store](https://apps.apple.com/us/app/pythonista-3/id1085978097). It's a paid app, but it's worth every penny if you are a power user.
- Download the code from [GitHub](https://github.com/nneonneo/iOS-SOCKS-Server/archive/master.zip).
- Open the Files app, navigate to Downloads, and tap on the zip file to uncompress it.
- Move the resulting `iOS-SOCKS-Server` folder to the Pythonista iCloud directory
- Open Pythonista, navigate to iCloud, `iOS-SOCKS-Server` and open the `socks5.py` script.
- Optionally, you can tap on the wrench and select `Shortcuts...` to add the script to your home screen. 

# Running (iOS)

- Connect your devices to the same WiFi network as your phone. If there's no suitable network, you can create a computer-to-computer (ad-hoc) network using your laptop and connect to it with your phone.
- Open the home screen shortcut (if you made one), or open the `socks5.py` script in Pythonista and hit Run. 
- Point your devices at the PAC URL (also called script URL, script address, etc.), or configure them to use the SOCKS proxy listed.
    - For iOS devices: open Settings, tap on Wi-Fi, tap on the (i) icon next to the network, scroll down to HTTP Proxy, tap on Configure Proxy, select Automatic, and enter the PAC URL as displayed in Pythonista in the URL field (the URL will look like http://123.123.123.123:8080/wpad.dat).
    - For macOS: open System Preferences -> Network, click on Wi-Fi, hit Advanced..., and under Proxies check SOCKS Proxy and set the host:port to the SOCKS Address as displayed in Pythonista (this will be of the form 123.123.123.123:9876).
        - If you are using an ad-hoc Wi-Fi network (i.e. Wi-Fi menu -> Create Network), you will need to do some extra setup here. Under the TCP/IP tab, copy the existing 169.254.y.z IPv4 address, then switch Configure IPv4 to Manually, enter the 169.254.y.z IP address in both IPv4 Address and Router, and enter 255.255.0.0 as Subnet Mask. Under the DNS tab, add 169.254.y.z to the DNS Servers list.
        - Make sure you set proxy settings in any other application that is not using the system proxy settings.
    - For Windows or Linux, please follow the appropriate instructions for configuring a proxy on your system. It is recommended that you use the PAC URL if possible (also called a setup script or automatic configuration script).
        - On Windows, you may consider using the [SSTap](https://sourceforge.net/projects/sstap/) project to force all connections to go through the proxy. Disclaimer: this project does not have any affiliation with SSTap and cannot provide support for any issues that arise from its use.
    - For Android: open Settings, Wi-Fi, select your network, expand the Advanced Settings, change the proxy setting to Manual, and enter the host and port for the *HTTP proxy*. Note that SOCKS proxy support on Android is limited, even when using the PAC URL, so the HTTP proxy is recommended.
        - Many applications on Android do not respect proxy settings, unfortunately, and in those cases you will have to configure the apps manually or use an app like Proxifier to force apps to use the proxy.

# Running (Android via Termux)

Note: recommended when you are comfortable working with termux on non-rooted Android devices.

## Install dependencies

```bash
pkg install python
pip install psutil
```

## Start the server (Android mode)

```bash
python3 socks5.py --mode android
```

## Client configuration

- SOCKS5: set host to the printed hotspot IP and port `9876`.
- HTTP proxy: set host to the printed hotspot IP and port `9877`.
- PAC URL is printed at startup and uses the hotspot IP.

# Why

Recently, while travelling, I found out that Google Fi doesn't support tethering on iOS (I guess it's a feature they want to keep Android-exclusive or something?). Since my phone has a nice, fast, unblocked connection, I wanted to let my computer access it too.

I previously wrote [Socks5-iOS](https://github.com/nneonneo/socks5-ios) for doing exactly this, but it turned out to be quite cumbersome to deploy and modify. Plus, the app expires frequently (if you don't have an iOS developer account), which makes it annoying if you need it in a pinch. Enter Pythonista - an App Store app which puts a complete Python interpreter on iOS.

This script can be used to implement a functional alternative to tethering, which I refer to fake-tethering. Fake-tethering has some substantial advantages over standard iOS tethering. It works even when carriers ban tethering, and it bypasses limits set on tethering speed since all connections originate from the phone.

While it's easiest to use this with websites, it's actually possible to tunnel any TCP connection over a SOCKS proxy. For example, here's how you would proxy an SSH connection:

`ssh -o ProxyCommand='nc -X 5 -x <IP>:9876 %h %p' user@host`

# Troubleshooting

## Doesn't work with an ad-hoc network on macOS

macOS appears to incorrectly assess the Internet as unreachable with an ad-hoc network, even if a proxy is configured. A workaround for this, tested on macOS 10.14, is described under [issue #1](https://github.com/nneonneo/iOS-SOCKS-Server/issues/1#issuecomment-583989079).
