# What

A simple SOCKS proxy designed to run on Pythonista on iOS, letting you fake-tether your devices to a phone. 

# Installation

- Install Pythonista from the [App Store](https://apps.apple.com/us/app/pythonista-3/id1085978097). It's a paid app, but it's worth every penny if you are a power user.
- Download the code from [GitHub](https://github.com/nneonneo/socks5-ios/archive/master.zip).
- Unpack the code in the Files app, then move the package to the Pythonista iCloud directory
- Navigate to the `socks5.py` script in Pythonista and open it. 
- Optionally, you can tap on the wrench to add the script to your home screen. 

# Running

- Connect your devices to the same WiFi network as your phone. If there's no suitable network, you can create a computer-to-computer (ad-hoc) network using your laptop and connect to it with your phone.
- Open the home screen shortcut (if you made one), or open the `socks5.py` script in Pythonista and hit Run. 
- Point your devices at the SOCKS proxy listed (on port 9876), or point them at the PAC (proxy autoconfiguration) URL if they don't support setting a SOCKS proxy (e.g. other iOS devices).

# Why

Recently, while travelling in China, I found out that Google Fi doesn't support tethering on iOS (I guess it's a feature they want to keep Android-exclusive or something?). Since my phone has a nice, fast, unblocked connection, I wanted to let my computer access it too.

I previously wrote [Socks5-iOS](https://github.com/nneonneo/socks5-ios) for doing exactly this, but it turned out to be quite cumbersome to deploy and modify. Plus, the app expires frequently (if you don't have an iOS developer account), which makes it annoying if you need it in a pinch. Enter Pythonista - an App Store app which puts a complete Python interpreter on iOS.

This script can be used to implement a functional alternative to tethering, which I refer to fake-tethering. Fake-tethering has some substantial advantages over standard iOS tethering. It works even when carriers ban tethering, and it bypasses limits set on tethering speed since all connections originate from the phone.

While it's easiest to use this with websites, it's actually possible to tunnel any TCP connection over a SOCKS proxy. For example, here's how you would proxy an SSH connection:

`ssh -o ProxyCommand='nc -X 5 -x <IP>:9876 %h %p' user@host`

# Troubleshooting

## Doesn't work with an ad-hoc network on macOS

macOS appears to incorrectly assess the Internet as unreachable with an ad-hoc network, even if a proxy is configured. A workaround for this, tested on macOS 10.14, is described under [issue #1](https://github.com/nneonneo/SOCKS-iOS/issues/1#issuecomment-583989079).
