# MfDESFire Authentication App

> **⚠️ WARNING:** This project is currently under active development and not yet ready for production use.

## About
This project originated as a university assignment to enable proper MfDESFire legacy authentication handling in Flipper Zero firmware. The initial goal was successfully achieved by adding authentication logic with known key and initialization vector.

However, the original implementation required direct modifications of the Flipper firmware nfc libraries, which is not maintainable long-term as it prevents seamless firmware updates. 

**Current Goal:** Refactor the authentication functionality into a separated Flipper application that can be maintained independently.

## Usage

> **⚠️ Note:** This app is not yet ready for end-user installation.

For development and testing purposes:

1. Clone this repository into the `applications_user` folder of your Flipper Zero firmware directory:
```shell
   cd /path/to/flipperzero-firmware/applications_user
   git clone https://github.com/Gatorixx/flipper-zero-legacy-authentication.git DesfireApp
```
2. Build and launch the application using the Flipper Build Tool:
```shell
./fbt launch APPSRC=applications_user/DesfireApp
```

## Contributing
Contributions are welcome! If you're interested in helping with:

- Testing and bug reports
- Code improvements
- Anything else

Please [open an issue](https://github.com/Gatorixx/flipper-zero-legacy-authentication/issues/new) to discuss your ideas or report problems. I appreciate any community feedback.