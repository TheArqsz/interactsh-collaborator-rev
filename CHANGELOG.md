## [1.4.0](https://github.com/TheArqsz/interactsh-collaborator-rev/compare/v1.3.0...v1.4.0) (2026-05-11)


### Features

* **config:** persist AES mode and debug logging settings ([51238f4](https://github.com/TheArqsz/interactsh-collaborator-rev/commit/51238f42a33edd441863f7c4764a33faff355abc))
* **ext:** add unloading flag, null-safe teardown, and debug log helper ([2b1612e](https://github.com/TheArqsz/interactsh-collaborator-rev/commit/2b1612e8e6cc71c593930a564f91ae6e6d5b8e3d))
* **ui:** add toast notifications for settings save and session lifecycle ([7baa8a9](https://github.com/TheArqsz/interactsh-collaborator-rev/commit/7baa8a9a6ed80737bdea0662f649d03e5fc38058))


### Bug Fixes

* **build:** remove java-xid dependency and fix fat JAR assembly ([62bbfe9](https://github.com/TheArqsz/interactsh-collaborator-rev/commit/62bbfe9f92cc5e12f3ecc212fcf186017a7d7073))
* **core:** add pre-flight DNS check and fix UnknownHostException detection ([a1b89bf](https://github.com/TheArqsz/interactsh-collaborator-rev/commit/a1b89bfd48228c008ce92738ddecce2113783c9a))
* **core:** replace Xid with UUID, fix AES decryption (byte key, correct slice, CTR/CFB auto-detect) ([9415dc9](https://github.com/TheArqsz/interactsh-collaborator-rev/commit/9415dc9031e7ac4f3767641c2c7d78f113c99f05))
* **threading:** resolve interrupt race and unloading safety in polling loop ([98cf153](https://github.com/TheArqsz/interactsh-collaborator-rev/commit/98cf153d7bb96d57388583c37d93d6e0ce34f14a))

## [1.3.0](https://github.com/TheArqsz/interactsh-collaborator-rev/compare/v1.2.1...v1.3.0) (2026-01-25)


### Features

* **formatters:** added dedicated formatters for protocols ([2c9d719](https://github.com/TheArqsz/interactsh-collaborator-rev/commit/2c9d719b943ced0b47882007e6c4b3f283f0d69b))

## [1.2.1](https://github.com/TheArqsz/interactsh-collaborator-rev/compare/v1.2.0...v1.2.1) (2025-12-18)


### Bug Fixes

* prevent NullPointerException on null HTTP responses during registration and polling ([7329845](https://github.com/TheArqsz/interactsh-collaborator-rev/commit/7329845992ebbb34d56f0cb1c410fcefeac02e26))

## [1.2.0](https://github.com/TheArqsz/interactsh-collaborator-rev/compare/v1.1.0...v1.2.0) (2025-09-27)


### Features

* Added toast notification for actions ([30cc86d](https://github.com/TheArqsz/interactsh-collaborator-rev/commit/30cc86da10a5097f92f706b2ac149aac8a78cdfe))

## 1.1.0 (2025-08-07)

