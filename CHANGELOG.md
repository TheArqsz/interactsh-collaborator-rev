## [1.6.0](https://github.com/TheArqsz/interactsh-collaborator-rev/compare/v1.5.0...v1.6.0) (2026-10-01)


### Features

* **config:** support custom correlation id lengths and verify session after registration ([e461f1b](https://github.com/TheArqsz/interactsh-collaborator-rev/commit/e461f1b59c0fc597396f09730cf0d6806cce8494))
* **core:** show wildcard interactions with an option to hide them ([41df176](https://github.com/TheArqsz/interactsh-collaborator-rev/commit/41df1768e264d9b62ada05e25eafca46ea009e6f))
* **ui:** add test settings button that verifies without saving ([d7ee7e6](https://github.com/TheArqsz/interactsh-collaborator-rev/commit/d7ee7e6a2219af89743e018547216ea70eae9ad5))


### Bug Fixes

* **config:** apply AES mode changes to the running session ([c0b32ab](https://github.com/TheArqsz/interactsh-collaborator-rev/commit/c0b32ab0b1009892f24c7b6e8043f17a4f3eeb3d))
* **config:** reset invalid port to the scheme default and report it ([bf84d2b](https://github.com/TheArqsz/interactsh-collaborator-rev/commit/bf84d2bcd2406ee643f134ef94eeace8021f02f4))
* **core:** check host once and report the registration failure reason ([dc55b43](https://github.com/TheArqsz/interactsh-collaborator-rev/commit/dc55b4314a4fbcb7f175c1a20098492600026971))
* **core:** coalesce repeated refresh requests ([3ff8664](https://github.com/TheArqsz/interactsh-collaborator-rev/commit/3ff866419443aff493f71e5845ab5f1c6ba60856))
* **core:** deregister session on regenerate, settings change and unload ([e27d76b](https://github.com/TheArqsz/interactsh-collaborator-rev/commit/e27d76b1b466ae7fc0b9488c80f7d6375cf981f4))
* **core:** drop late test callbacks for the whole session ([817c156](https://github.com/TheArqsz/interactsh-collaborator-rev/commit/817c1562ea981e88d5d6bb369b106f9429f94337))
* **core:** generate URL nonce from zbase32 alphabet ([a938cc8](https://github.com/TheArqsz/interactsh-collaborator-rev/commit/a938cc8ffe5934ddaeba25d30191215c268e6627))
* **core:** ignore registrations that finish after the listener was closed ([503ddcb](https://github.com/TheArqsz/interactsh-collaborator-rev/commit/503ddcb933d7c0b142eb5cec29d4530ea7aa6929))
* **core:** keep polling loop alive after a failed poll ([d9f2737](https://github.com/TheArqsz/interactsh-collaborator-rev/commit/d9f27376562f32a3b657a8466670d19fa8a52acc))
* **core:** re-register session when server no longer knows it ([f8ff737](https://github.com/TheArqsz/interactsh-collaborator-rev/commit/f8ff73774ae9b79b904d7bab7ec82cab59e57f00))
* **ui:** never render table cell text as HTML ([98f3e99](https://github.com/TheArqsz/interactsh-collaborator-rev/commit/98f3e99e34975c6101ff35e9963e0a2b44d71381))
* **ui:** report missing or rejected token on 401 during registration ([b70928a](https://github.com/TheArqsz/interactsh-collaborator-rev/commit/b70928ac3717c3fa1ec16f19f4e5d68dc91095ad))
* **ui:** show actual poll result in refresh toast ([31f921f](https://github.com/TheArqsz/interactsh-collaborator-rev/commit/31f921f0bf1f51c3f23689e66cc27788d3760996))

## [1.5.0](https://github.com/TheArqsz/interactsh-collaborator-rev/compare/v1.4.0...v1.5.0) (2026-10-01)


### Features

* **ui:** label and hide shared interactions, add Responder filter ([aebd5b8](https://github.com/TheArqsz/interactsh-collaborator-rev/commit/aebd5b866f17afecf34b704a9e7026c4e5317589))


### Bug Fixes

* **core:** read token-scoped interactions from poll extra field ([5de5bea](https://github.com/TheArqsz/interactsh-collaborator-rev/commit/5de5bea8b15c3dabef4bf84a2f37a1c1bdb091b3))
* **ui:** keep copy URL button colour on hover ([d4d9cc4](https://github.com/TheArqsz/interactsh-collaborator-rev/commit/d4d9cc4e212f1652902abcc430a0b19a2225ad95))

## [1.4.0](https://github.com/TheArqsz/interactsh-collaborator-rev/compare/v1.3.0...v1.4.0) (2026-05-11)


### Features

* **config:** persist AES mode and debug logging settings ([51238f4](https://github.com/TheArqsz/interactsh-collaborator-rev/commit/51238f42a33edd441863f7c4764a33faff355abc))
* **ext:** add unloading flag, null-safe teardown, and debug log helper ([2b1612e](https://github.com/TheArqsz/interactsh-collaborator-rev/commit/2b1612e8e6cc71c593930a564f91ae6e6d5b8e3d))
* **ui:** add toast notifications for settings save and session lifecycle ([7baa8a9](https://github.com/TheArqsz/interactsh-collaborator-rev/commit/7baa8a9a6ed80737bdea0662f649d03e5fc38058))


### Bug Fixes

* **build:** remove java-xid dependency and fix fat JAR assembly ([62bbfe9](https://github.com/TheArqsz/interactsh-collaborator-rev/commit/62bbfe9f92cc5e12f3ecc212fcf186017a7d7073))
* **ci:** update artifact rename glob to match fat JAR naming after appendAssemblyId=false ([170e1a8](https://github.com/TheArqsz/interactsh-collaborator-rev/commit/170e1a8acee9f0bceaf7095d0cd6a5a2c81d1587))
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

