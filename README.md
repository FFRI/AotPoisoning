# AOT Poisoning

## Introduction

Rosetta 2 is a translation mechanism that allows Apple Silicon Mac to run Intel-based applications. It offers two types of translation: Just-In-Time (JIT) and Ahead-Of-Time (AOT). AOT translation is usually employed, but JIT translation is also used for applications that generate dynamic code (e.g., web browsers). AOT translation result is saved as AOT files, which are cached and reused for the next application launch.

We presented a new code injection technique named "AOT Poisoning" abusing this caching mechanism at [Black Hat Asia 2023](https://www.blackhat.com/asia-23/briefings/schedule/index.html#dirty-bin-cache-a-new-code-injection-poisoning-binary-translation-cache-30907). This repository contains PoC code of AOT Poisoning and other utilities used in my research.

## Requirements

- Python
- [poetry](https://python-poetry.org/)

## How to use the PoC code of AOT Poisoning

Before running this script, you need to install the dependencies.

```
$ poetry install
```

This script has two commands: poison-aot-signed and poison-aot-nonsigned.

poison-aot-signed is a command that poisons an AOT file of a signed executable and injects shellcode through this.
This issue is currently fixed as CVE-2022-42789, so this code injection does not work for the latest macOS

```
$ poetry run python main.py poison-aot-signed <path to application bundle (or executable)> <path to shellcode payload>
```

poison-aot-nonsigned is a command that poisons an AOT file of an unsigned executable and injects shellcode through this.

```
$ poetry run python main.py poison-aot-nonsigned <path to application bundle (or executable)> <path to shellcode payload>
```

Some shellcode payloads used in my research are in [the shellcode directory](./shellcode).

## Other utilities

### [calc_hash](./calc_hash/)

calc_hash contains the code that calculates AOT lookup hash of an x64 executable. Rosetta 2 uses the AOT lookup hash to check whether the specified x64 executable was previously translated. If there is a previous translation result corresponding to the calculated hash value, the translation result is reused for the execution, resulting in reducing the redundant binary translation. For more details, see my Black Hat Asia 2023 talk slides.

### [mmap_timestamp_test](./mmap_timestamp_test)

mmap_timestamp_test contains the code that tests the behavior of the APFS timestamp updates issue. The issue is that writing to a file via mmap() & munmap() without calling msync() does not update ctime and mtime. I used code in this directory to check this behavior. You can find some results of this code for [Big Sur 11.5.2](./mmap_timestamp_test/bigsur_11.5.2.png) and [Big Sur 11.7.4](./mmap_timestamp_test/bigsur_11.7.4.png).

## Author

Koh M. Nakagawa. &copy; FFRI Security, Inc. 2023

## License

[Apache version 2.0](LICENSE)
