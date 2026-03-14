# Verbose Log Generation Report

Generated: 2026-03-13T21:14:07.609677+00:00
Dry run: False

## Summary

- Total cases scanned: 102
- No source code: 28
- Skipped (already have generated log): 0
- Compilation failed: 57
- Compiled but no log returned: 0
- Oracle exceptions: 0
- **Successfully generated logs: 17**
  - Verifier PASSED: 3
  - Verifier FAILED: 14
  - Log improved (longer than original): 11

## Successfully Generated Logs

| Case ID | Verifier | Old Log | New Log | Improved | Template |
|---------|----------|---------|---------|----------|----------|
| stackoverflow-56965789 | FAIL | 0 | 592 | YES | wrap-vmlinux |
| stackoverflow-67402772 | FAIL | 599 | 3858 | YES | raw-uapi |
| stackoverflow-69767533 | PASS | 1663 | 1825 | YES | raw-uapi |
| stackoverflow-70750259 | FAIL | 6539 | 6833 | YES | wrap-vmlinux |
| stackoverflow-70760516 | PASS | 23528 | 380 | no | wrap-vmlinux |
| stackoverflow-70841631 | FAIL | 1127 | 17 | no | raw-uapi |
| stackoverflow-72560675 | FAIL | 2898 | 1825 | no | raw-uapi |
| stackoverflow-75058008 | FAIL | 535 | 835 | YES | wrap-vmlinux |
| stackoverflow-75301643 | FAIL | 0 | 592 | YES | wrap-vmlinux |
| stackoverflow-75515263 | FAIL | 1288 | 592 | no | wrap-vmlinux |
| stackoverflow-76160985 | FAIL | 1671 | 946 | no | wrap-vmlinux |
| stackoverflow-76441958 | FAIL | 1469 | 2160 | YES | raw-vmlinux |
| stackoverflow-77673256 | PASS | 453 | 1761 | YES | wrap-vmlinux |
| stackoverflow-77713434 | FAIL | 2411 | 654 | no | wrap-vmlinux |
| stackoverflow-77967675 | FAIL | 0 | 3873 | YES | raw-uapi |
| stackoverflow-78236856 | FAIL | 2538 | 3308 | YES | wrap-vmlinux |
| stackoverflow-78525670 | FAIL | 84 | 592 | YES | wrap-vmlinux |

## Compilation Failures

| Case ID | Error |
|---------|-------|
| github-aya-rs-aya-1002 | Compilation failed (wrap-uapi): /usr/src/linux-headers-6.15.11-061511-generic/include/linux/compiler.h:390:10: fatal err |
| github-aya-rs-aya-1056 | Compilation failed (wrap-uapi): /usr/src/linux-headers-6.15.11-061511-generic/include/linux/compiler.h:390:10: fatal err |
| github-aya-rs-aya-1062 | Compilation failed (wrap-uapi): /usr/src/linux-headers-6.15.11-061511-generic/include/linux/compiler.h:390:10: fatal err |
| github-aya-rs-aya-1104 | Compilation failed (wrap-uapi): /usr/src/linux-headers-6.15.11-061511-generic/include/linux/compiler.h:390:10: fatal err |
| github-aya-rs-aya-1233 | Compilation failed (wrap-uapi): /usr/src/linux-headers-6.15.11-061511-generic/include/linux/compiler.h:390:10: fatal err |
| github-aya-rs-aya-1267 | Compilation failed (wrap-uapi): /usr/src/linux-headers-6.15.11-061511-generic/include/linux/compiler.h:390:10: fatal err |
| github-aya-rs-aya-1324 | Compilation failed (wrap-uapi): /usr/src/linux-headers-6.15.11-061511-generic/include/linux/compiler.h:390:10: fatal err |
| github-aya-rs-aya-407 | Compilation failed (wrap-uapi): /usr/src/linux-headers-6.15.11-061511-generic/include/linux/compiler.h:390:10: fatal err |
| github-aya-rs-aya-440 | Compilation failed (wrap-uapi): /usr/src/linux-headers-6.15.11-061511-generic/include/linux/compiler.h:390:10: fatal err |
| github-aya-rs-aya-521 | Compilation failed (wrap-uapi): /usr/src/linux-headers-6.15.11-061511-generic/include/linux/compiler.h:390:10: fatal err |
| github-aya-rs-aya-546 | Compilation failed (wrap-uapi): /usr/src/linux-headers-6.15.11-061511-generic/include/linux/compiler.h:390:10: fatal err |
| github-aya-rs-aya-863 | Compilation failed (wrap-uapi): /usr/src/linux-headers-6.15.11-061511-generic/include/linux/compiler.h:390:10: fatal err |
| github-aya-rs-aya-864 | Compilation failed (wrap-uapi): /usr/src/linux-headers-6.15.11-061511-generic/include/linux/compiler.h:390:10: fatal err |
| github-cilium-cilium-37478 | Compilation failed (wrap-uapi): /usr/src/linux-headers-6.15.11-061511-generic/include/linux/compiler.h:390:10: fatal err |
| github-cilium-cilium-41522 | Compilation failed (wrap-uapi): /usr/src/linux-headers-6.15.11-061511-generic/include/linux/compiler.h:390:10: fatal err |
| stackoverflow-47591176 | Compilation failed (wrap-uapi): /usr/src/linux-headers-6.15.11-061511-generic/include/linux/compiler.h:390:10: fatal err |
| stackoverflow-48267671 | Compilation failed (wrap-uapi): /usr/src/linux-headers-6.15.11-061511-generic/include/linux/compiler.h:390:10: fatal err |
| stackoverflow-53136145 | Compilation failed (wrap-uapi): /usr/src/linux-headers-6.15.11-061511-generic/include/linux/compiler.h:390:10: fatal err |
| stackoverflow-56872436 | Compilation failed (wrap-uapi): /usr/src/linux-headers-6.15.11-061511-generic/include/linux/compiler.h:390:10: fatal err |
| stackoverflow-60053570 | Compilation failed (wrap-uapi): /usr/src/linux-headers-6.15.11-061511-generic/include/linux/compiler.h:390:10: fatal err |
| stackoverflow-61945212 | Compilation failed (wrap-uapi): /usr/src/linux-headers-6.15.11-061511-generic/include/linux/compiler.h:390:10: fatal err |
| stackoverflow-67441023 | Compilation failed (wrap-uapi): /usr/src/linux-headers-6.15.11-061511-generic/include/linux/compiler.h:390:10: fatal err |
| stackoverflow-67679109 | Compilation failed (wrap-uapi): /usr/src/linux-headers-6.15.11-061511-generic/include/linux/compiler.h:390:10: fatal err |
| stackoverflow-68752893 | Compilation failed (wrap-uapi): /usr/src/linux-headers-6.15.11-061511-generic/include/linux/compiler.h:390:10: fatal err |
| stackoverflow-69413427 | Compilation failed (wrap-uapi): /usr/src/linux-headers-6.15.11-061511-generic/include/linux/compiler.h:390:10: fatal err |
| stackoverflow-70091221 | Compilation failed (wrap-uapi): /usr/src/linux-headers-6.15.11-061511-generic/include/linux/compiler.h:390:10: fatal err |
| stackoverflow-70392721 | Compilation failed (wrap-uapi): /usr/src/linux-headers-6.15.11-061511-generic/include/linux/compiler.h:390:10: fatal err |
| stackoverflow-70721661 | Compilation failed (wrap-uapi): /usr/src/linux-headers-6.15.11-061511-generic/include/linux/compiler.h:390:10: fatal err |
| stackoverflow-70873332 | Compilation failed (wrap-uapi): /usr/src/linux-headers-6.15.11-061511-generic/include/linux/compiler.h:390:10: fatal err |
| stackoverflow-71253472 | Compilation failed (wrap-uapi): /usr/src/linux-headers-6.15.11-061511-generic/include/linux/compiler.h:390:10: fatal err |
| stackoverflow-71522674 | Compilation failed (wrap-uapi): /usr/src/linux-headers-6.15.11-061511-generic/include/linux/compiler.h:390:10: fatal err |
| stackoverflow-71946593 | Compilation failed (wrap-uapi): /usr/src/linux-headers-6.15.11-061511-generic/include/linux/compiler.h:390:10: fatal err |
| stackoverflow-72005172 | Compilation failed (wrap-uapi): /usr/src/linux-headers-6.15.11-061511-generic/include/linux/compiler.h:390:10: fatal err |
| stackoverflow-72074115 | Compilation failed (wrap-uapi): /usr/src/linux-headers-6.15.11-061511-generic/include/linux/compiler.h:390:10: fatal err |
| stackoverflow-72575736 | Compilation failed (wrap-uapi): /usr/src/linux-headers-6.15.11-061511-generic/include/linux/compiler.h:390:10: fatal err |
| stackoverflow-72606055 | Compilation failed (wrap-uapi): /usr/src/linux-headers-6.15.11-061511-generic/include/linux/compiler.h:390:10: fatal err |
| stackoverflow-73088287 | Compilation failed (wrap-uapi): /usr/src/linux-headers-6.15.11-061511-generic/include/linux/compiler.h:390:10: fatal err |
| stackoverflow-74178703 | Compilation failed (wrap-uapi): /usr/src/linux-headers-6.15.11-061511-generic/include/linux/compiler.h:390:10: fatal err |
| stackoverflow-74531552 | Compilation failed (wrap-uapi): /usr/src/linux-headers-6.15.11-061511-generic/include/linux/compiler.h:390:10: fatal err |
| stackoverflow-75294010 | Compilation failed (wrap-uapi): /usr/src/linux-headers-6.15.11-061511-generic/include/linux/compiler.h:390:10: fatal err |
| stackoverflow-75300106 | Compilation failed (wrap-uapi): /usr/src/linux-headers-6.15.11-061511-generic/include/linux/compiler.h:390:10: fatal err |
| stackoverflow-76277872 | Compilation failed (wrap-uapi): /usr/src/linux-headers-6.15.11-061511-generic/include/linux/compiler.h:390:10: fatal err |
| stackoverflow-76371104 | Compilation failed (wrap-uapi): /usr/src/linux-headers-6.15.11-061511-generic/include/linux/compiler.h:390:10: fatal err |
| stackoverflow-76960866 | Compilation failed (wrap-uapi): /usr/src/linux-headers-6.15.11-061511-generic/include/linux/compiler.h:390:10: fatal err |
| stackoverflow-76994829 | Compilation failed (wrap-uapi): /usr/src/linux-headers-6.15.11-061511-generic/include/linux/compiler.h:390:10: fatal err |
| stackoverflow-77568308 | Compilation failed (wrap-uapi): /usr/src/linux-headers-6.15.11-061511-generic/include/linux/compiler.h:390:10: fatal err |
| stackoverflow-78266602 | Compilation failed (wrap-uapi): /usr/src/linux-headers-6.15.11-061511-generic/include/linux/compiler.h:390:10: fatal err |
| stackoverflow-78471487 | Compilation failed (wrap-uapi): /usr/src/linux-headers-6.15.11-061511-generic/include/linux/compiler.h:390:10: fatal err |
| stackoverflow-78603028 | Compilation failed (wrap-uapi): /usr/src/linux-headers-6.15.11-061511-generic/include/linux/compiler.h:390:10: fatal err |
| stackoverflow-78695342 | Compilation failed (wrap-uapi): /usr/src/linux-headers-6.15.11-061511-generic/include/linux/compiler.h:390:10: fatal err |
| stackoverflow-78753911 | Compilation failed (wrap-uapi): /usr/src/linux-headers-6.15.11-061511-generic/include/linux/compiler.h:390:10: fatal err |
| stackoverflow-78958420 | Compilation failed (wrap-uapi): /usr/src/linux-headers-6.15.11-061511-generic/include/linux/compiler.h:390:10: fatal err |
| stackoverflow-79485758 | Compilation failed (wrap-uapi): /usr/src/linux-headers-6.15.11-061511-generic/include/linux/compiler.h:390:10: fatal err |
| stackoverflow-79616493 | Compilation failed (wrap-uapi): /usr/src/linux-headers-6.15.11-061511-generic/include/linux/compiler.h:390:10: fatal err |
| stackoverflow-79752670 | Compilation failed (wrap-uapi): /usr/src/linux-headers-6.15.11-061511-generic/include/linux/compiler.h:390:10: fatal err |
| stackoverflow-79812509 | Compilation failed (wrap-uapi): /usr/src/linux-headers-6.15.11-061511-generic/include/linux/compiler.h:390:10: fatal err |
| stackoverflow-79817058 | Compilation failed (wrap-uapi): /usr/src/linux-headers-6.15.11-061511-generic/include/linux/compiler.h:390:10: fatal err |
