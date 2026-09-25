# Benchmarks

## Table of Contents

- [Benchmark Results](#benchmark-results)
    - [Issuer](#issuer)
    - [Holder](#holder)
    - [Verifier](#verifier)
    - [Verifier Batch](#verifier-batch)

## Benchmark Results

### Issuer

|           | `SHA-256`                  |
|:----------|:-------------------------- |
| **`0`**   | `12.98 us` (✅ **1.00x**)   |
| **`300`** | `508.54 us` (✅ **1.00x**)  |
| **`600`** | `1.03 ms` (✅ **1.00x**)    |
| **`900`** | `1.54 ms` (✅ **1.00x**)    |

### Holder

|           | `SHA-256`                  |
|:----------|:-------------------------- |
| **`0`**   | `13.94 us` (✅ **1.00x**)   |
| **`300`** | `110.55 us` (✅ **1.00x**)  |
| **`600`** | `192.87 us` (✅ **1.00x**)  |
| **`900`** | `296.34 us` (✅ **1.00x**)  |

### Verifier

|           | `SHA-256`                  |
|:----------|:-------------------------- |
| **`0`**   | `63.98 us` (✅ **1.00x**)   |
| **`300`** | `516.44 us` (✅ **1.00x**)  |
| **`600`** | `973.87 us` (✅ **1.00x**)  |
| **`900`** | `1.42 ms` (✅ **1.00x**)    |

### Verifier Batch

|                                   | `SHA-256`                  |
|:----------------------------------|:-------------------------- |
| **`1 SD-KBT with 10 claims`**     | `76.14 us` (✅ **1.00x**)   |
| **`301 SD-KBT with 10 claims`**   | `23.31 ms` (✅ **1.00x**)   |
| **`601 SD-KBT with 10 claims`**   | `48.78 ms` (✅ **1.00x**)   |
| **`901 SD-KBT with 10 claims`**   | `72.18 ms` (✅ **1.00x**)   |
| **`1 SD-KBT with 100 claims`**    | `208.44 us` (✅ **1.00x**)  |
| **`301 SD-KBT with 100 claims`**  | `120.49 ms` (✅ **1.00x**)  |
| **`601 SD-KBT with 100 claims`**  | `130.46 ms` (✅ **1.00x**)  |
| **`901 SD-KBT with 100 claims`**  | `199.02 ms` (✅ **1.00x**)  |
| **`1 SD-KBT with 1000 claims`**   | `1.57 ms` (✅ **1.00x**)    |
| **`301 SD-KBT with 1000 claims`** | `461.91 ms` (✅ **1.00x**)  |
| **`601 SD-KBT with 1000 claims`** | `924.03 ms` (✅ **1.00x**)  |
| **`901 SD-KBT with 1000 claims`** | `1.38 s` (✅ **1.00x**)     |

---
Made with [criterion-table](https://github.com/nu11ptr/criterion-table)

