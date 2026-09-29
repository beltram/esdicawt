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
| **`300`** | `518.79 us` (✅ **1.00x**)  |
| **`600`** | `1.09 ms` (✅ **1.00x**)    |
| **`900`** | `1.64 ms` (✅ **1.00x**)    |

### Holder

|           | `SHA-256`                  |
|:----------|:-------------------------- |
| **`0`**   | `14.02 us` (✅ **1.00x**)   |
| **`300`** | `101.59 us` (✅ **1.00x**)  |
| **`600`** | `198.26 us` (✅ **1.00x**)  |
| **`900`** | `290.89 us` (✅ **1.00x**)  |

### Verifier

|           | `SHA-256`                  |
|:----------|:-------------------------- |
| **`0`**   | `61.17 us` (✅ **1.00x**)   |
| **`300`** | `530.33 us` (✅ **1.00x**)  |
| **`600`** | `959.04 us` (✅ **1.00x**)  |
| **`900`** | `1.39 ms` (✅ **1.00x**)    |

### Verifier Batch

|                                   | `SHA-256`                  |
|:----------------------------------|:-------------------------- |
| **`1 SD-KBT with 10 claims`**     | `114.15 us` (✅ **1.00x**)  |
| **`301 SD-KBT with 10 claims`**   | `24.17 ms` (✅ **1.00x**)   |
| **`601 SD-KBT with 10 claims`**   | `49.42 ms` (✅ **1.00x**)   |
| **`901 SD-KBT with 10 claims`**   | `76.13 ms` (✅ **1.00x**)   |
| **`1 SD-KBT with 100 claims`**    | `222.98 us` (✅ **1.00x**)  |
| **`301 SD-KBT with 100 claims`**  | `66.91 ms` (✅ **1.00x**)   |
| **`601 SD-KBT with 100 claims`**  | `131.17 ms` (✅ **1.00x**)  |
| **`901 SD-KBT with 100 claims`**  | `208.13 ms` (✅ **1.00x**)  |
| **`1 SD-KBT with 1000 claims`**   | `1.66 ms` (✅ **1.00x**)    |
| **`301 SD-KBT with 1000 claims`** | `484.09 ms` (✅ **1.00x**)  |
| **`601 SD-KBT with 1000 claims`** | `1.01 s` (✅ **1.00x**)     |
| **`901 SD-KBT with 1000 claims`** | `2.74 s` (✅ **1.00x**)     |

---
Made with [criterion-table](https://github.com/nu11ptr/criterion-table)

