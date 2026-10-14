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
| **`0`**   | `12.91 us` (✅ **1.00x**)   |
| **`300`** | `502.70 us` (✅ **1.00x**)  |
| **`600`** | `987.81 us` (✅ **1.00x**)  |
| **`900`** | `1.47 ms` (✅ **1.00x**)    |

### Holder

|           | `SHA-256`                  |
|:----------|:-------------------------- |
| **`0`**   | `13.07 us` (✅ **1.00x**)   |
| **`300`** | `101.68 us` (✅ **1.00x**)  |
| **`600`** | `192.28 us` (✅ **1.00x**)  |
| **`900`** | `277.50 us` (✅ **1.00x**)  |

### Verifier

|           | `SHA-256`                  |
|:----------|:-------------------------- |
| **`0`**   | `52.90 us` (✅ **1.00x**)   |
| **`300`** | `319.66 us` (✅ **1.00x**)  |
| **`600`** | `601.92 us` (✅ **1.00x**)  |
| **`900`** | `865.49 us` (✅ **1.00x**)  |

### Verifier Batch

|                                   | `SHA-256`                  |
|:----------------------------------|:-------------------------- |
| **`1 SD-KBT with 10 claims`**     | `63.40 us` (✅ **1.00x**)   |
| **`301 SD-KBT with 10 claims`**   | `10.81 ms` (✅ **1.00x**)   |
| **`601 SD-KBT with 10 claims`**   | `20.79 ms` (✅ **1.00x**)   |
| **`901 SD-KBT with 10 claims`**   | `30.92 ms` (✅ **1.00x**)   |
| **`1 SD-KBT with 100 claims`**    | `141.81 us` (✅ **1.00x**)  |
| **`301 SD-KBT with 100 claims`**  | `35.48 ms` (✅ **1.00x**)   |
| **`601 SD-KBT with 100 claims`**  | `70.22 ms` (✅ **1.00x**)   |
| **`901 SD-KBT with 100 claims`**  | `105.13 ms` (✅ **1.00x**)  |
| **`1 SD-KBT with 1000 claims`**   | `955.32 us` (✅ **1.00x**)  |
| **`301 SD-KBT with 1000 claims`** | `285.12 ms` (✅ **1.00x**)  |
| **`601 SD-KBT with 1000 claims`** | `569.11 ms` (✅ **1.00x**)  |
| **`901 SD-KBT with 1000 claims`** | `860.42 ms` (✅ **1.00x**)  |

---
Made with [criterion-table](https://github.com/nu11ptr/criterion-table)

