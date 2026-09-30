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
| **`0`**   | `23.70 us` (✅ **1.00x**)   |
| **`300`** | `792.75 us` (✅ **1.00x**)  |
| **`600`** | `1.88 ms` (✅ **1.00x**)    |
| **`900`** | `1.67 ms` (✅ **1.00x**)    |

### Holder

|           | `SHA-256`                  |
|:----------|:-------------------------- |
| **`0`**   | `17.47 us` (✅ **1.00x**)   |
| **`300`** | `114.46 us` (✅ **1.00x**)  |
| **`600`** | `226.23 us` (✅ **1.00x**)  |
| **`900`** | `345.91 us` (✅ **1.00x**)  |

### Verifier

|           | `SHA-256`                  |
|:----------|:-------------------------- |
| **`0`**   | `67.34 us` (✅ **1.00x**)   |
| **`300`** | `513.07 us` (✅ **1.00x**)  |
| **`600`** | `791.21 us` (✅ **1.00x**)  |
| **`900`** | `1.16 ms` (✅ **1.00x**)    |

### Verifier Batch

|                                   | `SHA-256`                  |
|:----------------------------------|:-------------------------- |
| **`1 SD-KBT with 10 claims`**     | `77.34 us` (✅ **1.00x**)   |
| **`301 SD-KBT with 10 claims`**   | `13.27 ms` (✅ **1.00x**)   |
| **`601 SD-KBT with 10 claims`**   | `26.04 ms` (✅ **1.00x**)   |
| **`901 SD-KBT with 10 claims`**   | `40.26 ms` (✅ **1.00x**)   |
| **`1 SD-KBT with 100 claims`**    | `181.22 us` (✅ **1.00x**)  |
| **`301 SD-KBT with 100 claims`**  | `46.60 ms` (✅ **1.00x**)   |
| **`601 SD-KBT with 100 claims`**  | `92.93 ms` (✅ **1.00x**)   |
| **`901 SD-KBT with 100 claims`**  | `132.00 ms` (✅ **1.00x**)  |
| **`1 SD-KBT with 1000 claims`**   | `1.24 ms` (✅ **1.00x**)    |
| **`301 SD-KBT with 1000 claims`** | `371.90 ms` (✅ **1.00x**)  |
| **`601 SD-KBT with 1000 claims`** | `1.11 s` (✅ **1.00x**)     |

---
Made with [criterion-table](https://github.com/nu11ptr/criterion-table)

