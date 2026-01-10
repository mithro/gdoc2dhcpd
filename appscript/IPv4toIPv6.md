# IPv4 to IPv6 Conversion Process

## Input Format
```
10.A.B.C
```
Where A, B, C are numeric values.

## Output Format
```
{prefix}AB::C
```

## Conversion Rules

1. **Prefix**: Normalized to end with exactly one colon
   - `2404:e80:a137` → `2404:e80:a137:`

2. **A** (second octet): Output as-is, no padding
   - `1` → `1`
   - `12` → `12`

3. **B** (third octet): Zero-pad to 2 digits
   - `1` → `01`
   - `10` → `10`
   - `80` → `80`

4. **C** (fourth octet): Output as-is, no padding
   - `1` → `1`
   - `240` → `240`

5. **Assembly**: `{prefix}` + `A` + `B` (padded) + `::` + `C`

## Examples

| IPv4           | IPv6 Output                |
|----------------|----------------------------|
| `10.1.10.12`   | `2404:e80:a137:110::12`    |
| `10.12.80.240` | `2404:e80:a137:1280::240`  |
| `10.1.1.1`     | `2404:e80:a137:101::1`     |
| `10.99.99.256` | `2404:e80:a137:9999::256`  |
