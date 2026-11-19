`parse_number` in `src/bacnet/basic/sys/cJSON.c:105` accumulates the exponent digits in an `int`: `1e666...` overflows (UBSan: signed integer overflow). Upstream cJSON bug, not patched here.
