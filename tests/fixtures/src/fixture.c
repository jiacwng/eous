#include <stdint.h>
#include <stdio.h>

static uint32_t mix(uint32_t value) {
    value ^= value << 13;
    value ^= value >> 17;
    value ^= value << 5;
    return value;
}

static uint32_t checksum(const uint8_t *data, uint32_t length) {
    uint32_t state = 2166136261u;
    for (uint32_t i = 0; i < length; i++) {
        state = (state ^ data[i]) * 16777619u;
    }
    return state;
}

int main(void) {
    uint8_t buffer[64];
    uint32_t seed = 42;
    for (uint32_t i = 0; i < (uint32_t)sizeof(buffer); i++) {
        seed = mix(seed);
        buffer[i] = (uint8_t)(seed & 0xFFu);
    }
    printf("%08x\n", checksum(buffer, (uint32_t)sizeof(buffer)));
    return 0;
}
