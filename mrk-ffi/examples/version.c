#include <stdio.h>

#include "mrk_sdk.h"

int main(void) {
    printf("MRK SDK %s (ABI %u)\n", mrk_sdk_version(), mrk_sdk_abi_version());
    return 0;
}
