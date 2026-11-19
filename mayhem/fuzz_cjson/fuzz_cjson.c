/* JSON parser used for BACnet property-value import (src/bacnet/basic/sys/cJSON.c). */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "bacnet/basic/sys/cJSON.h"

static void walk(const cJSON *item, int depth)
{
    const cJSON *child;

    if (!item || depth > 64) {
        return;
    }
    (void)cJSON_IsString(item);
    (void)cJSON_IsNumber(item);
    (void)cJSON_GetArraySize(item);
    cJSON_ArrayForEach(child, item)
    {
        if (child->string) {
            (void)cJSON_GetObjectItem(item, child->string);
        }
        walk(child, depth + 1);
    }
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    char *text;
    cJSON *root;

    text = (char *)malloc(size + 1);
    if (!text) {
        return -1;
    }
    memcpy(text, data, size);
    text[size] = 0;
    root = cJSON_Parse(text);
    if (root) {
        walk(root, 0);
        cJSON_Delete(root);
    }
    free(text);
    return 0;
}
