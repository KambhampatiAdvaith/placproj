#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int contains(const unsigned char *data, size_t size, const char *pat)
{
    size_t len = strlen(pat);

    if (len == 0 || len > size)
        return 0;

    for (size_t i = 0; i <= size - len; i++) {
        if (memcmp(data + i, pat, len) == 0)
            return 1;
    }

    return 0;
}

int main(int argc, char *argv[])
{
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <file> <rulefile>\n", argv[0]);
        return 1;
    }

    FILE *fp = fopen(argv[1], "rb");
    if (!fp) {
        fprintf(stderr, "Cannot open file: %s\n", argv[1]);
        return 1;
    }

    if (fseek(fp, 0, SEEK_END) != 0) {
        fprintf(stderr, "Failed to seek file.\n");
        fclose(fp);
        return 1;
    }

    long fileSize = ftell(fp);
    if (fileSize < 0) {
        fprintf(stderr, "Failed to determine file size.\n");
        fclose(fp);
        return 1;
    }

    rewind(fp);

    if (fileSize == 0) {
        fprintf(stderr, "Target file is empty.\n");
        fclose(fp);
        return 1;
    }

    size_t size = (size_t)fileSize;

    unsigned char *buf = malloc(size);
    if (buf == NULL) {
        fprintf(stderr, "Memory allocation failed.\n");
        fclose(fp);
        return 1;
    }

    size_t bytesRead = fread(buf, 1, size, fp);
    fclose(fp);

    if (bytesRead != size) {
        fprintf(stderr, "Failed to read entire file.\n");
        free(buf);
        return 1;
    }

    FILE *rf = fopen(argv[2], "r");
    if (!rf) {
        fprintf(stderr, "Cannot open rule file: %s\n", argv[2]);
        free(buf);
        return 1;
    }

    char rule[256];
    int found = 0;

    while (fgets(rule, sizeof(rule), rf)) {

        rule[strcspn(rule, "\r\n")] = '\0';

        
        if (rule[0] == '\0')
            continue;

        if (contains(buf, size, rule)) {
            printf("Malware Detected: %s\n", rule);
            found = 1;
            break;
        }
    }

    if (!found)
        printf("File is Safe\n");

    fclose(rf);
    free(buf);

    return 0;
}
