#include "pes.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <openssl/evp.h>

// Convert hash to hex
void hash_to_hex(const ObjectID *id, char *hex_out) {
    for (int i = 0; i < HASH_SIZE; i++) {
        sprintf(hex_out + i * 2, "%02x", id->hash[i]);
    }
    hex_out[HASH_HEX_SIZE] = '\0';
}

// Convert hex to hash
int hex_to_hash(const char *hex, ObjectID *id_out) {
    if (strlen(hex) < HASH_HEX_SIZE) return -1;
    for (int i = 0; i < HASH_SIZE; i++) {
        unsigned int byte;
        if (sscanf(hex + i * 2, "%2x", &byte) != 1) return -1;
        id_out->hash[i] = (uint8_t)byte;
    }
    return 0;
}

// Compute SHA-256 hash
void compute_hash(const void *data, size_t len, ObjectID *id_out) {
    unsigned int hash_len;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(ctx, data, len);
    EVP_DigestFinal_ex(ctx, id_out->hash, &hash_len);
    EVP_MD_CTX_free(ctx);
}

// Get object path
void object_path(const ObjectID *id, char *path_out, size_t path_size) {
    char hex[HASH_HEX_SIZE + 1];
    hash_to_hex(id, hex);
    snprintf(path_out, path_size, "%s/%.2s/%s", OBJECTS_DIR, hex, hex + 2);
}

// Check if object exists
int object_exists(const ObjectID *id) {
    char path[512];
    object_path(id, path, sizeof(path));
    return access(path, F_OK) == 0;
}

// ---------------------- IMPLEMENTATION ----------------------

// Write object
int object_write(ObjectType type, const void *data, size_t len, ObjectID *id_out) {
    if (!data || !id_out) return -1;

    const char *type_str =
        (type == OBJ_BLOB) ? "blob" :
        (type == OBJ_TREE) ? "tree" :
        (type == OBJ_COMMIT) ? "commit" : "unknown";

    // Create header
    char header[64];
    int header_len = snprintf(header, sizeof(header), "%s %zu", type_str, len);
    header_len += 1; // include null byte

    // Combine header + data
    size_t total_size = header_len + len;
    char *buffer = malloc(total_size);
    if (!buffer) return -1;

    memcpy(buffer, header, header_len);
    memcpy(buffer + header_len, data, len);

    // Compute hash
    compute_hash(buffer, total_size, id_out);

    // Check if exists
    if (object_exists(id_out)) {
        free(buffer);
        return 0;
    }

    // Create directories
    mkdir(".pes", 0755);
    mkdir(".pes/objects", 0755);

    char hex[HASH_HEX_SIZE + 1];
    hash_to_hex(id_out, hex);

    char dir[256];
    snprintf(dir, sizeof(dir), ".pes/objects/%.2s", hex);
    mkdir(dir, 0755);

    // File path
    char path[512];
    snprintf(path, sizeof(path), "%s/%s", dir, hex + 2);

    // Write file
    int fd = open(path, O_CREAT | O_WRONLY, 0644);
    if (fd < 0) {
        free(buffer);
        return -1;
    }

    if (write(fd, buffer, total_size) != (ssize_t)total_size) {
        close(fd);
        free(buffer);
        return -1;
    }

    close(fd);
    free(buffer);
    return 0;
}

// Read object
int object_read(const ObjectID *id, ObjectType *type_out, void **data_out, size_t *len_out) {
    if (!id || !type_out || !data_out || !len_out) return -1;

    char path[512];
    object_path(id, path, sizeof(path));

    FILE *f = fopen(path, "rb");
    if (!f) return -1;

    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);

    char *buffer = malloc(size);
    if (!buffer) {
        fclose(f);
        return -1;
    }

    fread(buffer, 1, size, f);
    fclose(f);
    ObjectID computed_id;
compute_hash(buffer, size, &computed_id);

if (memcmp(computed_id.hash, id->hash, HASH_SIZE) != 0) {
    free(buffer);
    return -1;
}

    // Find header end
    char *data_start = memchr(buffer, '\0', size);
    if (!data_start) {
        free(buffer);
        return -1;
    }

    *data_start = '\0';
    data_start++;

    // Parse type
    if (strncmp(buffer, "blob", 4) == 0)
        *type_out = OBJ_BLOB;
    else if (strncmp(buffer, "tree", 4) == 0)
        *type_out = OBJ_TREE;
    else if (strncmp(buffer, "commit", 6) == 0)
        *type_out = OBJ_COMMIT;
    else {
        free(buffer);
        return -1;
    }

    size_t data_len = size - (data_start - buffer);

    void *out = malloc(data_len);
    memcpy(out, data_start, data_len);

    *data_out = out;
    *len_out = data_len;

    free(buffer);
    return 0;
}// phase 1 step 2
// phase 1 step 3
// phase 1 step 4
