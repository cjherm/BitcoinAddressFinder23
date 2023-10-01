/**
 * Author......: Christoph Hermann, 2023
 * License.....: MIT
 */

__attribute__((always_inline)) void generate_ripemd160(__global uchar *r, const u32 *k_local_u32, const int work_item_id);

/*
 * Accelerated kernel for generating a Bitcoin address from a given private key.
 * Instead of the entire address including the version byte, RIPEMD-160 hash and checksum,
 * only the hash together with the private key is written into the result buffer.
 * This avoids the time-consuming process of creating the checksum. At the same time,
 * the given private key is initially combined with the global_id to calculate a new key.
 * Only a kernel with global_id = 0 uses the initially passed key.
 *
 * OUTPUT uchar *r: Pointer to the result buffer storing all private keys and RIPEMD-160 hashes
 * INPUT u32 *k:    Pointer to the source buffer storing one private key
 */
__kernel void generate_ripemd160_chunk(__global uchar *r, __global const u32 *k){

    // id of current work item
    int work_item_id = get_global_id(0);
    u32 k_local_u32[PRIVATE_KEY_LENGTH];

    // get first private key from private key grid and "create" a new one
    k_local_u32[0] = k[0] | work_item_id;
    k_local_u32[1] = k[1];
    k_local_u32[2] = k[2];
    k_local_u32[3] = k[3];
    k_local_u32[4] = k[4];
    k_local_u32[5] = k[5];
    k_local_u32[6] = k[6];
    k_local_u32[7] = k[7];

    generate_ripemd160(r, k_local_u32, work_item_id);
}

/*
 * Accelerated kernel for generating a Bitcoin address from a given private key.
 * Instead of the entire address including the version byte, RIPEMD-160 hash and checksum,
 * only the hash together with the private key is written into the result buffer.
 * This avoids the time-consuming process of creating the checksum.
 *
 * OUTPUT uchar *r: Pointer to the result buffer storing all private keys and RIPEMD-160 hashes
 * INPUT u32 *k:    Pointer to the source buffer storing all private keys
 */
__kernel void generate_ripemd160_nonchunk(__global uchar *r, __global const u32 *k){

    // id of current work item
    int work_item_id = get_global_id(0);
    u32 k_local_u32[PRIVATE_KEY_LENGTH];

    // calculating offset to read private key
    int k_offset = PRIVATE_KEY_LENGTH * work_item_id;

    // get private key from private key grid
    k_local_u32[0] = k[0 + k_offset];
    k_local_u32[1] = k[1 + k_offset];
    k_local_u32[2] = k[2 + k_offset];
    k_local_u32[3] = k[3 + k_offset];
    k_local_u32[4] = k[4 + k_offset];
    k_local_u32[5] = k[5 + k_offset];
    k_local_u32[6] = k[6 + k_offset];
    k_local_u32[7] = k[7 + k_offset];

    generate_ripemd160(r, k_local_u32, work_item_id);
}

/*
 * Accelerated function for generating a Bitcoin address from a given private key.
 * Instead of the entire address including the version byte, RIPEMD-160 hash and checksum,
 * only the hash together with the private key is written into the result buffer.
 * This avoids the time-consuming process of creating the checksum.
 *
 * OUTPUT uchar *r:         Pointer to the result buffer storing all private keys and RIPEMD-160 hashes
 * INPUT u32 k_local_u32:   The private key
 * INPUT int work_item_id:  The ID of the current work-item
 */
__attribute__((always_inline)) void generate_ripemd160(__global uchar *r, const u32 *k_local_u32, const int work_item_id){

    u32 x_local_u32[PUBLIC_KEY_ONE_COORDINATE_LENGTH];
    u32 y_local_u32[PUBLIC_KEY_ONE_COORDINATE_LENGTH];
    secp256k1_t g_xy_local;

    // to store the padded public key and the padded SHA-256 result
    u32 padded_public_key[32];
    u32 padded_sha256_hash[16];

    // special data structures for SHA-256 and RIPEMD-160 hashing
    sha256_ctx_t sha256_hash;
    ripemd160_ctx_t ripemd160_hash;

    // temporary storages
    u32 byte_0, byte_1, byte_2, byte_3;

    // calculating offset to write private key and RIPEMD-160 hash into result buffer
    int r_offset_key = (PRIVATE_KEY_BYTES + RIPEMD160_HASH_BYTES) * work_item_id;
    int r_offset_hash = r_offset_key + PRIVATE_KEY_BYTES;


    // write bytes of u32 array storing private key into result buffer
    r[r_offset_key + 0] = (k_local_u32[7] >> 24) & 0xFF;
    r[r_offset_key + 1] = (k_local_u32[7] >> 16) & 0xFF;
    r[r_offset_key + 2] = (k_local_u32[7] >> 8) & 0xFF;
    r[r_offset_key + 3] = (k_local_u32[7] >> 0) & 0xFF;

    r[r_offset_key + 4] = (k_local_u32[6] >> 24) & 0xFF;
    r[r_offset_key + 5] = (k_local_u32[6] >> 16) & 0xFF;
    r[r_offset_key + 6] = (k_local_u32[6] >> 8) & 0xFF;
    r[r_offset_key + 7] = (k_local_u32[6] >> 0) & 0xFF;

    r[r_offset_key + 8] = (k_local_u32[5] >> 24) & 0xFF;
    r[r_offset_key + 9] = (k_local_u32[5] >> 16) & 0xFF;
    r[r_offset_key + 10] = (k_local_u32[5] >> 8) & 0xFF;
    r[r_offset_key + 11] = (k_local_u32[5] >> 0) & 0xFF;

    r[r_offset_key + 12] = (k_local_u32[4] >> 24) & 0xFF;
    r[r_offset_key + 13] = (k_local_u32[4] >> 16) & 0xFF;
    r[r_offset_key + 14] = (k_local_u32[4] >> 8) & 0xFF;
    r[r_offset_key + 15] = (k_local_u32[4] >> 0) & 0xFF;

    r[r_offset_key + 16] = (k_local_u32[3] >> 24) & 0xFF;
    r[r_offset_key + 17] = (k_local_u32[3] >> 16) & 0xFF;
    r[r_offset_key + 18] = (k_local_u32[3] >> 8) & 0xFF;
    r[r_offset_key + 19] = (k_local_u32[3] >> 0) & 0xFF;

    r[r_offset_key + 20] = (k_local_u32[2] >> 24) & 0xFF;
    r[r_offset_key + 21] = (k_local_u32[2] >> 16) & 0xFF;
    r[r_offset_key + 22] = (k_local_u32[2] >> 8) & 0xFF;
    r[r_offset_key + 23] = (k_local_u32[2] >> 0) & 0xFF;

    r[r_offset_key + 24] = (k_local_u32[1] >> 24) & 0xFF;
    r[r_offset_key + 25] = (k_local_u32[1] >> 16) & 0xFF;
    r[r_offset_key + 26] = (k_local_u32[1] >> 8) & 0xFF;
    r[r_offset_key + 27] = (k_local_u32[1] >> 0) & 0xFF;

    r[r_offset_key + 28] = (k_local_u32[0] >> 24) & 0xFF;
    r[r_offset_key + 29] = (k_local_u32[0] >> 16) & 0xFF;
    r[r_offset_key + 30] = (k_local_u32[0] >> 8) & 0xFF;
    r[r_offset_key + 31] = (k_local_u32[0] >> 0) & 0xFF;


    // calculating the public key coordinates
    set_precomputed_basepoint_g(&g_xy_local);
    point_mul_xy(x_local_u32, y_local_u32, k_local_u32, &g_xy_local);

    // write parity byte into padded public key for SHA-256
    byte_0 = PUBLIC_KEY_PARITY_BYTE << 24;

    // write x-coordinate into padded public key for SHA-256
    byte_1 = (x_local_u32[7] & 0xFF000000) >> 8;
    byte_2 = (x_local_u32[7] & 0x00FF0000) >> 8;
    byte_3 = (x_local_u32[7] & 0x0000FF00) >> 8;
    padded_public_key[0] = byte_0 | byte_1 | byte_2 | byte_3;

    byte_0 = x_local_u32[7] << 24;
    byte_1 = (x_local_u32[6] & 0xFF000000) >> 8;
    byte_2 = (x_local_u32[6] & 0x00FF0000) >> 8;
    byte_3 = (x_local_u32[6] & 0x0000FF00) >> 8;
    padded_public_key[1] = byte_0 | byte_1 | byte_2 | byte_3;

    byte_0 = x_local_u32[6] << 24;
    byte_1 = (x_local_u32[5] & 0xFF000000) >> 8;
    byte_2 = (x_local_u32[5] & 0x00FF0000) >> 8;
    byte_3 = (x_local_u32[5] & 0x0000FF00) >> 8;
    padded_public_key[2] = byte_0 | byte_1 | byte_2 | byte_3;

    byte_0 = x_local_u32[5] << 24;
    byte_1 = (x_local_u32[4] & 0xFF000000) >> 8;
    byte_2 = (x_local_u32[4] & 0x00FF0000) >> 8;
    byte_3 = (x_local_u32[4] & 0x0000FF00) >> 8;
    padded_public_key[3] = byte_0 | byte_1 | byte_2 | byte_3;

    byte_0 = x_local_u32[4] << 24;
    byte_1 = (x_local_u32[3] & 0xFF000000) >> 8;
    byte_2 = (x_local_u32[3] & 0x00FF0000) >> 8;
    byte_3 = (x_local_u32[3] & 0x0000FF00) >> 8;
    padded_public_key[4] = byte_0 | byte_1 | byte_2 | byte_3;

    byte_0 = x_local_u32[3] << 24;
    byte_1 = (x_local_u32[2] & 0xFF000000) >> 8;
    byte_2 = (x_local_u32[2] & 0x00FF0000) >> 8;
    byte_3 = (x_local_u32[2] & 0x0000FF00) >> 8;
    padded_public_key[5] = byte_0 | byte_1 | byte_2 | byte_3;

    byte_0 = x_local_u32[2] << 24;
    byte_1 = (x_local_u32[1] & 0xFF000000) >> 8;
    byte_2 = (x_local_u32[1] & 0x00FF0000) >> 8;
    byte_3 = (x_local_u32[1] & 0x0000FF00) >> 8;
    padded_public_key[6] = byte_0 | byte_1 | byte_2 | byte_3;

    byte_0 = x_local_u32[1] << 24;
    byte_1 = (x_local_u32[0] & 0xFF000000) >> 8;
    byte_2 = (x_local_u32[0] & 0x00FF0000) >> 8;
    byte_3 = (x_local_u32[0] & 0x0000FF00) >> 8;
    padded_public_key[7] = byte_0 | byte_1 | byte_2 | byte_3;

    byte_0 = x_local_u32[0] << 24;
    // write y-coordinate into padded public key for SHA-256
    byte_1 = (y_local_u32[7] & 0xFF000000) >> 8;
    byte_2 = (y_local_u32[7] & 0x00FF0000) >> 8;
    byte_3 = (y_local_u32[7] & 0x0000FF00) >> 8;
    padded_public_key[8] = byte_0 | byte_1 | byte_2 | byte_3;

    byte_0 = y_local_u32[7] << 24;
    byte_1 = (y_local_u32[6] & 0xFF000000) >> 8;
    byte_2 = (y_local_u32[6] & 0x00FF0000) >> 8;
    byte_3 = (y_local_u32[6] & 0x0000FF00) >> 8;
    padded_public_key[9] = byte_0 | byte_1 | byte_2 | byte_3;

    byte_0 = y_local_u32[6] << 24;
    byte_1 = (y_local_u32[5] & 0xFF000000) >> 8;
    byte_2 = (y_local_u32[5] & 0x00FF0000) >> 8;
    byte_3 = (y_local_u32[5] & 0x0000FF00) >> 8;
    padded_public_key[10] = byte_0 | byte_1 | byte_2 | byte_3;

    byte_0 = y_local_u32[5] << 24;
    byte_1 = (y_local_u32[4] & 0xFF000000) >> 8;
    byte_2 = (y_local_u32[4] & 0x00FF0000) >> 8;
    byte_3 = (y_local_u32[4] & 0x0000FF00) >> 8;
    padded_public_key[11] = byte_0 | byte_1 | byte_2 | byte_3;

    byte_0 = y_local_u32[4] << 24;
    byte_1 = (y_local_u32[3] & 0xFF000000) >> 8;
    byte_2 = (y_local_u32[3] & 0x00FF0000) >> 8;
    byte_3 = (y_local_u32[3] & 0x0000FF00) >> 8;
    padded_public_key[12] = byte_0 | byte_1 | byte_2 | byte_3;

    byte_0 = y_local_u32[3] << 24;
    byte_1 = (y_local_u32[2] & 0xFF000000) >> 8;
    byte_2 = (y_local_u32[2] & 0x00FF0000) >> 8;
    byte_3 = (y_local_u32[2] & 0x0000FF00) >> 8;
    padded_public_key[13] = byte_0 | byte_1 | byte_2 | byte_3;

    byte_0 = y_local_u32[2] << 24;
    byte_1 = (y_local_u32[1] & 0xFF000000) >> 8;
    byte_2 = (y_local_u32[1] & 0x00FF0000) >> 8;
    byte_3 = (y_local_u32[1] & 0x0000FF00) >> 8;
    padded_public_key[14] = byte_0 | byte_1 | byte_2 | byte_3;

    byte_0 = y_local_u32[1] << 24;
    byte_1 = (y_local_u32[0] & 0xFF000000) >> 8;
    byte_2 = (y_local_u32[0] & 0x00FF0000) >> 8;
    byte_3 = (y_local_u32[0] & 0x0000FF00) >> 8;
    padded_public_key[15] = byte_0 | byte_1 | byte_2 | byte_3;

    byte_0 = y_local_u32[0] << 24;

    // begin of padding bits

    // write "1" bit right after public key for SHA-256 padding
    // decimal (128 << 16) is 10000000 00000000 00000000 in binary
    byte_1 = 128 << 16;
    // fill rest with "0" bits for SHA-256 padding
    byte_2 = 0;
    byte_3 = 0;
    padded_public_key[16] = byte_0 | byte_1 | byte_2 | byte_3;

    padded_public_key[17] = 0;
    padded_public_key[18] = 0;
    padded_public_key[19] = 0;
    padded_public_key[20] = 0;
    padded_public_key[21] = 0;
    padded_public_key[22] = 0;
    padded_public_key[23] = 0;
    padded_public_key[24] = 0;
    padded_public_key[25] = 0;
    padded_public_key[26] = 0;
    padded_public_key[27] = 0;
    padded_public_key[28] = 0;
    padded_public_key[29] = 0;

    // begin of 64 length bits:
    // decimal ((2 << 8) | 8) is 00000010 00001000 in binary
    padded_public_key[30] = 0;
    byte_0 = 0;
    byte_1 = 0;
    byte_2 = 2 << 8;
    byte_3 = 8;
    padded_public_key[31] = byte_0 | byte_1 | byte_2 | byte_3;

    // hashing the padded public key with SHA-256
    sha256_init(&sha256_hash);
    sha256_update(&sha256_hash, padded_public_key, 128);

    // padding the SHA-256 result for RIPEMD-160:
    padded_sha256_hash[0] = sha256_hash.h[0];
    padded_sha256_hash[1] = sha256_hash.h[1];
    padded_sha256_hash[2] = sha256_hash.h[2];
    padded_sha256_hash[3] = sha256_hash.h[3];
    padded_sha256_hash[4] = sha256_hash.h[4];
    padded_sha256_hash[5] = sha256_hash.h[5];
    padded_sha256_hash[6] = sha256_hash.h[6];
    padded_sha256_hash[7] = sha256_hash.h[7];

    // begin of padding bits:

    // write "1" bit right after public key for SHA-256 padding
    // decimal 2147483648 10000000 00000000 00000000 00000000 in binary
    padded_sha256_hash[8] = 2147483648;

    // fill rest with "0"
    padded_sha256_hash[9] = 0;
    padded_sha256_hash[10] = 0;
    padded_sha256_hash[11] = 0;
    padded_sha256_hash[12] = 0;
    padded_sha256_hash[13] = 0;

    // begin of 64 length bits:
    // decimal 65536 is 00000000 00000001 00000000 00000000 in binary
    padded_sha256_hash[14] = 65536;
    padded_sha256_hash[15] = 0;

    // hashing the padded SHA-256 result with RIPEMD-160
    ripemd160_init(&ripemd160_hash);
    ripemd160_update_swap(&ripemd160_hash, padded_sha256_hash, 64);


    // write 5x 32-bit RIPEMD-160 result into the 20x 8-bit result buffer
    r[r_offset_hash + 0] = (ripemd160_hash.h[0] >> 0) & 0xFF;
    r[r_offset_hash + 1] = (ripemd160_hash.h[0] >> 8) & 0xFF;
    r[r_offset_hash + 2] = (ripemd160_hash.h[0] >> 16) & 0xFF;
    r[r_offset_hash + 3] = (ripemd160_hash.h[0] >> 24) & 0xFF;

    r[r_offset_hash + 4] = (ripemd160_hash.h[1] >> 0) & 0xFF;
    r[r_offset_hash + 5] = (ripemd160_hash.h[1] >> 8) & 0xFF;
    r[r_offset_hash + 6] = (ripemd160_hash.h[1] >> 16) & 0xFF;
    r[r_offset_hash + 7] = (ripemd160_hash.h[1] >> 24) & 0xFF;

    r[r_offset_hash + 8] = (ripemd160_hash.h[2] >> 0) & 0xFF;
    r[r_offset_hash + 9] = (ripemd160_hash.h[2] >> 8) & 0xFF;
    r[r_offset_hash + 10] = (ripemd160_hash.h[2] >> 16) & 0xFF;
    r[r_offset_hash + 11] = (ripemd160_hash.h[2] >> 24) & 0xFF;

    r[r_offset_hash + 12] = (ripemd160_hash.h[3] >> 0) & 0xFF;
    r[r_offset_hash + 13] = (ripemd160_hash.h[3] >> 8) & 0xFF;
    r[r_offset_hash + 14] = (ripemd160_hash.h[3] >> 16) & 0xFF;
    r[r_offset_hash + 15] = (ripemd160_hash.h[3] >> 24) & 0xFF;

    r[r_offset_hash + 16] = (ripemd160_hash.h[4] >> 0) & 0xFF;
    r[r_offset_hash + 17] = (ripemd160_hash.h[4] >> 8) & 0xFF;
    r[r_offset_hash + 18] = (ripemd160_hash.h[4] >> 16) & 0xFF;
    r[r_offset_hash + 19] = (ripemd160_hash.h[4] >> 24) & 0xFF;
}