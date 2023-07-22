/**
 * Author......: Bernard Ladenthin, 2020
 * License.....: MIT
 */
/*
// example private key (in)
// hex: 68e23530deb6d5011ab56d8ad9f7b4a3b424f1112f08606357497495929f72dc
// decimal: 47440210799387980664936216788675555637818488436833759923669526136462528967388
// WiF
// to generate the public key (out)
// 025d99d81d9e731e0d7eebd1c858b1155da7981b1f0a16d322a361f8b589ad2e3b
// hex:
k_local[7] = 0x68e23530;
k_local[6] = 0xdeb6d501;
k_local[5] = 0x1ab56d8a;
k_local[4] = 0xd9f7b4a3;
k_local[3] = 0xb424f111;
k_local[2] = 0x2f086063;
k_local[1] = 0x57497495;
k_local[0] = 0x929f72dc;
*/

/*
 * Generate a public key from a private key.
 * @param r out: x coordinate with leading parity, a pointer to an u32 array
 * with a size of 9.
 * @param k in: scalar to multiply the basepoint, a pointer to an u32 array with
 * a size of 8.
 */

__attribute__((always_inline)) void storeU32ToByteArray(const u32 *u32Array, const int numU32Elements, uchar *byteArray, const int byteArrayOffset);
__attribute__((always_inline)) void storeByteArrayToU32Array(const uchar *byteArray, u32 *u32Array, const uint arrayLength);
__attribute__((always_inline)) void create_public_key_from_coordinates(uchar *public_key_byte_array, const u32 *x_coordinate, const u32 *y_coordinate);
__attribute__((always_inline)) void sha256_padding(const uchar *input, const int numInputBytes, uchar *output);
__attribute__((always_inline)) void calculate_first_sha256(PRIVATE_AS const uchar *digest_bytes, u32 *sha256_hash);
__attribute__((always_inline)) void calculate_second_sha256(PRIVATE_AS const u32 *unpadded_digest_u32, u32 *sha256_hash);

/*
 * Generate a public key from a private key.
 * @param r out: x coordinate with leading parity, a pointer to an u32 array with a size of 9.
 * @param k in: scalar to multiply the basepoint, a pointer to an u32 array with a size of 8.
 */
__kernel void generateKeysKernel_parse_public(__global u32 *r, __global const u32 *k)
{

    u32 g_local[PUBLIC_KEY_LENGTH_WITH_PARITY];
    u32 r_local[PUBLIC_KEY_LENGTH_WITH_PARITY];
    u32 k_local[PRIVATE_KEY_LENGTH];
    secp256k1_t g_xy_local;
    u32 return_value;

    g_local[0] = SECP256K1_G_STRING0;
    g_local[1] = SECP256K1_G_STRING1;
    g_local[2] = SECP256K1_G_STRING2;
    g_local[3] = SECP256K1_G_STRING3;
    g_local[4] = SECP256K1_G_STRING4;
    g_local[5] = SECP256K1_G_STRING5;
    g_local[6] = SECP256K1_G_STRING6;
    g_local[7] = SECP256K1_G_STRING7;
    g_local[8] = SECP256K1_G_STRING8;

    // global to local
    k_local[0] = k[0];
    k_local[1] = k[1];
    k_local[2] = k[2];
    k_local[3] = k[3];
    k_local[4] = k[4];
    k_local[5] = k[5];
    k_local[6] = k[6];
    k_local[7] = k[7];
    
    return_value = parse_public(&g_xy_local, g_local);
    if (return_value != 0) {
        return;
    }
    
    point_mul(r_local, k_local, &g_xy_local);

    // local to global
    r[0] = r_local[0];
    r[1] = r_local[1];
    r[2] = r_local[2];
    r[3] = r_local[3];
    r[4] = r_local[4];
    r[5] = r_local[5];
    r[6] = r_local[6];
    r[7] = r_local[7];
    r[8] = r_local[8];
}

/*
 * Generate a secp256k1_t struct for the public point. pre-computed points: (x1,y1,-y1),(x3,y3,-y3),(x5,y5,-y5),(x7,y7,-y7).
 * @param r out: secp256k1_t structure, a pointer to an u32 array with a size of 96 (SECP256K1_PRE_COMPUTED_XY_SIZE).
 */
__kernel void get_precalculated_g(__global u32 *r)
{

    u32 g_local[PUBLIC_KEY_LENGTH_WITHOUT_PARITY];
    secp256k1_t g_xy_local;
    const u32 g_parity = SECP256K1_G_PARITY;
    u32 return_value;

    g_local[0] = SECP256K1_G0;
    g_local[1] = SECP256K1_G1;
    g_local[2] = SECP256K1_G2;
    g_local[3] = SECP256K1_G3;
    g_local[4] = SECP256K1_G4;
    g_local[5] = SECP256K1_G5;
    g_local[6] = SECP256K1_G6;
    g_local[7] = SECP256K1_G7;
    
    return_value = transform_public(&g_xy_local, g_local, g_parity);
    
    if (return_value != 0) {
        return;
    }
    
    for(int i=0; i<SECP256K1_PRE_COMPUTED_XY_SIZE; i++) {
        r[i] = g_xy_local.xy[i];
    }
}

__kernel void generateKeysKernel_transform_public(__global u32 *r, __global const u32 *k)
{

    u32 g_local[PUBLIC_KEY_LENGTH_WITHOUT_PARITY];
    u32 r_local[PUBLIC_KEY_LENGTH_WITH_PARITY];
    u32 k_local[PRIVATE_KEY_LENGTH];
    secp256k1_t g_xy_local;
    const u32 g_parity = SECP256K1_G_PARITY;
    u32 return_value;

    g_local[0] = SECP256K1_G0;
    g_local[1] = SECP256K1_G1;
    g_local[2] = SECP256K1_G2;
    g_local[3] = SECP256K1_G3;
    g_local[4] = SECP256K1_G4;
    g_local[5] = SECP256K1_G5;
    g_local[6] = SECP256K1_G6;
    g_local[7] = SECP256K1_G7;

    // global to local
    k_local[0] = k[0];
    k_local[1] = k[1];
    k_local[2] = k[2];
    k_local[3] = k[3];
    k_local[4] = k[4];
    k_local[5] = k[5];
    k_local[6] = k[6];
    k_local[7] = k[7];
    
    return_value = transform_public(&g_xy_local, g_local, g_parity);
    
    if (return_value != 0) {
        return;
    }
    
    point_mul(r_local, k_local, &g_xy_local);

    // local to global
    r[0] = r_local[0];
    r[1] = r_local[1];
    r[2] = r_local[2];
    r[3] = r_local[3];
    r[4] = r_local[4];
    r[5] = r_local[5];
    r[6] = r_local[6];
    r[7] = r_local[7];
    r[8] = r_local[8];
}

/*
 * Calculates the public key from a given private key. Will manipulate that private key depending on the global id.
 *
 * OUTPUT u32 *r:   The u32 array storing the result of this kernel
 * INPUT u32 *k:    The u32 array storing the initial private key which will be modified in this kernel method
 */
__kernel void generateKeyChunkKernel_grid(__global u32 *r, __global const u32 *k)
{
    u32 x_local[PUBLIC_KEY_LENGTH_WITHOUT_PARITY];
    u32 y_local[PUBLIC_KEY_LENGTH_WITHOUT_PARITY];
    u32 k_local[PRIVATE_KEY_LENGTH];
    secp256k1_t g_xy_local;

    // get_global_id(dim) where dim is the dimension index (0 for first, 1 for second dimension etc.)
    // The above call is equivalent to get_local_size(dim)*get_group_id(dim) + get_local_id(dim)
    // size_t global_id = get_global_id(0);
    u32 global_id = get_global_id(0);

    // global to local
    k_local[0] = k[0] | global_id;
    k_local[1] = k[1];
    k_local[2] = k[2];
    k_local[3] = k[3];
    k_local[4] = k[4];
    k_local[5] = k[5];
    k_local[6] = k[6];
    k_local[7] = k[7];

    set_precomputed_basepoint_g(&g_xy_local);

    point_mul_xy(x_local, y_local, k_local, &g_xy_local);

    // local to global
    int r_offset = PUBLIC_KEY_LENGTH_X_Y_WITHOUT_PARITY * global_id;

    // x
    r[r_offset+ 0] = x_local[0];
    r[r_offset+ 1] = x_local[1];
    r[r_offset+ 2] = x_local[2];
    r[r_offset+ 3] = x_local[3];
    r[r_offset+ 4] = x_local[4];
    r[r_offset+ 5] = x_local[5];
    r[r_offset+ 6] = x_local[6];
    r[r_offset+ 7] = x_local[7];

    // y
    r[r_offset+ 8] = y_local[0];
    r[r_offset+ 9] = y_local[1];
    r[r_offset+10] = y_local[2];
    r[r_offset+11] = y_local[3];
    r[r_offset+12] = y_local[4];
    r[r_offset+13] = y_local[5];
    r[r_offset+14] = y_local[6];
    r[r_offset+15] = y_local[7];
}

/*
 * Calculates the public key from a given private key.
 *
 * OUTPUT u32 *r:   The u32 array storing the result of this kernel
 * INPUT u32 *k:    The u32 array storing the private key
 */
__kernel void generateKeysKernel_grid(__global u32 *r, __global const u32 *k) {
    u32 x_local[PUBLIC_KEY_LENGTH_WITHOUT_PARITY];
    u32 y_local[PUBLIC_KEY_LENGTH_WITHOUT_PARITY];
    u32 k_local[PRIVATE_KEY_LENGTH];
    secp256k1_t g_xy_local;

    // get_global_id(dim) where dim is the dimension index (0 for first, 1 for
    // second dimension etc.) The above call is equivalent to
    // get_local_size(dim)*get_group_id(dim) + get_local_id(dim) size_t global_id
    // = get_global_id(0);
    u32 global_id = get_global_id(0);

    // new offset for private keys
    int k_offset = PRIVATE_KEY_LENGTH * global_id;

    // get private key from private key grid
    k_local[0] = k[0 + k_offset];
    k_local[1] = k[1 + k_offset];
    k_local[2] = k[2 + k_offset];
    k_local[3] = k[3 + k_offset];
    k_local[4] = k[4 + k_offset];
    k_local[5] = k[5 + k_offset];
    k_local[6] = k[6 + k_offset];
    k_local[7] = k[7 + k_offset];

    set_precomputed_basepoint_g(&g_xy_local);

    // calculating the public key
    // K = public key
    // k = private key
    // G = generator point (pre-calculated)
    // K = k * G
    point_mul_xy(x_local, y_local, k_local, &g_xy_local);

    int r_offset = PUBLIC_KEY_LENGTH_X_Y_WITHOUT_PARITY * global_id;

    // local to global
    // x
    r[r_offset + 0] = x_local[0];
    r[r_offset + 1] = x_local[1];
    r[r_offset + 2] = x_local[2];
    r[r_offset + 3] = x_local[3];
    r[r_offset + 4] = x_local[4];
    r[r_offset + 5] = x_local[5];
    r[r_offset + 6] = x_local[6];
    r[r_offset + 7] = x_local[7];

    // y
    r[r_offset + 8] = y_local[0];
    r[r_offset + 9] = y_local[1];
    r[r_offset + 10] = y_local[2];
    r[r_offset + 11] = y_local[3];
    r[r_offset + 12] = y_local[4];
    r[r_offset + 13] = y_local[5];
    r[r_offset + 14] = y_local[6];
    r[r_offset + 15] = y_local[7];
}

/*
 * Calculates the public key from a given private key. Will manipulate that private key depending on the global id.
 * Then hashes the calculated public key twice with SHA-256.
 *
 * OUTPUT u32 *r:   The u32 array storing the result of this kernel (x,y coordinates, first hash, second hash)
 * INPUT u32 *k:    The u32 array storing the initial private key which will be modified in this kernel method
 */
__kernel void generateSha256ChunkKernel_grid(__global u32 *r, __global const u32 *k) {

    u32 x_local[PUBLIC_KEY_LENGTH_WITHOUT_PARITY];
    u32 y_local[PUBLIC_KEY_LENGTH_WITHOUT_PARITY];
    u32 k_local[PRIVATE_KEY_LENGTH];
    uchar public_key[PUBLIC_KEY_BYTES_WITH_PARITY];

    // to store the results of the SHA-256 hashes
    u32 first_sha256_hash[SHA256_HASH_U32_LEN];
    u32 second_sha256_hash[SHA256_HASH_U32_LEN];

    secp256k1_t g_xy_local;

    // get_global_id(dim) where dim is the dimension index (0 for first, 1 for
    // second dimension etc.)
    u32 global_id = get_global_id(0);

    // global to local
    k_local[0] = k[0] | global_id;
    k_local[1] = k[1];
    k_local[2] = k[2];
    k_local[3] = k[3];
    k_local[4] = k[4];
    k_local[5] = k[5];
    k_local[6] = k[6];
    k_local[7] = k[7];

    set_precomputed_basepoint_g(&g_xy_local);

    point_mul_xy(x_local, y_local, k_local, &g_xy_local);

    // write the x-coordinate into the result array
    int r_offset_x = PUBKEY_LEN_WITHOUT_PARITY_WITH_SHA256 * global_id;
    r[r_offset_x + 0] = x_local[0];
    r[r_offset_x + 1] = x_local[1];
    r[r_offset_x + 2] = x_local[2];
    r[r_offset_x + 3] = x_local[3];
    r[r_offset_x + 4] = x_local[4];
    r[r_offset_x + 5] = x_local[5];
    r[r_offset_x + 6] = x_local[6];
    r[r_offset_x + 7] = x_local[7];

    // write the y-coordinate into the result array
    int r_offset_y = r_offset_x + PUBLIC_KEY_ONE_COORDINATE_LENGTH;
    r[r_offset_y + 0] = y_local[0];
    r[r_offset_y + 1] = y_local[1];
    r[r_offset_y + 2] = y_local[2];
    r[r_offset_y + 3] = y_local[3];
    r[r_offset_y + 4] = y_local[4];
    r[r_offset_y + 5] = y_local[5];
    r[r_offset_y + 6] = y_local[6];
    r[r_offset_y + 7] = y_local[7];

    create_public_key_from_coordinates(public_key, x_local, y_local);

    calculate_first_sha256(public_key, first_sha256_hash);

    // write the first SHA-256 hash into the result array
    int r_offset_first_hash = r_offset_y + PUBLIC_KEY_ONE_COORDINATE_LENGTH;
    r[r_offset_first_hash + 0] = first_sha256_hash[7];
    r[r_offset_first_hash + 1] = first_sha256_hash[6];
    r[r_offset_first_hash + 2] = first_sha256_hash[5];
    r[r_offset_first_hash + 3] = first_sha256_hash[4];
    r[r_offset_first_hash + 4] = first_sha256_hash[3];
    r[r_offset_first_hash + 5] = first_sha256_hash[2];
    r[r_offset_first_hash + 6] = first_sha256_hash[1];
    r[r_offset_first_hash + 7] = first_sha256_hash[0];

    calculate_second_sha256(first_sha256_hash, second_sha256_hash);

    // write the second SHA-256 hash into the result array
    int r_offset_second_hash = r_offset_first_hash + SHA256_HASH_U32_LEN;
    r[r_offset_second_hash + 0] = second_sha256_hash[7];
    r[r_offset_second_hash + 1] = second_sha256_hash[6];
    r[r_offset_second_hash + 2] = second_sha256_hash[5];
    r[r_offset_second_hash + 3] = second_sha256_hash[4];
    r[r_offset_second_hash + 4] = second_sha256_hash[3];
    r[r_offset_second_hash + 5] = second_sha256_hash[2];
    r[r_offset_second_hash + 6] = second_sha256_hash[1];
    r[r_offset_second_hash + 7] = second_sha256_hash[0];
}

/*
 * Calculates the public key from a given private key and then hashes the result twice with SHA-256.
 *
 * OUTPUT u32 *r:   The u32 array storing the result of this kernel (x,y coordinates, first hash, second hash)
 * INPUT u32 *k:    The u32 array storing the private key
 */
__kernel void generateSha256Kernel_grid(__global u32 *r, __global const u32 *k) {

    u32 x_local[PUBLIC_KEY_LENGTH_WITHOUT_PARITY];
    u32 y_local[PUBLIC_KEY_LENGTH_WITHOUT_PARITY];
    u32 k_local[PRIVATE_KEY_LENGTH];
    uchar public_key[PUBLIC_KEY_BYTES_WITH_PARITY];

    // to store the results of the SHA-256 hashes
    u32 first_sha256_hash[SHA256_HASH_U32_LEN];
    u32 second_sha256_hash[SHA256_HASH_U32_LEN];

    secp256k1_t g_xy_local;

    // get_global_id(dim) where dim is the dimension index (0 for first, 1 for
    // second dimension etc.)
    u32 global_id = get_global_id(0);

    // new offset for private keys
    int k_offset = PRIVATE_KEY_LENGTH * global_id;

    // get private key from private key grid
    k_local[0] = k[0 + k_offset];
    k_local[1] = k[1 + k_offset];
    k_local[2] = k[2 + k_offset];
    k_local[3] = k[3 + k_offset];
    k_local[4] = k[4 + k_offset];
    k_local[5] = k[5 + k_offset];
    k_local[6] = k[6 + k_offset];
    k_local[7] = k[7 + k_offset];

    set_precomputed_basepoint_g(&g_xy_local);

    point_mul_xy(x_local, y_local, k_local, &g_xy_local);

    // write the x-coordinate into the result array
    int r_offset_x = PUBKEY_LEN_WITHOUT_PARITY_WITH_SHA256 * global_id;
    r[r_offset_x + 0] = x_local[0];
    r[r_offset_x + 1] = x_local[1];
    r[r_offset_x + 2] = x_local[2];
    r[r_offset_x + 3] = x_local[3];
    r[r_offset_x + 4] = x_local[4];
    r[r_offset_x + 5] = x_local[5];
    r[r_offset_x + 6] = x_local[6];
    r[r_offset_x + 7] = x_local[7];

    // write the y-coordinate into the result array
    int r_offset_y = r_offset_x + PUBLIC_KEY_ONE_COORDINATE_LENGTH;
    r[r_offset_y + 0] = y_local[0];
    r[r_offset_y + 1] = y_local[1];
    r[r_offset_y + 2] = y_local[2];
    r[r_offset_y + 3] = y_local[3];
    r[r_offset_y + 4] = y_local[4];
    r[r_offset_y + 5] = y_local[5];
    r[r_offset_y + 6] = y_local[6];
    r[r_offset_y + 7] = y_local[7];

    create_public_key_from_coordinates(public_key, x_local, y_local);

    calculate_first_sha256(public_key, first_sha256_hash);

    // write the first SHA-256 hash into the result array
    int r_offset_first_hash = r_offset_y + PUBLIC_KEY_ONE_COORDINATE_LENGTH;
    r[r_offset_first_hash + 0] = first_sha256_hash[7];
    r[r_offset_first_hash + 1] = first_sha256_hash[6];
    r[r_offset_first_hash + 2] = first_sha256_hash[5];
    r[r_offset_first_hash + 3] = first_sha256_hash[4];
    r[r_offset_first_hash + 4] = first_sha256_hash[3];
    r[r_offset_first_hash + 5] = first_sha256_hash[2];
    r[r_offset_first_hash + 6] = first_sha256_hash[1];
    r[r_offset_first_hash + 7] = first_sha256_hash[0];

    calculate_second_sha256(first_sha256_hash, second_sha256_hash);

    // write the second SHA-256 hash into the result array
    int r_offset_second_hash = r_offset_first_hash + SHA256_HASH_U32_LEN;
    r[r_offset_second_hash + 0] = second_sha256_hash[7];
    r[r_offset_second_hash + 1] = second_sha256_hash[6];
    r[r_offset_second_hash + 2] = second_sha256_hash[5];
    r[r_offset_second_hash + 3] = second_sha256_hash[4];
    r[r_offset_second_hash + 4] = second_sha256_hash[3];
    r[r_offset_second_hash + 5] = second_sha256_hash[2];
    r[r_offset_second_hash + 6] = second_sha256_hash[1];
    r[r_offset_second_hash + 7] = second_sha256_hash[0];
}

 /*
  * Calculates the SHA-256 hash from a given digest.
  *
  * INPUT uchar *digest_bytes:  Pointer to the digest as byte array to be hashed
  * OUTPUT u32 *sha256_hash:     Pointer to the resulting hash as an u32 array
  */
__attribute__((always_inline)) void calculate_first_sha256(PRIVATE_AS const uchar *digest_bytes, u32 *sha256_hash) {

    // digest to be hashed
    u32 digest_u32[SHA256_HASH_BYTES_LEN];

    // padded byte array for correct sha256 digest length
    uchar padded_digest_bytes[DOUBLE_SIZED_SHA256_INPUT_BYTES];

    // prepare hash
    sha256_padding(digest_bytes, PUBLIC_KEY_BYTES_WITH_PARITY, padded_digest_bytes);
    storeByteArrayToU32Array(padded_digest_bytes, digest_u32, DOUBLE_SIZED_SHA256_INPUT_BYTES);

    // perform hash
    sha256_ctx_t ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, digest_u32, DOUBLE_SIZED_SHA256_INPUT_BYTES);

    // store hash in output
    sha256_hash[0] = ctx.h[0];
    sha256_hash[1] = ctx.h[1];
    sha256_hash[2] = ctx.h[2];
    sha256_hash[3] = ctx.h[3];
    sha256_hash[4] = ctx.h[4];
    sha256_hash[5] = ctx.h[5];
    sha256_hash[6] = ctx.h[6];
    sha256_hash[7] = ctx.h[7];
}

 /*
  * Calculates the SHA-256 hash from a given digest.
  *
  * INPUT uchar *unpadded_digest_u32:   Pointer to the digest as u32 array to be hashed
  * OUTPUT u32 *sha256_hash:            Pointer to the resulting hash as an u32 array
  */
__attribute__((always_inline)) void calculate_second_sha256(PRIVATE_AS const u32 *unpadded_digest_u32, u32 *sha256_hash){

    // unpadded digest as byte array (needed for bytewise padding)
    uchar unpadded_digest_bytes[SHA256_HASH_BYTES_LEN];

    // padded digest as byte array
    uchar padded_digest_bytes[SINGLE_SIZED_SHA256_INPUT_BYTES];

    // padded digest as u32 array
    u32 padded_digest_u32[SINGLE_SIZED_SHA256_INPUT_U32];

    storeU32ToByteArray(unpadded_digest_u32, SHA256_HASH_U32_LEN, unpadded_digest_bytes, 0);

    sha256_padding(unpadded_digest_bytes, SHA256_HASH_BYTES_LEN, padded_digest_bytes);
    storeByteArrayToU32Array(padded_digest_bytes, padded_digest_u32, SINGLE_SIZED_SHA256_INPUT_BYTES);

    // perform hash
    sha256_ctx_t ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, padded_digest_u32, SINGLE_SIZED_SHA256_INPUT_BYTES);

    // store hash in output
    sha256_hash[0] = ctx.h[0];
    sha256_hash[1] = ctx.h[1];
    sha256_hash[2] = ctx.h[2];
    sha256_hash[3] = ctx.h[3];
    sha256_hash[4] = ctx.h[4];
    sha256_hash[5] = ctx.h[5];
    sha256_hash[6] = ctx.h[6];
    sha256_hash[7] = ctx.h[7];
}

 /*
  * This function will perform a SHA-256 input padding on a given byte array.
  * For SHA-256 the input must be a multiple 64 bytes.
  * If the input smaller, a special padding operation must be performed.
  *
  * INPUT uchar *input:         Pointer to the byte array to be padded
  * PARAM int numInputBytes:    Size of the byte array to be padded
  * OUTPUT uchar *output:       Pointer to the byte array to store the padded byte array
  */
__attribute__((always_inline)) void sha256_padding(const uchar *input, const int numInputBytes, uchar *output) {

    int multiples_of_64 = 0;
    int temp = numInputBytes;
    while(temp > 0){
        multiples_of_64 = multiples_of_64 + 1;
        temp = temp - SINGLE_SIZED_SHA256_INPUT_BYTES;
    }

    int output_size = multiples_of_64 * SINGLE_SIZED_SHA256_INPUT_BYTES;

    // copy input to output
    for(int i = 0; i < numInputBytes; i++){
        output[i] = input[i];
    }

    // store bits 10000000 in output right after the last input byte
    output[numInputBytes] = 128;

    // number of bytes containing 00000000
    int numZeroBytes = output_size - 8 - numInputBytes - 1;
    int offset = numInputBytes + 1 + numZeroBytes;

    for(int i = (numInputBytes + 1); i < offset; i++){
        output[i] = 0;
    }

    long numInputBits = numInputBytes * 8;

    output[(offset + 0)] = numInputBits >> 56 & 0xFF;
    output[(offset + 1)] = numInputBits >> 48 & 0xFF;
    output[(offset + 2)] = numInputBits >> 40 & 0xFF;
    output[(offset + 3)] = numInputBits >> 32 & 0xFF;
    output[(offset + 4)] = numInputBits >> 24 & 0xFF;
    output[(offset + 5)] = numInputBits >> 16 & 0xFF;
    output[(offset + 6)] = numInputBits >> 8 & 0xFF;
    output[(offset + 7)] = numInputBits & 0xFF;
}

/*
 * Stores an array of u32 elements into an array of bytes.
 *
 * INPUT u32 *u32Array:         Pointer to the u32 array to be stored in the byte array
 * PARAM uint numU32Elements:   Size of the outgoing byte array
 * OUTPUT uchar *byteArray:     Pointer to the byte array to store the u32 array
 * PARAM int byteArrayOffset:   Offset of how many indices will be skipped before writing in the byte array
 */
__attribute__((always_inline)) void storeU32ToByteArray(const u32 *u32Array, const int numU32Elements, uchar *byteArray, const int byteArrayOffset) {
    for (int i = 0; i < numU32Elements; i++) {
        uint value = u32Array[i];
        int byteIndex = i * 4 + byteArrayOffset;
        byteArray[byteIndex + 0] = (value >> 24) & 0xFF;
        byteArray[byteIndex + 1] = (value >> 16) & 0xFF;
        byteArray[byteIndex + 2] = (value >> 8) & 0xFF;
        byteArray[byteIndex + 3] = value & 0xFF;
    }
}

/*
 * Stores an array of bytes into an array of u32 elements.
 *
 * INPUT uchar *byteArray:      Pointer to the byte array to be stored in the u32 array
 * OUTPUT u32 *u32Array:        Pointer to the u32 array to store the byte array
 * PARAM uint u32ArrayLength:   Size of the outgoing u32 array
 */
__attribute__((always_inline)) void storeByteArrayToU32Array(const uchar *byteArray, u32 *u32Array, const uint u32ArrayLength) {
    for (uint i = 0; i < u32ArrayLength / 4; i++) {
        u32 bits1to8 = byteArray[i * 4 + 3];
        u32 bits9to16 = byteArray[i * 4 + 2] << 8;
        u32 bits17to24 = byteArray[i * 4 + 1] << 16;
        u32 bits25to32 = byteArray[i * 4] << 24;
        u32 bits1to32 = bits1to8 | bits9to16 | bits17to24 | bits25to32;
        u32Array[i] = bits1to32;
    }
}

/*
 * Creates a private key from given x,y coordinates.
 *
 * OUTPUT uchar *public_key_byte_array: Pointer to created public key as a byte array
 * INPUT u32 *x_coordinate:             Pointer to the x coordinate as an u32 array
 * INPUT u32 *y_coordinate:             Pointer to the y coordinate as an u32 array
 */
__attribute__((always_inline)) void create_public_key_from_coordinates(uchar *public_key_byte_array, const u32 *x_coordinate, const u32 *y_coordinate) {

    u32 public_key_u32_array[PUBLIC_KEY_LENGTH_X_Y_WITHOUT_PARITY];

    // copy x to public_key_u32_array
    public_key_u32_array[0] = x_coordinate[7];
    public_key_u32_array[1] = x_coordinate[6];
    public_key_u32_array[2] = x_coordinate[5];
    public_key_u32_array[3] = x_coordinate[4];
    public_key_u32_array[4] = x_coordinate[3];
    public_key_u32_array[5] = x_coordinate[2];
    public_key_u32_array[6] = x_coordinate[1];
    public_key_u32_array[7] = x_coordinate[0];

    // copy y to public_key_u32_array
    public_key_u32_array[8] = y_coordinate[7];
    public_key_u32_array[9] = y_coordinate[6];
    public_key_u32_array[10] = y_coordinate[5];
    public_key_u32_array[11] = y_coordinate[4];
    public_key_u32_array[12] = y_coordinate[3];
    public_key_u32_array[13] = y_coordinate[2];
    public_key_u32_array[14] = y_coordinate[1];
    public_key_u32_array[15] = y_coordinate[0];

    // Set the first element to 4
    public_key_byte_array[0] = PUBLIC_KEY_PARITY_BYTE;

    storeU32ToByteArray(public_key_u32_array, PUBLIC_KEY_LENGTH_X_Y_WITHOUT_PARITY, public_key_byte_array, 1);
}

__kernel void test_kernel_do_nothing(__global u32 *r, __global const u32 *k) {
    // empty kernel
}