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

__attribute__((always_inline)) void calculate_sha256(PRIVATE_AS sha256_ctx_t *ctx, PRIVATE_AS const u32 *digest, const int len, u32 *target);
__attribute__((always_inline)) void array_copy_from_to(const u32 *src, const int start_index_src, u32 *dest, const int start_index_dest, const int len);
__attribute__((always_inline)) void storeU32ToByteArray(const u32 *u32Array, uchar* byteArray, const int numElements);
void sha256_padding_to_128_byte_array(const uchar *input, const int numInputBytes, uchar *output);
void storeByteArrayToU32Array(const uchar *byteArray, u32 *u32Array, const uint arrayLength);

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

    //int local_id = get_local_id(0);
    //int local_size = get_local_size(0);

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
 * Generates the public key
 * @param r out: result storing private key and the calculated address
 * @param k in: private key grid
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

  // int local_id = get_local_id(0);
  // int local_size = get_local_size(0);

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
 * Calculates the public key and then hashes the result once with Sha256
 * @param r out: result storing public key and its sha256 hash
 * @param k in: single private key
 */
__kernel void generateSha256ChunkKernel_grid(__global u32 *r, __global const u32 *k) {

    u32 x_local[PUBLIC_KEY_LENGTH_WITHOUT_PARITY];
    u32 y_local[PUBLIC_KEY_LENGTH_WITHOUT_PARITY];
    u32 k_local[PRIVATE_KEY_LENGTH];

    // to store the public keys coordinates for hashing
    u32 digest[32];
    uchar padded_byte_digest_1024[128];

    // to store the result of the sha256 hash
    u32 sha256_hash[SHA256_HASH_LEN];

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

    // the byte length of the result
    int r_offset = PUBKEY_LEN_WITHOUT_PARITY_WITH_SHA256 * global_id;

    // write the x-coordinate into the result array
    array_copy_from_to(x_local, 0, r, r_offset, PUBLIC_KEY_ONE_COORDINATE_LENGTH);

    // write the y-coordinate into the result array
    array_copy_from_to(y_local, 0, r, (r_offset + PUBLIC_KEY_ONE_COORDINATE_LENGTH), PUBLIC_KEY_ONE_COORDINATE_LENGTH);

    // copy x to digest
    digest[0] = x_local[7];
    digest[1] = x_local[6];
    digest[2] = x_local[5];
    digest[3] = x_local[4];
    digest[4] = x_local[3];
    digest[5] = x_local[2];
    digest[6] = x_local[1];
    digest[7] = x_local[0];

    // copy y to digest
    digest[8] = y_local[7];
    digest[9] = y_local[6];
    digest[10] = y_local[5];
    digest[11] = y_local[4];
    digest[12] = y_local[3];
    digest[13] = y_local[2];
    digest[14] = y_local[1];
    digest[15] = y_local[0];

    uchar byteArray[65];

    storeU32ToByteArray(digest, byteArray, 17);

    sha256_padding_to_128_byte_array(byteArray, 65, padded_byte_digest_1024);

    storeByteArrayToU32Array(padded_byte_digest_1024, digest, 128);

    sha256_ctx_t ctx;

    calculate_sha256(&ctx, digest, 128, sha256_hash);

    // write the sha256-hash into the result array
    array_copy_from_to(sha256_hash, 0, r, (r_offset + PUBLIC_KEY_LENGTH_X_Y_WITHOUT_PARITY), SHA256_HASH_LEN);
}

/*
 * Calculates the public key and then hashes the result once with Sha256
 * @param r out: result storing public key and its sha256 hash
 * @param k in: private key grid
 */
__kernel void generateSha256Kernel_grid(__global u32 *r, __global const u32 *k) {

    u32 x_local[PUBLIC_KEY_LENGTH_WITHOUT_PARITY];
    u32 y_local[PUBLIC_KEY_LENGTH_WITHOUT_PARITY];
    u32 k_local[PRIVATE_KEY_LENGTH];

    // to store the public keys coordinates for hashing
    u32 digest[32];
    uchar padded_byte_digest_1024[128];

    // to store the result of the sha256 hash
    u32 sha256_hash[SHA256_HASH_LEN];

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

    // the byte length of the result
    int r_offset = PUBKEY_LEN_WITHOUT_PARITY_WITH_SHA256 * global_id;

    // write the x-coordinate into the result array
    array_copy_from_to(x_local, 0, r, r_offset, PUBLIC_KEY_ONE_COORDINATE_LENGTH);

    // write the y-coordinate into the result array
    array_copy_from_to(y_local, 0, r, (r_offset + PUBLIC_KEY_ONE_COORDINATE_LENGTH), PUBLIC_KEY_ONE_COORDINATE_LENGTH);

    // copy x to digest
    digest[0] = x_local[7];
    digest[1] = x_local[6];
    digest[2] = x_local[5];
    digest[3] = x_local[4];
    digest[4] = x_local[3];
    digest[5] = x_local[2];
    digest[6] = x_local[1];
    digest[7] = x_local[0];

    // copy y to digest
    digest[8] = y_local[7];
    digest[9] = y_local[6];
    digest[10] = y_local[5];
    digest[11] = y_local[4];
    digest[12] = y_local[3];
    digest[13] = y_local[2];
    digest[14] = y_local[1];
    digest[15] = y_local[0];

    uchar byteArray[65];

    storeU32ToByteArray(digest, byteArray, 17);

    sha256_padding_to_128_byte_array(byteArray, 65, padded_byte_digest_1024);

    storeByteArrayToU32Array(padded_byte_digest_1024, digest, 128);

    sha256_ctx_t ctx;

    calculate_sha256(&ctx, digest, 128, sha256_hash);

    // write the sha256-hash into the result array
    array_copy_from_to(sha256_hash, 0, r, (r_offset + PUBLIC_KEY_LENGTH_X_Y_WITHOUT_PARITY), SHA256_HASH_LEN);
}

__attribute__((always_inline)) void calculate_sha256(PRIVATE_AS sha256_ctx_t *ctx, PRIVATE_AS const u32 *digest, const int len, u32* target) {

    sha256_init(ctx);
    sha256_update(ctx, digest, len);

    for(int i = 0; i < SHA256_HASH_LEN; i++){
        target[i] = ctx->h[i];
    }
}

__attribute__((always_inline)) void array_copy_from_to(const u32 *src, const int start_index_src, u32 *dest, const int start_index_dest, const int len) {
    for (int i = 0; i < len; i++) {
        dest[start_index_dest + i] = src[start_index_src + i];
    }
}

__attribute__((always_inline)) void storeU32ToByteArray(const u32 *u32Array, uchar* byteArray, const int numElements) {
    byteArray[0] = PUBLIC_KEY_PARITY_BYTE; // Set the first element to 4

    for (int i = 0; i < numElements; i++) {
        uint value = u32Array[i];
        int byteIndex = i * 4 + 1; // Start from the second byte

        byteArray[byteIndex + 0] = (value >> 24) & 0xFF;
        byteArray[byteIndex + 1] = (value >> 16) & 0xFF;
        byteArray[byteIndex + 2] = (value >> 8) & 0xFF;
        byteArray[byteIndex + 3] = value & 0xFF;
    }
}

/*
 *  the input must be in bytes, padding will only be done bytewise and not bitwise
 *  output muste be byte array with size 128
 *  input must be smaller than 120 bytes
 */
void sha256_padding_to_128_byte_array(const uchar *input, const int numInputBytes, uchar *output) {

    // copy input to output
    for(int i = 0; i < numInputBytes; i++){
        output[i] = input[i];
    }

    // store bits 10000000 in output right after the last input byte
    output[numInputBytes] = 128;

    // number of bytes containing 00000000
    int numZeroBytes = 128 - 8 - numInputBytes - 1;

    for(int i = (numInputBytes + 1); i < (numInputBytes + 1 + numZeroBytes); i++){
        output[i] = 0;
    }

    int offset = numInputBytes + 1 + numZeroBytes;
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

void storeByteArrayToU32Array(const uchar *byteArray, u32 *u32Array, const uint arrayLength) {
    for (uint i = 0; i < arrayLength / 4; i++) {
        u32 bits1to8 = byteArray[i * 4 + 3];
        u32 bits9to16 = byteArray[i * 4 + 2] << 8;
        u32 bits17to24 = byteArray[i * 4 + 1] << 16;
        u32 bits25to32 = byteArray[i * 4] << 24;
        u32 bits1to32 = bits1to8 | bits9to16 | bits17to24 | bits25to32;
        u32Array[i] = bits1to32;
    }
}

__kernel void test_kernel_do_nothing(__global u32 *r, __global const u32 *k) {
    // empty kernel
}