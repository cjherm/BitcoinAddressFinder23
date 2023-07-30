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

    calculate_sha256_from_bytes(public_key, first_sha256_hash);

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

    calculate_sha256_from_u32(first_sha256_hash, second_sha256_hash);

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

    calculate_sha256_from_bytes(public_key, first_sha256_hash);

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

    calculate_sha256_from_u32(first_sha256_hash, second_sha256_hash);

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
 * Calculates the public key from a given private key and then hashes the result with SHA-256 and again with RIPEMD-160.
 *
 * OUTPUT u32 *r:   The u32 array storing the result of this kernel (x,y coordinates, first hash, second hash)
 * INPUT u32 *k:    The u32 array storing the private key
 */
__kernel void generateRipemd160ChunkKernel_grid(__global u32 *r, __global const u32 *k) {

    u32 x_local[PUBLIC_KEY_LENGTH_WITHOUT_PARITY];
    u32 y_local[PUBLIC_KEY_LENGTH_WITHOUT_PARITY];
    u32 k_local[PRIVATE_KEY_LENGTH];
    uchar public_key[PUBLIC_KEY_BYTES_WITH_PARITY];

    // to store the results of the SHA-256 and RIPEMD-160 hashes
    u32 sha256_hash[SHA256_HASH_U32_LEN];
    u32 ripemd160_hash[RIPEMD160_HASH_U32_LEN];

    secp256k1_t g_xy_local;

    // get_global_id(dim) where dim is the dimension index (0 for first, 1 for
    // second dimension etc.)
    u32 global_id = get_global_id(0);

    // get private key from private key grid
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
    int r_offset_x = RESULT_U32_LEN_WITH_RIPEMD160 * global_id;
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

    calculate_sha256_from_bytes(public_key, sha256_hash);

    // write the SHA-256 hash into the result array
    int r_offset_sha256_hash = r_offset_y + PUBLIC_KEY_ONE_COORDINATE_LENGTH;
    r[r_offset_sha256_hash + 0] = sha256_hash[7];
    r[r_offset_sha256_hash + 1] = sha256_hash[6];
    r[r_offset_sha256_hash + 2] = sha256_hash[5];
    r[r_offset_sha256_hash + 3] = sha256_hash[4];
    r[r_offset_sha256_hash + 4] = sha256_hash[3];
    r[r_offset_sha256_hash + 5] = sha256_hash[2];
    r[r_offset_sha256_hash + 6] = sha256_hash[1];
    r[r_offset_sha256_hash + 7] = sha256_hash[0];

    calculate_ripemd160_from_u32(sha256_hash, ripemd160_hash);

    // write the RIPEMD-160 hash into the result array
    int r_offset_ripemd160_hash = r_offset_sha256_hash + SHA256_HASH_U32_LEN;
    r[r_offset_ripemd160_hash + 0] = ripemd160_hash[4];
    r[r_offset_ripemd160_hash + 1] = ripemd160_hash[3];
    r[r_offset_ripemd160_hash + 2] = ripemd160_hash[2];
    r[r_offset_ripemd160_hash + 3] = ripemd160_hash[1];
    r[r_offset_ripemd160_hash + 4] = ripemd160_hash[0];
}

/*
 * Calculates the public key from a given private key and then hashes the result with SHA-256 and again with RIPEMD-160.
 *
 * OUTPUT u32 *r:   The u32 array storing the result of this kernel (x,y coordinates, first hash, second hash)
 * INPUT u32 *k:    The u32 array storing the private keys
 */
__kernel void generateRipemd160Kernel_grid(__global u32 *r, __global const u32 *k) {

    u32 x_local[PUBLIC_KEY_LENGTH_WITHOUT_PARITY];
    u32 y_local[PUBLIC_KEY_LENGTH_WITHOUT_PARITY];
    u32 k_local[PRIVATE_KEY_LENGTH];
    uchar public_key[PUBLIC_KEY_BYTES_WITH_PARITY];

    // to store the results of the SHA-256 and RIPEMD-160 hashes
    u32 sha256_hash[SHA256_HASH_U32_LEN];
    u32 ripemd160_hash[RIPEMD160_HASH_U32_LEN];

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
    int r_offset_x = RESULT_U32_LEN_WITH_RIPEMD160 * global_id;
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

    calculate_sha256_from_bytes(public_key, sha256_hash);

    // write the SHA-256 hash into the result array
    int r_offset_sha256_hash = r_offset_y + PUBLIC_KEY_ONE_COORDINATE_LENGTH;
    r[r_offset_sha256_hash + 0] = sha256_hash[7];
    r[r_offset_sha256_hash + 1] = sha256_hash[6];
    r[r_offset_sha256_hash + 2] = sha256_hash[5];
    r[r_offset_sha256_hash + 3] = sha256_hash[4];
    r[r_offset_sha256_hash + 4] = sha256_hash[3];
    r[r_offset_sha256_hash + 5] = sha256_hash[2];
    r[r_offset_sha256_hash + 6] = sha256_hash[1];
    r[r_offset_sha256_hash + 7] = sha256_hash[0];

    calculate_ripemd160_from_u32(sha256_hash, ripemd160_hash);

    // write the RIPEMD-160 hash into the result array
    int r_offset_ripemd160_hash = r_offset_sha256_hash + SHA256_HASH_U32_LEN;
    r[r_offset_ripemd160_hash + 0] = ripemd160_hash[4];
    r[r_offset_ripemd160_hash + 1] = ripemd160_hash[3];
    r[r_offset_ripemd160_hash + 2] = ripemd160_hash[2];
    r[r_offset_ripemd160_hash + 3] = ripemd160_hash[1];
    r[r_offset_ripemd160_hash + 4] = ripemd160_hash[0];
}

__kernel void test_kernel_do_nothing(__global u32 *r, __global const u32 *k) {
    // empty kernel
}