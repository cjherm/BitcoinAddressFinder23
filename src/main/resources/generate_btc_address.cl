/**
 * Author......: Bernard Ladenthin & Christoph Hermann, 2023
 * License.....: MIT
 */

/*
 * Creates a public key from a given private key.
 *
 * OUTPUT uchar *r: Pointer to the result buffer to store all results
 * INPUT u32 *k:    Pointer to the private key buffer storing all private keys
 */
__kernel void generate_until_publickey(__global uchar *r, __global const u32 *k){

    u32 k_local_u32[PRIVATE_KEY_LENGTH];
    u32 x_local_u32[PUBLIC_KEY_ONE_COORDINATE_LENGTH];
    u32 y_local_u32[PUBLIC_KEY_ONE_COORDINATE_LENGTH];
    uchar public_key_bytes[PUBLIC_KEY_BYTES_WITH_PARITY];
    secp256k1_t g_xy_local;

    // id of current work item
    int work_item_id = get_global_id(0);

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

    // calculating the public key coordinates
    set_precomputed_basepoint_g(&g_xy_local);
    point_mul_xy(x_local_u32, y_local_u32, k_local_u32, &g_xy_local);


    // calculating offset to write results in byte buffer
    int r_offset_bytes_private_key = (PRIVATE_KEY_BYTES + PUBLIC_KEY_BYTES_WITH_PARITY) * work_item_id;

    // write bytes of u32 array storing private key into result buffer
    r[r_offset_bytes_private_key + 0] = (k_local_u32[7] >> 24) & 0xFF;
    r[r_offset_bytes_private_key + 1] = (k_local_u32[7] >> 16) & 0xFF;
    r[r_offset_bytes_private_key + 2] = (k_local_u32[7] >> 8) & 0xFF;
    r[r_offset_bytes_private_key + 3] = (k_local_u32[7] >> 0) & 0xFF;

    r[r_offset_bytes_private_key + 4] = (k_local_u32[6] >> 24) & 0xFF;
    r[r_offset_bytes_private_key + 5] = (k_local_u32[6] >> 16) & 0xFF;
    r[r_offset_bytes_private_key + 6] = (k_local_u32[6] >> 8) & 0xFF;
    r[r_offset_bytes_private_key + 7] = (k_local_u32[6] >> 0) & 0xFF;

    r[r_offset_bytes_private_key + 8] = (k_local_u32[5] >> 24) & 0xFF;
    r[r_offset_bytes_private_key + 9] = (k_local_u32[5] >> 16) & 0xFF;
    r[r_offset_bytes_private_key + 10] = (k_local_u32[5] >> 8) & 0xFF;
    r[r_offset_bytes_private_key + 11] = (k_local_u32[5] >> 0) & 0xFF;

    r[r_offset_bytes_private_key + 12] = (k_local_u32[4] >> 24) & 0xFF;
    r[r_offset_bytes_private_key + 13] = (k_local_u32[4] >> 16) & 0xFF;
    r[r_offset_bytes_private_key + 14] = (k_local_u32[4] >> 8) & 0xFF;
    r[r_offset_bytes_private_key + 15] = (k_local_u32[4] >> 0) & 0xFF;

    r[r_offset_bytes_private_key + 16] = (k_local_u32[3] >> 24) & 0xFF;
    r[r_offset_bytes_private_key + 17] = (k_local_u32[3] >> 16) & 0xFF;
    r[r_offset_bytes_private_key + 18] = (k_local_u32[3] >> 8) & 0xFF;
    r[r_offset_bytes_private_key + 19] = (k_local_u32[3] >> 0) & 0xFF;

    r[r_offset_bytes_private_key + 20] = (k_local_u32[2] >> 24) & 0xFF;
    r[r_offset_bytes_private_key + 21] = (k_local_u32[2] >> 16) & 0xFF;
    r[r_offset_bytes_private_key + 22] = (k_local_u32[2] >> 8) & 0xFF;
    r[r_offset_bytes_private_key + 23] = (k_local_u32[2] >> 0) & 0xFF;

    r[r_offset_bytes_private_key + 24] = (k_local_u32[1] >> 24) & 0xFF;
    r[r_offset_bytes_private_key + 25] = (k_local_u32[1] >> 16) & 0xFF;
    r[r_offset_bytes_private_key + 26] = (k_local_u32[1] >> 8) & 0xFF;
    r[r_offset_bytes_private_key + 27] = (k_local_u32[1] >> 0) & 0xFF;

    r[r_offset_bytes_private_key + 28] = (k_local_u32[0] >> 24) & 0xFF;
    r[r_offset_bytes_private_key + 29] = (k_local_u32[0] >> 16) & 0xFF;
    r[r_offset_bytes_private_key + 30] = (k_local_u32[0] >> 8) & 0xFF;
    r[r_offset_bytes_private_key + 31] = (k_local_u32[0] >> 0) & 0xFF;


    // creating the public key from coordinates and parity byte for hashing
    create_public_key_from_coordinates(public_key_bytes, x_local_u32, y_local_u32);

    int r_offset_public_key = r_offset_bytes_private_key + PRIVATE_KEY_BYTES;

    // write public key parity byte into result buffer
    r[r_offset_public_key + 0] = 0x04;

    // write bytes of u32 array storing x coordinate into result buffer
    r[r_offset_public_key + 1] = (x_local_u32[7] >> 24) & 0xFF;
    r[r_offset_public_key + 2] = (x_local_u32[7] >> 16) & 0xFF;
    r[r_offset_public_key + 3] = (x_local_u32[7] >> 8) & 0xFF;
    r[r_offset_public_key + 4] = (x_local_u32[7] >> 0) & 0xFF;

    r[r_offset_public_key + 5] = (x_local_u32[6] >> 24) & 0xFF;
    r[r_offset_public_key + 6] = (x_local_u32[6] >> 16) & 0xFF;
    r[r_offset_public_key + 7] = (x_local_u32[6] >> 8) & 0xFF;
    r[r_offset_public_key + 8] = (x_local_u32[6] >> 0) & 0xFF;

    r[r_offset_public_key + 9] = (x_local_u32[5] >> 24) & 0xFF;
    r[r_offset_public_key + 10] = (x_local_u32[5] >> 16) & 0xFF;
    r[r_offset_public_key + 11] = (x_local_u32[5] >> 8) & 0xFF;
    r[r_offset_public_key + 12] = (x_local_u32[5] >> 0) & 0xFF;

    r[r_offset_public_key + 13] = (x_local_u32[4] >> 24) & 0xFF;
    r[r_offset_public_key + 14] = (x_local_u32[4] >> 16) & 0xFF;
    r[r_offset_public_key + 15] = (x_local_u32[4] >> 8) & 0xFF;
    r[r_offset_public_key + 16] = (x_local_u32[4] >> 0) & 0xFF;

    r[r_offset_public_key + 17] = (x_local_u32[3] >> 24) & 0xFF;
    r[r_offset_public_key + 18] = (x_local_u32[3] >> 16) & 0xFF;
    r[r_offset_public_key + 19] = (x_local_u32[3] >> 8) & 0xFF;
    r[r_offset_public_key + 20] = (x_local_u32[3] >> 0) & 0xFF;

    r[r_offset_public_key + 21] = (x_local_u32[2] >> 24) & 0xFF;
    r[r_offset_public_key + 22] = (x_local_u32[2] >> 16) & 0xFF;
    r[r_offset_public_key + 23] = (x_local_u32[2] >> 8) & 0xFF;
    r[r_offset_public_key + 24] = (x_local_u32[2] >> 0) & 0xFF;

    r[r_offset_public_key + 25] = (x_local_u32[1] >> 24) & 0xFF;
    r[r_offset_public_key + 26] = (x_local_u32[1] >> 16) & 0xFF;
    r[r_offset_public_key + 27] = (x_local_u32[1] >> 8) & 0xFF;
    r[r_offset_public_key + 28] = (x_local_u32[1] >> 0) & 0xFF;

    r[r_offset_public_key + 29] = (x_local_u32[0] >> 24) & 0xFF;
    r[r_offset_public_key + 30] = (x_local_u32[0] >> 16) & 0xFF;
    r[r_offset_public_key + 31] = (x_local_u32[0] >> 8) & 0xFF;
    r[r_offset_public_key + 32] = (x_local_u32[0] >> 0) & 0xFF;

    // write bytes of u32 array storing y coordinate into result buffer
    r[r_offset_public_key + 33] = (y_local_u32[7] >> 24) & 0xFF;
    r[r_offset_public_key + 34] = (y_local_u32[7] >> 16) & 0xFF;
    r[r_offset_public_key + 35] = (y_local_u32[7] >> 8) & 0xFF;
    r[r_offset_public_key + 36] = (y_local_u32[7] >> 0) & 0xFF;

    r[r_offset_public_key + 37] = (y_local_u32[6] >> 24) & 0xFF;
    r[r_offset_public_key + 38] = (y_local_u32[6] >> 16) & 0xFF;
    r[r_offset_public_key + 39] = (y_local_u32[6] >> 8) & 0xFF;
    r[r_offset_public_key + 40] = (y_local_u32[6] >> 0) & 0xFF;

    r[r_offset_public_key + 41] = (y_local_u32[5] >> 24) & 0xFF;
    r[r_offset_public_key + 42] = (y_local_u32[5] >> 16) & 0xFF;
    r[r_offset_public_key + 43] = (y_local_u32[5] >> 8) & 0xFF;
    r[r_offset_public_key + 44] = (y_local_u32[5] >> 0) & 0xFF;

    r[r_offset_public_key + 45] = (y_local_u32[4] >> 24) & 0xFF;
    r[r_offset_public_key + 46] = (y_local_u32[4] >> 16) & 0xFF;
    r[r_offset_public_key + 47] = (y_local_u32[4] >> 8) & 0xFF;
    r[r_offset_public_key + 48] = (y_local_u32[4] >> 0) & 0xFF;

    r[r_offset_public_key + 49] = (y_local_u32[3] >> 24) & 0xFF;
    r[r_offset_public_key + 50] = (y_local_u32[3] >> 16) & 0xFF;
    r[r_offset_public_key + 51] = (y_local_u32[3] >> 8) & 0xFF;
    r[r_offset_public_key + 52] = (y_local_u32[3] >> 0) & 0xFF;

    r[r_offset_public_key + 53] = (y_local_u32[2] >> 24) & 0xFF;
    r[r_offset_public_key + 54] = (y_local_u32[2] >> 16) & 0xFF;
    r[r_offset_public_key + 55] = (y_local_u32[2] >> 8) & 0xFF;
    r[r_offset_public_key + 56] = (y_local_u32[2] >> 0) & 0xFF;

    r[r_offset_public_key + 57] = (y_local_u32[1] >> 24) & 0xFF;
    r[r_offset_public_key + 58] = (y_local_u32[1] >> 16) & 0xFF;
    r[r_offset_public_key + 59] = (y_local_u32[1] >> 8) & 0xFF;
    r[r_offset_public_key + 60] = (y_local_u32[1] >> 0) & 0xFF;

    r[r_offset_public_key + 61] = (y_local_u32[0] >> 24) & 0xFF;
    r[r_offset_public_key + 62] = (y_local_u32[0] >> 16) & 0xFF;
    r[r_offset_public_key + 63] = (y_local_u32[0] >> 8) & 0xFF;
    r[r_offset_public_key + 64] = (y_local_u32[0] >> 0) & 0xFF;
}

/*
 * "Creates" private keys from a single private key and then calculates the public key.
 *
 * OUTPUT uchar *r: Pointer to the result buffer to store all results
 * INPUT u32 *k:    Pointer to the private key buffer storing a single private key
 */
__kernel void generate_chunk_until_publickey(__global uchar *r, __global const u32 *k){

    u32 k_local_u32[PRIVATE_KEY_LENGTH];
    u32 x_local_u32[PUBLIC_KEY_ONE_COORDINATE_LENGTH];
    u32 y_local_u32[PUBLIC_KEY_ONE_COORDINATE_LENGTH];
    uchar public_key_bytes[PUBLIC_KEY_BYTES_WITH_PARITY];
    secp256k1_t g_xy_local;

    // id of current work item
    int work_item_id = get_global_id(0);

    // get first private key from private key grid and "create" a new one
    k_local_u32[0] = k[0] | work_item_id;
    k_local_u32[1] = k[1];
    k_local_u32[2] = k[2];
    k_local_u32[3] = k[3];
    k_local_u32[4] = k[4];
    k_local_u32[5] = k[5];
    k_local_u32[6] = k[6];
    k_local_u32[7] = k[7];

    // calculating the public key coordinates
    set_precomputed_basepoint_g(&g_xy_local);
    point_mul_xy(x_local_u32, y_local_u32, k_local_u32, &g_xy_local);


    // calculating offset to write results in byte buffer
    int r_offset_bytes_private_key = (PRIVATE_KEY_BYTES + PUBLIC_KEY_BYTES_WITH_PARITY) * work_item_id;

    // write bytes of u32 array storing private key into result buffer
    r[r_offset_bytes_private_key + 0] = (k_local_u32[7] >> 24) & 0xFF;
    r[r_offset_bytes_private_key + 1] = (k_local_u32[7] >> 16) & 0xFF;
    r[r_offset_bytes_private_key + 2] = (k_local_u32[7] >> 8) & 0xFF;
    r[r_offset_bytes_private_key + 3] = (k_local_u32[7] >> 0) & 0xFF;

    r[r_offset_bytes_private_key + 4] = (k_local_u32[6] >> 24) & 0xFF;
    r[r_offset_bytes_private_key + 5] = (k_local_u32[6] >> 16) & 0xFF;
    r[r_offset_bytes_private_key + 6] = (k_local_u32[6] >> 8) & 0xFF;
    r[r_offset_bytes_private_key + 7] = (k_local_u32[6] >> 0) & 0xFF;

    r[r_offset_bytes_private_key + 8] = (k_local_u32[5] >> 24) & 0xFF;
    r[r_offset_bytes_private_key + 9] = (k_local_u32[5] >> 16) & 0xFF;
    r[r_offset_bytes_private_key + 10] = (k_local_u32[5] >> 8) & 0xFF;
    r[r_offset_bytes_private_key + 11] = (k_local_u32[5] >> 0) & 0xFF;

    r[r_offset_bytes_private_key + 12] = (k_local_u32[4] >> 24) & 0xFF;
    r[r_offset_bytes_private_key + 13] = (k_local_u32[4] >> 16) & 0xFF;
    r[r_offset_bytes_private_key + 14] = (k_local_u32[4] >> 8) & 0xFF;
    r[r_offset_bytes_private_key + 15] = (k_local_u32[4] >> 0) & 0xFF;

    r[r_offset_bytes_private_key + 16] = (k_local_u32[3] >> 24) & 0xFF;
    r[r_offset_bytes_private_key + 17] = (k_local_u32[3] >> 16) & 0xFF;
    r[r_offset_bytes_private_key + 18] = (k_local_u32[3] >> 8) & 0xFF;
    r[r_offset_bytes_private_key + 19] = (k_local_u32[3] >> 0) & 0xFF;

    r[r_offset_bytes_private_key + 20] = (k_local_u32[2] >> 24) & 0xFF;
    r[r_offset_bytes_private_key + 21] = (k_local_u32[2] >> 16) & 0xFF;
    r[r_offset_bytes_private_key + 22] = (k_local_u32[2] >> 8) & 0xFF;
    r[r_offset_bytes_private_key + 23] = (k_local_u32[2] >> 0) & 0xFF;

    r[r_offset_bytes_private_key + 24] = (k_local_u32[1] >> 24) & 0xFF;
    r[r_offset_bytes_private_key + 25] = (k_local_u32[1] >> 16) & 0xFF;
    r[r_offset_bytes_private_key + 26] = (k_local_u32[1] >> 8) & 0xFF;
    r[r_offset_bytes_private_key + 27] = (k_local_u32[1] >> 0) & 0xFF;

    r[r_offset_bytes_private_key + 28] = (k_local_u32[0] >> 24) & 0xFF;
    r[r_offset_bytes_private_key + 29] = (k_local_u32[0] >> 16) & 0xFF;
    r[r_offset_bytes_private_key + 30] = (k_local_u32[0] >> 8) & 0xFF;
    r[r_offset_bytes_private_key + 31] = (k_local_u32[0] >> 0) & 0xFF;


    // creating the public key from coordinates and parity byte for hashing
    create_public_key_from_coordinates(public_key_bytes, x_local_u32, y_local_u32);

    int r_offset_public_key = r_offset_bytes_private_key + PRIVATE_KEY_BYTES;

    // write public key parity byte into result buffer
    r[r_offset_public_key + 0] = 0x04;

    // write bytes of u32 array storing x coordinate into result buffer
    r[r_offset_public_key + 1] = (x_local_u32[7] >> 24) & 0xFF;
    r[r_offset_public_key + 2] = (x_local_u32[7] >> 16) & 0xFF;
    r[r_offset_public_key + 3] = (x_local_u32[7] >> 8) & 0xFF;
    r[r_offset_public_key + 4] = (x_local_u32[7] >> 0) & 0xFF;

    r[r_offset_public_key + 5] = (x_local_u32[6] >> 24) & 0xFF;
    r[r_offset_public_key + 6] = (x_local_u32[6] >> 16) & 0xFF;
    r[r_offset_public_key + 7] = (x_local_u32[6] >> 8) & 0xFF;
    r[r_offset_public_key + 8] = (x_local_u32[6] >> 0) & 0xFF;

    r[r_offset_public_key + 9] = (x_local_u32[5] >> 24) & 0xFF;
    r[r_offset_public_key + 10] = (x_local_u32[5] >> 16) & 0xFF;
    r[r_offset_public_key + 11] = (x_local_u32[5] >> 8) & 0xFF;
    r[r_offset_public_key + 12] = (x_local_u32[5] >> 0) & 0xFF;

    r[r_offset_public_key + 13] = (x_local_u32[4] >> 24) & 0xFF;
    r[r_offset_public_key + 14] = (x_local_u32[4] >> 16) & 0xFF;
    r[r_offset_public_key + 15] = (x_local_u32[4] >> 8) & 0xFF;
    r[r_offset_public_key + 16] = (x_local_u32[4] >> 0) & 0xFF;

    r[r_offset_public_key + 17] = (x_local_u32[3] >> 24) & 0xFF;
    r[r_offset_public_key + 18] = (x_local_u32[3] >> 16) & 0xFF;
    r[r_offset_public_key + 19] = (x_local_u32[3] >> 8) & 0xFF;
    r[r_offset_public_key + 20] = (x_local_u32[3] >> 0) & 0xFF;

    r[r_offset_public_key + 21] = (x_local_u32[2] >> 24) & 0xFF;
    r[r_offset_public_key + 22] = (x_local_u32[2] >> 16) & 0xFF;
    r[r_offset_public_key + 23] = (x_local_u32[2] >> 8) & 0xFF;
    r[r_offset_public_key + 24] = (x_local_u32[2] >> 0) & 0xFF;

    r[r_offset_public_key + 25] = (x_local_u32[1] >> 24) & 0xFF;
    r[r_offset_public_key + 26] = (x_local_u32[1] >> 16) & 0xFF;
    r[r_offset_public_key + 27] = (x_local_u32[1] >> 8) & 0xFF;
    r[r_offset_public_key + 28] = (x_local_u32[1] >> 0) & 0xFF;

    r[r_offset_public_key + 29] = (x_local_u32[0] >> 24) & 0xFF;
    r[r_offset_public_key + 30] = (x_local_u32[0] >> 16) & 0xFF;
    r[r_offset_public_key + 31] = (x_local_u32[0] >> 8) & 0xFF;
    r[r_offset_public_key + 32] = (x_local_u32[0] >> 0) & 0xFF;

    // write bytes of u32 array storing y coordinate into result buffer
    r[r_offset_public_key + 33] = (y_local_u32[7] >> 24) & 0xFF;
    r[r_offset_public_key + 34] = (y_local_u32[7] >> 16) & 0xFF;
    r[r_offset_public_key + 35] = (y_local_u32[7] >> 8) & 0xFF;
    r[r_offset_public_key + 36] = (y_local_u32[7] >> 0) & 0xFF;

    r[r_offset_public_key + 37] = (y_local_u32[6] >> 24) & 0xFF;
    r[r_offset_public_key + 38] = (y_local_u32[6] >> 16) & 0xFF;
    r[r_offset_public_key + 39] = (y_local_u32[6] >> 8) & 0xFF;
    r[r_offset_public_key + 40] = (y_local_u32[6] >> 0) & 0xFF;

    r[r_offset_public_key + 41] = (y_local_u32[5] >> 24) & 0xFF;
    r[r_offset_public_key + 42] = (y_local_u32[5] >> 16) & 0xFF;
    r[r_offset_public_key + 43] = (y_local_u32[5] >> 8) & 0xFF;
    r[r_offset_public_key + 44] = (y_local_u32[5] >> 0) & 0xFF;

    r[r_offset_public_key + 45] = (y_local_u32[4] >> 24) & 0xFF;
    r[r_offset_public_key + 46] = (y_local_u32[4] >> 16) & 0xFF;
    r[r_offset_public_key + 47] = (y_local_u32[4] >> 8) & 0xFF;
    r[r_offset_public_key + 48] = (y_local_u32[4] >> 0) & 0xFF;

    r[r_offset_public_key + 49] = (y_local_u32[3] >> 24) & 0xFF;
    r[r_offset_public_key + 50] = (y_local_u32[3] >> 16) & 0xFF;
    r[r_offset_public_key + 51] = (y_local_u32[3] >> 8) & 0xFF;
    r[r_offset_public_key + 52] = (y_local_u32[3] >> 0) & 0xFF;

    r[r_offset_public_key + 53] = (y_local_u32[2] >> 24) & 0xFF;
    r[r_offset_public_key + 54] = (y_local_u32[2] >> 16) & 0xFF;
    r[r_offset_public_key + 55] = (y_local_u32[2] >> 8) & 0xFF;
    r[r_offset_public_key + 56] = (y_local_u32[2] >> 0) & 0xFF;

    r[r_offset_public_key + 57] = (y_local_u32[1] >> 24) & 0xFF;
    r[r_offset_public_key + 58] = (y_local_u32[1] >> 16) & 0xFF;
    r[r_offset_public_key + 59] = (y_local_u32[1] >> 8) & 0xFF;
    r[r_offset_public_key + 60] = (y_local_u32[1] >> 0) & 0xFF;

    r[r_offset_public_key + 61] = (y_local_u32[0] >> 24) & 0xFF;
    r[r_offset_public_key + 62] = (y_local_u32[0] >> 16) & 0xFF;
    r[r_offset_public_key + 63] = (y_local_u32[0] >> 8) & 0xFF;
    r[r_offset_public_key + 64] = (y_local_u32[0] >> 0) & 0xFF;
}

/*
 * Creates a public key from a given private key, then hashes it with SHA-256.
 *
 * OUTPUT uchar *r: Pointer to the result buffer to store all results
 * INPUT u32 *k:    Pointer to the private key buffer storing all private keys
 */
__kernel void generate_until_first_sha256(__global uchar *r, __global const u32 *k){

    u32 k_local_u32[PRIVATE_KEY_LENGTH];
    u32 x_local_u32[PUBLIC_KEY_ONE_COORDINATE_LENGTH];
    u32 y_local_u32[PUBLIC_KEY_ONE_COORDINATE_LENGTH];
    uchar public_key_bytes[PUBLIC_KEY_BYTES_WITH_PARITY];
    secp256k1_t g_xy_local;

    // to store the results of the SHA-256 and RIPEMD-160 hashes
    u32 first_sha256_hash[SHA256_HASH_U32_LEN];

    // id of current work item
    int work_item_id = get_global_id(0);

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

    // calculating the public key coordinates
    set_precomputed_basepoint_g(&g_xy_local);
    point_mul_xy(x_local_u32, y_local_u32, k_local_u32, &g_xy_local);


    // calculating offset to write results in byte buffer
    int r_offset_bytes_private_key = (PRIVATE_KEY_BYTES + PUBLIC_KEY_BYTES_WITH_PARITY + SHA256_HASH_BYTES_LEN) * work_item_id;

    // write bytes of u32 array storing private key into result buffer
    r[r_offset_bytes_private_key + 0] = (k_local_u32[7] >> 24) & 0xFF;
    r[r_offset_bytes_private_key + 1] = (k_local_u32[7] >> 16) & 0xFF;
    r[r_offset_bytes_private_key + 2] = (k_local_u32[7] >> 8) & 0xFF;
    r[r_offset_bytes_private_key + 3] = (k_local_u32[7] >> 0) & 0xFF;

    r[r_offset_bytes_private_key + 4] = (k_local_u32[6] >> 24) & 0xFF;
    r[r_offset_bytes_private_key + 5] = (k_local_u32[6] >> 16) & 0xFF;
    r[r_offset_bytes_private_key + 6] = (k_local_u32[6] >> 8) & 0xFF;
    r[r_offset_bytes_private_key + 7] = (k_local_u32[6] >> 0) & 0xFF;

    r[r_offset_bytes_private_key + 8] = (k_local_u32[5] >> 24) & 0xFF;
    r[r_offset_bytes_private_key + 9] = (k_local_u32[5] >> 16) & 0xFF;
    r[r_offset_bytes_private_key + 10] = (k_local_u32[5] >> 8) & 0xFF;
    r[r_offset_bytes_private_key + 11] = (k_local_u32[5] >> 0) & 0xFF;

    r[r_offset_bytes_private_key + 12] = (k_local_u32[4] >> 24) & 0xFF;
    r[r_offset_bytes_private_key + 13] = (k_local_u32[4] >> 16) & 0xFF;
    r[r_offset_bytes_private_key + 14] = (k_local_u32[4] >> 8) & 0xFF;
    r[r_offset_bytes_private_key + 15] = (k_local_u32[4] >> 0) & 0xFF;

    r[r_offset_bytes_private_key + 16] = (k_local_u32[3] >> 24) & 0xFF;
    r[r_offset_bytes_private_key + 17] = (k_local_u32[3] >> 16) & 0xFF;
    r[r_offset_bytes_private_key + 18] = (k_local_u32[3] >> 8) & 0xFF;
    r[r_offset_bytes_private_key + 19] = (k_local_u32[3] >> 0) & 0xFF;

    r[r_offset_bytes_private_key + 20] = (k_local_u32[2] >> 24) & 0xFF;
    r[r_offset_bytes_private_key + 21] = (k_local_u32[2] >> 16) & 0xFF;
    r[r_offset_bytes_private_key + 22] = (k_local_u32[2] >> 8) & 0xFF;
    r[r_offset_bytes_private_key + 23] = (k_local_u32[2] >> 0) & 0xFF;

    r[r_offset_bytes_private_key + 24] = (k_local_u32[1] >> 24) & 0xFF;
    r[r_offset_bytes_private_key + 25] = (k_local_u32[1] >> 16) & 0xFF;
    r[r_offset_bytes_private_key + 26] = (k_local_u32[1] >> 8) & 0xFF;
    r[r_offset_bytes_private_key + 27] = (k_local_u32[1] >> 0) & 0xFF;

    r[r_offset_bytes_private_key + 28] = (k_local_u32[0] >> 24) & 0xFF;
    r[r_offset_bytes_private_key + 29] = (k_local_u32[0] >> 16) & 0xFF;
    r[r_offset_bytes_private_key + 30] = (k_local_u32[0] >> 8) & 0xFF;
    r[r_offset_bytes_private_key + 31] = (k_local_u32[0] >> 0) & 0xFF;


    // creating the public key from coordinates and parity byte for hashing
    create_public_key_from_coordinates(public_key_bytes, x_local_u32, y_local_u32);

    int r_offset_public_key = r_offset_bytes_private_key + PRIVATE_KEY_BYTES;

    // write public key parity byte into result buffer
    r[r_offset_public_key + 0] = 0x04;

    // write bytes of u32 array storing x coordinate into result buffer
    r[r_offset_public_key + 1] = (x_local_u32[7] >> 24) & 0xFF;
    r[r_offset_public_key + 2] = (x_local_u32[7] >> 16) & 0xFF;
    r[r_offset_public_key + 3] = (x_local_u32[7] >> 8) & 0xFF;
    r[r_offset_public_key + 4] = (x_local_u32[7] >> 0) & 0xFF;

    r[r_offset_public_key + 5] = (x_local_u32[6] >> 24) & 0xFF;
    r[r_offset_public_key + 6] = (x_local_u32[6] >> 16) & 0xFF;
    r[r_offset_public_key + 7] = (x_local_u32[6] >> 8) & 0xFF;
    r[r_offset_public_key + 8] = (x_local_u32[6] >> 0) & 0xFF;

    r[r_offset_public_key + 9] = (x_local_u32[5] >> 24) & 0xFF;
    r[r_offset_public_key + 10] = (x_local_u32[5] >> 16) & 0xFF;
    r[r_offset_public_key + 11] = (x_local_u32[5] >> 8) & 0xFF;
    r[r_offset_public_key + 12] = (x_local_u32[5] >> 0) & 0xFF;

    r[r_offset_public_key + 13] = (x_local_u32[4] >> 24) & 0xFF;
    r[r_offset_public_key + 14] = (x_local_u32[4] >> 16) & 0xFF;
    r[r_offset_public_key + 15] = (x_local_u32[4] >> 8) & 0xFF;
    r[r_offset_public_key + 16] = (x_local_u32[4] >> 0) & 0xFF;

    r[r_offset_public_key + 17] = (x_local_u32[3] >> 24) & 0xFF;
    r[r_offset_public_key + 18] = (x_local_u32[3] >> 16) & 0xFF;
    r[r_offset_public_key + 19] = (x_local_u32[3] >> 8) & 0xFF;
    r[r_offset_public_key + 20] = (x_local_u32[3] >> 0) & 0xFF;

    r[r_offset_public_key + 21] = (x_local_u32[2] >> 24) & 0xFF;
    r[r_offset_public_key + 22] = (x_local_u32[2] >> 16) & 0xFF;
    r[r_offset_public_key + 23] = (x_local_u32[2] >> 8) & 0xFF;
    r[r_offset_public_key + 24] = (x_local_u32[2] >> 0) & 0xFF;

    r[r_offset_public_key + 25] = (x_local_u32[1] >> 24) & 0xFF;
    r[r_offset_public_key + 26] = (x_local_u32[1] >> 16) & 0xFF;
    r[r_offset_public_key + 27] = (x_local_u32[1] >> 8) & 0xFF;
    r[r_offset_public_key + 28] = (x_local_u32[1] >> 0) & 0xFF;

    r[r_offset_public_key + 29] = (x_local_u32[0] >> 24) & 0xFF;
    r[r_offset_public_key + 30] = (x_local_u32[0] >> 16) & 0xFF;
    r[r_offset_public_key + 31] = (x_local_u32[0] >> 8) & 0xFF;
    r[r_offset_public_key + 32] = (x_local_u32[0] >> 0) & 0xFF;

    // write bytes of u32 array storing y coordinate into result buffer
    r[r_offset_public_key + 33] = (y_local_u32[7] >> 24) & 0xFF;
    r[r_offset_public_key + 34] = (y_local_u32[7] >> 16) & 0xFF;
    r[r_offset_public_key + 35] = (y_local_u32[7] >> 8) & 0xFF;
    r[r_offset_public_key + 36] = (y_local_u32[7] >> 0) & 0xFF;

    r[r_offset_public_key + 37] = (y_local_u32[6] >> 24) & 0xFF;
    r[r_offset_public_key + 38] = (y_local_u32[6] >> 16) & 0xFF;
    r[r_offset_public_key + 39] = (y_local_u32[6] >> 8) & 0xFF;
    r[r_offset_public_key + 40] = (y_local_u32[6] >> 0) & 0xFF;

    r[r_offset_public_key + 41] = (y_local_u32[5] >> 24) & 0xFF;
    r[r_offset_public_key + 42] = (y_local_u32[5] >> 16) & 0xFF;
    r[r_offset_public_key + 43] = (y_local_u32[5] >> 8) & 0xFF;
    r[r_offset_public_key + 44] = (y_local_u32[5] >> 0) & 0xFF;

    r[r_offset_public_key + 45] = (y_local_u32[4] >> 24) & 0xFF;
    r[r_offset_public_key + 46] = (y_local_u32[4] >> 16) & 0xFF;
    r[r_offset_public_key + 47] = (y_local_u32[4] >> 8) & 0xFF;
    r[r_offset_public_key + 48] = (y_local_u32[4] >> 0) & 0xFF;

    r[r_offset_public_key + 49] = (y_local_u32[3] >> 24) & 0xFF;
    r[r_offset_public_key + 50] = (y_local_u32[3] >> 16) & 0xFF;
    r[r_offset_public_key + 51] = (y_local_u32[3] >> 8) & 0xFF;
    r[r_offset_public_key + 52] = (y_local_u32[3] >> 0) & 0xFF;

    r[r_offset_public_key + 53] = (y_local_u32[2] >> 24) & 0xFF;
    r[r_offset_public_key + 54] = (y_local_u32[2] >> 16) & 0xFF;
    r[r_offset_public_key + 55] = (y_local_u32[2] >> 8) & 0xFF;
    r[r_offset_public_key + 56] = (y_local_u32[2] >> 0) & 0xFF;

    r[r_offset_public_key + 57] = (y_local_u32[1] >> 24) & 0xFF;
    r[r_offset_public_key + 58] = (y_local_u32[1] >> 16) & 0xFF;
    r[r_offset_public_key + 59] = (y_local_u32[1] >> 8) & 0xFF;
    r[r_offset_public_key + 60] = (y_local_u32[1] >> 0) & 0xFF;

    r[r_offset_public_key + 61] = (y_local_u32[0] >> 24) & 0xFF;
    r[r_offset_public_key + 62] = (y_local_u32[0] >> 16) & 0xFF;
    r[r_offset_public_key + 63] = (y_local_u32[0] >> 8) & 0xFF;
    r[r_offset_public_key + 64] = (y_local_u32[0] >> 0) & 0xFF;


    // hash the public key with SHA-256
    calculate_sha256_from_public_key(public_key_bytes, first_sha256_hash);

    int r_offset_first_sha256 = r_offset_public_key + PUBLIC_KEY_BYTES_WITH_PARITY;

    // write bytes of u32 array storing sha256_hash into result buffer
    r[r_offset_first_sha256 + 0] = (first_sha256_hash[0] >> 24) & 0xFF;
    r[r_offset_first_sha256 + 1] = (first_sha256_hash[0] >> 16) & 0xFF;
    r[r_offset_first_sha256 + 2] = (first_sha256_hash[0] >> 8) & 0xFF;
    r[r_offset_first_sha256 + 3] = (first_sha256_hash[0] >> 0) & 0xFF;

    r[r_offset_first_sha256 + 4] = (first_sha256_hash[1] >> 24) & 0xFF;
    r[r_offset_first_sha256 + 5] = (first_sha256_hash[1] >> 16) & 0xFF;
    r[r_offset_first_sha256 + 6] = (first_sha256_hash[1] >> 8) & 0xFF;
    r[r_offset_first_sha256 + 7] = (first_sha256_hash[1] >> 0) & 0xFF;

    r[r_offset_first_sha256 + 8] = (first_sha256_hash[2] >> 24) & 0xFF;
    r[r_offset_first_sha256 + 9] = (first_sha256_hash[2] >> 16) & 0xFF;
    r[r_offset_first_sha256 + 10] = (first_sha256_hash[2] >> 8) & 0xFF;
    r[r_offset_first_sha256 + 11] = (first_sha256_hash[2] >> 0) & 0xFF;

    r[r_offset_first_sha256 + 12] = (first_sha256_hash[3] >> 24) & 0xFF;
    r[r_offset_first_sha256 + 13] = (first_sha256_hash[3] >> 16) & 0xFF;
    r[r_offset_first_sha256 + 14] = (first_sha256_hash[3] >> 8) & 0xFF;
    r[r_offset_first_sha256 + 15] = (first_sha256_hash[3] >> 0) & 0xFF;

    r[r_offset_first_sha256 + 16] = (first_sha256_hash[4] >> 24) & 0xFF;
    r[r_offset_first_sha256 + 17] = (first_sha256_hash[4] >> 16) & 0xFF;
    r[r_offset_first_sha256 + 18] = (first_sha256_hash[4] >> 8) & 0xFF;
    r[r_offset_first_sha256 + 19] = (first_sha256_hash[4] >> 0) & 0xFF;

    r[r_offset_first_sha256 + 20] = (first_sha256_hash[5] >> 24) & 0xFF;
    r[r_offset_first_sha256 + 21] = (first_sha256_hash[5] >> 16) & 0xFF;
    r[r_offset_first_sha256 + 22] = (first_sha256_hash[5] >> 8) & 0xFF;
    r[r_offset_first_sha256 + 23] = (first_sha256_hash[5] >> 0) & 0xFF;

    r[r_offset_first_sha256 + 24] = (first_sha256_hash[6] >> 24) & 0xFF;
    r[r_offset_first_sha256 + 25] = (first_sha256_hash[6] >> 16) & 0xFF;
    r[r_offset_first_sha256 + 26] = (first_sha256_hash[6] >> 8) & 0xFF;
    r[r_offset_first_sha256 + 27] = (first_sha256_hash[6] >> 0) & 0xFF;

    r[r_offset_first_sha256 + 28] = (first_sha256_hash[7] >> 24) & 0xFF;
    r[r_offset_first_sha256 + 29] = (first_sha256_hash[7] >> 16) & 0xFF;
    r[r_offset_first_sha256 + 30] = (first_sha256_hash[7] >> 8) & 0xFF;
    r[r_offset_first_sha256 + 31] = (first_sha256_hash[7] >> 0) & 0xFF;
}

/*
 * "Creates" private keys from a single private key and then calculates the public key,
 * then hashes it with SHA-256.
 *
 * OUTPUT uchar *r: Pointer to the result buffer to store all results
 * INPUT u32 *k:    Pointer to the private key buffer storing a single private key
 */
__kernel void generate_chunk_until_first_sha256(__global uchar *r, __global const u32 *k){

    u32 k_local_u32[PRIVATE_KEY_LENGTH];
    u32 x_local_u32[PUBLIC_KEY_ONE_COORDINATE_LENGTH];
    u32 y_local_u32[PUBLIC_KEY_ONE_COORDINATE_LENGTH];
    uchar public_key_bytes[PUBLIC_KEY_BYTES_WITH_PARITY];
    secp256k1_t g_xy_local;

    // to store the results of the SHA-256 and RIPEMD-160 hashes
    u32 first_sha256_hash[SHA256_HASH_U32_LEN];

    // id of current work item
    int work_item_id = get_global_id(0);

    // get first private key from private key grid and "create" a new one
    k_local_u32[0] = k[0] | work_item_id;
    k_local_u32[1] = k[1];
    k_local_u32[2] = k[2];
    k_local_u32[3] = k[3];
    k_local_u32[4] = k[4];
    k_local_u32[5] = k[5];
    k_local_u32[6] = k[6];
    k_local_u32[7] = k[7];

    // calculating the public key coordinates
    set_precomputed_basepoint_g(&g_xy_local);
    point_mul_xy(x_local_u32, y_local_u32, k_local_u32, &g_xy_local);


    // calculating offset to write results in byte buffer
    int r_offset_bytes_private_key = (PRIVATE_KEY_BYTES + PUBLIC_KEY_BYTES_WITH_PARITY + SHA256_HASH_BYTES_LEN) * work_item_id;

    // write bytes of u32 array storing private key into result buffer
    r[r_offset_bytes_private_key + 0] = (k_local_u32[7] >> 24) & 0xFF;
    r[r_offset_bytes_private_key + 1] = (k_local_u32[7] >> 16) & 0xFF;
    r[r_offset_bytes_private_key + 2] = (k_local_u32[7] >> 8) & 0xFF;
    r[r_offset_bytes_private_key + 3] = (k_local_u32[7] >> 0) & 0xFF;

    r[r_offset_bytes_private_key + 4] = (k_local_u32[6] >> 24) & 0xFF;
    r[r_offset_bytes_private_key + 5] = (k_local_u32[6] >> 16) & 0xFF;
    r[r_offset_bytes_private_key + 6] = (k_local_u32[6] >> 8) & 0xFF;
    r[r_offset_bytes_private_key + 7] = (k_local_u32[6] >> 0) & 0xFF;

    r[r_offset_bytes_private_key + 8] = (k_local_u32[5] >> 24) & 0xFF;
    r[r_offset_bytes_private_key + 9] = (k_local_u32[5] >> 16) & 0xFF;
    r[r_offset_bytes_private_key + 10] = (k_local_u32[5] >> 8) & 0xFF;
    r[r_offset_bytes_private_key + 11] = (k_local_u32[5] >> 0) & 0xFF;

    r[r_offset_bytes_private_key + 12] = (k_local_u32[4] >> 24) & 0xFF;
    r[r_offset_bytes_private_key + 13] = (k_local_u32[4] >> 16) & 0xFF;
    r[r_offset_bytes_private_key + 14] = (k_local_u32[4] >> 8) & 0xFF;
    r[r_offset_bytes_private_key + 15] = (k_local_u32[4] >> 0) & 0xFF;

    r[r_offset_bytes_private_key + 16] = (k_local_u32[3] >> 24) & 0xFF;
    r[r_offset_bytes_private_key + 17] = (k_local_u32[3] >> 16) & 0xFF;
    r[r_offset_bytes_private_key + 18] = (k_local_u32[3] >> 8) & 0xFF;
    r[r_offset_bytes_private_key + 19] = (k_local_u32[3] >> 0) & 0xFF;

    r[r_offset_bytes_private_key + 20] = (k_local_u32[2] >> 24) & 0xFF;
    r[r_offset_bytes_private_key + 21] = (k_local_u32[2] >> 16) & 0xFF;
    r[r_offset_bytes_private_key + 22] = (k_local_u32[2] >> 8) & 0xFF;
    r[r_offset_bytes_private_key + 23] = (k_local_u32[2] >> 0) & 0xFF;

    r[r_offset_bytes_private_key + 24] = (k_local_u32[1] >> 24) & 0xFF;
    r[r_offset_bytes_private_key + 25] = (k_local_u32[1] >> 16) & 0xFF;
    r[r_offset_bytes_private_key + 26] = (k_local_u32[1] >> 8) & 0xFF;
    r[r_offset_bytes_private_key + 27] = (k_local_u32[1] >> 0) & 0xFF;

    r[r_offset_bytes_private_key + 28] = (k_local_u32[0] >> 24) & 0xFF;
    r[r_offset_bytes_private_key + 29] = (k_local_u32[0] >> 16) & 0xFF;
    r[r_offset_bytes_private_key + 30] = (k_local_u32[0] >> 8) & 0xFF;
    r[r_offset_bytes_private_key + 31] = (k_local_u32[0] >> 0) & 0xFF;


    // creating the public key from coordinates and parity byte for hashing
    create_public_key_from_coordinates(public_key_bytes, x_local_u32, y_local_u32);

    int r_offset_public_key = r_offset_bytes_private_key + PRIVATE_KEY_BYTES;

    // write public key parity byte into result buffer
    r[r_offset_public_key + 0] = 0x04;

    // write bytes of u32 array storing x coordinate into result buffer
    r[r_offset_public_key + 1] = (x_local_u32[7] >> 24) & 0xFF;
    r[r_offset_public_key + 2] = (x_local_u32[7] >> 16) & 0xFF;
    r[r_offset_public_key + 3] = (x_local_u32[7] >> 8) & 0xFF;
    r[r_offset_public_key + 4] = (x_local_u32[7] >> 0) & 0xFF;

    r[r_offset_public_key + 5] = (x_local_u32[6] >> 24) & 0xFF;
    r[r_offset_public_key + 6] = (x_local_u32[6] >> 16) & 0xFF;
    r[r_offset_public_key + 7] = (x_local_u32[6] >> 8) & 0xFF;
    r[r_offset_public_key + 8] = (x_local_u32[6] >> 0) & 0xFF;

    r[r_offset_public_key + 9] = (x_local_u32[5] >> 24) & 0xFF;
    r[r_offset_public_key + 10] = (x_local_u32[5] >> 16) & 0xFF;
    r[r_offset_public_key + 11] = (x_local_u32[5] >> 8) & 0xFF;
    r[r_offset_public_key + 12] = (x_local_u32[5] >> 0) & 0xFF;

    r[r_offset_public_key + 13] = (x_local_u32[4] >> 24) & 0xFF;
    r[r_offset_public_key + 14] = (x_local_u32[4] >> 16) & 0xFF;
    r[r_offset_public_key + 15] = (x_local_u32[4] >> 8) & 0xFF;
    r[r_offset_public_key + 16] = (x_local_u32[4] >> 0) & 0xFF;

    r[r_offset_public_key + 17] = (x_local_u32[3] >> 24) & 0xFF;
    r[r_offset_public_key + 18] = (x_local_u32[3] >> 16) & 0xFF;
    r[r_offset_public_key + 19] = (x_local_u32[3] >> 8) & 0xFF;
    r[r_offset_public_key + 20] = (x_local_u32[3] >> 0) & 0xFF;

    r[r_offset_public_key + 21] = (x_local_u32[2] >> 24) & 0xFF;
    r[r_offset_public_key + 22] = (x_local_u32[2] >> 16) & 0xFF;
    r[r_offset_public_key + 23] = (x_local_u32[2] >> 8) & 0xFF;
    r[r_offset_public_key + 24] = (x_local_u32[2] >> 0) & 0xFF;

    r[r_offset_public_key + 25] = (x_local_u32[1] >> 24) & 0xFF;
    r[r_offset_public_key + 26] = (x_local_u32[1] >> 16) & 0xFF;
    r[r_offset_public_key + 27] = (x_local_u32[1] >> 8) & 0xFF;
    r[r_offset_public_key + 28] = (x_local_u32[1] >> 0) & 0xFF;

    r[r_offset_public_key + 29] = (x_local_u32[0] >> 24) & 0xFF;
    r[r_offset_public_key + 30] = (x_local_u32[0] >> 16) & 0xFF;
    r[r_offset_public_key + 31] = (x_local_u32[0] >> 8) & 0xFF;
    r[r_offset_public_key + 32] = (x_local_u32[0] >> 0) & 0xFF;

    // write bytes of u32 array storing y coordinate into result buffer
    r[r_offset_public_key + 33] = (y_local_u32[7] >> 24) & 0xFF;
    r[r_offset_public_key + 34] = (y_local_u32[7] >> 16) & 0xFF;
    r[r_offset_public_key + 35] = (y_local_u32[7] >> 8) & 0xFF;
    r[r_offset_public_key + 36] = (y_local_u32[7] >> 0) & 0xFF;

    r[r_offset_public_key + 37] = (y_local_u32[6] >> 24) & 0xFF;
    r[r_offset_public_key + 38] = (y_local_u32[6] >> 16) & 0xFF;
    r[r_offset_public_key + 39] = (y_local_u32[6] >> 8) & 0xFF;
    r[r_offset_public_key + 40] = (y_local_u32[6] >> 0) & 0xFF;

    r[r_offset_public_key + 41] = (y_local_u32[5] >> 24) & 0xFF;
    r[r_offset_public_key + 42] = (y_local_u32[5] >> 16) & 0xFF;
    r[r_offset_public_key + 43] = (y_local_u32[5] >> 8) & 0xFF;
    r[r_offset_public_key + 44] = (y_local_u32[5] >> 0) & 0xFF;

    r[r_offset_public_key + 45] = (y_local_u32[4] >> 24) & 0xFF;
    r[r_offset_public_key + 46] = (y_local_u32[4] >> 16) & 0xFF;
    r[r_offset_public_key + 47] = (y_local_u32[4] >> 8) & 0xFF;
    r[r_offset_public_key + 48] = (y_local_u32[4] >> 0) & 0xFF;

    r[r_offset_public_key + 49] = (y_local_u32[3] >> 24) & 0xFF;
    r[r_offset_public_key + 50] = (y_local_u32[3] >> 16) & 0xFF;
    r[r_offset_public_key + 51] = (y_local_u32[3] >> 8) & 0xFF;
    r[r_offset_public_key + 52] = (y_local_u32[3] >> 0) & 0xFF;

    r[r_offset_public_key + 53] = (y_local_u32[2] >> 24) & 0xFF;
    r[r_offset_public_key + 54] = (y_local_u32[2] >> 16) & 0xFF;
    r[r_offset_public_key + 55] = (y_local_u32[2] >> 8) & 0xFF;
    r[r_offset_public_key + 56] = (y_local_u32[2] >> 0) & 0xFF;

    r[r_offset_public_key + 57] = (y_local_u32[1] >> 24) & 0xFF;
    r[r_offset_public_key + 58] = (y_local_u32[1] >> 16) & 0xFF;
    r[r_offset_public_key + 59] = (y_local_u32[1] >> 8) & 0xFF;
    r[r_offset_public_key + 60] = (y_local_u32[1] >> 0) & 0xFF;

    r[r_offset_public_key + 61] = (y_local_u32[0] >> 24) & 0xFF;
    r[r_offset_public_key + 62] = (y_local_u32[0] >> 16) & 0xFF;
    r[r_offset_public_key + 63] = (y_local_u32[0] >> 8) & 0xFF;
    r[r_offset_public_key + 64] = (y_local_u32[0] >> 0) & 0xFF;


    // hash the public key with SHA-256
    calculate_sha256_from_public_key(public_key_bytes, first_sha256_hash);

    int r_offset_first_sha256 = r_offset_public_key + PUBLIC_KEY_BYTES_WITH_PARITY;

    // write bytes of u32 array storing sha256_hash into result buffer
    r[r_offset_first_sha256 + 0] = (first_sha256_hash[0] >> 24) & 0xFF;
    r[r_offset_first_sha256 + 1] = (first_sha256_hash[0] >> 16) & 0xFF;
    r[r_offset_first_sha256 + 2] = (first_sha256_hash[0] >> 8) & 0xFF;
    r[r_offset_first_sha256 + 3] = (first_sha256_hash[0] >> 0) & 0xFF;

    r[r_offset_first_sha256 + 4] = (first_sha256_hash[1] >> 24) & 0xFF;
    r[r_offset_first_sha256 + 5] = (first_sha256_hash[1] >> 16) & 0xFF;
    r[r_offset_first_sha256 + 6] = (first_sha256_hash[1] >> 8) & 0xFF;
    r[r_offset_first_sha256 + 7] = (first_sha256_hash[1] >> 0) & 0xFF;

    r[r_offset_first_sha256 + 8] = (first_sha256_hash[2] >> 24) & 0xFF;
    r[r_offset_first_sha256 + 9] = (first_sha256_hash[2] >> 16) & 0xFF;
    r[r_offset_first_sha256 + 10] = (first_sha256_hash[2] >> 8) & 0xFF;
    r[r_offset_first_sha256 + 11] = (first_sha256_hash[2] >> 0) & 0xFF;

    r[r_offset_first_sha256 + 12] = (first_sha256_hash[3] >> 24) & 0xFF;
    r[r_offset_first_sha256 + 13] = (first_sha256_hash[3] >> 16) & 0xFF;
    r[r_offset_first_sha256 + 14] = (first_sha256_hash[3] >> 8) & 0xFF;
    r[r_offset_first_sha256 + 15] = (first_sha256_hash[3] >> 0) & 0xFF;

    r[r_offset_first_sha256 + 16] = (first_sha256_hash[4] >> 24) & 0xFF;
    r[r_offset_first_sha256 + 17] = (first_sha256_hash[4] >> 16) & 0xFF;
    r[r_offset_first_sha256 + 18] = (first_sha256_hash[4] >> 8) & 0xFF;
    r[r_offset_first_sha256 + 19] = (first_sha256_hash[4] >> 0) & 0xFF;

    r[r_offset_first_sha256 + 20] = (first_sha256_hash[5] >> 24) & 0xFF;
    r[r_offset_first_sha256 + 21] = (first_sha256_hash[5] >> 16) & 0xFF;
    r[r_offset_first_sha256 + 22] = (first_sha256_hash[5] >> 8) & 0xFF;
    r[r_offset_first_sha256 + 23] = (first_sha256_hash[5] >> 0) & 0xFF;

    r[r_offset_first_sha256 + 24] = (first_sha256_hash[6] >> 24) & 0xFF;
    r[r_offset_first_sha256 + 25] = (first_sha256_hash[6] >> 16) & 0xFF;
    r[r_offset_first_sha256 + 26] = (first_sha256_hash[6] >> 8) & 0xFF;
    r[r_offset_first_sha256 + 27] = (first_sha256_hash[6] >> 0) & 0xFF;

    r[r_offset_first_sha256 + 28] = (first_sha256_hash[7] >> 24) & 0xFF;
    r[r_offset_first_sha256 + 29] = (first_sha256_hash[7] >> 16) & 0xFF;
    r[r_offset_first_sha256 + 30] = (first_sha256_hash[7] >> 8) & 0xFF;
    r[r_offset_first_sha256 + 31] = (first_sha256_hash[7] >> 0) & 0xFF;
}

/*
 * Creates a public key from a given private key, then hashes it with SHA-256 and RIPEMD-160.
 *
 * OUTPUT uchar *r: Pointer to the result buffer to store all results
 * INPUT u32 *k:    Pointer to the private key buffer storing all private keys
 */
__kernel void generate_until_ripemd160(__global uchar *r, __global const u32 *k){

    u32 k_local_u32[PRIVATE_KEY_LENGTH];
    u32 x_local_u32[PUBLIC_KEY_ONE_COORDINATE_LENGTH];
    u32 y_local_u32[PUBLIC_KEY_ONE_COORDINATE_LENGTH];
    uchar public_key_bytes[PUBLIC_KEY_BYTES_WITH_PARITY];
    secp256k1_t g_xy_local;

    // to store the results of the SHA-256 and RIPEMD-160 hashes
    u32 sha256_hash[SHA256_HASH_U32_LEN];
    u32 ripemd160_hash[RIPEMD160_HASH_U32_LEN];

    // id of current work item
    int work_item_id = get_global_id(0);

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

    // calculating the public key coordinates
    set_precomputed_basepoint_g(&g_xy_local);
    point_mul_xy(x_local_u32, y_local_u32, k_local_u32, &g_xy_local);


    // calculating offset to write results in byte buffer
    int r_offset_bytes_private_key = (PRIVATE_KEY_BYTES + PUBLIC_KEY_BYTES_WITH_PARITY + SHA256_HASH_BYTES_LEN + RIPEMD160_HASH_BYTES) * work_item_id;

    // write bytes of u32 array storing private key into result buffer
    r[r_offset_bytes_private_key + 0] = (k_local_u32[7] >> 24) & 0xFF;
    r[r_offset_bytes_private_key + 1] = (k_local_u32[7] >> 16) & 0xFF;
    r[r_offset_bytes_private_key + 2] = (k_local_u32[7] >> 8) & 0xFF;
    r[r_offset_bytes_private_key + 3] = (k_local_u32[7] >> 0) & 0xFF;

    r[r_offset_bytes_private_key + 4] = (k_local_u32[6] >> 24) & 0xFF;
    r[r_offset_bytes_private_key + 5] = (k_local_u32[6] >> 16) & 0xFF;
    r[r_offset_bytes_private_key + 6] = (k_local_u32[6] >> 8) & 0xFF;
    r[r_offset_bytes_private_key + 7] = (k_local_u32[6] >> 0) & 0xFF;

    r[r_offset_bytes_private_key + 8] = (k_local_u32[5] >> 24) & 0xFF;
    r[r_offset_bytes_private_key + 9] = (k_local_u32[5] >> 16) & 0xFF;
    r[r_offset_bytes_private_key + 10] = (k_local_u32[5] >> 8) & 0xFF;
    r[r_offset_bytes_private_key + 11] = (k_local_u32[5] >> 0) & 0xFF;

    r[r_offset_bytes_private_key + 12] = (k_local_u32[4] >> 24) & 0xFF;
    r[r_offset_bytes_private_key + 13] = (k_local_u32[4] >> 16) & 0xFF;
    r[r_offset_bytes_private_key + 14] = (k_local_u32[4] >> 8) & 0xFF;
    r[r_offset_bytes_private_key + 15] = (k_local_u32[4] >> 0) & 0xFF;

    r[r_offset_bytes_private_key + 16] = (k_local_u32[3] >> 24) & 0xFF;
    r[r_offset_bytes_private_key + 17] = (k_local_u32[3] >> 16) & 0xFF;
    r[r_offset_bytes_private_key + 18] = (k_local_u32[3] >> 8) & 0xFF;
    r[r_offset_bytes_private_key + 19] = (k_local_u32[3] >> 0) & 0xFF;

    r[r_offset_bytes_private_key + 20] = (k_local_u32[2] >> 24) & 0xFF;
    r[r_offset_bytes_private_key + 21] = (k_local_u32[2] >> 16) & 0xFF;
    r[r_offset_bytes_private_key + 22] = (k_local_u32[2] >> 8) & 0xFF;
    r[r_offset_bytes_private_key + 23] = (k_local_u32[2] >> 0) & 0xFF;

    r[r_offset_bytes_private_key + 24] = (k_local_u32[1] >> 24) & 0xFF;
    r[r_offset_bytes_private_key + 25] = (k_local_u32[1] >> 16) & 0xFF;
    r[r_offset_bytes_private_key + 26] = (k_local_u32[1] >> 8) & 0xFF;
    r[r_offset_bytes_private_key + 27] = (k_local_u32[1] >> 0) & 0xFF;

    r[r_offset_bytes_private_key + 28] = (k_local_u32[0] >> 24) & 0xFF;
    r[r_offset_bytes_private_key + 29] = (k_local_u32[0] >> 16) & 0xFF;
    r[r_offset_bytes_private_key + 30] = (k_local_u32[0] >> 8) & 0xFF;
    r[r_offset_bytes_private_key + 31] = (k_local_u32[0] >> 0) & 0xFF;


    // creating the public key from coordinates and parity byte for hashing
    create_public_key_from_coordinates(public_key_bytes, x_local_u32, y_local_u32);

    int r_offset_public_key = r_offset_bytes_private_key + PRIVATE_KEY_BYTES;

    // write public key parity byte into result buffer
    r[r_offset_public_key + 0] = 0x04;

    // write bytes of u32 array storing x coordinate into result buffer
    r[r_offset_public_key + 1] = (x_local_u32[7] >> 24) & 0xFF;
    r[r_offset_public_key + 2] = (x_local_u32[7] >> 16) & 0xFF;
    r[r_offset_public_key + 3] = (x_local_u32[7] >> 8) & 0xFF;
    r[r_offset_public_key + 4] = (x_local_u32[7] >> 0) & 0xFF;

    r[r_offset_public_key + 5] = (x_local_u32[6] >> 24) & 0xFF;
    r[r_offset_public_key + 6] = (x_local_u32[6] >> 16) & 0xFF;
    r[r_offset_public_key + 7] = (x_local_u32[6] >> 8) & 0xFF;
    r[r_offset_public_key + 8] = (x_local_u32[6] >> 0) & 0xFF;

    r[r_offset_public_key + 9] = (x_local_u32[5] >> 24) & 0xFF;
    r[r_offset_public_key + 10] = (x_local_u32[5] >> 16) & 0xFF;
    r[r_offset_public_key + 11] = (x_local_u32[5] >> 8) & 0xFF;
    r[r_offset_public_key + 12] = (x_local_u32[5] >> 0) & 0xFF;

    r[r_offset_public_key + 13] = (x_local_u32[4] >> 24) & 0xFF;
    r[r_offset_public_key + 14] = (x_local_u32[4] >> 16) & 0xFF;
    r[r_offset_public_key + 15] = (x_local_u32[4] >> 8) & 0xFF;
    r[r_offset_public_key + 16] = (x_local_u32[4] >> 0) & 0xFF;

    r[r_offset_public_key + 17] = (x_local_u32[3] >> 24) & 0xFF;
    r[r_offset_public_key + 18] = (x_local_u32[3] >> 16) & 0xFF;
    r[r_offset_public_key + 19] = (x_local_u32[3] >> 8) & 0xFF;
    r[r_offset_public_key + 20] = (x_local_u32[3] >> 0) & 0xFF;

    r[r_offset_public_key + 21] = (x_local_u32[2] >> 24) & 0xFF;
    r[r_offset_public_key + 22] = (x_local_u32[2] >> 16) & 0xFF;
    r[r_offset_public_key + 23] = (x_local_u32[2] >> 8) & 0xFF;
    r[r_offset_public_key + 24] = (x_local_u32[2] >> 0) & 0xFF;

    r[r_offset_public_key + 25] = (x_local_u32[1] >> 24) & 0xFF;
    r[r_offset_public_key + 26] = (x_local_u32[1] >> 16) & 0xFF;
    r[r_offset_public_key + 27] = (x_local_u32[1] >> 8) & 0xFF;
    r[r_offset_public_key + 28] = (x_local_u32[1] >> 0) & 0xFF;

    r[r_offset_public_key + 29] = (x_local_u32[0] >> 24) & 0xFF;
    r[r_offset_public_key + 30] = (x_local_u32[0] >> 16) & 0xFF;
    r[r_offset_public_key + 31] = (x_local_u32[0] >> 8) & 0xFF;
    r[r_offset_public_key + 32] = (x_local_u32[0] >> 0) & 0xFF;

    // write bytes of u32 array storing y coordinate into result buffer
    r[r_offset_public_key + 33] = (y_local_u32[7] >> 24) & 0xFF;
    r[r_offset_public_key + 34] = (y_local_u32[7] >> 16) & 0xFF;
    r[r_offset_public_key + 35] = (y_local_u32[7] >> 8) & 0xFF;
    r[r_offset_public_key + 36] = (y_local_u32[7] >> 0) & 0xFF;

    r[r_offset_public_key + 37] = (y_local_u32[6] >> 24) & 0xFF;
    r[r_offset_public_key + 38] = (y_local_u32[6] >> 16) & 0xFF;
    r[r_offset_public_key + 39] = (y_local_u32[6] >> 8) & 0xFF;
    r[r_offset_public_key + 40] = (y_local_u32[6] >> 0) & 0xFF;

    r[r_offset_public_key + 41] = (y_local_u32[5] >> 24) & 0xFF;
    r[r_offset_public_key + 42] = (y_local_u32[5] >> 16) & 0xFF;
    r[r_offset_public_key + 43] = (y_local_u32[5] >> 8) & 0xFF;
    r[r_offset_public_key + 44] = (y_local_u32[5] >> 0) & 0xFF;

    r[r_offset_public_key + 45] = (y_local_u32[4] >> 24) & 0xFF;
    r[r_offset_public_key + 46] = (y_local_u32[4] >> 16) & 0xFF;
    r[r_offset_public_key + 47] = (y_local_u32[4] >> 8) & 0xFF;
    r[r_offset_public_key + 48] = (y_local_u32[4] >> 0) & 0xFF;

    r[r_offset_public_key + 49] = (y_local_u32[3] >> 24) & 0xFF;
    r[r_offset_public_key + 50] = (y_local_u32[3] >> 16) & 0xFF;
    r[r_offset_public_key + 51] = (y_local_u32[3] >> 8) & 0xFF;
    r[r_offset_public_key + 52] = (y_local_u32[3] >> 0) & 0xFF;

    r[r_offset_public_key + 53] = (y_local_u32[2] >> 24) & 0xFF;
    r[r_offset_public_key + 54] = (y_local_u32[2] >> 16) & 0xFF;
    r[r_offset_public_key + 55] = (y_local_u32[2] >> 8) & 0xFF;
    r[r_offset_public_key + 56] = (y_local_u32[2] >> 0) & 0xFF;

    r[r_offset_public_key + 57] = (y_local_u32[1] >> 24) & 0xFF;
    r[r_offset_public_key + 58] = (y_local_u32[1] >> 16) & 0xFF;
    r[r_offset_public_key + 59] = (y_local_u32[1] >> 8) & 0xFF;
    r[r_offset_public_key + 60] = (y_local_u32[1] >> 0) & 0xFF;

    r[r_offset_public_key + 61] = (y_local_u32[0] >> 24) & 0xFF;
    r[r_offset_public_key + 62] = (y_local_u32[0] >> 16) & 0xFF;
    r[r_offset_public_key + 63] = (y_local_u32[0] >> 8) & 0xFF;
    r[r_offset_public_key + 64] = (y_local_u32[0] >> 0) & 0xFF;


    // hash the public key with SHA-256
    calculate_sha256_from_public_key(public_key_bytes, sha256_hash);

    int r_offset_first_sha256 = r_offset_public_key + PUBLIC_KEY_BYTES_WITH_PARITY;

    // write bytes of u32 array storing sha256_hash into result buffer
    r[r_offset_first_sha256 + 0] = (sha256_hash[0] >> 24) & 0xFF;
    r[r_offset_first_sha256 + 1] = (sha256_hash[0] >> 16) & 0xFF;
    r[r_offset_first_sha256 + 2] = (sha256_hash[0] >> 8) & 0xFF;
    r[r_offset_first_sha256 + 3] = (sha256_hash[0] >> 0) & 0xFF;

    r[r_offset_first_sha256 + 4] = (sha256_hash[1] >> 24) & 0xFF;
    r[r_offset_first_sha256 + 5] = (sha256_hash[1] >> 16) & 0xFF;
    r[r_offset_first_sha256 + 6] = (sha256_hash[1] >> 8) & 0xFF;
    r[r_offset_first_sha256 + 7] = (sha256_hash[1] >> 0) & 0xFF;

    r[r_offset_first_sha256 + 8] = (sha256_hash[2] >> 24) & 0xFF;
    r[r_offset_first_sha256 + 9] = (sha256_hash[2] >> 16) & 0xFF;
    r[r_offset_first_sha256 + 10] = (sha256_hash[2] >> 8) & 0xFF;
    r[r_offset_first_sha256 + 11] = (sha256_hash[2] >> 0) & 0xFF;

    r[r_offset_first_sha256 + 12] = (sha256_hash[3] >> 24) & 0xFF;
    r[r_offset_first_sha256 + 13] = (sha256_hash[3] >> 16) & 0xFF;
    r[r_offset_first_sha256 + 14] = (sha256_hash[3] >> 8) & 0xFF;
    r[r_offset_first_sha256 + 15] = (sha256_hash[3] >> 0) & 0xFF;

    r[r_offset_first_sha256 + 16] = (sha256_hash[4] >> 24) & 0xFF;
    r[r_offset_first_sha256 + 17] = (sha256_hash[4] >> 16) & 0xFF;
    r[r_offset_first_sha256 + 18] = (sha256_hash[4] >> 8) & 0xFF;
    r[r_offset_first_sha256 + 19] = (sha256_hash[4] >> 0) & 0xFF;

    r[r_offset_first_sha256 + 20] = (sha256_hash[5] >> 24) & 0xFF;
    r[r_offset_first_sha256 + 21] = (sha256_hash[5] >> 16) & 0xFF;
    r[r_offset_first_sha256 + 22] = (sha256_hash[5] >> 8) & 0xFF;
    r[r_offset_first_sha256 + 23] = (sha256_hash[5] >> 0) & 0xFF;

    r[r_offset_first_sha256 + 24] = (sha256_hash[6] >> 24) & 0xFF;
    r[r_offset_first_sha256 + 25] = (sha256_hash[6] >> 16) & 0xFF;
    r[r_offset_first_sha256 + 26] = (sha256_hash[6] >> 8) & 0xFF;
    r[r_offset_first_sha256 + 27] = (sha256_hash[6] >> 0) & 0xFF;

    r[r_offset_first_sha256 + 28] = (sha256_hash[7] >> 24) & 0xFF;
    r[r_offset_first_sha256 + 29] = (sha256_hash[7] >> 16) & 0xFF;
    r[r_offset_first_sha256 + 30] = (sha256_hash[7] >> 8) & 0xFF;
    r[r_offset_first_sha256 + 31] = (sha256_hash[7] >> 0) & 0xFF;


    // hash the SHA-256 result with RIPEMD-160
    calculate_ripemd160_from_u32(sha256_hash, ripemd160_hash);

    int r_offset_ripemd160 = r_offset_first_sha256 + SHA256_HASH_BYTES_LEN;

    // write bytes of u32 array storing ripemd160_hash into result buffer
    r[r_offset_ripemd160 + 0] = (ripemd160_hash[0] >> 0) & 0xFF;
    r[r_offset_ripemd160 + 1] = (ripemd160_hash[0] >> 8) & 0xFF;
    r[r_offset_ripemd160 + 2] = (ripemd160_hash[0] >> 16) & 0xFF;
    r[r_offset_ripemd160 + 3] = (ripemd160_hash[0] >> 24) & 0xFF;

    r[r_offset_ripemd160 + 4] = (ripemd160_hash[1] >> 0) & 0xFF;
    r[r_offset_ripemd160 + 5] = (ripemd160_hash[1] >> 8) & 0xFF;
    r[r_offset_ripemd160 + 6] = (ripemd160_hash[1] >> 16) & 0xFF;
    r[r_offset_ripemd160 + 7] = (ripemd160_hash[1] >> 24) & 0xFF;

    r[r_offset_ripemd160 + 8] = (ripemd160_hash[2] >> 0) & 0xFF;
    r[r_offset_ripemd160 + 9] = (ripemd160_hash[2] >> 8) & 0xFF;
    r[r_offset_ripemd160 + 10] = (ripemd160_hash[2] >> 16) & 0xFF;
    r[r_offset_ripemd160 + 11] = (ripemd160_hash[2] >> 24) & 0xFF;

    r[r_offset_ripemd160 + 12] = (ripemd160_hash[3] >> 0) & 0xFF;
    r[r_offset_ripemd160 + 13] = (ripemd160_hash[3] >> 8) & 0xFF;
    r[r_offset_ripemd160 + 14] = (ripemd160_hash[3] >> 16) & 0xFF;
    r[r_offset_ripemd160 + 15] = (ripemd160_hash[3] >> 24) & 0xFF;

    r[r_offset_ripemd160 + 16] = (ripemd160_hash[4] >> 0) & 0xFF;
    r[r_offset_ripemd160 + 17] = (ripemd160_hash[4] >> 8) & 0xFF;
    r[r_offset_ripemd160 + 18] = (ripemd160_hash[4] >> 16) & 0xFF;
    r[r_offset_ripemd160 + 19] = (ripemd160_hash[4] >> 24) & 0xFF;
}

/*
 * "Creates" private keys from a single private key and then calculates the public key,
 * then hashes it with SHA-256 and RIPEMD-160.
 *
 * OUTPUT uchar *r: Pointer to the result buffer to store all results
 * INPUT u32 *k:    Pointer to the private key buffer storing a single private key
 */
__kernel void generate_chunk_until_ripemd160(__global uchar *r, __global const u32 *k){

    u32 k_local_u32[PRIVATE_KEY_LENGTH];
    u32 x_local_u32[PUBLIC_KEY_ONE_COORDINATE_LENGTH];
    u32 y_local_u32[PUBLIC_KEY_ONE_COORDINATE_LENGTH];
    uchar public_key_bytes[PUBLIC_KEY_BYTES_WITH_PARITY];
    secp256k1_t g_xy_local;

    // to store the results of the SHA-256 and RIPEMD-160 hashes
    u32 sha256_hash[SHA256_HASH_U32_LEN];
    u32 ripemd160_hash[RIPEMD160_HASH_U32_LEN];

    // id of current work item
    int work_item_id = get_global_id(0);

    // get first private key from private key grid and "create" a new one
    k_local_u32[0] = k[0] | work_item_id;
    k_local_u32[1] = k[1];
    k_local_u32[2] = k[2];
    k_local_u32[3] = k[3];
    k_local_u32[4] = k[4];
    k_local_u32[5] = k[5];
    k_local_u32[6] = k[6];
    k_local_u32[7] = k[7];

    // calculating the public key coordinates
    set_precomputed_basepoint_g(&g_xy_local);
    point_mul_xy(x_local_u32, y_local_u32, k_local_u32, &g_xy_local);


    // calculating offset to write results in byte buffer
    int r_offset_bytes_private_key = (PRIVATE_KEY_BYTES + PUBLIC_KEY_BYTES_WITH_PARITY + SHA256_HASH_BYTES_LEN + RIPEMD160_HASH_BYTES) * work_item_id;

    // write bytes of u32 array storing private key into result buffer
    r[r_offset_bytes_private_key + 0] = (k_local_u32[7] >> 24) & 0xFF;
    r[r_offset_bytes_private_key + 1] = (k_local_u32[7] >> 16) & 0xFF;
    r[r_offset_bytes_private_key + 2] = (k_local_u32[7] >> 8) & 0xFF;
    r[r_offset_bytes_private_key + 3] = (k_local_u32[7] >> 0) & 0xFF;

    r[r_offset_bytes_private_key + 4] = (k_local_u32[6] >> 24) & 0xFF;
    r[r_offset_bytes_private_key + 5] = (k_local_u32[6] >> 16) & 0xFF;
    r[r_offset_bytes_private_key + 6] = (k_local_u32[6] >> 8) & 0xFF;
    r[r_offset_bytes_private_key + 7] = (k_local_u32[6] >> 0) & 0xFF;

    r[r_offset_bytes_private_key + 8] = (k_local_u32[5] >> 24) & 0xFF;
    r[r_offset_bytes_private_key + 9] = (k_local_u32[5] >> 16) & 0xFF;
    r[r_offset_bytes_private_key + 10] = (k_local_u32[5] >> 8) & 0xFF;
    r[r_offset_bytes_private_key + 11] = (k_local_u32[5] >> 0) & 0xFF;

    r[r_offset_bytes_private_key + 12] = (k_local_u32[4] >> 24) & 0xFF;
    r[r_offset_bytes_private_key + 13] = (k_local_u32[4] >> 16) & 0xFF;
    r[r_offset_bytes_private_key + 14] = (k_local_u32[4] >> 8) & 0xFF;
    r[r_offset_bytes_private_key + 15] = (k_local_u32[4] >> 0) & 0xFF;

    r[r_offset_bytes_private_key + 16] = (k_local_u32[3] >> 24) & 0xFF;
    r[r_offset_bytes_private_key + 17] = (k_local_u32[3] >> 16) & 0xFF;
    r[r_offset_bytes_private_key + 18] = (k_local_u32[3] >> 8) & 0xFF;
    r[r_offset_bytes_private_key + 19] = (k_local_u32[3] >> 0) & 0xFF;

    r[r_offset_bytes_private_key + 20] = (k_local_u32[2] >> 24) & 0xFF;
    r[r_offset_bytes_private_key + 21] = (k_local_u32[2] >> 16) & 0xFF;
    r[r_offset_bytes_private_key + 22] = (k_local_u32[2] >> 8) & 0xFF;
    r[r_offset_bytes_private_key + 23] = (k_local_u32[2] >> 0) & 0xFF;

    r[r_offset_bytes_private_key + 24] = (k_local_u32[1] >> 24) & 0xFF;
    r[r_offset_bytes_private_key + 25] = (k_local_u32[1] >> 16) & 0xFF;
    r[r_offset_bytes_private_key + 26] = (k_local_u32[1] >> 8) & 0xFF;
    r[r_offset_bytes_private_key + 27] = (k_local_u32[1] >> 0) & 0xFF;

    r[r_offset_bytes_private_key + 28] = (k_local_u32[0] >> 24) & 0xFF;
    r[r_offset_bytes_private_key + 29] = (k_local_u32[0] >> 16) & 0xFF;
    r[r_offset_bytes_private_key + 30] = (k_local_u32[0] >> 8) & 0xFF;
    r[r_offset_bytes_private_key + 31] = (k_local_u32[0] >> 0) & 0xFF;


    // creating the public key from coordinates and parity byte for hashing
    create_public_key_from_coordinates(public_key_bytes, x_local_u32, y_local_u32);

    int r_offset_public_key = r_offset_bytes_private_key + PRIVATE_KEY_BYTES;

    // write public key parity byte into result buffer
    r[r_offset_public_key + 0] = 0x04;

    // write bytes of u32 array storing x coordinate into result buffer
    r[r_offset_public_key + 1] = (x_local_u32[7] >> 24) & 0xFF;
    r[r_offset_public_key + 2] = (x_local_u32[7] >> 16) & 0xFF;
    r[r_offset_public_key + 3] = (x_local_u32[7] >> 8) & 0xFF;
    r[r_offset_public_key + 4] = (x_local_u32[7] >> 0) & 0xFF;

    r[r_offset_public_key + 5] = (x_local_u32[6] >> 24) & 0xFF;
    r[r_offset_public_key + 6] = (x_local_u32[6] >> 16) & 0xFF;
    r[r_offset_public_key + 7] = (x_local_u32[6] >> 8) & 0xFF;
    r[r_offset_public_key + 8] = (x_local_u32[6] >> 0) & 0xFF;

    r[r_offset_public_key + 9] = (x_local_u32[5] >> 24) & 0xFF;
    r[r_offset_public_key + 10] = (x_local_u32[5] >> 16) & 0xFF;
    r[r_offset_public_key + 11] = (x_local_u32[5] >> 8) & 0xFF;
    r[r_offset_public_key + 12] = (x_local_u32[5] >> 0) & 0xFF;

    r[r_offset_public_key + 13] = (x_local_u32[4] >> 24) & 0xFF;
    r[r_offset_public_key + 14] = (x_local_u32[4] >> 16) & 0xFF;
    r[r_offset_public_key + 15] = (x_local_u32[4] >> 8) & 0xFF;
    r[r_offset_public_key + 16] = (x_local_u32[4] >> 0) & 0xFF;

    r[r_offset_public_key + 17] = (x_local_u32[3] >> 24) & 0xFF;
    r[r_offset_public_key + 18] = (x_local_u32[3] >> 16) & 0xFF;
    r[r_offset_public_key + 19] = (x_local_u32[3] >> 8) & 0xFF;
    r[r_offset_public_key + 20] = (x_local_u32[3] >> 0) & 0xFF;

    r[r_offset_public_key + 21] = (x_local_u32[2] >> 24) & 0xFF;
    r[r_offset_public_key + 22] = (x_local_u32[2] >> 16) & 0xFF;
    r[r_offset_public_key + 23] = (x_local_u32[2] >> 8) & 0xFF;
    r[r_offset_public_key + 24] = (x_local_u32[2] >> 0) & 0xFF;

    r[r_offset_public_key + 25] = (x_local_u32[1] >> 24) & 0xFF;
    r[r_offset_public_key + 26] = (x_local_u32[1] >> 16) & 0xFF;
    r[r_offset_public_key + 27] = (x_local_u32[1] >> 8) & 0xFF;
    r[r_offset_public_key + 28] = (x_local_u32[1] >> 0) & 0xFF;

    r[r_offset_public_key + 29] = (x_local_u32[0] >> 24) & 0xFF;
    r[r_offset_public_key + 30] = (x_local_u32[0] >> 16) & 0xFF;
    r[r_offset_public_key + 31] = (x_local_u32[0] >> 8) & 0xFF;
    r[r_offset_public_key + 32] = (x_local_u32[0] >> 0) & 0xFF;

    // write bytes of u32 array storing y coordinate into result buffer
    r[r_offset_public_key + 33] = (y_local_u32[7] >> 24) & 0xFF;
    r[r_offset_public_key + 34] = (y_local_u32[7] >> 16) & 0xFF;
    r[r_offset_public_key + 35] = (y_local_u32[7] >> 8) & 0xFF;
    r[r_offset_public_key + 36] = (y_local_u32[7] >> 0) & 0xFF;

    r[r_offset_public_key + 37] = (y_local_u32[6] >> 24) & 0xFF;
    r[r_offset_public_key + 38] = (y_local_u32[6] >> 16) & 0xFF;
    r[r_offset_public_key + 39] = (y_local_u32[6] >> 8) & 0xFF;
    r[r_offset_public_key + 40] = (y_local_u32[6] >> 0) & 0xFF;

    r[r_offset_public_key + 41] = (y_local_u32[5] >> 24) & 0xFF;
    r[r_offset_public_key + 42] = (y_local_u32[5] >> 16) & 0xFF;
    r[r_offset_public_key + 43] = (y_local_u32[5] >> 8) & 0xFF;
    r[r_offset_public_key + 44] = (y_local_u32[5] >> 0) & 0xFF;

    r[r_offset_public_key + 45] = (y_local_u32[4] >> 24) & 0xFF;
    r[r_offset_public_key + 46] = (y_local_u32[4] >> 16) & 0xFF;
    r[r_offset_public_key + 47] = (y_local_u32[4] >> 8) & 0xFF;
    r[r_offset_public_key + 48] = (y_local_u32[4] >> 0) & 0xFF;

    r[r_offset_public_key + 49] = (y_local_u32[3] >> 24) & 0xFF;
    r[r_offset_public_key + 50] = (y_local_u32[3] >> 16) & 0xFF;
    r[r_offset_public_key + 51] = (y_local_u32[3] >> 8) & 0xFF;
    r[r_offset_public_key + 52] = (y_local_u32[3] >> 0) & 0xFF;

    r[r_offset_public_key + 53] = (y_local_u32[2] >> 24) & 0xFF;
    r[r_offset_public_key + 54] = (y_local_u32[2] >> 16) & 0xFF;
    r[r_offset_public_key + 55] = (y_local_u32[2] >> 8) & 0xFF;
    r[r_offset_public_key + 56] = (y_local_u32[2] >> 0) & 0xFF;

    r[r_offset_public_key + 57] = (y_local_u32[1] >> 24) & 0xFF;
    r[r_offset_public_key + 58] = (y_local_u32[1] >> 16) & 0xFF;
    r[r_offset_public_key + 59] = (y_local_u32[1] >> 8) & 0xFF;
    r[r_offset_public_key + 60] = (y_local_u32[1] >> 0) & 0xFF;

    r[r_offset_public_key + 61] = (y_local_u32[0] >> 24) & 0xFF;
    r[r_offset_public_key + 62] = (y_local_u32[0] >> 16) & 0xFF;
    r[r_offset_public_key + 63] = (y_local_u32[0] >> 8) & 0xFF;
    r[r_offset_public_key + 64] = (y_local_u32[0] >> 0) & 0xFF;


    // hash the public key with SHA-256
    calculate_sha256_from_public_key(public_key_bytes, sha256_hash);

    int r_offset_first_sha256 = r_offset_public_key + PUBLIC_KEY_BYTES_WITH_PARITY;

    // write bytes of u32 array storing sha256_hash into result buffer
    r[r_offset_first_sha256 + 0] = (sha256_hash[0] >> 24) & 0xFF;
    r[r_offset_first_sha256 + 1] = (sha256_hash[0] >> 16) & 0xFF;
    r[r_offset_first_sha256 + 2] = (sha256_hash[0] >> 8) & 0xFF;
    r[r_offset_first_sha256 + 3] = (sha256_hash[0] >> 0) & 0xFF;

    r[r_offset_first_sha256 + 4] = (sha256_hash[1] >> 24) & 0xFF;
    r[r_offset_first_sha256 + 5] = (sha256_hash[1] >> 16) & 0xFF;
    r[r_offset_first_sha256 + 6] = (sha256_hash[1] >> 8) & 0xFF;
    r[r_offset_first_sha256 + 7] = (sha256_hash[1] >> 0) & 0xFF;

    r[r_offset_first_sha256 + 8] = (sha256_hash[2] >> 24) & 0xFF;
    r[r_offset_first_sha256 + 9] = (sha256_hash[2] >> 16) & 0xFF;
    r[r_offset_first_sha256 + 10] = (sha256_hash[2] >> 8) & 0xFF;
    r[r_offset_first_sha256 + 11] = (sha256_hash[2] >> 0) & 0xFF;

    r[r_offset_first_sha256 + 12] = (sha256_hash[3] >> 24) & 0xFF;
    r[r_offset_first_sha256 + 13] = (sha256_hash[3] >> 16) & 0xFF;
    r[r_offset_first_sha256 + 14] = (sha256_hash[3] >> 8) & 0xFF;
    r[r_offset_first_sha256 + 15] = (sha256_hash[3] >> 0) & 0xFF;

    r[r_offset_first_sha256 + 16] = (sha256_hash[4] >> 24) & 0xFF;
    r[r_offset_first_sha256 + 17] = (sha256_hash[4] >> 16) & 0xFF;
    r[r_offset_first_sha256 + 18] = (sha256_hash[4] >> 8) & 0xFF;
    r[r_offset_first_sha256 + 19] = (sha256_hash[4] >> 0) & 0xFF;

    r[r_offset_first_sha256 + 20] = (sha256_hash[5] >> 24) & 0xFF;
    r[r_offset_first_sha256 + 21] = (sha256_hash[5] >> 16) & 0xFF;
    r[r_offset_first_sha256 + 22] = (sha256_hash[5] >> 8) & 0xFF;
    r[r_offset_first_sha256 + 23] = (sha256_hash[5] >> 0) & 0xFF;

    r[r_offset_first_sha256 + 24] = (sha256_hash[6] >> 24) & 0xFF;
    r[r_offset_first_sha256 + 25] = (sha256_hash[6] >> 16) & 0xFF;
    r[r_offset_first_sha256 + 26] = (sha256_hash[6] >> 8) & 0xFF;
    r[r_offset_first_sha256 + 27] = (sha256_hash[6] >> 0) & 0xFF;

    r[r_offset_first_sha256 + 28] = (sha256_hash[7] >> 24) & 0xFF;
    r[r_offset_first_sha256 + 29] = (sha256_hash[7] >> 16) & 0xFF;
    r[r_offset_first_sha256 + 30] = (sha256_hash[7] >> 8) & 0xFF;
    r[r_offset_first_sha256 + 31] = (sha256_hash[7] >> 0) & 0xFF;


    // hash the SHA-256 result with RIPEMD-160
    calculate_ripemd160_from_u32(sha256_hash, ripemd160_hash);

    int r_offset_ripemd160 = r_offset_first_sha256 + SHA256_HASH_BYTES_LEN;

    // write bytes of u32 array storing ripemd160_hash into result buffer
    r[r_offset_ripemd160 + 0] = (ripemd160_hash[0] >> 0) & 0xFF;
    r[r_offset_ripemd160 + 1] = (ripemd160_hash[0] >> 8) & 0xFF;
    r[r_offset_ripemd160 + 2] = (ripemd160_hash[0] >> 16) & 0xFF;
    r[r_offset_ripemd160 + 3] = (ripemd160_hash[0] >> 24) & 0xFF;

    r[r_offset_ripemd160 + 4] = (ripemd160_hash[1] >> 0) & 0xFF;
    r[r_offset_ripemd160 + 5] = (ripemd160_hash[1] >> 8) & 0xFF;
    r[r_offset_ripemd160 + 6] = (ripemd160_hash[1] >> 16) & 0xFF;
    r[r_offset_ripemd160 + 7] = (ripemd160_hash[1] >> 24) & 0xFF;

    r[r_offset_ripemd160 + 8] = (ripemd160_hash[2] >> 0) & 0xFF;
    r[r_offset_ripemd160 + 9] = (ripemd160_hash[2] >> 8) & 0xFF;
    r[r_offset_ripemd160 + 10] = (ripemd160_hash[2] >> 16) & 0xFF;
    r[r_offset_ripemd160 + 11] = (ripemd160_hash[2] >> 24) & 0xFF;

    r[r_offset_ripemd160 + 12] = (ripemd160_hash[3] >> 0) & 0xFF;
    r[r_offset_ripemd160 + 13] = (ripemd160_hash[3] >> 8) & 0xFF;
    r[r_offset_ripemd160 + 14] = (ripemd160_hash[3] >> 16) & 0xFF;
    r[r_offset_ripemd160 + 15] = (ripemd160_hash[3] >> 24) & 0xFF;

    r[r_offset_ripemd160 + 16] = (ripemd160_hash[4] >> 0) & 0xFF;
    r[r_offset_ripemd160 + 17] = (ripemd160_hash[4] >> 8) & 0xFF;
    r[r_offset_ripemd160 + 18] = (ripemd160_hash[4] >> 16) & 0xFF;
    r[r_offset_ripemd160 + 19] = (ripemd160_hash[4] >> 24) & 0xFF;
}

/*
 * "Creates" private keys from a single private key and then calculates the public key,
 * then hashes it with SHA-256, RIPEMD-160, adds version byte and then hashes it again
 * with SHA-256 again.
 *
 * OUTPUT uchar *r: Pointer to the result buffer to store all results
 * INPUT u32 *k:    Pointer to the private key buffer storing a single private key
 */
__kernel void generate_chunk_until_second_sha256(__global uchar *r, __global const u32 *k){

    u32 k_local_u32[PRIVATE_KEY_LENGTH];
    u32 x_local_u32[PUBLIC_KEY_ONE_COORDINATE_LENGTH];
    u32 y_local_u32[PUBLIC_KEY_ONE_COORDINATE_LENGTH];
    uchar public_key_bytes[PUBLIC_KEY_BYTES_WITH_PARITY];
    secp256k1_t g_xy_local;

    // to store the results of the SHA-256 and RIPEMD-160 hashes
    u32 sha256_hash[SHA256_HASH_U32_LEN];
    u32 ripemd160_hash[RIPEMD160_HASH_U32_LEN];
    uchar version[RIPEMD160_HASH_WITH_VERSION_BYTES];
    u32 second_sha256_hash[SHA256_HASH_U32_LEN];

    // id of current work item
    int work_item_id = get_global_id(0);

    // get first private key from private key grid and "create" a new one
    k_local_u32[0] = k[0] | work_item_id;
    k_local_u32[1] = k[1];
    k_local_u32[2] = k[2];
    k_local_u32[3] = k[3];
    k_local_u32[4] = k[4];
    k_local_u32[5] = k[5];
    k_local_u32[6] = k[6];
    k_local_u32[7] = k[7];

    // calculating the public key coordinates
    set_precomputed_basepoint_g(&g_xy_local);
    point_mul_xy(x_local_u32, y_local_u32, k_local_u32, &g_xy_local);


    // calculating offset to write results in byte buffer
    int r_offset_bytes_private_key = (PRIVATE_KEY_BYTES + PUBLIC_KEY_BYTES_WITH_PARITY + SHA256_HASH_BYTES_LEN + RIPEMD160_HASH_BYTES + SHA256_HASH_BYTES_LEN) * work_item_id;

    // write bytes of u32 array storing private key into result buffer
    r[r_offset_bytes_private_key + 0] = (k_local_u32[7] >> 24) & 0xFF;
    r[r_offset_bytes_private_key + 1] = (k_local_u32[7] >> 16) & 0xFF;
    r[r_offset_bytes_private_key + 2] = (k_local_u32[7] >> 8) & 0xFF;
    r[r_offset_bytes_private_key + 3] = (k_local_u32[7] >> 0) & 0xFF;

    r[r_offset_bytes_private_key + 4] = (k_local_u32[6] >> 24) & 0xFF;
    r[r_offset_bytes_private_key + 5] = (k_local_u32[6] >> 16) & 0xFF;
    r[r_offset_bytes_private_key + 6] = (k_local_u32[6] >> 8) & 0xFF;
    r[r_offset_bytes_private_key + 7] = (k_local_u32[6] >> 0) & 0xFF;

    r[r_offset_bytes_private_key + 8] = (k_local_u32[5] >> 24) & 0xFF;
    r[r_offset_bytes_private_key + 9] = (k_local_u32[5] >> 16) & 0xFF;
    r[r_offset_bytes_private_key + 10] = (k_local_u32[5] >> 8) & 0xFF;
    r[r_offset_bytes_private_key + 11] = (k_local_u32[5] >> 0) & 0xFF;

    r[r_offset_bytes_private_key + 12] = (k_local_u32[4] >> 24) & 0xFF;
    r[r_offset_bytes_private_key + 13] = (k_local_u32[4] >> 16) & 0xFF;
    r[r_offset_bytes_private_key + 14] = (k_local_u32[4] >> 8) & 0xFF;
    r[r_offset_bytes_private_key + 15] = (k_local_u32[4] >> 0) & 0xFF;

    r[r_offset_bytes_private_key + 16] = (k_local_u32[3] >> 24) & 0xFF;
    r[r_offset_bytes_private_key + 17] = (k_local_u32[3] >> 16) & 0xFF;
    r[r_offset_bytes_private_key + 18] = (k_local_u32[3] >> 8) & 0xFF;
    r[r_offset_bytes_private_key + 19] = (k_local_u32[3] >> 0) & 0xFF;

    r[r_offset_bytes_private_key + 20] = (k_local_u32[2] >> 24) & 0xFF;
    r[r_offset_bytes_private_key + 21] = (k_local_u32[2] >> 16) & 0xFF;
    r[r_offset_bytes_private_key + 22] = (k_local_u32[2] >> 8) & 0xFF;
    r[r_offset_bytes_private_key + 23] = (k_local_u32[2] >> 0) & 0xFF;

    r[r_offset_bytes_private_key + 24] = (k_local_u32[1] >> 24) & 0xFF;
    r[r_offset_bytes_private_key + 25] = (k_local_u32[1] >> 16) & 0xFF;
    r[r_offset_bytes_private_key + 26] = (k_local_u32[1] >> 8) & 0xFF;
    r[r_offset_bytes_private_key + 27] = (k_local_u32[1] >> 0) & 0xFF;

    r[r_offset_bytes_private_key + 28] = (k_local_u32[0] >> 24) & 0xFF;
    r[r_offset_bytes_private_key + 29] = (k_local_u32[0] >> 16) & 0xFF;
    r[r_offset_bytes_private_key + 30] = (k_local_u32[0] >> 8) & 0xFF;
    r[r_offset_bytes_private_key + 31] = (k_local_u32[0] >> 0) & 0xFF;


    // creating the public key from coordinates and parity byte for hashing
    create_public_key_from_coordinates(public_key_bytes, x_local_u32, y_local_u32);

    int r_offset_public_key = r_offset_bytes_private_key + PRIVATE_KEY_BYTES;

    // write public key parity byte into result buffer
    r[r_offset_public_key + 0] = 0x04;

    // write bytes of u32 array storing x coordinate into result buffer
    r[r_offset_public_key + 1] = (x_local_u32[7] >> 24) & 0xFF;
    r[r_offset_public_key + 2] = (x_local_u32[7] >> 16) & 0xFF;
    r[r_offset_public_key + 3] = (x_local_u32[7] >> 8) & 0xFF;
    r[r_offset_public_key + 4] = (x_local_u32[7] >> 0) & 0xFF;

    r[r_offset_public_key + 5] = (x_local_u32[6] >> 24) & 0xFF;
    r[r_offset_public_key + 6] = (x_local_u32[6] >> 16) & 0xFF;
    r[r_offset_public_key + 7] = (x_local_u32[6] >> 8) & 0xFF;
    r[r_offset_public_key + 8] = (x_local_u32[6] >> 0) & 0xFF;

    r[r_offset_public_key + 9] = (x_local_u32[5] >> 24) & 0xFF;
    r[r_offset_public_key + 10] = (x_local_u32[5] >> 16) & 0xFF;
    r[r_offset_public_key + 11] = (x_local_u32[5] >> 8) & 0xFF;
    r[r_offset_public_key + 12] = (x_local_u32[5] >> 0) & 0xFF;

    r[r_offset_public_key + 13] = (x_local_u32[4] >> 24) & 0xFF;
    r[r_offset_public_key + 14] = (x_local_u32[4] >> 16) & 0xFF;
    r[r_offset_public_key + 15] = (x_local_u32[4] >> 8) & 0xFF;
    r[r_offset_public_key + 16] = (x_local_u32[4] >> 0) & 0xFF;

    r[r_offset_public_key + 17] = (x_local_u32[3] >> 24) & 0xFF;
    r[r_offset_public_key + 18] = (x_local_u32[3] >> 16) & 0xFF;
    r[r_offset_public_key + 19] = (x_local_u32[3] >> 8) & 0xFF;
    r[r_offset_public_key + 20] = (x_local_u32[3] >> 0) & 0xFF;

    r[r_offset_public_key + 21] = (x_local_u32[2] >> 24) & 0xFF;
    r[r_offset_public_key + 22] = (x_local_u32[2] >> 16) & 0xFF;
    r[r_offset_public_key + 23] = (x_local_u32[2] >> 8) & 0xFF;
    r[r_offset_public_key + 24] = (x_local_u32[2] >> 0) & 0xFF;

    r[r_offset_public_key + 25] = (x_local_u32[1] >> 24) & 0xFF;
    r[r_offset_public_key + 26] = (x_local_u32[1] >> 16) & 0xFF;
    r[r_offset_public_key + 27] = (x_local_u32[1] >> 8) & 0xFF;
    r[r_offset_public_key + 28] = (x_local_u32[1] >> 0) & 0xFF;

    r[r_offset_public_key + 29] = (x_local_u32[0] >> 24) & 0xFF;
    r[r_offset_public_key + 30] = (x_local_u32[0] >> 16) & 0xFF;
    r[r_offset_public_key + 31] = (x_local_u32[0] >> 8) & 0xFF;
    r[r_offset_public_key + 32] = (x_local_u32[0] >> 0) & 0xFF;

    // write bytes of u32 array storing y coordinate into result buffer
    r[r_offset_public_key + 33] = (y_local_u32[7] >> 24) & 0xFF;
    r[r_offset_public_key + 34] = (y_local_u32[7] >> 16) & 0xFF;
    r[r_offset_public_key + 35] = (y_local_u32[7] >> 8) & 0xFF;
    r[r_offset_public_key + 36] = (y_local_u32[7] >> 0) & 0xFF;

    r[r_offset_public_key + 37] = (y_local_u32[6] >> 24) & 0xFF;
    r[r_offset_public_key + 38] = (y_local_u32[6] >> 16) & 0xFF;
    r[r_offset_public_key + 39] = (y_local_u32[6] >> 8) & 0xFF;
    r[r_offset_public_key + 40] = (y_local_u32[6] >> 0) & 0xFF;

    r[r_offset_public_key + 41] = (y_local_u32[5] >> 24) & 0xFF;
    r[r_offset_public_key + 42] = (y_local_u32[5] >> 16) & 0xFF;
    r[r_offset_public_key + 43] = (y_local_u32[5] >> 8) & 0xFF;
    r[r_offset_public_key + 44] = (y_local_u32[5] >> 0) & 0xFF;

    r[r_offset_public_key + 45] = (y_local_u32[4] >> 24) & 0xFF;
    r[r_offset_public_key + 46] = (y_local_u32[4] >> 16) & 0xFF;
    r[r_offset_public_key + 47] = (y_local_u32[4] >> 8) & 0xFF;
    r[r_offset_public_key + 48] = (y_local_u32[4] >> 0) & 0xFF;

    r[r_offset_public_key + 49] = (y_local_u32[3] >> 24) & 0xFF;
    r[r_offset_public_key + 50] = (y_local_u32[3] >> 16) & 0xFF;
    r[r_offset_public_key + 51] = (y_local_u32[3] >> 8) & 0xFF;
    r[r_offset_public_key + 52] = (y_local_u32[3] >> 0) & 0xFF;

    r[r_offset_public_key + 53] = (y_local_u32[2] >> 24) & 0xFF;
    r[r_offset_public_key + 54] = (y_local_u32[2] >> 16) & 0xFF;
    r[r_offset_public_key + 55] = (y_local_u32[2] >> 8) & 0xFF;
    r[r_offset_public_key + 56] = (y_local_u32[2] >> 0) & 0xFF;

    r[r_offset_public_key + 57] = (y_local_u32[1] >> 24) & 0xFF;
    r[r_offset_public_key + 58] = (y_local_u32[1] >> 16) & 0xFF;
    r[r_offset_public_key + 59] = (y_local_u32[1] >> 8) & 0xFF;
    r[r_offset_public_key + 60] = (y_local_u32[1] >> 0) & 0xFF;

    r[r_offset_public_key + 61] = (y_local_u32[0] >> 24) & 0xFF;
    r[r_offset_public_key + 62] = (y_local_u32[0] >> 16) & 0xFF;
    r[r_offset_public_key + 63] = (y_local_u32[0] >> 8) & 0xFF;
    r[r_offset_public_key + 64] = (y_local_u32[0] >> 0) & 0xFF;


    // hash the public key with SHA-256
    calculate_sha256_from_public_key(public_key_bytes, sha256_hash);

    int r_offset_first_sha256 = r_offset_public_key + PUBLIC_KEY_BYTES_WITH_PARITY;

    // write bytes of u32 array storing sha256_hash into result buffer
    r[r_offset_first_sha256 + 0] = (sha256_hash[0] >> 24) & 0xFF;
    r[r_offset_first_sha256 + 1] = (sha256_hash[0] >> 16) & 0xFF;
    r[r_offset_first_sha256 + 2] = (sha256_hash[0] >> 8) & 0xFF;
    r[r_offset_first_sha256 + 3] = (sha256_hash[0] >> 0) & 0xFF;

    r[r_offset_first_sha256 + 4] = (sha256_hash[1] >> 24) & 0xFF;
    r[r_offset_first_sha256 + 5] = (sha256_hash[1] >> 16) & 0xFF;
    r[r_offset_first_sha256 + 6] = (sha256_hash[1] >> 8) & 0xFF;
    r[r_offset_first_sha256 + 7] = (sha256_hash[1] >> 0) & 0xFF;

    r[r_offset_first_sha256 + 8] = (sha256_hash[2] >> 24) & 0xFF;
    r[r_offset_first_sha256 + 9] = (sha256_hash[2] >> 16) & 0xFF;
    r[r_offset_first_sha256 + 10] = (sha256_hash[2] >> 8) & 0xFF;
    r[r_offset_first_sha256 + 11] = (sha256_hash[2] >> 0) & 0xFF;

    r[r_offset_first_sha256 + 12] = (sha256_hash[3] >> 24) & 0xFF;
    r[r_offset_first_sha256 + 13] = (sha256_hash[3] >> 16) & 0xFF;
    r[r_offset_first_sha256 + 14] = (sha256_hash[3] >> 8) & 0xFF;
    r[r_offset_first_sha256 + 15] = (sha256_hash[3] >> 0) & 0xFF;

    r[r_offset_first_sha256 + 16] = (sha256_hash[4] >> 24) & 0xFF;
    r[r_offset_first_sha256 + 17] = (sha256_hash[4] >> 16) & 0xFF;
    r[r_offset_first_sha256 + 18] = (sha256_hash[4] >> 8) & 0xFF;
    r[r_offset_first_sha256 + 19] = (sha256_hash[4] >> 0) & 0xFF;

    r[r_offset_first_sha256 + 20] = (sha256_hash[5] >> 24) & 0xFF;
    r[r_offset_first_sha256 + 21] = (sha256_hash[5] >> 16) & 0xFF;
    r[r_offset_first_sha256 + 22] = (sha256_hash[5] >> 8) & 0xFF;
    r[r_offset_first_sha256 + 23] = (sha256_hash[5] >> 0) & 0xFF;

    r[r_offset_first_sha256 + 24] = (sha256_hash[6] >> 24) & 0xFF;
    r[r_offset_first_sha256 + 25] = (sha256_hash[6] >> 16) & 0xFF;
    r[r_offset_first_sha256 + 26] = (sha256_hash[6] >> 8) & 0xFF;
    r[r_offset_first_sha256 + 27] = (sha256_hash[6] >> 0) & 0xFF;

    r[r_offset_first_sha256 + 28] = (sha256_hash[7] >> 24) & 0xFF;
    r[r_offset_first_sha256 + 29] = (sha256_hash[7] >> 16) & 0xFF;
    r[r_offset_first_sha256 + 30] = (sha256_hash[7] >> 8) & 0xFF;
    r[r_offset_first_sha256 + 31] = (sha256_hash[7] >> 0) & 0xFF;


    // hash the SHA-256 result with RIPEMD-160
    calculate_ripemd160_from_u32(sha256_hash, ripemd160_hash);

    int r_offset_ripemd160 = r_offset_first_sha256 + SHA256_HASH_BYTES_LEN;

    // write bytes of u32 array storing ripemd160_hash into result buffer
    r[r_offset_ripemd160 + 0] = (ripemd160_hash[0] >> 0) & 0xFF;
    r[r_offset_ripemd160 + 1] = (ripemd160_hash[0] >> 8) & 0xFF;
    r[r_offset_ripemd160 + 2] = (ripemd160_hash[0] >> 16) & 0xFF;
    r[r_offset_ripemd160 + 3] = (ripemd160_hash[0] >> 24) & 0xFF;

    r[r_offset_ripemd160 + 4] = (ripemd160_hash[1] >> 0) & 0xFF;
    r[r_offset_ripemd160 + 5] = (ripemd160_hash[1] >> 8) & 0xFF;
    r[r_offset_ripemd160 + 6] = (ripemd160_hash[1] >> 16) & 0xFF;
    r[r_offset_ripemd160 + 7] = (ripemd160_hash[1] >> 24) & 0xFF;

    r[r_offset_ripemd160 + 8] = (ripemd160_hash[2] >> 0) & 0xFF;
    r[r_offset_ripemd160 + 9] = (ripemd160_hash[2] >> 8) & 0xFF;
    r[r_offset_ripemd160 + 10] = (ripemd160_hash[2] >> 16) & 0xFF;
    r[r_offset_ripemd160 + 11] = (ripemd160_hash[2] >> 24) & 0xFF;

    r[r_offset_ripemd160 + 12] = (ripemd160_hash[3] >> 0) & 0xFF;
    r[r_offset_ripemd160 + 13] = (ripemd160_hash[3] >> 8) & 0xFF;
    r[r_offset_ripemd160 + 14] = (ripemd160_hash[3] >> 16) & 0xFF;
    r[r_offset_ripemd160 + 15] = (ripemd160_hash[3] >> 24) & 0xFF;

    r[r_offset_ripemd160 + 16] = (ripemd160_hash[4] >> 0) & 0xFF;
    r[r_offset_ripemd160 + 17] = (ripemd160_hash[4] >> 8) & 0xFF;
    r[r_offset_ripemd160 + 18] = (ripemd160_hash[4] >> 16) & 0xFF;
    r[r_offset_ripemd160 + 19] = (ripemd160_hash[4] >> 24) & 0xFF;


    // version = 0x00 + RIPEMD-160 hash
    version[0] = RIPEMD160_HASH_VERSION_BYTE;

    version[1] = (ripemd160_hash[0] >> 0) & 0xFF;
    version[2] = (ripemd160_hash[0] >> 8) & 0xFF;
    version[3] = (ripemd160_hash[0] >> 16) & 0xFF;
    version[4] = (ripemd160_hash[0] >> 24) & 0xFF;

    version[5] = (ripemd160_hash[1] >> 0) & 0xFF;
    version[6] = (ripemd160_hash[1] >> 8) & 0xFF;
    version[7] = (ripemd160_hash[1] >> 16) & 0xFF;
    version[8] = (ripemd160_hash[1] >> 24) & 0xFF;

    version[9] = (ripemd160_hash[2] >> 0) & 0xFF;
    version[10] = (ripemd160_hash[2] >> 8) & 0xFF;
    version[11] = (ripemd160_hash[2] >> 16) & 0xFF;
    version[12] = (ripemd160_hash[2] >> 24) & 0xFF;

    version[13] = (ripemd160_hash[3] >> 0) & 0xFF;
    version[14] = (ripemd160_hash[3] >> 8) & 0xFF;
    version[15] = (ripemd160_hash[3] >> 16) & 0xFF;
    version[16] = (ripemd160_hash[3] >> 24) & 0xFF;

    version[17] = (ripemd160_hash[4] >> 0) & 0xFF;
    version[18] = (ripemd160_hash[4] >> 8) & 0xFF;
    version[19] = (ripemd160_hash[4] >> 16) & 0xFF;
    version[20] = (ripemd160_hash[4] >> 24) & 0xFF;

    // hash the RIPEMD-160 hash incl version byte with SHA-256
    calculate_sha256_from_version(version, second_sha256_hash);

    int r_offset_second_sha256 = r_offset_ripemd160 + RIPEMD160_HASH_BYTES;

    // write bytes of u32 array storing second SHA-256 hash into result buffer
    r[r_offset_second_sha256 + 0] = (second_sha256_hash[0] >> 24) & 0xFF;
    r[r_offset_second_sha256 + 1] = (second_sha256_hash[0] >> 16) & 0xFF;
    r[r_offset_second_sha256 + 2] = (second_sha256_hash[0] >> 8) & 0xFF;
    r[r_offset_second_sha256 + 3] = (second_sha256_hash[0] >> 0) & 0xFF;

    r[r_offset_second_sha256 + 4] = (second_sha256_hash[1] >> 24) & 0xFF;
    r[r_offset_second_sha256 + 5] = (second_sha256_hash[1] >> 16) & 0xFF;
    r[r_offset_second_sha256 + 6] = (second_sha256_hash[1] >> 8) & 0xFF;
    r[r_offset_second_sha256 + 7] = (second_sha256_hash[1] >> 0) & 0xFF;

    r[r_offset_second_sha256 + 8] = (second_sha256_hash[2] >> 24) & 0xFF;
    r[r_offset_second_sha256 + 9] = (second_sha256_hash[2] >> 16) & 0xFF;
    r[r_offset_second_sha256 + 10] = (second_sha256_hash[2] >> 8) & 0xFF;
    r[r_offset_second_sha256 + 11] = (second_sha256_hash[2] >> 0) & 0xFF;

    r[r_offset_second_sha256 + 12] = (second_sha256_hash[3] >> 24) & 0xFF;
    r[r_offset_second_sha256 + 13] = (second_sha256_hash[3] >> 16) & 0xFF;
    r[r_offset_second_sha256 + 14] = (second_sha256_hash[3] >> 8) & 0xFF;
    r[r_offset_second_sha256 + 15] = (second_sha256_hash[3] >> 0) & 0xFF;

    r[r_offset_second_sha256 + 16] = (second_sha256_hash[4] >> 24) & 0xFF;
    r[r_offset_second_sha256 + 17] = (second_sha256_hash[4] >> 16) & 0xFF;
    r[r_offset_second_sha256 + 18] = (second_sha256_hash[4] >> 8) & 0xFF;
    r[r_offset_second_sha256 + 19] = (second_sha256_hash[4] >> 0) & 0xFF;

    r[r_offset_second_sha256 + 20] = (second_sha256_hash[5] >> 24) & 0xFF;
    r[r_offset_second_sha256 + 21] = (second_sha256_hash[5] >> 16) & 0xFF;
    r[r_offset_second_sha256 + 22] = (second_sha256_hash[5] >> 8) & 0xFF;
    r[r_offset_second_sha256 + 23] = (second_sha256_hash[5] >> 0) & 0xFF;

    r[r_offset_second_sha256 + 24] = (second_sha256_hash[6] >> 24) & 0xFF;
    r[r_offset_second_sha256 + 25] = (second_sha256_hash[6] >> 16) & 0xFF;
    r[r_offset_second_sha256 + 26] = (second_sha256_hash[6] >> 8) & 0xFF;
    r[r_offset_second_sha256 + 27] = (second_sha256_hash[6] >> 0) & 0xFF;

    r[r_offset_second_sha256 + 28] = (second_sha256_hash[7] >> 24) & 0xFF;
    r[r_offset_second_sha256 + 29] = (second_sha256_hash[7] >> 16) & 0xFF;
    r[r_offset_second_sha256 + 30] = (second_sha256_hash[7] >> 8) & 0xFF;
    r[r_offset_second_sha256 + 31] = (second_sha256_hash[7] >> 0) & 0xFF;
}

/*
 * Calculates the public key from given private key,
 * then hashes it with SHA-256, RIPEMD-160, adds version byte and then hashes it again
 * with SHA-256 again.
 *
 * OUTPUT uchar *r: Pointer to the result buffer to store all results
 * INPUT u32 *k:    Pointer to the private key buffer storing all private keys
 */
__kernel void generate_until_second_sha256(__global uchar *r, __global const u32 *k){

    u32 k_local_u32[PRIVATE_KEY_LENGTH];
    u32 x_local_u32[PUBLIC_KEY_ONE_COORDINATE_LENGTH];
    u32 y_local_u32[PUBLIC_KEY_ONE_COORDINATE_LENGTH];
    uchar public_key_bytes[PUBLIC_KEY_BYTES_WITH_PARITY];
    secp256k1_t g_xy_local;

    // to store the results of the SHA-256 and RIPEMD-160 hashes
    u32 sha256_hash[SHA256_HASH_U32_LEN];
    u32 ripemd160_hash[RIPEMD160_HASH_U32_LEN];
    uchar version[RIPEMD160_HASH_WITH_VERSION_BYTES];
    u32 second_sha256_hash[SHA256_HASH_U32_LEN];

    // id of current work item
    int work_item_id = get_global_id(0);

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

    // calculating the public key coordinates
    set_precomputed_basepoint_g(&g_xy_local);
    point_mul_xy(x_local_u32, y_local_u32, k_local_u32, &g_xy_local);


    // calculating offset to write results in byte buffer
    int r_offset_bytes_private_key = (PRIVATE_KEY_BYTES + PUBLIC_KEY_BYTES_WITH_PARITY + SHA256_HASH_BYTES_LEN + RIPEMD160_HASH_BYTES + SHA256_HASH_BYTES_LEN) * work_item_id;

    // write bytes of u32 array storing private key into result buffer
    r[r_offset_bytes_private_key + 0] = (k_local_u32[7] >> 24) & 0xFF;
    r[r_offset_bytes_private_key + 1] = (k_local_u32[7] >> 16) & 0xFF;
    r[r_offset_bytes_private_key + 2] = (k_local_u32[7] >> 8) & 0xFF;
    r[r_offset_bytes_private_key + 3] = (k_local_u32[7] >> 0) & 0xFF;

    r[r_offset_bytes_private_key + 4] = (k_local_u32[6] >> 24) & 0xFF;
    r[r_offset_bytes_private_key + 5] = (k_local_u32[6] >> 16) & 0xFF;
    r[r_offset_bytes_private_key + 6] = (k_local_u32[6] >> 8) & 0xFF;
    r[r_offset_bytes_private_key + 7] = (k_local_u32[6] >> 0) & 0xFF;

    r[r_offset_bytes_private_key + 8] = (k_local_u32[5] >> 24) & 0xFF;
    r[r_offset_bytes_private_key + 9] = (k_local_u32[5] >> 16) & 0xFF;
    r[r_offset_bytes_private_key + 10] = (k_local_u32[5] >> 8) & 0xFF;
    r[r_offset_bytes_private_key + 11] = (k_local_u32[5] >> 0) & 0xFF;

    r[r_offset_bytes_private_key + 12] = (k_local_u32[4] >> 24) & 0xFF;
    r[r_offset_bytes_private_key + 13] = (k_local_u32[4] >> 16) & 0xFF;
    r[r_offset_bytes_private_key + 14] = (k_local_u32[4] >> 8) & 0xFF;
    r[r_offset_bytes_private_key + 15] = (k_local_u32[4] >> 0) & 0xFF;

    r[r_offset_bytes_private_key + 16] = (k_local_u32[3] >> 24) & 0xFF;
    r[r_offset_bytes_private_key + 17] = (k_local_u32[3] >> 16) & 0xFF;
    r[r_offset_bytes_private_key + 18] = (k_local_u32[3] >> 8) & 0xFF;
    r[r_offset_bytes_private_key + 19] = (k_local_u32[3] >> 0) & 0xFF;

    r[r_offset_bytes_private_key + 20] = (k_local_u32[2] >> 24) & 0xFF;
    r[r_offset_bytes_private_key + 21] = (k_local_u32[2] >> 16) & 0xFF;
    r[r_offset_bytes_private_key + 22] = (k_local_u32[2] >> 8) & 0xFF;
    r[r_offset_bytes_private_key + 23] = (k_local_u32[2] >> 0) & 0xFF;

    r[r_offset_bytes_private_key + 24] = (k_local_u32[1] >> 24) & 0xFF;
    r[r_offset_bytes_private_key + 25] = (k_local_u32[1] >> 16) & 0xFF;
    r[r_offset_bytes_private_key + 26] = (k_local_u32[1] >> 8) & 0xFF;
    r[r_offset_bytes_private_key + 27] = (k_local_u32[1] >> 0) & 0xFF;

    r[r_offset_bytes_private_key + 28] = (k_local_u32[0] >> 24) & 0xFF;
    r[r_offset_bytes_private_key + 29] = (k_local_u32[0] >> 16) & 0xFF;
    r[r_offset_bytes_private_key + 30] = (k_local_u32[0] >> 8) & 0xFF;
    r[r_offset_bytes_private_key + 31] = (k_local_u32[0] >> 0) & 0xFF;


    // creating the public key from coordinates and parity byte for hashing
    create_public_key_from_coordinates(public_key_bytes, x_local_u32, y_local_u32);

    int r_offset_public_key = r_offset_bytes_private_key + PRIVATE_KEY_BYTES;

    // write public key parity byte into result buffer
    r[r_offset_public_key + 0] = 0x04;

    // write bytes of u32 array storing x coordinate into result buffer
    r[r_offset_public_key + 1] = (x_local_u32[7] >> 24) & 0xFF;
    r[r_offset_public_key + 2] = (x_local_u32[7] >> 16) & 0xFF;
    r[r_offset_public_key + 3] = (x_local_u32[7] >> 8) & 0xFF;
    r[r_offset_public_key + 4] = (x_local_u32[7] >> 0) & 0xFF;

    r[r_offset_public_key + 5] = (x_local_u32[6] >> 24) & 0xFF;
    r[r_offset_public_key + 6] = (x_local_u32[6] >> 16) & 0xFF;
    r[r_offset_public_key + 7] = (x_local_u32[6] >> 8) & 0xFF;
    r[r_offset_public_key + 8] = (x_local_u32[6] >> 0) & 0xFF;

    r[r_offset_public_key + 9] = (x_local_u32[5] >> 24) & 0xFF;
    r[r_offset_public_key + 10] = (x_local_u32[5] >> 16) & 0xFF;
    r[r_offset_public_key + 11] = (x_local_u32[5] >> 8) & 0xFF;
    r[r_offset_public_key + 12] = (x_local_u32[5] >> 0) & 0xFF;

    r[r_offset_public_key + 13] = (x_local_u32[4] >> 24) & 0xFF;
    r[r_offset_public_key + 14] = (x_local_u32[4] >> 16) & 0xFF;
    r[r_offset_public_key + 15] = (x_local_u32[4] >> 8) & 0xFF;
    r[r_offset_public_key + 16] = (x_local_u32[4] >> 0) & 0xFF;

    r[r_offset_public_key + 17] = (x_local_u32[3] >> 24) & 0xFF;
    r[r_offset_public_key + 18] = (x_local_u32[3] >> 16) & 0xFF;
    r[r_offset_public_key + 19] = (x_local_u32[3] >> 8) & 0xFF;
    r[r_offset_public_key + 20] = (x_local_u32[3] >> 0) & 0xFF;

    r[r_offset_public_key + 21] = (x_local_u32[2] >> 24) & 0xFF;
    r[r_offset_public_key + 22] = (x_local_u32[2] >> 16) & 0xFF;
    r[r_offset_public_key + 23] = (x_local_u32[2] >> 8) & 0xFF;
    r[r_offset_public_key + 24] = (x_local_u32[2] >> 0) & 0xFF;

    r[r_offset_public_key + 25] = (x_local_u32[1] >> 24) & 0xFF;
    r[r_offset_public_key + 26] = (x_local_u32[1] >> 16) & 0xFF;
    r[r_offset_public_key + 27] = (x_local_u32[1] >> 8) & 0xFF;
    r[r_offset_public_key + 28] = (x_local_u32[1] >> 0) & 0xFF;

    r[r_offset_public_key + 29] = (x_local_u32[0] >> 24) & 0xFF;
    r[r_offset_public_key + 30] = (x_local_u32[0] >> 16) & 0xFF;
    r[r_offset_public_key + 31] = (x_local_u32[0] >> 8) & 0xFF;
    r[r_offset_public_key + 32] = (x_local_u32[0] >> 0) & 0xFF;

    // write bytes of u32 array storing y coordinate into result buffer
    r[r_offset_public_key + 33] = (y_local_u32[7] >> 24) & 0xFF;
    r[r_offset_public_key + 34] = (y_local_u32[7] >> 16) & 0xFF;
    r[r_offset_public_key + 35] = (y_local_u32[7] >> 8) & 0xFF;
    r[r_offset_public_key + 36] = (y_local_u32[7] >> 0) & 0xFF;

    r[r_offset_public_key + 37] = (y_local_u32[6] >> 24) & 0xFF;
    r[r_offset_public_key + 38] = (y_local_u32[6] >> 16) & 0xFF;
    r[r_offset_public_key + 39] = (y_local_u32[6] >> 8) & 0xFF;
    r[r_offset_public_key + 40] = (y_local_u32[6] >> 0) & 0xFF;

    r[r_offset_public_key + 41] = (y_local_u32[5] >> 24) & 0xFF;
    r[r_offset_public_key + 42] = (y_local_u32[5] >> 16) & 0xFF;
    r[r_offset_public_key + 43] = (y_local_u32[5] >> 8) & 0xFF;
    r[r_offset_public_key + 44] = (y_local_u32[5] >> 0) & 0xFF;

    r[r_offset_public_key + 45] = (y_local_u32[4] >> 24) & 0xFF;
    r[r_offset_public_key + 46] = (y_local_u32[4] >> 16) & 0xFF;
    r[r_offset_public_key + 47] = (y_local_u32[4] >> 8) & 0xFF;
    r[r_offset_public_key + 48] = (y_local_u32[4] >> 0) & 0xFF;

    r[r_offset_public_key + 49] = (y_local_u32[3] >> 24) & 0xFF;
    r[r_offset_public_key + 50] = (y_local_u32[3] >> 16) & 0xFF;
    r[r_offset_public_key + 51] = (y_local_u32[3] >> 8) & 0xFF;
    r[r_offset_public_key + 52] = (y_local_u32[3] >> 0) & 0xFF;

    r[r_offset_public_key + 53] = (y_local_u32[2] >> 24) & 0xFF;
    r[r_offset_public_key + 54] = (y_local_u32[2] >> 16) & 0xFF;
    r[r_offset_public_key + 55] = (y_local_u32[2] >> 8) & 0xFF;
    r[r_offset_public_key + 56] = (y_local_u32[2] >> 0) & 0xFF;

    r[r_offset_public_key + 57] = (y_local_u32[1] >> 24) & 0xFF;
    r[r_offset_public_key + 58] = (y_local_u32[1] >> 16) & 0xFF;
    r[r_offset_public_key + 59] = (y_local_u32[1] >> 8) & 0xFF;
    r[r_offset_public_key + 60] = (y_local_u32[1] >> 0) & 0xFF;

    r[r_offset_public_key + 61] = (y_local_u32[0] >> 24) & 0xFF;
    r[r_offset_public_key + 62] = (y_local_u32[0] >> 16) & 0xFF;
    r[r_offset_public_key + 63] = (y_local_u32[0] >> 8) & 0xFF;
    r[r_offset_public_key + 64] = (y_local_u32[0] >> 0) & 0xFF;


    // hash the public key with SHA-256
    calculate_sha256_from_public_key(public_key_bytes, sha256_hash);

    int r_offset_first_sha256 = r_offset_public_key + PUBLIC_KEY_BYTES_WITH_PARITY;

    // write bytes of u32 array storing sha256_hash into result buffer
    r[r_offset_first_sha256 + 0] = (sha256_hash[0] >> 24) & 0xFF;
    r[r_offset_first_sha256 + 1] = (sha256_hash[0] >> 16) & 0xFF;
    r[r_offset_first_sha256 + 2] = (sha256_hash[0] >> 8) & 0xFF;
    r[r_offset_first_sha256 + 3] = (sha256_hash[0] >> 0) & 0xFF;

    r[r_offset_first_sha256 + 4] = (sha256_hash[1] >> 24) & 0xFF;
    r[r_offset_first_sha256 + 5] = (sha256_hash[1] >> 16) & 0xFF;
    r[r_offset_first_sha256 + 6] = (sha256_hash[1] >> 8) & 0xFF;
    r[r_offset_first_sha256 + 7] = (sha256_hash[1] >> 0) & 0xFF;

    r[r_offset_first_sha256 + 8] = (sha256_hash[2] >> 24) & 0xFF;
    r[r_offset_first_sha256 + 9] = (sha256_hash[2] >> 16) & 0xFF;
    r[r_offset_first_sha256 + 10] = (sha256_hash[2] >> 8) & 0xFF;
    r[r_offset_first_sha256 + 11] = (sha256_hash[2] >> 0) & 0xFF;

    r[r_offset_first_sha256 + 12] = (sha256_hash[3] >> 24) & 0xFF;
    r[r_offset_first_sha256 + 13] = (sha256_hash[3] >> 16) & 0xFF;
    r[r_offset_first_sha256 + 14] = (sha256_hash[3] >> 8) & 0xFF;
    r[r_offset_first_sha256 + 15] = (sha256_hash[3] >> 0) & 0xFF;

    r[r_offset_first_sha256 + 16] = (sha256_hash[4] >> 24) & 0xFF;
    r[r_offset_first_sha256 + 17] = (sha256_hash[4] >> 16) & 0xFF;
    r[r_offset_first_sha256 + 18] = (sha256_hash[4] >> 8) & 0xFF;
    r[r_offset_first_sha256 + 19] = (sha256_hash[4] >> 0) & 0xFF;

    r[r_offset_first_sha256 + 20] = (sha256_hash[5] >> 24) & 0xFF;
    r[r_offset_first_sha256 + 21] = (sha256_hash[5] >> 16) & 0xFF;
    r[r_offset_first_sha256 + 22] = (sha256_hash[5] >> 8) & 0xFF;
    r[r_offset_first_sha256 + 23] = (sha256_hash[5] >> 0) & 0xFF;

    r[r_offset_first_sha256 + 24] = (sha256_hash[6] >> 24) & 0xFF;
    r[r_offset_first_sha256 + 25] = (sha256_hash[6] >> 16) & 0xFF;
    r[r_offset_first_sha256 + 26] = (sha256_hash[6] >> 8) & 0xFF;
    r[r_offset_first_sha256 + 27] = (sha256_hash[6] >> 0) & 0xFF;

    r[r_offset_first_sha256 + 28] = (sha256_hash[7] >> 24) & 0xFF;
    r[r_offset_first_sha256 + 29] = (sha256_hash[7] >> 16) & 0xFF;
    r[r_offset_first_sha256 + 30] = (sha256_hash[7] >> 8) & 0xFF;
    r[r_offset_first_sha256 + 31] = (sha256_hash[7] >> 0) & 0xFF;


    // hash the SHA-256 result with RIPEMD-160
    calculate_ripemd160_from_u32(sha256_hash, ripemd160_hash);

    int r_offset_ripemd160 = r_offset_first_sha256 + SHA256_HASH_BYTES_LEN;

    // write bytes of u32 array storing ripemd160_hash into result buffer
    r[r_offset_ripemd160 + 0] = (ripemd160_hash[0] >> 0) & 0xFF;
    r[r_offset_ripemd160 + 1] = (ripemd160_hash[0] >> 8) & 0xFF;
    r[r_offset_ripemd160 + 2] = (ripemd160_hash[0] >> 16) & 0xFF;
    r[r_offset_ripemd160 + 3] = (ripemd160_hash[0] >> 24) & 0xFF;

    r[r_offset_ripemd160 + 4] = (ripemd160_hash[1] >> 0) & 0xFF;
    r[r_offset_ripemd160 + 5] = (ripemd160_hash[1] >> 8) & 0xFF;
    r[r_offset_ripemd160 + 6] = (ripemd160_hash[1] >> 16) & 0xFF;
    r[r_offset_ripemd160 + 7] = (ripemd160_hash[1] >> 24) & 0xFF;

    r[r_offset_ripemd160 + 8] = (ripemd160_hash[2] >> 0) & 0xFF;
    r[r_offset_ripemd160 + 9] = (ripemd160_hash[2] >> 8) & 0xFF;
    r[r_offset_ripemd160 + 10] = (ripemd160_hash[2] >> 16) & 0xFF;
    r[r_offset_ripemd160 + 11] = (ripemd160_hash[2] >> 24) & 0xFF;

    r[r_offset_ripemd160 + 12] = (ripemd160_hash[3] >> 0) & 0xFF;
    r[r_offset_ripemd160 + 13] = (ripemd160_hash[3] >> 8) & 0xFF;
    r[r_offset_ripemd160 + 14] = (ripemd160_hash[3] >> 16) & 0xFF;
    r[r_offset_ripemd160 + 15] = (ripemd160_hash[3] >> 24) & 0xFF;

    r[r_offset_ripemd160 + 16] = (ripemd160_hash[4] >> 0) & 0xFF;
    r[r_offset_ripemd160 + 17] = (ripemd160_hash[4] >> 8) & 0xFF;
    r[r_offset_ripemd160 + 18] = (ripemd160_hash[4] >> 16) & 0xFF;
    r[r_offset_ripemd160 + 19] = (ripemd160_hash[4] >> 24) & 0xFF;


    // version = 0x00 + RIPEMD-160 hash
    version[0] = RIPEMD160_HASH_VERSION_BYTE;

    version[1] = (ripemd160_hash[0] >> 0) & 0xFF;
    version[2] = (ripemd160_hash[0] >> 8) & 0xFF;
    version[3] = (ripemd160_hash[0] >> 16) & 0xFF;
    version[4] = (ripemd160_hash[0] >> 24) & 0xFF;

    version[5] = (ripemd160_hash[1] >> 0) & 0xFF;
    version[6] = (ripemd160_hash[1] >> 8) & 0xFF;
    version[7] = (ripemd160_hash[1] >> 16) & 0xFF;
    version[8] = (ripemd160_hash[1] >> 24) & 0xFF;

    version[9] = (ripemd160_hash[2] >> 0) & 0xFF;
    version[10] = (ripemd160_hash[2] >> 8) & 0xFF;
    version[11] = (ripemd160_hash[2] >> 16) & 0xFF;
    version[12] = (ripemd160_hash[2] >> 24) & 0xFF;

    version[13] = (ripemd160_hash[3] >> 0) & 0xFF;
    version[14] = (ripemd160_hash[3] >> 8) & 0xFF;
    version[15] = (ripemd160_hash[3] >> 16) & 0xFF;
    version[16] = (ripemd160_hash[3] >> 24) & 0xFF;

    version[17] = (ripemd160_hash[4] >> 0) & 0xFF;
    version[18] = (ripemd160_hash[4] >> 8) & 0xFF;
    version[19] = (ripemd160_hash[4] >> 16) & 0xFF;
    version[20] = (ripemd160_hash[4] >> 24) & 0xFF;

    // hash the RIPEMD-160 hash incl version byte with SHA-256
    calculate_sha256_from_version(version, second_sha256_hash);

    int r_offset_second_sha256 = r_offset_ripemd160 + RIPEMD160_HASH_BYTES;

    // write bytes of u32 array storing second SHA-256 hash into result buffer
    r[r_offset_second_sha256 + 0] = (second_sha256_hash[0] >> 24) & 0xFF;
    r[r_offset_second_sha256 + 1] = (second_sha256_hash[0] >> 16) & 0xFF;
    r[r_offset_second_sha256 + 2] = (second_sha256_hash[0] >> 8) & 0xFF;
    r[r_offset_second_sha256 + 3] = (second_sha256_hash[0] >> 0) & 0xFF;

    r[r_offset_second_sha256 + 4] = (second_sha256_hash[1] >> 24) & 0xFF;
    r[r_offset_second_sha256 + 5] = (second_sha256_hash[1] >> 16) & 0xFF;
    r[r_offset_second_sha256 + 6] = (second_sha256_hash[1] >> 8) & 0xFF;
    r[r_offset_second_sha256 + 7] = (second_sha256_hash[1] >> 0) & 0xFF;

    r[r_offset_second_sha256 + 8] = (second_sha256_hash[2] >> 24) & 0xFF;
    r[r_offset_second_sha256 + 9] = (second_sha256_hash[2] >> 16) & 0xFF;
    r[r_offset_second_sha256 + 10] = (second_sha256_hash[2] >> 8) & 0xFF;
    r[r_offset_second_sha256 + 11] = (second_sha256_hash[2] >> 0) & 0xFF;

    r[r_offset_second_sha256 + 12] = (second_sha256_hash[3] >> 24) & 0xFF;
    r[r_offset_second_sha256 + 13] = (second_sha256_hash[3] >> 16) & 0xFF;
    r[r_offset_second_sha256 + 14] = (second_sha256_hash[3] >> 8) & 0xFF;
    r[r_offset_second_sha256 + 15] = (second_sha256_hash[3] >> 0) & 0xFF;

    r[r_offset_second_sha256 + 16] = (second_sha256_hash[4] >> 24) & 0xFF;
    r[r_offset_second_sha256 + 17] = (second_sha256_hash[4] >> 16) & 0xFF;
    r[r_offset_second_sha256 + 18] = (second_sha256_hash[4] >> 8) & 0xFF;
    r[r_offset_second_sha256 + 19] = (second_sha256_hash[4] >> 0) & 0xFF;

    r[r_offset_second_sha256 + 20] = (second_sha256_hash[5] >> 24) & 0xFF;
    r[r_offset_second_sha256 + 21] = (second_sha256_hash[5] >> 16) & 0xFF;
    r[r_offset_second_sha256 + 22] = (second_sha256_hash[5] >> 8) & 0xFF;
    r[r_offset_second_sha256 + 23] = (second_sha256_hash[5] >> 0) & 0xFF;

    r[r_offset_second_sha256 + 24] = (second_sha256_hash[6] >> 24) & 0xFF;
    r[r_offset_second_sha256 + 25] = (second_sha256_hash[6] >> 16) & 0xFF;
    r[r_offset_second_sha256 + 26] = (second_sha256_hash[6] >> 8) & 0xFF;
    r[r_offset_second_sha256 + 27] = (second_sha256_hash[6] >> 0) & 0xFF;

    r[r_offset_second_sha256 + 28] = (second_sha256_hash[7] >> 24) & 0xFF;
    r[r_offset_second_sha256 + 29] = (second_sha256_hash[7] >> 16) & 0xFF;
    r[r_offset_second_sha256 + 30] = (second_sha256_hash[7] >> 8) & 0xFF;
    r[r_offset_second_sha256 + 31] = (second_sha256_hash[7] >> 0) & 0xFF;
}

/*
 * "Creates" private keys from a single private key and then calculates the public key,
 * then hashes it with SHA-256, RIPEMD-160, adds version byte and then hashes it again
 * with SHA-256 two times.
 *
 * OUTPUT uchar *r: Pointer to the result buffer to store all results
 * INPUT u32 *k:    Pointer to the private key buffer storing a single private key
 */
__kernel void generate_chunk_until_third_sha256(__global uchar *r, __global const u32 *k){

    u32 k_local_u32[PRIVATE_KEY_LENGTH];
    u32 x_local_u32[PUBLIC_KEY_ONE_COORDINATE_LENGTH];
    u32 y_local_u32[PUBLIC_KEY_ONE_COORDINATE_LENGTH];
    uchar public_key_bytes[PUBLIC_KEY_BYTES_WITH_PARITY];
    secp256k1_t g_xy_local;

    // to store the results of the SHA-256 and RIPEMD-160 hashes
    u32 sha256_hash[SHA256_HASH_U32_LEN];
    u32 ripemd160_hash[RIPEMD160_HASH_U32_LEN];
    uchar version[RIPEMD160_HASH_WITH_VERSION_BYTES];
    u32 second_sha256_hash[SHA256_HASH_U32_LEN];
    u32 third_sha256_hash[SHA256_HASH_U32_LEN];

    // id of current work item
    int work_item_id = get_global_id(0);

    // get first private key from private key grid and "create" a new one
    k_local_u32[0] = k[0] | work_item_id;
    k_local_u32[1] = k[1];
    k_local_u32[2] = k[2];
    k_local_u32[3] = k[3];
    k_local_u32[4] = k[4];
    k_local_u32[5] = k[5];
    k_local_u32[6] = k[6];
    k_local_u32[7] = k[7];

    // calculating the public key coordinates
    set_precomputed_basepoint_g(&g_xy_local);
    point_mul_xy(x_local_u32, y_local_u32, k_local_u32, &g_xy_local);


    // calculating offset to write results in byte buffer
    int r_offset_bytes_private_key = (PRIVATE_KEY_BYTES + PUBLIC_KEY_BYTES_WITH_PARITY + SHA256_HASH_BYTES_LEN + RIPEMD160_HASH_BYTES + SHA256_HASH_BYTES_LEN + SHA256_HASH_BYTES_LEN) * work_item_id;

    // write bytes of u32 array storing private key into result buffer
    r[r_offset_bytes_private_key + 0] = (k_local_u32[7] >> 24) & 0xFF;
    r[r_offset_bytes_private_key + 1] = (k_local_u32[7] >> 16) & 0xFF;
    r[r_offset_bytes_private_key + 2] = (k_local_u32[7] >> 8) & 0xFF;
    r[r_offset_bytes_private_key + 3] = (k_local_u32[7] >> 0) & 0xFF;

    r[r_offset_bytes_private_key + 4] = (k_local_u32[6] >> 24) & 0xFF;
    r[r_offset_bytes_private_key + 5] = (k_local_u32[6] >> 16) & 0xFF;
    r[r_offset_bytes_private_key + 6] = (k_local_u32[6] >> 8) & 0xFF;
    r[r_offset_bytes_private_key + 7] = (k_local_u32[6] >> 0) & 0xFF;

    r[r_offset_bytes_private_key + 8] = (k_local_u32[5] >> 24) & 0xFF;
    r[r_offset_bytes_private_key + 9] = (k_local_u32[5] >> 16) & 0xFF;
    r[r_offset_bytes_private_key + 10] = (k_local_u32[5] >> 8) & 0xFF;
    r[r_offset_bytes_private_key + 11] = (k_local_u32[5] >> 0) & 0xFF;

    r[r_offset_bytes_private_key + 12] = (k_local_u32[4] >> 24) & 0xFF;
    r[r_offset_bytes_private_key + 13] = (k_local_u32[4] >> 16) & 0xFF;
    r[r_offset_bytes_private_key + 14] = (k_local_u32[4] >> 8) & 0xFF;
    r[r_offset_bytes_private_key + 15] = (k_local_u32[4] >> 0) & 0xFF;

    r[r_offset_bytes_private_key + 16] = (k_local_u32[3] >> 24) & 0xFF;
    r[r_offset_bytes_private_key + 17] = (k_local_u32[3] >> 16) & 0xFF;
    r[r_offset_bytes_private_key + 18] = (k_local_u32[3] >> 8) & 0xFF;
    r[r_offset_bytes_private_key + 19] = (k_local_u32[3] >> 0) & 0xFF;

    r[r_offset_bytes_private_key + 20] = (k_local_u32[2] >> 24) & 0xFF;
    r[r_offset_bytes_private_key + 21] = (k_local_u32[2] >> 16) & 0xFF;
    r[r_offset_bytes_private_key + 22] = (k_local_u32[2] >> 8) & 0xFF;
    r[r_offset_bytes_private_key + 23] = (k_local_u32[2] >> 0) & 0xFF;

    r[r_offset_bytes_private_key + 24] = (k_local_u32[1] >> 24) & 0xFF;
    r[r_offset_bytes_private_key + 25] = (k_local_u32[1] >> 16) & 0xFF;
    r[r_offset_bytes_private_key + 26] = (k_local_u32[1] >> 8) & 0xFF;
    r[r_offset_bytes_private_key + 27] = (k_local_u32[1] >> 0) & 0xFF;

    r[r_offset_bytes_private_key + 28] = (k_local_u32[0] >> 24) & 0xFF;
    r[r_offset_bytes_private_key + 29] = (k_local_u32[0] >> 16) & 0xFF;
    r[r_offset_bytes_private_key + 30] = (k_local_u32[0] >> 8) & 0xFF;
    r[r_offset_bytes_private_key + 31] = (k_local_u32[0] >> 0) & 0xFF;


    // creating the public key from coordinates and parity byte for hashing
    create_public_key_from_coordinates(public_key_bytes, x_local_u32, y_local_u32);

    int r_offset_public_key = r_offset_bytes_private_key + PRIVATE_KEY_BYTES;

    // write public key parity byte into result buffer
    r[r_offset_public_key + 0] = 0x04;

    // write bytes of u32 array storing x coordinate into result buffer
    r[r_offset_public_key + 1] = (x_local_u32[7] >> 24) & 0xFF;
    r[r_offset_public_key + 2] = (x_local_u32[7] >> 16) & 0xFF;
    r[r_offset_public_key + 3] = (x_local_u32[7] >> 8) & 0xFF;
    r[r_offset_public_key + 4] = (x_local_u32[7] >> 0) & 0xFF;

    r[r_offset_public_key + 5] = (x_local_u32[6] >> 24) & 0xFF;
    r[r_offset_public_key + 6] = (x_local_u32[6] >> 16) & 0xFF;
    r[r_offset_public_key + 7] = (x_local_u32[6] >> 8) & 0xFF;
    r[r_offset_public_key + 8] = (x_local_u32[6] >> 0) & 0xFF;

    r[r_offset_public_key + 9] = (x_local_u32[5] >> 24) & 0xFF;
    r[r_offset_public_key + 10] = (x_local_u32[5] >> 16) & 0xFF;
    r[r_offset_public_key + 11] = (x_local_u32[5] >> 8) & 0xFF;
    r[r_offset_public_key + 12] = (x_local_u32[5] >> 0) & 0xFF;

    r[r_offset_public_key + 13] = (x_local_u32[4] >> 24) & 0xFF;
    r[r_offset_public_key + 14] = (x_local_u32[4] >> 16) & 0xFF;
    r[r_offset_public_key + 15] = (x_local_u32[4] >> 8) & 0xFF;
    r[r_offset_public_key + 16] = (x_local_u32[4] >> 0) & 0xFF;

    r[r_offset_public_key + 17] = (x_local_u32[3] >> 24) & 0xFF;
    r[r_offset_public_key + 18] = (x_local_u32[3] >> 16) & 0xFF;
    r[r_offset_public_key + 19] = (x_local_u32[3] >> 8) & 0xFF;
    r[r_offset_public_key + 20] = (x_local_u32[3] >> 0) & 0xFF;

    r[r_offset_public_key + 21] = (x_local_u32[2] >> 24) & 0xFF;
    r[r_offset_public_key + 22] = (x_local_u32[2] >> 16) & 0xFF;
    r[r_offset_public_key + 23] = (x_local_u32[2] >> 8) & 0xFF;
    r[r_offset_public_key + 24] = (x_local_u32[2] >> 0) & 0xFF;

    r[r_offset_public_key + 25] = (x_local_u32[1] >> 24) & 0xFF;
    r[r_offset_public_key + 26] = (x_local_u32[1] >> 16) & 0xFF;
    r[r_offset_public_key + 27] = (x_local_u32[1] >> 8) & 0xFF;
    r[r_offset_public_key + 28] = (x_local_u32[1] >> 0) & 0xFF;

    r[r_offset_public_key + 29] = (x_local_u32[0] >> 24) & 0xFF;
    r[r_offset_public_key + 30] = (x_local_u32[0] >> 16) & 0xFF;
    r[r_offset_public_key + 31] = (x_local_u32[0] >> 8) & 0xFF;
    r[r_offset_public_key + 32] = (x_local_u32[0] >> 0) & 0xFF;

    // write bytes of u32 array storing y coordinate into result buffer
    r[r_offset_public_key + 33] = (y_local_u32[7] >> 24) & 0xFF;
    r[r_offset_public_key + 34] = (y_local_u32[7] >> 16) & 0xFF;
    r[r_offset_public_key + 35] = (y_local_u32[7] >> 8) & 0xFF;
    r[r_offset_public_key + 36] = (y_local_u32[7] >> 0) & 0xFF;

    r[r_offset_public_key + 37] = (y_local_u32[6] >> 24) & 0xFF;
    r[r_offset_public_key + 38] = (y_local_u32[6] >> 16) & 0xFF;
    r[r_offset_public_key + 39] = (y_local_u32[6] >> 8) & 0xFF;
    r[r_offset_public_key + 40] = (y_local_u32[6] >> 0) & 0xFF;

    r[r_offset_public_key + 41] = (y_local_u32[5] >> 24) & 0xFF;
    r[r_offset_public_key + 42] = (y_local_u32[5] >> 16) & 0xFF;
    r[r_offset_public_key + 43] = (y_local_u32[5] >> 8) & 0xFF;
    r[r_offset_public_key + 44] = (y_local_u32[5] >> 0) & 0xFF;

    r[r_offset_public_key + 45] = (y_local_u32[4] >> 24) & 0xFF;
    r[r_offset_public_key + 46] = (y_local_u32[4] >> 16) & 0xFF;
    r[r_offset_public_key + 47] = (y_local_u32[4] >> 8) & 0xFF;
    r[r_offset_public_key + 48] = (y_local_u32[4] >> 0) & 0xFF;

    r[r_offset_public_key + 49] = (y_local_u32[3] >> 24) & 0xFF;
    r[r_offset_public_key + 50] = (y_local_u32[3] >> 16) & 0xFF;
    r[r_offset_public_key + 51] = (y_local_u32[3] >> 8) & 0xFF;
    r[r_offset_public_key + 52] = (y_local_u32[3] >> 0) & 0xFF;

    r[r_offset_public_key + 53] = (y_local_u32[2] >> 24) & 0xFF;
    r[r_offset_public_key + 54] = (y_local_u32[2] >> 16) & 0xFF;
    r[r_offset_public_key + 55] = (y_local_u32[2] >> 8) & 0xFF;
    r[r_offset_public_key + 56] = (y_local_u32[2] >> 0) & 0xFF;

    r[r_offset_public_key + 57] = (y_local_u32[1] >> 24) & 0xFF;
    r[r_offset_public_key + 58] = (y_local_u32[1] >> 16) & 0xFF;
    r[r_offset_public_key + 59] = (y_local_u32[1] >> 8) & 0xFF;
    r[r_offset_public_key + 60] = (y_local_u32[1] >> 0) & 0xFF;

    r[r_offset_public_key + 61] = (y_local_u32[0] >> 24) & 0xFF;
    r[r_offset_public_key + 62] = (y_local_u32[0] >> 16) & 0xFF;
    r[r_offset_public_key + 63] = (y_local_u32[0] >> 8) & 0xFF;
    r[r_offset_public_key + 64] = (y_local_u32[0] >> 0) & 0xFF;


    // hash the public key with SHA-256
    calculate_sha256_from_public_key(public_key_bytes, sha256_hash);

    int r_offset_first_sha256 = r_offset_public_key + PUBLIC_KEY_BYTES_WITH_PARITY;

    // write bytes of u32 array storing sha256_hash into result buffer
    r[r_offset_first_sha256 + 0] = (sha256_hash[0] >> 24) & 0xFF;
    r[r_offset_first_sha256 + 1] = (sha256_hash[0] >> 16) & 0xFF;
    r[r_offset_first_sha256 + 2] = (sha256_hash[0] >> 8) & 0xFF;
    r[r_offset_first_sha256 + 3] = (sha256_hash[0] >> 0) & 0xFF;

    r[r_offset_first_sha256 + 4] = (sha256_hash[1] >> 24) & 0xFF;
    r[r_offset_first_sha256 + 5] = (sha256_hash[1] >> 16) & 0xFF;
    r[r_offset_first_sha256 + 6] = (sha256_hash[1] >> 8) & 0xFF;
    r[r_offset_first_sha256 + 7] = (sha256_hash[1] >> 0) & 0xFF;

    r[r_offset_first_sha256 + 8] = (sha256_hash[2] >> 24) & 0xFF;
    r[r_offset_first_sha256 + 9] = (sha256_hash[2] >> 16) & 0xFF;
    r[r_offset_first_sha256 + 10] = (sha256_hash[2] >> 8) & 0xFF;
    r[r_offset_first_sha256 + 11] = (sha256_hash[2] >> 0) & 0xFF;

    r[r_offset_first_sha256 + 12] = (sha256_hash[3] >> 24) & 0xFF;
    r[r_offset_first_sha256 + 13] = (sha256_hash[3] >> 16) & 0xFF;
    r[r_offset_first_sha256 + 14] = (sha256_hash[3] >> 8) & 0xFF;
    r[r_offset_first_sha256 + 15] = (sha256_hash[3] >> 0) & 0xFF;

    r[r_offset_first_sha256 + 16] = (sha256_hash[4] >> 24) & 0xFF;
    r[r_offset_first_sha256 + 17] = (sha256_hash[4] >> 16) & 0xFF;
    r[r_offset_first_sha256 + 18] = (sha256_hash[4] >> 8) & 0xFF;
    r[r_offset_first_sha256 + 19] = (sha256_hash[4] >> 0) & 0xFF;

    r[r_offset_first_sha256 + 20] = (sha256_hash[5] >> 24) & 0xFF;
    r[r_offset_first_sha256 + 21] = (sha256_hash[5] >> 16) & 0xFF;
    r[r_offset_first_sha256 + 22] = (sha256_hash[5] >> 8) & 0xFF;
    r[r_offset_first_sha256 + 23] = (sha256_hash[5] >> 0) & 0xFF;

    r[r_offset_first_sha256 + 24] = (sha256_hash[6] >> 24) & 0xFF;
    r[r_offset_first_sha256 + 25] = (sha256_hash[6] >> 16) & 0xFF;
    r[r_offset_first_sha256 + 26] = (sha256_hash[6] >> 8) & 0xFF;
    r[r_offset_first_sha256 + 27] = (sha256_hash[6] >> 0) & 0xFF;

    r[r_offset_first_sha256 + 28] = (sha256_hash[7] >> 24) & 0xFF;
    r[r_offset_first_sha256 + 29] = (sha256_hash[7] >> 16) & 0xFF;
    r[r_offset_first_sha256 + 30] = (sha256_hash[7] >> 8) & 0xFF;
    r[r_offset_first_sha256 + 31] = (sha256_hash[7] >> 0) & 0xFF;


    // hash the SHA-256 result with RIPEMD-160
    calculate_ripemd160_from_u32(sha256_hash, ripemd160_hash);

    int r_offset_ripemd160 = r_offset_first_sha256 + SHA256_HASH_BYTES_LEN;

    // write bytes of u32 array storing ripemd160_hash into result buffer
    r[r_offset_ripemd160 + 0] = (ripemd160_hash[0] >> 0) & 0xFF;
    r[r_offset_ripemd160 + 1] = (ripemd160_hash[0] >> 8) & 0xFF;
    r[r_offset_ripemd160 + 2] = (ripemd160_hash[0] >> 16) & 0xFF;
    r[r_offset_ripemd160 + 3] = (ripemd160_hash[0] >> 24) & 0xFF;

    r[r_offset_ripemd160 + 4] = (ripemd160_hash[1] >> 0) & 0xFF;
    r[r_offset_ripemd160 + 5] = (ripemd160_hash[1] >> 8) & 0xFF;
    r[r_offset_ripemd160 + 6] = (ripemd160_hash[1] >> 16) & 0xFF;
    r[r_offset_ripemd160 + 7] = (ripemd160_hash[1] >> 24) & 0xFF;

    r[r_offset_ripemd160 + 8] = (ripemd160_hash[2] >> 0) & 0xFF;
    r[r_offset_ripemd160 + 9] = (ripemd160_hash[2] >> 8) & 0xFF;
    r[r_offset_ripemd160 + 10] = (ripemd160_hash[2] >> 16) & 0xFF;
    r[r_offset_ripemd160 + 11] = (ripemd160_hash[2] >> 24) & 0xFF;

    r[r_offset_ripemd160 + 12] = (ripemd160_hash[3] >> 0) & 0xFF;
    r[r_offset_ripemd160 + 13] = (ripemd160_hash[3] >> 8) & 0xFF;
    r[r_offset_ripemd160 + 14] = (ripemd160_hash[3] >> 16) & 0xFF;
    r[r_offset_ripemd160 + 15] = (ripemd160_hash[3] >> 24) & 0xFF;

    r[r_offset_ripemd160 + 16] = (ripemd160_hash[4] >> 0) & 0xFF;
    r[r_offset_ripemd160 + 17] = (ripemd160_hash[4] >> 8) & 0xFF;
    r[r_offset_ripemd160 + 18] = (ripemd160_hash[4] >> 16) & 0xFF;
    r[r_offset_ripemd160 + 19] = (ripemd160_hash[4] >> 24) & 0xFF;


    // version = 0x00 + RIPEMD-160 hash
    version[0] = RIPEMD160_HASH_VERSION_BYTE;

    version[1] = (ripemd160_hash[0] >> 0) & 0xFF;
    version[2] = (ripemd160_hash[0] >> 8) & 0xFF;
    version[3] = (ripemd160_hash[0] >> 16) & 0xFF;
    version[4] = (ripemd160_hash[0] >> 24) & 0xFF;

    version[5] = (ripemd160_hash[1] >> 0) & 0xFF;
    version[6] = (ripemd160_hash[1] >> 8) & 0xFF;
    version[7] = (ripemd160_hash[1] >> 16) & 0xFF;
    version[8] = (ripemd160_hash[1] >> 24) & 0xFF;

    version[9] = (ripemd160_hash[2] >> 0) & 0xFF;
    version[10] = (ripemd160_hash[2] >> 8) & 0xFF;
    version[11] = (ripemd160_hash[2] >> 16) & 0xFF;
    version[12] = (ripemd160_hash[2] >> 24) & 0xFF;

    version[13] = (ripemd160_hash[3] >> 0) & 0xFF;
    version[14] = (ripemd160_hash[3] >> 8) & 0xFF;
    version[15] = (ripemd160_hash[3] >> 16) & 0xFF;
    version[16] = (ripemd160_hash[3] >> 24) & 0xFF;

    version[17] = (ripemd160_hash[4] >> 0) & 0xFF;
    version[18] = (ripemd160_hash[4] >> 8) & 0xFF;
    version[19] = (ripemd160_hash[4] >> 16) & 0xFF;
    version[20] = (ripemd160_hash[4] >> 24) & 0xFF;

    // hash the RIPEMD-160 hash incl version byte with SHA-256
    calculate_sha256_from_version(version, second_sha256_hash);

    int r_offset_second_sha256 = r_offset_ripemd160 + RIPEMD160_HASH_BYTES;

    // write bytes of u32 array storing second SHA-256 hash into result buffer
    r[r_offset_second_sha256 + 0] = (second_sha256_hash[0] >> 24) & 0xFF;
    r[r_offset_second_sha256 + 1] = (second_sha256_hash[0] >> 16) & 0xFF;
    r[r_offset_second_sha256 + 2] = (second_sha256_hash[0] >> 8) & 0xFF;
    r[r_offset_second_sha256 + 3] = (second_sha256_hash[0] >> 0) & 0xFF;

    r[r_offset_second_sha256 + 4] = (second_sha256_hash[1] >> 24) & 0xFF;
    r[r_offset_second_sha256 + 5] = (second_sha256_hash[1] >> 16) & 0xFF;
    r[r_offset_second_sha256 + 6] = (second_sha256_hash[1] >> 8) & 0xFF;
    r[r_offset_second_sha256 + 7] = (second_sha256_hash[1] >> 0) & 0xFF;

    r[r_offset_second_sha256 + 8] = (second_sha256_hash[2] >> 24) & 0xFF;
    r[r_offset_second_sha256 + 9] = (second_sha256_hash[2] >> 16) & 0xFF;
    r[r_offset_second_sha256 + 10] = (second_sha256_hash[2] >> 8) & 0xFF;
    r[r_offset_second_sha256 + 11] = (second_sha256_hash[2] >> 0) & 0xFF;

    r[r_offset_second_sha256 + 12] = (second_sha256_hash[3] >> 24) & 0xFF;
    r[r_offset_second_sha256 + 13] = (second_sha256_hash[3] >> 16) & 0xFF;
    r[r_offset_second_sha256 + 14] = (second_sha256_hash[3] >> 8) & 0xFF;
    r[r_offset_second_sha256 + 15] = (second_sha256_hash[3] >> 0) & 0xFF;

    r[r_offset_second_sha256 + 16] = (second_sha256_hash[4] >> 24) & 0xFF;
    r[r_offset_second_sha256 + 17] = (second_sha256_hash[4] >> 16) & 0xFF;
    r[r_offset_second_sha256 + 18] = (second_sha256_hash[4] >> 8) & 0xFF;
    r[r_offset_second_sha256 + 19] = (second_sha256_hash[4] >> 0) & 0xFF;

    r[r_offset_second_sha256 + 20] = (second_sha256_hash[5] >> 24) & 0xFF;
    r[r_offset_second_sha256 + 21] = (second_sha256_hash[5] >> 16) & 0xFF;
    r[r_offset_second_sha256 + 22] = (second_sha256_hash[5] >> 8) & 0xFF;
    r[r_offset_second_sha256 + 23] = (second_sha256_hash[5] >> 0) & 0xFF;

    r[r_offset_second_sha256 + 24] = (second_sha256_hash[6] >> 24) & 0xFF;
    r[r_offset_second_sha256 + 25] = (second_sha256_hash[6] >> 16) & 0xFF;
    r[r_offset_second_sha256 + 26] = (second_sha256_hash[6] >> 8) & 0xFF;
    r[r_offset_second_sha256 + 27] = (second_sha256_hash[6] >> 0) & 0xFF;

    r[r_offset_second_sha256 + 28] = (second_sha256_hash[7] >> 24) & 0xFF;
    r[r_offset_second_sha256 + 29] = (second_sha256_hash[7] >> 16) & 0xFF;
    r[r_offset_second_sha256 + 30] = (second_sha256_hash[7] >> 8) & 0xFF;
    r[r_offset_second_sha256 + 31] = (second_sha256_hash[7] >> 0) & 0xFF;


    // hash the SHA-256 hash with SHA-256
    calculate_sha256_from_sha256(second_sha256_hash, third_sha256_hash);

    int r_offset_third_sha256 = r_offset_second_sha256 + SHA256_HASH_BYTES_LEN;

    // write bytes of u32 array storing third SHA-256 hash into result buffer
    r[r_offset_third_sha256 + 0] = (third_sha256_hash[0] >> 24) & 0xFF;
    r[r_offset_third_sha256 + 1] = (third_sha256_hash[0] >> 16) & 0xFF;
    r[r_offset_third_sha256 + 2] = (third_sha256_hash[0] >> 8) & 0xFF;
    r[r_offset_third_sha256 + 3] = (third_sha256_hash[0] >> 0) & 0xFF;

    r[r_offset_third_sha256 + 4] = (third_sha256_hash[1] >> 24) & 0xFF;
    r[r_offset_third_sha256 + 5] = (third_sha256_hash[1] >> 16) & 0xFF;
    r[r_offset_third_sha256 + 6] = (third_sha256_hash[1] >> 8) & 0xFF;
    r[r_offset_third_sha256 + 7] = (third_sha256_hash[1] >> 0) & 0xFF;

    r[r_offset_third_sha256 + 8] = (third_sha256_hash[2] >> 24) & 0xFF;
    r[r_offset_third_sha256 + 9] = (third_sha256_hash[2] >> 16) & 0xFF;
    r[r_offset_third_sha256 + 10] = (third_sha256_hash[2] >> 8) & 0xFF;
    r[r_offset_third_sha256 + 11] = (third_sha256_hash[2] >> 0) & 0xFF;

    r[r_offset_third_sha256 + 12] = (third_sha256_hash[3] >> 24) & 0xFF;
    r[r_offset_third_sha256 + 13] = (third_sha256_hash[3] >> 16) & 0xFF;
    r[r_offset_third_sha256 + 14] = (third_sha256_hash[3] >> 8) & 0xFF;
    r[r_offset_third_sha256 + 15] = (third_sha256_hash[3] >> 0) & 0xFF;

    r[r_offset_third_sha256 + 16] = (third_sha256_hash[4] >> 24) & 0xFF;
    r[r_offset_third_sha256 + 17] = (third_sha256_hash[4] >> 16) & 0xFF;
    r[r_offset_third_sha256 + 18] = (third_sha256_hash[4] >> 8) & 0xFF;
    r[r_offset_third_sha256 + 19] = (third_sha256_hash[4] >> 0) & 0xFF;

    r[r_offset_third_sha256 + 20] = (third_sha256_hash[5] >> 24) & 0xFF;
    r[r_offset_third_sha256 + 21] = (third_sha256_hash[5] >> 16) & 0xFF;
    r[r_offset_third_sha256 + 22] = (third_sha256_hash[5] >> 8) & 0xFF;
    r[r_offset_third_sha256 + 23] = (third_sha256_hash[5] >> 0) & 0xFF;

    r[r_offset_third_sha256 + 24] = (third_sha256_hash[6] >> 24) & 0xFF;
    r[r_offset_third_sha256 + 25] = (third_sha256_hash[6] >> 16) & 0xFF;
    r[r_offset_third_sha256 + 26] = (third_sha256_hash[6] >> 8) & 0xFF;
    r[r_offset_third_sha256 + 27] = (third_sha256_hash[6] >> 0) & 0xFF;

    r[r_offset_third_sha256 + 28] = (third_sha256_hash[7] >> 24) & 0xFF;
    r[r_offset_third_sha256 + 29] = (third_sha256_hash[7] >> 16) & 0xFF;
    r[r_offset_third_sha256 + 30] = (third_sha256_hash[7] >> 8) & 0xFF;
    r[r_offset_third_sha256 + 31] = (third_sha256_hash[7] >> 0) & 0xFF;
}

/*
 * Calculates the public key from given private key,
 * then hashes it with SHA-256, RIPEMD-160, adds version byte and then hashes it again
 * with SHA-256 two times.
 *
 * OUTPUT uchar *r: Pointer to the result buffer to store all results
 * INPUT u32 *k:    Pointer to the private key buffer storing all private keys
 */
__kernel void generate_until_third_sha256(__global uchar *r, __global const u32 *k){

    u32 k_local_u32[PRIVATE_KEY_LENGTH];
    u32 x_local_u32[PUBLIC_KEY_ONE_COORDINATE_LENGTH];
    u32 y_local_u32[PUBLIC_KEY_ONE_COORDINATE_LENGTH];
    uchar public_key_bytes[PUBLIC_KEY_BYTES_WITH_PARITY];
    secp256k1_t g_xy_local;

    // to store the results of the SHA-256 and RIPEMD-160 hashes
    u32 sha256_hash[SHA256_HASH_U32_LEN];
    u32 ripemd160_hash[RIPEMD160_HASH_U32_LEN];
    uchar version[RIPEMD160_HASH_WITH_VERSION_BYTES];
    u32 second_sha256_hash[SHA256_HASH_U32_LEN];
    u32 third_sha256_hash[SHA256_HASH_U32_LEN];

    // id of current work item
    int work_item_id = get_global_id(0);

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

    // calculating the public key coordinates
    set_precomputed_basepoint_g(&g_xy_local);
    point_mul_xy(x_local_u32, y_local_u32, k_local_u32, &g_xy_local);


    // calculating offset to write results in byte buffer
    int r_offset_bytes_private_key = (PRIVATE_KEY_BYTES + PUBLIC_KEY_BYTES_WITH_PARITY + SHA256_HASH_BYTES_LEN + RIPEMD160_HASH_BYTES + SHA256_HASH_BYTES_LEN + SHA256_HASH_BYTES_LEN) * work_item_id;

    // write bytes of u32 array storing private key into result buffer
    r[r_offset_bytes_private_key + 0] = (k_local_u32[7] >> 24) & 0xFF;
    r[r_offset_bytes_private_key + 1] = (k_local_u32[7] >> 16) & 0xFF;
    r[r_offset_bytes_private_key + 2] = (k_local_u32[7] >> 8) & 0xFF;
    r[r_offset_bytes_private_key + 3] = (k_local_u32[7] >> 0) & 0xFF;

    r[r_offset_bytes_private_key + 4] = (k_local_u32[6] >> 24) & 0xFF;
    r[r_offset_bytes_private_key + 5] = (k_local_u32[6] >> 16) & 0xFF;
    r[r_offset_bytes_private_key + 6] = (k_local_u32[6] >> 8) & 0xFF;
    r[r_offset_bytes_private_key + 7] = (k_local_u32[6] >> 0) & 0xFF;

    r[r_offset_bytes_private_key + 8] = (k_local_u32[5] >> 24) & 0xFF;
    r[r_offset_bytes_private_key + 9] = (k_local_u32[5] >> 16) & 0xFF;
    r[r_offset_bytes_private_key + 10] = (k_local_u32[5] >> 8) & 0xFF;
    r[r_offset_bytes_private_key + 11] = (k_local_u32[5] >> 0) & 0xFF;

    r[r_offset_bytes_private_key + 12] = (k_local_u32[4] >> 24) & 0xFF;
    r[r_offset_bytes_private_key + 13] = (k_local_u32[4] >> 16) & 0xFF;
    r[r_offset_bytes_private_key + 14] = (k_local_u32[4] >> 8) & 0xFF;
    r[r_offset_bytes_private_key + 15] = (k_local_u32[4] >> 0) & 0xFF;

    r[r_offset_bytes_private_key + 16] = (k_local_u32[3] >> 24) & 0xFF;
    r[r_offset_bytes_private_key + 17] = (k_local_u32[3] >> 16) & 0xFF;
    r[r_offset_bytes_private_key + 18] = (k_local_u32[3] >> 8) & 0xFF;
    r[r_offset_bytes_private_key + 19] = (k_local_u32[3] >> 0) & 0xFF;

    r[r_offset_bytes_private_key + 20] = (k_local_u32[2] >> 24) & 0xFF;
    r[r_offset_bytes_private_key + 21] = (k_local_u32[2] >> 16) & 0xFF;
    r[r_offset_bytes_private_key + 22] = (k_local_u32[2] >> 8) & 0xFF;
    r[r_offset_bytes_private_key + 23] = (k_local_u32[2] >> 0) & 0xFF;

    r[r_offset_bytes_private_key + 24] = (k_local_u32[1] >> 24) & 0xFF;
    r[r_offset_bytes_private_key + 25] = (k_local_u32[1] >> 16) & 0xFF;
    r[r_offset_bytes_private_key + 26] = (k_local_u32[1] >> 8) & 0xFF;
    r[r_offset_bytes_private_key + 27] = (k_local_u32[1] >> 0) & 0xFF;

    r[r_offset_bytes_private_key + 28] = (k_local_u32[0] >> 24) & 0xFF;
    r[r_offset_bytes_private_key + 29] = (k_local_u32[0] >> 16) & 0xFF;
    r[r_offset_bytes_private_key + 30] = (k_local_u32[0] >> 8) & 0xFF;
    r[r_offset_bytes_private_key + 31] = (k_local_u32[0] >> 0) & 0xFF;


    // creating the public key from coordinates and parity byte for hashing
    create_public_key_from_coordinates(public_key_bytes, x_local_u32, y_local_u32);

    int r_offset_public_key = r_offset_bytes_private_key + PRIVATE_KEY_BYTES;

    // write public key parity byte into result buffer
    r[r_offset_public_key + 0] = 0x04;

    // write bytes of u32 array storing x coordinate into result buffer
    r[r_offset_public_key + 1] = (x_local_u32[7] >> 24) & 0xFF;
    r[r_offset_public_key + 2] = (x_local_u32[7] >> 16) & 0xFF;
    r[r_offset_public_key + 3] = (x_local_u32[7] >> 8) & 0xFF;
    r[r_offset_public_key + 4] = (x_local_u32[7] >> 0) & 0xFF;

    r[r_offset_public_key + 5] = (x_local_u32[6] >> 24) & 0xFF;
    r[r_offset_public_key + 6] = (x_local_u32[6] >> 16) & 0xFF;
    r[r_offset_public_key + 7] = (x_local_u32[6] >> 8) & 0xFF;
    r[r_offset_public_key + 8] = (x_local_u32[6] >> 0) & 0xFF;

    r[r_offset_public_key + 9] = (x_local_u32[5] >> 24) & 0xFF;
    r[r_offset_public_key + 10] = (x_local_u32[5] >> 16) & 0xFF;
    r[r_offset_public_key + 11] = (x_local_u32[5] >> 8) & 0xFF;
    r[r_offset_public_key + 12] = (x_local_u32[5] >> 0) & 0xFF;

    r[r_offset_public_key + 13] = (x_local_u32[4] >> 24) & 0xFF;
    r[r_offset_public_key + 14] = (x_local_u32[4] >> 16) & 0xFF;
    r[r_offset_public_key + 15] = (x_local_u32[4] >> 8) & 0xFF;
    r[r_offset_public_key + 16] = (x_local_u32[4] >> 0) & 0xFF;

    r[r_offset_public_key + 17] = (x_local_u32[3] >> 24) & 0xFF;
    r[r_offset_public_key + 18] = (x_local_u32[3] >> 16) & 0xFF;
    r[r_offset_public_key + 19] = (x_local_u32[3] >> 8) & 0xFF;
    r[r_offset_public_key + 20] = (x_local_u32[3] >> 0) & 0xFF;

    r[r_offset_public_key + 21] = (x_local_u32[2] >> 24) & 0xFF;
    r[r_offset_public_key + 22] = (x_local_u32[2] >> 16) & 0xFF;
    r[r_offset_public_key + 23] = (x_local_u32[2] >> 8) & 0xFF;
    r[r_offset_public_key + 24] = (x_local_u32[2] >> 0) & 0xFF;

    r[r_offset_public_key + 25] = (x_local_u32[1] >> 24) & 0xFF;
    r[r_offset_public_key + 26] = (x_local_u32[1] >> 16) & 0xFF;
    r[r_offset_public_key + 27] = (x_local_u32[1] >> 8) & 0xFF;
    r[r_offset_public_key + 28] = (x_local_u32[1] >> 0) & 0xFF;

    r[r_offset_public_key + 29] = (x_local_u32[0] >> 24) & 0xFF;
    r[r_offset_public_key + 30] = (x_local_u32[0] >> 16) & 0xFF;
    r[r_offset_public_key + 31] = (x_local_u32[0] >> 8) & 0xFF;
    r[r_offset_public_key + 32] = (x_local_u32[0] >> 0) & 0xFF;

    // write bytes of u32 array storing y coordinate into result buffer
    r[r_offset_public_key + 33] = (y_local_u32[7] >> 24) & 0xFF;
    r[r_offset_public_key + 34] = (y_local_u32[7] >> 16) & 0xFF;
    r[r_offset_public_key + 35] = (y_local_u32[7] >> 8) & 0xFF;
    r[r_offset_public_key + 36] = (y_local_u32[7] >> 0) & 0xFF;

    r[r_offset_public_key + 37] = (y_local_u32[6] >> 24) & 0xFF;
    r[r_offset_public_key + 38] = (y_local_u32[6] >> 16) & 0xFF;
    r[r_offset_public_key + 39] = (y_local_u32[6] >> 8) & 0xFF;
    r[r_offset_public_key + 40] = (y_local_u32[6] >> 0) & 0xFF;

    r[r_offset_public_key + 41] = (y_local_u32[5] >> 24) & 0xFF;
    r[r_offset_public_key + 42] = (y_local_u32[5] >> 16) & 0xFF;
    r[r_offset_public_key + 43] = (y_local_u32[5] >> 8) & 0xFF;
    r[r_offset_public_key + 44] = (y_local_u32[5] >> 0) & 0xFF;

    r[r_offset_public_key + 45] = (y_local_u32[4] >> 24) & 0xFF;
    r[r_offset_public_key + 46] = (y_local_u32[4] >> 16) & 0xFF;
    r[r_offset_public_key + 47] = (y_local_u32[4] >> 8) & 0xFF;
    r[r_offset_public_key + 48] = (y_local_u32[4] >> 0) & 0xFF;

    r[r_offset_public_key + 49] = (y_local_u32[3] >> 24) & 0xFF;
    r[r_offset_public_key + 50] = (y_local_u32[3] >> 16) & 0xFF;
    r[r_offset_public_key + 51] = (y_local_u32[3] >> 8) & 0xFF;
    r[r_offset_public_key + 52] = (y_local_u32[3] >> 0) & 0xFF;

    r[r_offset_public_key + 53] = (y_local_u32[2] >> 24) & 0xFF;
    r[r_offset_public_key + 54] = (y_local_u32[2] >> 16) & 0xFF;
    r[r_offset_public_key + 55] = (y_local_u32[2] >> 8) & 0xFF;
    r[r_offset_public_key + 56] = (y_local_u32[2] >> 0) & 0xFF;

    r[r_offset_public_key + 57] = (y_local_u32[1] >> 24) & 0xFF;
    r[r_offset_public_key + 58] = (y_local_u32[1] >> 16) & 0xFF;
    r[r_offset_public_key + 59] = (y_local_u32[1] >> 8) & 0xFF;
    r[r_offset_public_key + 60] = (y_local_u32[1] >> 0) & 0xFF;

    r[r_offset_public_key + 61] = (y_local_u32[0] >> 24) & 0xFF;
    r[r_offset_public_key + 62] = (y_local_u32[0] >> 16) & 0xFF;
    r[r_offset_public_key + 63] = (y_local_u32[0] >> 8) & 0xFF;
    r[r_offset_public_key + 64] = (y_local_u32[0] >> 0) & 0xFF;


    // hash the public key with SHA-256
    calculate_sha256_from_public_key(public_key_bytes, sha256_hash);

    int r_offset_first_sha256 = r_offset_public_key + PUBLIC_KEY_BYTES_WITH_PARITY;

    // write bytes of u32 array storing sha256_hash into result buffer
    r[r_offset_first_sha256 + 0] = (sha256_hash[0] >> 24) & 0xFF;
    r[r_offset_first_sha256 + 1] = (sha256_hash[0] >> 16) & 0xFF;
    r[r_offset_first_sha256 + 2] = (sha256_hash[0] >> 8) & 0xFF;
    r[r_offset_first_sha256 + 3] = (sha256_hash[0] >> 0) & 0xFF;

    r[r_offset_first_sha256 + 4] = (sha256_hash[1] >> 24) & 0xFF;
    r[r_offset_first_sha256 + 5] = (sha256_hash[1] >> 16) & 0xFF;
    r[r_offset_first_sha256 + 6] = (sha256_hash[1] >> 8) & 0xFF;
    r[r_offset_first_sha256 + 7] = (sha256_hash[1] >> 0) & 0xFF;

    r[r_offset_first_sha256 + 8] = (sha256_hash[2] >> 24) & 0xFF;
    r[r_offset_first_sha256 + 9] = (sha256_hash[2] >> 16) & 0xFF;
    r[r_offset_first_sha256 + 10] = (sha256_hash[2] >> 8) & 0xFF;
    r[r_offset_first_sha256 + 11] = (sha256_hash[2] >> 0) & 0xFF;

    r[r_offset_first_sha256 + 12] = (sha256_hash[3] >> 24) & 0xFF;
    r[r_offset_first_sha256 + 13] = (sha256_hash[3] >> 16) & 0xFF;
    r[r_offset_first_sha256 + 14] = (sha256_hash[3] >> 8) & 0xFF;
    r[r_offset_first_sha256 + 15] = (sha256_hash[3] >> 0) & 0xFF;

    r[r_offset_first_sha256 + 16] = (sha256_hash[4] >> 24) & 0xFF;
    r[r_offset_first_sha256 + 17] = (sha256_hash[4] >> 16) & 0xFF;
    r[r_offset_first_sha256 + 18] = (sha256_hash[4] >> 8) & 0xFF;
    r[r_offset_first_sha256 + 19] = (sha256_hash[4] >> 0) & 0xFF;

    r[r_offset_first_sha256 + 20] = (sha256_hash[5] >> 24) & 0xFF;
    r[r_offset_first_sha256 + 21] = (sha256_hash[5] >> 16) & 0xFF;
    r[r_offset_first_sha256 + 22] = (sha256_hash[5] >> 8) & 0xFF;
    r[r_offset_first_sha256 + 23] = (sha256_hash[5] >> 0) & 0xFF;

    r[r_offset_first_sha256 + 24] = (sha256_hash[6] >> 24) & 0xFF;
    r[r_offset_first_sha256 + 25] = (sha256_hash[6] >> 16) & 0xFF;
    r[r_offset_first_sha256 + 26] = (sha256_hash[6] >> 8) & 0xFF;
    r[r_offset_first_sha256 + 27] = (sha256_hash[6] >> 0) & 0xFF;

    r[r_offset_first_sha256 + 28] = (sha256_hash[7] >> 24) & 0xFF;
    r[r_offset_first_sha256 + 29] = (sha256_hash[7] >> 16) & 0xFF;
    r[r_offset_first_sha256 + 30] = (sha256_hash[7] >> 8) & 0xFF;
    r[r_offset_first_sha256 + 31] = (sha256_hash[7] >> 0) & 0xFF;


    // hash the SHA-256 result with RIPEMD-160
    calculate_ripemd160_from_u32(sha256_hash, ripemd160_hash);

    int r_offset_ripemd160 = r_offset_first_sha256 + SHA256_HASH_BYTES_LEN;

    // write bytes of u32 array storing ripemd160_hash into result buffer
    r[r_offset_ripemd160 + 0] = (ripemd160_hash[0] >> 0) & 0xFF;
    r[r_offset_ripemd160 + 1] = (ripemd160_hash[0] >> 8) & 0xFF;
    r[r_offset_ripemd160 + 2] = (ripemd160_hash[0] >> 16) & 0xFF;
    r[r_offset_ripemd160 + 3] = (ripemd160_hash[0] >> 24) & 0xFF;

    r[r_offset_ripemd160 + 4] = (ripemd160_hash[1] >> 0) & 0xFF;
    r[r_offset_ripemd160 + 5] = (ripemd160_hash[1] >> 8) & 0xFF;
    r[r_offset_ripemd160 + 6] = (ripemd160_hash[1] >> 16) & 0xFF;
    r[r_offset_ripemd160 + 7] = (ripemd160_hash[1] >> 24) & 0xFF;

    r[r_offset_ripemd160 + 8] = (ripemd160_hash[2] >> 0) & 0xFF;
    r[r_offset_ripemd160 + 9] = (ripemd160_hash[2] >> 8) & 0xFF;
    r[r_offset_ripemd160 + 10] = (ripemd160_hash[2] >> 16) & 0xFF;
    r[r_offset_ripemd160 + 11] = (ripemd160_hash[2] >> 24) & 0xFF;

    r[r_offset_ripemd160 + 12] = (ripemd160_hash[3] >> 0) & 0xFF;
    r[r_offset_ripemd160 + 13] = (ripemd160_hash[3] >> 8) & 0xFF;
    r[r_offset_ripemd160 + 14] = (ripemd160_hash[3] >> 16) & 0xFF;
    r[r_offset_ripemd160 + 15] = (ripemd160_hash[3] >> 24) & 0xFF;

    r[r_offset_ripemd160 + 16] = (ripemd160_hash[4] >> 0) & 0xFF;
    r[r_offset_ripemd160 + 17] = (ripemd160_hash[4] >> 8) & 0xFF;
    r[r_offset_ripemd160 + 18] = (ripemd160_hash[4] >> 16) & 0xFF;
    r[r_offset_ripemd160 + 19] = (ripemd160_hash[4] >> 24) & 0xFF;


    // version = 0x00 + RIPEMD-160 hash
    version[0] = RIPEMD160_HASH_VERSION_BYTE;

    version[1] = (ripemd160_hash[0] >> 0) & 0xFF;
    version[2] = (ripemd160_hash[0] >> 8) & 0xFF;
    version[3] = (ripemd160_hash[0] >> 16) & 0xFF;
    version[4] = (ripemd160_hash[0] >> 24) & 0xFF;

    version[5] = (ripemd160_hash[1] >> 0) & 0xFF;
    version[6] = (ripemd160_hash[1] >> 8) & 0xFF;
    version[7] = (ripemd160_hash[1] >> 16) & 0xFF;
    version[8] = (ripemd160_hash[1] >> 24) & 0xFF;

    version[9] = (ripemd160_hash[2] >> 0) & 0xFF;
    version[10] = (ripemd160_hash[2] >> 8) & 0xFF;
    version[11] = (ripemd160_hash[2] >> 16) & 0xFF;
    version[12] = (ripemd160_hash[2] >> 24) & 0xFF;

    version[13] = (ripemd160_hash[3] >> 0) & 0xFF;
    version[14] = (ripemd160_hash[3] >> 8) & 0xFF;
    version[15] = (ripemd160_hash[3] >> 16) & 0xFF;
    version[16] = (ripemd160_hash[3] >> 24) & 0xFF;

    version[17] = (ripemd160_hash[4] >> 0) & 0xFF;
    version[18] = (ripemd160_hash[4] >> 8) & 0xFF;
    version[19] = (ripemd160_hash[4] >> 16) & 0xFF;
    version[20] = (ripemd160_hash[4] >> 24) & 0xFF;

    // hash the RIPEMD-160 hash incl version byte with SHA-256
    calculate_sha256_from_version(version, second_sha256_hash);

    int r_offset_second_sha256 = r_offset_ripemd160 + RIPEMD160_HASH_BYTES;

    // write bytes of u32 array storing second SHA-256 hash into result buffer
    r[r_offset_second_sha256 + 0] = (second_sha256_hash[0] >> 24) & 0xFF;
    r[r_offset_second_sha256 + 1] = (second_sha256_hash[0] >> 16) & 0xFF;
    r[r_offset_second_sha256 + 2] = (second_sha256_hash[0] >> 8) & 0xFF;
    r[r_offset_second_sha256 + 3] = (second_sha256_hash[0] >> 0) & 0xFF;

    r[r_offset_second_sha256 + 4] = (second_sha256_hash[1] >> 24) & 0xFF;
    r[r_offset_second_sha256 + 5] = (second_sha256_hash[1] >> 16) & 0xFF;
    r[r_offset_second_sha256 + 6] = (second_sha256_hash[1] >> 8) & 0xFF;
    r[r_offset_second_sha256 + 7] = (second_sha256_hash[1] >> 0) & 0xFF;

    r[r_offset_second_sha256 + 8] = (second_sha256_hash[2] >> 24) & 0xFF;
    r[r_offset_second_sha256 + 9] = (second_sha256_hash[2] >> 16) & 0xFF;
    r[r_offset_second_sha256 + 10] = (second_sha256_hash[2] >> 8) & 0xFF;
    r[r_offset_second_sha256 + 11] = (second_sha256_hash[2] >> 0) & 0xFF;

    r[r_offset_second_sha256 + 12] = (second_sha256_hash[3] >> 24) & 0xFF;
    r[r_offset_second_sha256 + 13] = (second_sha256_hash[3] >> 16) & 0xFF;
    r[r_offset_second_sha256 + 14] = (second_sha256_hash[3] >> 8) & 0xFF;
    r[r_offset_second_sha256 + 15] = (second_sha256_hash[3] >> 0) & 0xFF;

    r[r_offset_second_sha256 + 16] = (second_sha256_hash[4] >> 24) & 0xFF;
    r[r_offset_second_sha256 + 17] = (second_sha256_hash[4] >> 16) & 0xFF;
    r[r_offset_second_sha256 + 18] = (second_sha256_hash[4] >> 8) & 0xFF;
    r[r_offset_second_sha256 + 19] = (second_sha256_hash[4] >> 0) & 0xFF;

    r[r_offset_second_sha256 + 20] = (second_sha256_hash[5] >> 24) & 0xFF;
    r[r_offset_second_sha256 + 21] = (second_sha256_hash[5] >> 16) & 0xFF;
    r[r_offset_second_sha256 + 22] = (second_sha256_hash[5] >> 8) & 0xFF;
    r[r_offset_second_sha256 + 23] = (second_sha256_hash[5] >> 0) & 0xFF;

    r[r_offset_second_sha256 + 24] = (second_sha256_hash[6] >> 24) & 0xFF;
    r[r_offset_second_sha256 + 25] = (second_sha256_hash[6] >> 16) & 0xFF;
    r[r_offset_second_sha256 + 26] = (second_sha256_hash[6] >> 8) & 0xFF;
    r[r_offset_second_sha256 + 27] = (second_sha256_hash[6] >> 0) & 0xFF;

    r[r_offset_second_sha256 + 28] = (second_sha256_hash[7] >> 24) & 0xFF;
    r[r_offset_second_sha256 + 29] = (second_sha256_hash[7] >> 16) & 0xFF;
    r[r_offset_second_sha256 + 30] = (second_sha256_hash[7] >> 8) & 0xFF;
    r[r_offset_second_sha256 + 31] = (second_sha256_hash[7] >> 0) & 0xFF;


    // hash the SHA-256 hash with SHA-256
    calculate_sha256_from_sha256(second_sha256_hash, third_sha256_hash);

    int r_offset_third_sha256 = r_offset_second_sha256 + SHA256_HASH_BYTES_LEN;

    // write bytes of u32 array storing third SHA-256 hash into result buffer
    r[r_offset_third_sha256 + 0] = (third_sha256_hash[0] >> 24) & 0xFF;
    r[r_offset_third_sha256 + 1] = (third_sha256_hash[0] >> 16) & 0xFF;
    r[r_offset_third_sha256 + 2] = (third_sha256_hash[0] >> 8) & 0xFF;
    r[r_offset_third_sha256 + 3] = (third_sha256_hash[0] >> 0) & 0xFF;

    r[r_offset_third_sha256 + 4] = (third_sha256_hash[1] >> 24) & 0xFF;
    r[r_offset_third_sha256 + 5] = (third_sha256_hash[1] >> 16) & 0xFF;
    r[r_offset_third_sha256 + 6] = (third_sha256_hash[1] >> 8) & 0xFF;
    r[r_offset_third_sha256 + 7] = (third_sha256_hash[1] >> 0) & 0xFF;

    r[r_offset_third_sha256 + 8] = (third_sha256_hash[2] >> 24) & 0xFF;
    r[r_offset_third_sha256 + 9] = (third_sha256_hash[2] >> 16) & 0xFF;
    r[r_offset_third_sha256 + 10] = (third_sha256_hash[2] >> 8) & 0xFF;
    r[r_offset_third_sha256 + 11] = (third_sha256_hash[2] >> 0) & 0xFF;

    r[r_offset_third_sha256 + 12] = (third_sha256_hash[3] >> 24) & 0xFF;
    r[r_offset_third_sha256 + 13] = (third_sha256_hash[3] >> 16) & 0xFF;
    r[r_offset_third_sha256 + 14] = (third_sha256_hash[3] >> 8) & 0xFF;
    r[r_offset_third_sha256 + 15] = (third_sha256_hash[3] >> 0) & 0xFF;

    r[r_offset_third_sha256 + 16] = (third_sha256_hash[4] >> 24) & 0xFF;
    r[r_offset_third_sha256 + 17] = (third_sha256_hash[4] >> 16) & 0xFF;
    r[r_offset_third_sha256 + 18] = (third_sha256_hash[4] >> 8) & 0xFF;
    r[r_offset_third_sha256 + 19] = (third_sha256_hash[4] >> 0) & 0xFF;

    r[r_offset_third_sha256 + 20] = (third_sha256_hash[5] >> 24) & 0xFF;
    r[r_offset_third_sha256 + 21] = (third_sha256_hash[5] >> 16) & 0xFF;
    r[r_offset_third_sha256 + 22] = (third_sha256_hash[5] >> 8) & 0xFF;
    r[r_offset_third_sha256 + 23] = (third_sha256_hash[5] >> 0) & 0xFF;

    r[r_offset_third_sha256 + 24] = (third_sha256_hash[6] >> 24) & 0xFF;
    r[r_offset_third_sha256 + 25] = (third_sha256_hash[6] >> 16) & 0xFF;
    r[r_offset_third_sha256 + 26] = (third_sha256_hash[6] >> 8) & 0xFF;
    r[r_offset_third_sha256 + 27] = (third_sha256_hash[6] >> 0) & 0xFF;

    r[r_offset_third_sha256 + 28] = (third_sha256_hash[7] >> 24) & 0xFF;
    r[r_offset_third_sha256 + 29] = (third_sha256_hash[7] >> 16) & 0xFF;
    r[r_offset_third_sha256 + 30] = (third_sha256_hash[7] >> 8) & 0xFF;
    r[r_offset_third_sha256 + 31] = (third_sha256_hash[7] >> 0) & 0xFF;
}

/*
 * "Creates" private keys from a single private key and then calculates the public key,
 * then hashes it with SHA-256, RIPEMD-160, adds version byte and then hashes it again
 * with SHA-256 two times. Then assembles the address.
 *
 * OUTPUT uchar *r: Pointer to the result buffer to store all results
 * INPUT u32 *k:    Pointer to the private key buffer storing a single private key
 */
__kernel void generate_chunk_until_address(__global uchar *r, __global const u32 *k){

    u32 k_local_u32[PRIVATE_KEY_LENGTH];
    u32 x_local_u32[PUBLIC_KEY_ONE_COORDINATE_LENGTH];
    u32 y_local_u32[PUBLIC_KEY_ONE_COORDINATE_LENGTH];
    uchar public_key_bytes[PUBLIC_KEY_BYTES_WITH_PARITY];
    secp256k1_t g_xy_local;

    // to store the results of the SHA-256 and RIPEMD-160 hashes
    u32 sha256_hash[SHA256_HASH_U32_LEN];
    u32 ripemd160_hash[RIPEMD160_HASH_U32_LEN];
    uchar version[RIPEMD160_HASH_WITH_VERSION_BYTES];
    u32 second_sha256_hash[SHA256_HASH_U32_LEN];
    u32 third_sha256_hash[SHA256_HASH_U32_LEN];
    uchar address[ADDRESS_BYTES_LEN];

    // id of current work item
    int work_item_id = get_global_id(0);

    // get first private key from private key grid and "create" a new one
    k_local_u32[0] = k[0] | work_item_id;
    k_local_u32[1] = k[1];
    k_local_u32[2] = k[2];
    k_local_u32[3] = k[3];
    k_local_u32[4] = k[4];
    k_local_u32[5] = k[5];
    k_local_u32[6] = k[6];
    k_local_u32[7] = k[7];

    // calculating the public key coordinates
    set_precomputed_basepoint_g(&g_xy_local);
    point_mul_xy(x_local_u32, y_local_u32, k_local_u32, &g_xy_local);


    // calculating offset to write results in byte buffer
    int r_offset_bytes_private_key = (PRIVATE_KEY_BYTES + PUBLIC_KEY_BYTES_WITH_PARITY + SHA256_HASH_BYTES_LEN + RIPEMD160_HASH_BYTES + SHA256_HASH_BYTES_LEN + SHA256_HASH_BYTES_LEN + ADDRESS_BYTES_LEN) * work_item_id;

    // write bytes of u32 array storing private key into result buffer
    r[r_offset_bytes_private_key + 0] = (k_local_u32[7] >> 24) & 0xFF;
    r[r_offset_bytes_private_key + 1] = (k_local_u32[7] >> 16) & 0xFF;
    r[r_offset_bytes_private_key + 2] = (k_local_u32[7] >> 8) & 0xFF;
    r[r_offset_bytes_private_key + 3] = (k_local_u32[7] >> 0) & 0xFF;

    r[r_offset_bytes_private_key + 4] = (k_local_u32[6] >> 24) & 0xFF;
    r[r_offset_bytes_private_key + 5] = (k_local_u32[6] >> 16) & 0xFF;
    r[r_offset_bytes_private_key + 6] = (k_local_u32[6] >> 8) & 0xFF;
    r[r_offset_bytes_private_key + 7] = (k_local_u32[6] >> 0) & 0xFF;

    r[r_offset_bytes_private_key + 8] = (k_local_u32[5] >> 24) & 0xFF;
    r[r_offset_bytes_private_key + 9] = (k_local_u32[5] >> 16) & 0xFF;
    r[r_offset_bytes_private_key + 10] = (k_local_u32[5] >> 8) & 0xFF;
    r[r_offset_bytes_private_key + 11] = (k_local_u32[5] >> 0) & 0xFF;

    r[r_offset_bytes_private_key + 12] = (k_local_u32[4] >> 24) & 0xFF;
    r[r_offset_bytes_private_key + 13] = (k_local_u32[4] >> 16) & 0xFF;
    r[r_offset_bytes_private_key + 14] = (k_local_u32[4] >> 8) & 0xFF;
    r[r_offset_bytes_private_key + 15] = (k_local_u32[4] >> 0) & 0xFF;

    r[r_offset_bytes_private_key + 16] = (k_local_u32[3] >> 24) & 0xFF;
    r[r_offset_bytes_private_key + 17] = (k_local_u32[3] >> 16) & 0xFF;
    r[r_offset_bytes_private_key + 18] = (k_local_u32[3] >> 8) & 0xFF;
    r[r_offset_bytes_private_key + 19] = (k_local_u32[3] >> 0) & 0xFF;

    r[r_offset_bytes_private_key + 20] = (k_local_u32[2] >> 24) & 0xFF;
    r[r_offset_bytes_private_key + 21] = (k_local_u32[2] >> 16) & 0xFF;
    r[r_offset_bytes_private_key + 22] = (k_local_u32[2] >> 8) & 0xFF;
    r[r_offset_bytes_private_key + 23] = (k_local_u32[2] >> 0) & 0xFF;

    r[r_offset_bytes_private_key + 24] = (k_local_u32[1] >> 24) & 0xFF;
    r[r_offset_bytes_private_key + 25] = (k_local_u32[1] >> 16) & 0xFF;
    r[r_offset_bytes_private_key + 26] = (k_local_u32[1] >> 8) & 0xFF;
    r[r_offset_bytes_private_key + 27] = (k_local_u32[1] >> 0) & 0xFF;

    r[r_offset_bytes_private_key + 28] = (k_local_u32[0] >> 24) & 0xFF;
    r[r_offset_bytes_private_key + 29] = (k_local_u32[0] >> 16) & 0xFF;
    r[r_offset_bytes_private_key + 30] = (k_local_u32[0] >> 8) & 0xFF;
    r[r_offset_bytes_private_key + 31] = (k_local_u32[0] >> 0) & 0xFF;


    // creating the public key from coordinates and parity byte for hashing
    create_public_key_from_coordinates(public_key_bytes, x_local_u32, y_local_u32);

    int r_offset_public_key = r_offset_bytes_private_key + PRIVATE_KEY_BYTES;

    // write public key parity byte into result buffer
    r[r_offset_public_key + 0] = 0x04;

    // write bytes of u32 array storing x coordinate into result buffer
    r[r_offset_public_key + 1] = (x_local_u32[7] >> 24) & 0xFF;
    r[r_offset_public_key + 2] = (x_local_u32[7] >> 16) & 0xFF;
    r[r_offset_public_key + 3] = (x_local_u32[7] >> 8) & 0xFF;
    r[r_offset_public_key + 4] = (x_local_u32[7] >> 0) & 0xFF;

    r[r_offset_public_key + 5] = (x_local_u32[6] >> 24) & 0xFF;
    r[r_offset_public_key + 6] = (x_local_u32[6] >> 16) & 0xFF;
    r[r_offset_public_key + 7] = (x_local_u32[6] >> 8) & 0xFF;
    r[r_offset_public_key + 8] = (x_local_u32[6] >> 0) & 0xFF;

    r[r_offset_public_key + 9] = (x_local_u32[5] >> 24) & 0xFF;
    r[r_offset_public_key + 10] = (x_local_u32[5] >> 16) & 0xFF;
    r[r_offset_public_key + 11] = (x_local_u32[5] >> 8) & 0xFF;
    r[r_offset_public_key + 12] = (x_local_u32[5] >> 0) & 0xFF;

    r[r_offset_public_key + 13] = (x_local_u32[4] >> 24) & 0xFF;
    r[r_offset_public_key + 14] = (x_local_u32[4] >> 16) & 0xFF;
    r[r_offset_public_key + 15] = (x_local_u32[4] >> 8) & 0xFF;
    r[r_offset_public_key + 16] = (x_local_u32[4] >> 0) & 0xFF;

    r[r_offset_public_key + 17] = (x_local_u32[3] >> 24) & 0xFF;
    r[r_offset_public_key + 18] = (x_local_u32[3] >> 16) & 0xFF;
    r[r_offset_public_key + 19] = (x_local_u32[3] >> 8) & 0xFF;
    r[r_offset_public_key + 20] = (x_local_u32[3] >> 0) & 0xFF;

    r[r_offset_public_key + 21] = (x_local_u32[2] >> 24) & 0xFF;
    r[r_offset_public_key + 22] = (x_local_u32[2] >> 16) & 0xFF;
    r[r_offset_public_key + 23] = (x_local_u32[2] >> 8) & 0xFF;
    r[r_offset_public_key + 24] = (x_local_u32[2] >> 0) & 0xFF;

    r[r_offset_public_key + 25] = (x_local_u32[1] >> 24) & 0xFF;
    r[r_offset_public_key + 26] = (x_local_u32[1] >> 16) & 0xFF;
    r[r_offset_public_key + 27] = (x_local_u32[1] >> 8) & 0xFF;
    r[r_offset_public_key + 28] = (x_local_u32[1] >> 0) & 0xFF;

    r[r_offset_public_key + 29] = (x_local_u32[0] >> 24) & 0xFF;
    r[r_offset_public_key + 30] = (x_local_u32[0] >> 16) & 0xFF;
    r[r_offset_public_key + 31] = (x_local_u32[0] >> 8) & 0xFF;
    r[r_offset_public_key + 32] = (x_local_u32[0] >> 0) & 0xFF;

    // write bytes of u32 array storing y coordinate into result buffer
    r[r_offset_public_key + 33] = (y_local_u32[7] >> 24) & 0xFF;
    r[r_offset_public_key + 34] = (y_local_u32[7] >> 16) & 0xFF;
    r[r_offset_public_key + 35] = (y_local_u32[7] >> 8) & 0xFF;
    r[r_offset_public_key + 36] = (y_local_u32[7] >> 0) & 0xFF;

    r[r_offset_public_key + 37] = (y_local_u32[6] >> 24) & 0xFF;
    r[r_offset_public_key + 38] = (y_local_u32[6] >> 16) & 0xFF;
    r[r_offset_public_key + 39] = (y_local_u32[6] >> 8) & 0xFF;
    r[r_offset_public_key + 40] = (y_local_u32[6] >> 0) & 0xFF;

    r[r_offset_public_key + 41] = (y_local_u32[5] >> 24) & 0xFF;
    r[r_offset_public_key + 42] = (y_local_u32[5] >> 16) & 0xFF;
    r[r_offset_public_key + 43] = (y_local_u32[5] >> 8) & 0xFF;
    r[r_offset_public_key + 44] = (y_local_u32[5] >> 0) & 0xFF;

    r[r_offset_public_key + 45] = (y_local_u32[4] >> 24) & 0xFF;
    r[r_offset_public_key + 46] = (y_local_u32[4] >> 16) & 0xFF;
    r[r_offset_public_key + 47] = (y_local_u32[4] >> 8) & 0xFF;
    r[r_offset_public_key + 48] = (y_local_u32[4] >> 0) & 0xFF;

    r[r_offset_public_key + 49] = (y_local_u32[3] >> 24) & 0xFF;
    r[r_offset_public_key + 50] = (y_local_u32[3] >> 16) & 0xFF;
    r[r_offset_public_key + 51] = (y_local_u32[3] >> 8) & 0xFF;
    r[r_offset_public_key + 52] = (y_local_u32[3] >> 0) & 0xFF;

    r[r_offset_public_key + 53] = (y_local_u32[2] >> 24) & 0xFF;
    r[r_offset_public_key + 54] = (y_local_u32[2] >> 16) & 0xFF;
    r[r_offset_public_key + 55] = (y_local_u32[2] >> 8) & 0xFF;
    r[r_offset_public_key + 56] = (y_local_u32[2] >> 0) & 0xFF;

    r[r_offset_public_key + 57] = (y_local_u32[1] >> 24) & 0xFF;
    r[r_offset_public_key + 58] = (y_local_u32[1] >> 16) & 0xFF;
    r[r_offset_public_key + 59] = (y_local_u32[1] >> 8) & 0xFF;
    r[r_offset_public_key + 60] = (y_local_u32[1] >> 0) & 0xFF;

    r[r_offset_public_key + 61] = (y_local_u32[0] >> 24) & 0xFF;
    r[r_offset_public_key + 62] = (y_local_u32[0] >> 16) & 0xFF;
    r[r_offset_public_key + 63] = (y_local_u32[0] >> 8) & 0xFF;
    r[r_offset_public_key + 64] = (y_local_u32[0] >> 0) & 0xFF;


    // hash the public key with SHA-256
    calculate_sha256_from_public_key(public_key_bytes, sha256_hash);

    int r_offset_first_sha256 = r_offset_public_key + PUBLIC_KEY_BYTES_WITH_PARITY;

    // write bytes of u32 array storing sha256_hash into result buffer
    r[r_offset_first_sha256 + 0] = (sha256_hash[0] >> 24) & 0xFF;
    r[r_offset_first_sha256 + 1] = (sha256_hash[0] >> 16) & 0xFF;
    r[r_offset_first_sha256 + 2] = (sha256_hash[0] >> 8) & 0xFF;
    r[r_offset_first_sha256 + 3] = (sha256_hash[0] >> 0) & 0xFF;

    r[r_offset_first_sha256 + 4] = (sha256_hash[1] >> 24) & 0xFF;
    r[r_offset_first_sha256 + 5] = (sha256_hash[1] >> 16) & 0xFF;
    r[r_offset_first_sha256 + 6] = (sha256_hash[1] >> 8) & 0xFF;
    r[r_offset_first_sha256 + 7] = (sha256_hash[1] >> 0) & 0xFF;

    r[r_offset_first_sha256 + 8] = (sha256_hash[2] >> 24) & 0xFF;
    r[r_offset_first_sha256 + 9] = (sha256_hash[2] >> 16) & 0xFF;
    r[r_offset_first_sha256 + 10] = (sha256_hash[2] >> 8) & 0xFF;
    r[r_offset_first_sha256 + 11] = (sha256_hash[2] >> 0) & 0xFF;

    r[r_offset_first_sha256 + 12] = (sha256_hash[3] >> 24) & 0xFF;
    r[r_offset_first_sha256 + 13] = (sha256_hash[3] >> 16) & 0xFF;
    r[r_offset_first_sha256 + 14] = (sha256_hash[3] >> 8) & 0xFF;
    r[r_offset_first_sha256 + 15] = (sha256_hash[3] >> 0) & 0xFF;

    r[r_offset_first_sha256 + 16] = (sha256_hash[4] >> 24) & 0xFF;
    r[r_offset_first_sha256 + 17] = (sha256_hash[4] >> 16) & 0xFF;
    r[r_offset_first_sha256 + 18] = (sha256_hash[4] >> 8) & 0xFF;
    r[r_offset_first_sha256 + 19] = (sha256_hash[4] >> 0) & 0xFF;

    r[r_offset_first_sha256 + 20] = (sha256_hash[5] >> 24) & 0xFF;
    r[r_offset_first_sha256 + 21] = (sha256_hash[5] >> 16) & 0xFF;
    r[r_offset_first_sha256 + 22] = (sha256_hash[5] >> 8) & 0xFF;
    r[r_offset_first_sha256 + 23] = (sha256_hash[5] >> 0) & 0xFF;

    r[r_offset_first_sha256 + 24] = (sha256_hash[6] >> 24) & 0xFF;
    r[r_offset_first_sha256 + 25] = (sha256_hash[6] >> 16) & 0xFF;
    r[r_offset_first_sha256 + 26] = (sha256_hash[6] >> 8) & 0xFF;
    r[r_offset_first_sha256 + 27] = (sha256_hash[6] >> 0) & 0xFF;

    r[r_offset_first_sha256 + 28] = (sha256_hash[7] >> 24) & 0xFF;
    r[r_offset_first_sha256 + 29] = (sha256_hash[7] >> 16) & 0xFF;
    r[r_offset_first_sha256 + 30] = (sha256_hash[7] >> 8) & 0xFF;
    r[r_offset_first_sha256 + 31] = (sha256_hash[7] >> 0) & 0xFF;


    // hash the SHA-256 result with RIPEMD-160
    calculate_ripemd160_from_u32(sha256_hash, ripemd160_hash);

    int r_offset_ripemd160 = r_offset_first_sha256 + SHA256_HASH_BYTES_LEN;

    // write bytes of u32 array storing ripemd160_hash into result buffer
    r[r_offset_ripemd160 + 0] = (ripemd160_hash[0] >> 0) & 0xFF;
    r[r_offset_ripemd160 + 1] = (ripemd160_hash[0] >> 8) & 0xFF;
    r[r_offset_ripemd160 + 2] = (ripemd160_hash[0] >> 16) & 0xFF;
    r[r_offset_ripemd160 + 3] = (ripemd160_hash[0] >> 24) & 0xFF;

    r[r_offset_ripemd160 + 4] = (ripemd160_hash[1] >> 0) & 0xFF;
    r[r_offset_ripemd160 + 5] = (ripemd160_hash[1] >> 8) & 0xFF;
    r[r_offset_ripemd160 + 6] = (ripemd160_hash[1] >> 16) & 0xFF;
    r[r_offset_ripemd160 + 7] = (ripemd160_hash[1] >> 24) & 0xFF;

    r[r_offset_ripemd160 + 8] = (ripemd160_hash[2] >> 0) & 0xFF;
    r[r_offset_ripemd160 + 9] = (ripemd160_hash[2] >> 8) & 0xFF;
    r[r_offset_ripemd160 + 10] = (ripemd160_hash[2] >> 16) & 0xFF;
    r[r_offset_ripemd160 + 11] = (ripemd160_hash[2] >> 24) & 0xFF;

    r[r_offset_ripemd160 + 12] = (ripemd160_hash[3] >> 0) & 0xFF;
    r[r_offset_ripemd160 + 13] = (ripemd160_hash[3] >> 8) & 0xFF;
    r[r_offset_ripemd160 + 14] = (ripemd160_hash[3] >> 16) & 0xFF;
    r[r_offset_ripemd160 + 15] = (ripemd160_hash[3] >> 24) & 0xFF;

    r[r_offset_ripemd160 + 16] = (ripemd160_hash[4] >> 0) & 0xFF;
    r[r_offset_ripemd160 + 17] = (ripemd160_hash[4] >> 8) & 0xFF;
    r[r_offset_ripemd160 + 18] = (ripemd160_hash[4] >> 16) & 0xFF;
    r[r_offset_ripemd160 + 19] = (ripemd160_hash[4] >> 24) & 0xFF;


    // version = 0x00 + RIPEMD-160 hash
    version[0] = RIPEMD160_HASH_VERSION_BYTE;

    version[1] = (ripemd160_hash[0] >> 0) & 0xFF;
    version[2] = (ripemd160_hash[0] >> 8) & 0xFF;
    version[3] = (ripemd160_hash[0] >> 16) & 0xFF;
    version[4] = (ripemd160_hash[0] >> 24) & 0xFF;

    version[5] = (ripemd160_hash[1] >> 0) & 0xFF;
    version[6] = (ripemd160_hash[1] >> 8) & 0xFF;
    version[7] = (ripemd160_hash[1] >> 16) & 0xFF;
    version[8] = (ripemd160_hash[1] >> 24) & 0xFF;

    version[9] = (ripemd160_hash[2] >> 0) & 0xFF;
    version[10] = (ripemd160_hash[2] >> 8) & 0xFF;
    version[11] = (ripemd160_hash[2] >> 16) & 0xFF;
    version[12] = (ripemd160_hash[2] >> 24) & 0xFF;

    version[13] = (ripemd160_hash[3] >> 0) & 0xFF;
    version[14] = (ripemd160_hash[3] >> 8) & 0xFF;
    version[15] = (ripemd160_hash[3] >> 16) & 0xFF;
    version[16] = (ripemd160_hash[3] >> 24) & 0xFF;

    version[17] = (ripemd160_hash[4] >> 0) & 0xFF;
    version[18] = (ripemd160_hash[4] >> 8) & 0xFF;
    version[19] = (ripemd160_hash[4] >> 16) & 0xFF;
    version[20] = (ripemd160_hash[4] >> 24) & 0xFF;

    // hash the RIPEMD-160 hash incl version byte with SHA-256
    calculate_sha256_from_version(version, second_sha256_hash);

    int r_offset_second_sha256 = r_offset_ripemd160 + RIPEMD160_HASH_BYTES;

    // write bytes of u32 array storing second SHA-256 hash into result buffer
    r[r_offset_second_sha256 + 0] = (second_sha256_hash[0] >> 24) & 0xFF;
    r[r_offset_second_sha256 + 1] = (second_sha256_hash[0] >> 16) & 0xFF;
    r[r_offset_second_sha256 + 2] = (second_sha256_hash[0] >> 8) & 0xFF;
    r[r_offset_second_sha256 + 3] = (second_sha256_hash[0] >> 0) & 0xFF;

    r[r_offset_second_sha256 + 4] = (second_sha256_hash[1] >> 24) & 0xFF;
    r[r_offset_second_sha256 + 5] = (second_sha256_hash[1] >> 16) & 0xFF;
    r[r_offset_second_sha256 + 6] = (second_sha256_hash[1] >> 8) & 0xFF;
    r[r_offset_second_sha256 + 7] = (second_sha256_hash[1] >> 0) & 0xFF;

    r[r_offset_second_sha256 + 8] = (second_sha256_hash[2] >> 24) & 0xFF;
    r[r_offset_second_sha256 + 9] = (second_sha256_hash[2] >> 16) & 0xFF;
    r[r_offset_second_sha256 + 10] = (second_sha256_hash[2] >> 8) & 0xFF;
    r[r_offset_second_sha256 + 11] = (second_sha256_hash[2] >> 0) & 0xFF;

    r[r_offset_second_sha256 + 12] = (second_sha256_hash[3] >> 24) & 0xFF;
    r[r_offset_second_sha256 + 13] = (second_sha256_hash[3] >> 16) & 0xFF;
    r[r_offset_second_sha256 + 14] = (second_sha256_hash[3] >> 8) & 0xFF;
    r[r_offset_second_sha256 + 15] = (second_sha256_hash[3] >> 0) & 0xFF;

    r[r_offset_second_sha256 + 16] = (second_sha256_hash[4] >> 24) & 0xFF;
    r[r_offset_second_sha256 + 17] = (second_sha256_hash[4] >> 16) & 0xFF;
    r[r_offset_second_sha256 + 18] = (second_sha256_hash[4] >> 8) & 0xFF;
    r[r_offset_second_sha256 + 19] = (second_sha256_hash[4] >> 0) & 0xFF;

    r[r_offset_second_sha256 + 20] = (second_sha256_hash[5] >> 24) & 0xFF;
    r[r_offset_second_sha256 + 21] = (second_sha256_hash[5] >> 16) & 0xFF;
    r[r_offset_second_sha256 + 22] = (second_sha256_hash[5] >> 8) & 0xFF;
    r[r_offset_second_sha256 + 23] = (second_sha256_hash[5] >> 0) & 0xFF;

    r[r_offset_second_sha256 + 24] = (second_sha256_hash[6] >> 24) & 0xFF;
    r[r_offset_second_sha256 + 25] = (second_sha256_hash[6] >> 16) & 0xFF;
    r[r_offset_second_sha256 + 26] = (second_sha256_hash[6] >> 8) & 0xFF;
    r[r_offset_second_sha256 + 27] = (second_sha256_hash[6] >> 0) & 0xFF;

    r[r_offset_second_sha256 + 28] = (second_sha256_hash[7] >> 24) & 0xFF;
    r[r_offset_second_sha256 + 29] = (second_sha256_hash[7] >> 16) & 0xFF;
    r[r_offset_second_sha256 + 30] = (second_sha256_hash[7] >> 8) & 0xFF;
    r[r_offset_second_sha256 + 31] = (second_sha256_hash[7] >> 0) & 0xFF;


    // hash the SHA-256 hash with SHA-256
    calculate_sha256_from_sha256(second_sha256_hash, third_sha256_hash);

    int r_offset_third_sha256 = r_offset_second_sha256 + SHA256_HASH_BYTES_LEN;

    // write bytes of u32 array storing third SHA-256 hash into result buffer
    r[r_offset_third_sha256 + 0] = (third_sha256_hash[0] >> 24) & 0xFF;
    r[r_offset_third_sha256 + 1] = (third_sha256_hash[0] >> 16) & 0xFF;
    r[r_offset_third_sha256 + 2] = (third_sha256_hash[0] >> 8) & 0xFF;
    r[r_offset_third_sha256 + 3] = (third_sha256_hash[0] >> 0) & 0xFF;

    r[r_offset_third_sha256 + 4] = (third_sha256_hash[1] >> 24) & 0xFF;
    r[r_offset_third_sha256 + 5] = (third_sha256_hash[1] >> 16) & 0xFF;
    r[r_offset_third_sha256 + 6] = (third_sha256_hash[1] >> 8) & 0xFF;
    r[r_offset_third_sha256 + 7] = (third_sha256_hash[1] >> 0) & 0xFF;

    r[r_offset_third_sha256 + 8] = (third_sha256_hash[2] >> 24) & 0xFF;
    r[r_offset_third_sha256 + 9] = (third_sha256_hash[2] >> 16) & 0xFF;
    r[r_offset_third_sha256 + 10] = (third_sha256_hash[2] >> 8) & 0xFF;
    r[r_offset_third_sha256 + 11] = (third_sha256_hash[2] >> 0) & 0xFF;

    r[r_offset_third_sha256 + 12] = (third_sha256_hash[3] >> 24) & 0xFF;
    r[r_offset_third_sha256 + 13] = (third_sha256_hash[3] >> 16) & 0xFF;
    r[r_offset_third_sha256 + 14] = (third_sha256_hash[3] >> 8) & 0xFF;
    r[r_offset_third_sha256 + 15] = (third_sha256_hash[3] >> 0) & 0xFF;

    r[r_offset_third_sha256 + 16] = (third_sha256_hash[4] >> 24) & 0xFF;
    r[r_offset_third_sha256 + 17] = (third_sha256_hash[4] >> 16) & 0xFF;
    r[r_offset_third_sha256 + 18] = (third_sha256_hash[4] >> 8) & 0xFF;
    r[r_offset_third_sha256 + 19] = (third_sha256_hash[4] >> 0) & 0xFF;

    r[r_offset_third_sha256 + 20] = (third_sha256_hash[5] >> 24) & 0xFF;
    r[r_offset_third_sha256 + 21] = (third_sha256_hash[5] >> 16) & 0xFF;
    r[r_offset_third_sha256 + 22] = (third_sha256_hash[5] >> 8) & 0xFF;
    r[r_offset_third_sha256 + 23] = (third_sha256_hash[5] >> 0) & 0xFF;

    r[r_offset_third_sha256 + 24] = (third_sha256_hash[6] >> 24) & 0xFF;
    r[r_offset_third_sha256 + 25] = (third_sha256_hash[6] >> 16) & 0xFF;
    r[r_offset_third_sha256 + 26] = (third_sha256_hash[6] >> 8) & 0xFF;
    r[r_offset_third_sha256 + 27] = (third_sha256_hash[6] >> 0) & 0xFF;

    r[r_offset_third_sha256 + 28] = (third_sha256_hash[7] >> 24) & 0xFF;
    r[r_offset_third_sha256 + 29] = (third_sha256_hash[7] >> 16) & 0xFF;
    r[r_offset_third_sha256 + 30] = (third_sha256_hash[7] >> 8) & 0xFF;
    r[r_offset_third_sha256 + 31] = (third_sha256_hash[7] >> 0) & 0xFF;

    // write bytes of uchar array storing RIPEMD-160 hash with version byte into address array
    address[0] = version[0];

    address[1] = version[1];
    address[2] = version[2];
    address[3] = version[3];
    address[4] = version[4];

    address[5] = version[5];
    address[6] = version[6];
    address[7] = version[7];
    address[8] = version[8];

    address[9] = version[9];
    address[10] = version[10];
    address[11] = version[11];
    address[12] = version[12];

    address[13] = version[13];
    address[14] = version[14];
    address[15] = version[15];
    address[16] = version[16];

    address[17] = version[17];
    address[18] = version[18];
    address[19] = version[19];
    address[20] = version[20];

    // write first four bytes of uchar array storing third SHA-256 hash into address array
    address[21] = (third_sha256_hash[0] >> 24) & 0xFF;
    address[22] = (third_sha256_hash[0] >> 16) & 0xFF;
    address[23] = (third_sha256_hash[0] >> 8) & 0xFF;
    address[24] = (third_sha256_hash[0] >> 0) & 0xFF;

    int r_offset_address = r_offset_third_sha256 + SHA256_HASH_BYTES_LEN;

    // write bytes of uchar array storing address bytes into result buffer
    r[r_offset_address + 0] = address[0];
    r[r_offset_address + 1] = address[1];
    r[r_offset_address + 2] = address[2];
    r[r_offset_address + 3] = address[3];
    r[r_offset_address + 4] = address[4];

    r[r_offset_address + 5] = address[5];
    r[r_offset_address + 6] = address[6];
    r[r_offset_address + 7] = address[7];
    r[r_offset_address + 8] = address[8];
    r[r_offset_address + 9] = address[9];

    r[r_offset_address + 10] = address[10];
    r[r_offset_address + 11] = address[11];
    r[r_offset_address + 12] = address[12];
    r[r_offset_address + 13] = address[13];
    r[r_offset_address + 14] = address[14];

    r[r_offset_address + 15] = address[15];
    r[r_offset_address + 16] = address[16];
    r[r_offset_address + 17] = address[17];
    r[r_offset_address + 18] = address[18];
    r[r_offset_address + 19] = address[19];

    r[r_offset_address + 20] = address[20];
    r[r_offset_address + 21] = address[21];
    r[r_offset_address + 22] = address[22];
    r[r_offset_address + 23] = address[23];
    r[r_offset_address + 24] = address[24];
}

/*
 * Calculates the public key from given private key,
 * then hashes it with SHA-256, RIPEMD-160, adds version byte and then hashes it again
 * with SHA-256 two times. Then assembles the address.
 *
 * OUTPUT uchar *r: Pointer to the result buffer to store all results
 * INPUT u32 *k:    Pointer to the private key buffer storing all private keys
 */
__kernel void generate_until_address(__global uchar *r, __global const u32 *k){

    u32 k_local_u32[PRIVATE_KEY_LENGTH];
    u32 x_local_u32[PUBLIC_KEY_ONE_COORDINATE_LENGTH];
    u32 y_local_u32[PUBLIC_KEY_ONE_COORDINATE_LENGTH];
    uchar public_key_bytes[PUBLIC_KEY_BYTES_WITH_PARITY];
    secp256k1_t g_xy_local;

    // to store the results of the SHA-256 and RIPEMD-160 hashes
    u32 sha256_hash[SHA256_HASH_U32_LEN];
    u32 ripemd160_hash[RIPEMD160_HASH_U32_LEN];
    uchar version[RIPEMD160_HASH_WITH_VERSION_BYTES];
    u32 second_sha256_hash[SHA256_HASH_U32_LEN];
    u32 third_sha256_hash[SHA256_HASH_U32_LEN];
    uchar address[ADDRESS_BYTES_LEN];

    // id of current work item
    int work_item_id = get_global_id(0);

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

    // calculating the public key coordinates
    set_precomputed_basepoint_g(&g_xy_local);
    point_mul_xy(x_local_u32, y_local_u32, k_local_u32, &g_xy_local);


    // calculating offset to write results in byte buffer
    int r_offset_bytes_private_key = (PRIVATE_KEY_BYTES + PUBLIC_KEY_BYTES_WITH_PARITY + SHA256_HASH_BYTES_LEN + RIPEMD160_HASH_BYTES + SHA256_HASH_BYTES_LEN + SHA256_HASH_BYTES_LEN + ADDRESS_BYTES_LEN) * work_item_id;

    // write bytes of u32 array storing private key into result buffer
    r[r_offset_bytes_private_key + 0] = (k_local_u32[7] >> 24) & 0xFF;
    r[r_offset_bytes_private_key + 1] = (k_local_u32[7] >> 16) & 0xFF;
    r[r_offset_bytes_private_key + 2] = (k_local_u32[7] >> 8) & 0xFF;
    r[r_offset_bytes_private_key + 3] = (k_local_u32[7] >> 0) & 0xFF;

    r[r_offset_bytes_private_key + 4] = (k_local_u32[6] >> 24) & 0xFF;
    r[r_offset_bytes_private_key + 5] = (k_local_u32[6] >> 16) & 0xFF;
    r[r_offset_bytes_private_key + 6] = (k_local_u32[6] >> 8) & 0xFF;
    r[r_offset_bytes_private_key + 7] = (k_local_u32[6] >> 0) & 0xFF;

    r[r_offset_bytes_private_key + 8] = (k_local_u32[5] >> 24) & 0xFF;
    r[r_offset_bytes_private_key + 9] = (k_local_u32[5] >> 16) & 0xFF;
    r[r_offset_bytes_private_key + 10] = (k_local_u32[5] >> 8) & 0xFF;
    r[r_offset_bytes_private_key + 11] = (k_local_u32[5] >> 0) & 0xFF;

    r[r_offset_bytes_private_key + 12] = (k_local_u32[4] >> 24) & 0xFF;
    r[r_offset_bytes_private_key + 13] = (k_local_u32[4] >> 16) & 0xFF;
    r[r_offset_bytes_private_key + 14] = (k_local_u32[4] >> 8) & 0xFF;
    r[r_offset_bytes_private_key + 15] = (k_local_u32[4] >> 0) & 0xFF;

    r[r_offset_bytes_private_key + 16] = (k_local_u32[3] >> 24) & 0xFF;
    r[r_offset_bytes_private_key + 17] = (k_local_u32[3] >> 16) & 0xFF;
    r[r_offset_bytes_private_key + 18] = (k_local_u32[3] >> 8) & 0xFF;
    r[r_offset_bytes_private_key + 19] = (k_local_u32[3] >> 0) & 0xFF;

    r[r_offset_bytes_private_key + 20] = (k_local_u32[2] >> 24) & 0xFF;
    r[r_offset_bytes_private_key + 21] = (k_local_u32[2] >> 16) & 0xFF;
    r[r_offset_bytes_private_key + 22] = (k_local_u32[2] >> 8) & 0xFF;
    r[r_offset_bytes_private_key + 23] = (k_local_u32[2] >> 0) & 0xFF;

    r[r_offset_bytes_private_key + 24] = (k_local_u32[1] >> 24) & 0xFF;
    r[r_offset_bytes_private_key + 25] = (k_local_u32[1] >> 16) & 0xFF;
    r[r_offset_bytes_private_key + 26] = (k_local_u32[1] >> 8) & 0xFF;
    r[r_offset_bytes_private_key + 27] = (k_local_u32[1] >> 0) & 0xFF;

    r[r_offset_bytes_private_key + 28] = (k_local_u32[0] >> 24) & 0xFF;
    r[r_offset_bytes_private_key + 29] = (k_local_u32[0] >> 16) & 0xFF;
    r[r_offset_bytes_private_key + 30] = (k_local_u32[0] >> 8) & 0xFF;
    r[r_offset_bytes_private_key + 31] = (k_local_u32[0] >> 0) & 0xFF;


    // creating the public key from coordinates and parity byte for hashing
    create_public_key_from_coordinates(public_key_bytes, x_local_u32, y_local_u32);

    int r_offset_public_key = r_offset_bytes_private_key + PRIVATE_KEY_BYTES;

    // write public key parity byte into result buffer
    r[r_offset_public_key + 0] = 0x04;

    // write bytes of u32 array storing x coordinate into result buffer
    r[r_offset_public_key + 1] = (x_local_u32[7] >> 24) & 0xFF;
    r[r_offset_public_key + 2] = (x_local_u32[7] >> 16) & 0xFF;
    r[r_offset_public_key + 3] = (x_local_u32[7] >> 8) & 0xFF;
    r[r_offset_public_key + 4] = (x_local_u32[7] >> 0) & 0xFF;

    r[r_offset_public_key + 5] = (x_local_u32[6] >> 24) & 0xFF;
    r[r_offset_public_key + 6] = (x_local_u32[6] >> 16) & 0xFF;
    r[r_offset_public_key + 7] = (x_local_u32[6] >> 8) & 0xFF;
    r[r_offset_public_key + 8] = (x_local_u32[6] >> 0) & 0xFF;

    r[r_offset_public_key + 9] = (x_local_u32[5] >> 24) & 0xFF;
    r[r_offset_public_key + 10] = (x_local_u32[5] >> 16) & 0xFF;
    r[r_offset_public_key + 11] = (x_local_u32[5] >> 8) & 0xFF;
    r[r_offset_public_key + 12] = (x_local_u32[5] >> 0) & 0xFF;

    r[r_offset_public_key + 13] = (x_local_u32[4] >> 24) & 0xFF;
    r[r_offset_public_key + 14] = (x_local_u32[4] >> 16) & 0xFF;
    r[r_offset_public_key + 15] = (x_local_u32[4] >> 8) & 0xFF;
    r[r_offset_public_key + 16] = (x_local_u32[4] >> 0) & 0xFF;

    r[r_offset_public_key + 17] = (x_local_u32[3] >> 24) & 0xFF;
    r[r_offset_public_key + 18] = (x_local_u32[3] >> 16) & 0xFF;
    r[r_offset_public_key + 19] = (x_local_u32[3] >> 8) & 0xFF;
    r[r_offset_public_key + 20] = (x_local_u32[3] >> 0) & 0xFF;

    r[r_offset_public_key + 21] = (x_local_u32[2] >> 24) & 0xFF;
    r[r_offset_public_key + 22] = (x_local_u32[2] >> 16) & 0xFF;
    r[r_offset_public_key + 23] = (x_local_u32[2] >> 8) & 0xFF;
    r[r_offset_public_key + 24] = (x_local_u32[2] >> 0) & 0xFF;

    r[r_offset_public_key + 25] = (x_local_u32[1] >> 24) & 0xFF;
    r[r_offset_public_key + 26] = (x_local_u32[1] >> 16) & 0xFF;
    r[r_offset_public_key + 27] = (x_local_u32[1] >> 8) & 0xFF;
    r[r_offset_public_key + 28] = (x_local_u32[1] >> 0) & 0xFF;

    r[r_offset_public_key + 29] = (x_local_u32[0] >> 24) & 0xFF;
    r[r_offset_public_key + 30] = (x_local_u32[0] >> 16) & 0xFF;
    r[r_offset_public_key + 31] = (x_local_u32[0] >> 8) & 0xFF;
    r[r_offset_public_key + 32] = (x_local_u32[0] >> 0) & 0xFF;

    // write bytes of u32 array storing y coordinate into result buffer
    r[r_offset_public_key + 33] = (y_local_u32[7] >> 24) & 0xFF;
    r[r_offset_public_key + 34] = (y_local_u32[7] >> 16) & 0xFF;
    r[r_offset_public_key + 35] = (y_local_u32[7] >> 8) & 0xFF;
    r[r_offset_public_key + 36] = (y_local_u32[7] >> 0) & 0xFF;

    r[r_offset_public_key + 37] = (y_local_u32[6] >> 24) & 0xFF;
    r[r_offset_public_key + 38] = (y_local_u32[6] >> 16) & 0xFF;
    r[r_offset_public_key + 39] = (y_local_u32[6] >> 8) & 0xFF;
    r[r_offset_public_key + 40] = (y_local_u32[6] >> 0) & 0xFF;

    r[r_offset_public_key + 41] = (y_local_u32[5] >> 24) & 0xFF;
    r[r_offset_public_key + 42] = (y_local_u32[5] >> 16) & 0xFF;
    r[r_offset_public_key + 43] = (y_local_u32[5] >> 8) & 0xFF;
    r[r_offset_public_key + 44] = (y_local_u32[5] >> 0) & 0xFF;

    r[r_offset_public_key + 45] = (y_local_u32[4] >> 24) & 0xFF;
    r[r_offset_public_key + 46] = (y_local_u32[4] >> 16) & 0xFF;
    r[r_offset_public_key + 47] = (y_local_u32[4] >> 8) & 0xFF;
    r[r_offset_public_key + 48] = (y_local_u32[4] >> 0) & 0xFF;

    r[r_offset_public_key + 49] = (y_local_u32[3] >> 24) & 0xFF;
    r[r_offset_public_key + 50] = (y_local_u32[3] >> 16) & 0xFF;
    r[r_offset_public_key + 51] = (y_local_u32[3] >> 8) & 0xFF;
    r[r_offset_public_key + 52] = (y_local_u32[3] >> 0) & 0xFF;

    r[r_offset_public_key + 53] = (y_local_u32[2] >> 24) & 0xFF;
    r[r_offset_public_key + 54] = (y_local_u32[2] >> 16) & 0xFF;
    r[r_offset_public_key + 55] = (y_local_u32[2] >> 8) & 0xFF;
    r[r_offset_public_key + 56] = (y_local_u32[2] >> 0) & 0xFF;

    r[r_offset_public_key + 57] = (y_local_u32[1] >> 24) & 0xFF;
    r[r_offset_public_key + 58] = (y_local_u32[1] >> 16) & 0xFF;
    r[r_offset_public_key + 59] = (y_local_u32[1] >> 8) & 0xFF;
    r[r_offset_public_key + 60] = (y_local_u32[1] >> 0) & 0xFF;

    r[r_offset_public_key + 61] = (y_local_u32[0] >> 24) & 0xFF;
    r[r_offset_public_key + 62] = (y_local_u32[0] >> 16) & 0xFF;
    r[r_offset_public_key + 63] = (y_local_u32[0] >> 8) & 0xFF;
    r[r_offset_public_key + 64] = (y_local_u32[0] >> 0) & 0xFF;


    // hash the public key with SHA-256
    calculate_sha256_from_public_key(public_key_bytes, sha256_hash);

    int r_offset_first_sha256 = r_offset_public_key + PUBLIC_KEY_BYTES_WITH_PARITY;

    // write bytes of u32 array storing sha256_hash into result buffer
    r[r_offset_first_sha256 + 0] = (sha256_hash[0] >> 24) & 0xFF;
    r[r_offset_first_sha256 + 1] = (sha256_hash[0] >> 16) & 0xFF;
    r[r_offset_first_sha256 + 2] = (sha256_hash[0] >> 8) & 0xFF;
    r[r_offset_first_sha256 + 3] = (sha256_hash[0] >> 0) & 0xFF;

    r[r_offset_first_sha256 + 4] = (sha256_hash[1] >> 24) & 0xFF;
    r[r_offset_first_sha256 + 5] = (sha256_hash[1] >> 16) & 0xFF;
    r[r_offset_first_sha256 + 6] = (sha256_hash[1] >> 8) & 0xFF;
    r[r_offset_first_sha256 + 7] = (sha256_hash[1] >> 0) & 0xFF;

    r[r_offset_first_sha256 + 8] = (sha256_hash[2] >> 24) & 0xFF;
    r[r_offset_first_sha256 + 9] = (sha256_hash[2] >> 16) & 0xFF;
    r[r_offset_first_sha256 + 10] = (sha256_hash[2] >> 8) & 0xFF;
    r[r_offset_first_sha256 + 11] = (sha256_hash[2] >> 0) & 0xFF;

    r[r_offset_first_sha256 + 12] = (sha256_hash[3] >> 24) & 0xFF;
    r[r_offset_first_sha256 + 13] = (sha256_hash[3] >> 16) & 0xFF;
    r[r_offset_first_sha256 + 14] = (sha256_hash[3] >> 8) & 0xFF;
    r[r_offset_first_sha256 + 15] = (sha256_hash[3] >> 0) & 0xFF;

    r[r_offset_first_sha256 + 16] = (sha256_hash[4] >> 24) & 0xFF;
    r[r_offset_first_sha256 + 17] = (sha256_hash[4] >> 16) & 0xFF;
    r[r_offset_first_sha256 + 18] = (sha256_hash[4] >> 8) & 0xFF;
    r[r_offset_first_sha256 + 19] = (sha256_hash[4] >> 0) & 0xFF;

    r[r_offset_first_sha256 + 20] = (sha256_hash[5] >> 24) & 0xFF;
    r[r_offset_first_sha256 + 21] = (sha256_hash[5] >> 16) & 0xFF;
    r[r_offset_first_sha256 + 22] = (sha256_hash[5] >> 8) & 0xFF;
    r[r_offset_first_sha256 + 23] = (sha256_hash[5] >> 0) & 0xFF;

    r[r_offset_first_sha256 + 24] = (sha256_hash[6] >> 24) & 0xFF;
    r[r_offset_first_sha256 + 25] = (sha256_hash[6] >> 16) & 0xFF;
    r[r_offset_first_sha256 + 26] = (sha256_hash[6] >> 8) & 0xFF;
    r[r_offset_first_sha256 + 27] = (sha256_hash[6] >> 0) & 0xFF;

    r[r_offset_first_sha256 + 28] = (sha256_hash[7] >> 24) & 0xFF;
    r[r_offset_first_sha256 + 29] = (sha256_hash[7] >> 16) & 0xFF;
    r[r_offset_first_sha256 + 30] = (sha256_hash[7] >> 8) & 0xFF;
    r[r_offset_first_sha256 + 31] = (sha256_hash[7] >> 0) & 0xFF;


    // hash the SHA-256 result with RIPEMD-160
    calculate_ripemd160_from_u32(sha256_hash, ripemd160_hash);

    int r_offset_ripemd160 = r_offset_first_sha256 + SHA256_HASH_BYTES_LEN;

    // write bytes of u32 array storing ripemd160_hash into result buffer
    r[r_offset_ripemd160 + 0] = (ripemd160_hash[0] >> 0) & 0xFF;
    r[r_offset_ripemd160 + 1] = (ripemd160_hash[0] >> 8) & 0xFF;
    r[r_offset_ripemd160 + 2] = (ripemd160_hash[0] >> 16) & 0xFF;
    r[r_offset_ripemd160 + 3] = (ripemd160_hash[0] >> 24) & 0xFF;

    r[r_offset_ripemd160 + 4] = (ripemd160_hash[1] >> 0) & 0xFF;
    r[r_offset_ripemd160 + 5] = (ripemd160_hash[1] >> 8) & 0xFF;
    r[r_offset_ripemd160 + 6] = (ripemd160_hash[1] >> 16) & 0xFF;
    r[r_offset_ripemd160 + 7] = (ripemd160_hash[1] >> 24) & 0xFF;

    r[r_offset_ripemd160 + 8] = (ripemd160_hash[2] >> 0) & 0xFF;
    r[r_offset_ripemd160 + 9] = (ripemd160_hash[2] >> 8) & 0xFF;
    r[r_offset_ripemd160 + 10] = (ripemd160_hash[2] >> 16) & 0xFF;
    r[r_offset_ripemd160 + 11] = (ripemd160_hash[2] >> 24) & 0xFF;

    r[r_offset_ripemd160 + 12] = (ripemd160_hash[3] >> 0) & 0xFF;
    r[r_offset_ripemd160 + 13] = (ripemd160_hash[3] >> 8) & 0xFF;
    r[r_offset_ripemd160 + 14] = (ripemd160_hash[3] >> 16) & 0xFF;
    r[r_offset_ripemd160 + 15] = (ripemd160_hash[3] >> 24) & 0xFF;

    r[r_offset_ripemd160 + 16] = (ripemd160_hash[4] >> 0) & 0xFF;
    r[r_offset_ripemd160 + 17] = (ripemd160_hash[4] >> 8) & 0xFF;
    r[r_offset_ripemd160 + 18] = (ripemd160_hash[4] >> 16) & 0xFF;
    r[r_offset_ripemd160 + 19] = (ripemd160_hash[4] >> 24) & 0xFF;


    // version = 0x00 + RIPEMD-160 hash
    version[0] = RIPEMD160_HASH_VERSION_BYTE;

    version[1] = (ripemd160_hash[0] >> 0) & 0xFF;
    version[2] = (ripemd160_hash[0] >> 8) & 0xFF;
    version[3] = (ripemd160_hash[0] >> 16) & 0xFF;
    version[4] = (ripemd160_hash[0] >> 24) & 0xFF;

    version[5] = (ripemd160_hash[1] >> 0) & 0xFF;
    version[6] = (ripemd160_hash[1] >> 8) & 0xFF;
    version[7] = (ripemd160_hash[1] >> 16) & 0xFF;
    version[8] = (ripemd160_hash[1] >> 24) & 0xFF;

    version[9] = (ripemd160_hash[2] >> 0) & 0xFF;
    version[10] = (ripemd160_hash[2] >> 8) & 0xFF;
    version[11] = (ripemd160_hash[2] >> 16) & 0xFF;
    version[12] = (ripemd160_hash[2] >> 24) & 0xFF;

    version[13] = (ripemd160_hash[3] >> 0) & 0xFF;
    version[14] = (ripemd160_hash[3] >> 8) & 0xFF;
    version[15] = (ripemd160_hash[3] >> 16) & 0xFF;
    version[16] = (ripemd160_hash[3] >> 24) & 0xFF;

    version[17] = (ripemd160_hash[4] >> 0) & 0xFF;
    version[18] = (ripemd160_hash[4] >> 8) & 0xFF;
    version[19] = (ripemd160_hash[4] >> 16) & 0xFF;
    version[20] = (ripemd160_hash[4] >> 24) & 0xFF;

    // hash the RIPEMD-160 hash incl version byte with SHA-256
    calculate_sha256_from_version(version, second_sha256_hash);

    int r_offset_second_sha256 = r_offset_ripemd160 + RIPEMD160_HASH_BYTES;

    // write bytes of u32 array storing second SHA-256 hash into result buffer
    r[r_offset_second_sha256 + 0] = (second_sha256_hash[0] >> 24) & 0xFF;
    r[r_offset_second_sha256 + 1] = (second_sha256_hash[0] >> 16) & 0xFF;
    r[r_offset_second_sha256 + 2] = (second_sha256_hash[0] >> 8) & 0xFF;
    r[r_offset_second_sha256 + 3] = (second_sha256_hash[0] >> 0) & 0xFF;

    r[r_offset_second_sha256 + 4] = (second_sha256_hash[1] >> 24) & 0xFF;
    r[r_offset_second_sha256 + 5] = (second_sha256_hash[1] >> 16) & 0xFF;
    r[r_offset_second_sha256 + 6] = (second_sha256_hash[1] >> 8) & 0xFF;
    r[r_offset_second_sha256 + 7] = (second_sha256_hash[1] >> 0) & 0xFF;

    r[r_offset_second_sha256 + 8] = (second_sha256_hash[2] >> 24) & 0xFF;
    r[r_offset_second_sha256 + 9] = (second_sha256_hash[2] >> 16) & 0xFF;
    r[r_offset_second_sha256 + 10] = (second_sha256_hash[2] >> 8) & 0xFF;
    r[r_offset_second_sha256 + 11] = (second_sha256_hash[2] >> 0) & 0xFF;

    r[r_offset_second_sha256 + 12] = (second_sha256_hash[3] >> 24) & 0xFF;
    r[r_offset_second_sha256 + 13] = (second_sha256_hash[3] >> 16) & 0xFF;
    r[r_offset_second_sha256 + 14] = (second_sha256_hash[3] >> 8) & 0xFF;
    r[r_offset_second_sha256 + 15] = (second_sha256_hash[3] >> 0) & 0xFF;

    r[r_offset_second_sha256 + 16] = (second_sha256_hash[4] >> 24) & 0xFF;
    r[r_offset_second_sha256 + 17] = (second_sha256_hash[4] >> 16) & 0xFF;
    r[r_offset_second_sha256 + 18] = (second_sha256_hash[4] >> 8) & 0xFF;
    r[r_offset_second_sha256 + 19] = (second_sha256_hash[4] >> 0) & 0xFF;

    r[r_offset_second_sha256 + 20] = (second_sha256_hash[5] >> 24) & 0xFF;
    r[r_offset_second_sha256 + 21] = (second_sha256_hash[5] >> 16) & 0xFF;
    r[r_offset_second_sha256 + 22] = (second_sha256_hash[5] >> 8) & 0xFF;
    r[r_offset_second_sha256 + 23] = (second_sha256_hash[5] >> 0) & 0xFF;

    r[r_offset_second_sha256 + 24] = (second_sha256_hash[6] >> 24) & 0xFF;
    r[r_offset_second_sha256 + 25] = (second_sha256_hash[6] >> 16) & 0xFF;
    r[r_offset_second_sha256 + 26] = (second_sha256_hash[6] >> 8) & 0xFF;
    r[r_offset_second_sha256 + 27] = (second_sha256_hash[6] >> 0) & 0xFF;

    r[r_offset_second_sha256 + 28] = (second_sha256_hash[7] >> 24) & 0xFF;
    r[r_offset_second_sha256 + 29] = (second_sha256_hash[7] >> 16) & 0xFF;
    r[r_offset_second_sha256 + 30] = (second_sha256_hash[7] >> 8) & 0xFF;
    r[r_offset_second_sha256 + 31] = (second_sha256_hash[7] >> 0) & 0xFF;


    // hash the SHA-256 hash with SHA-256
    calculate_sha256_from_sha256(second_sha256_hash, third_sha256_hash);

    int r_offset_third_sha256 = r_offset_second_sha256 + SHA256_HASH_BYTES_LEN;

    // write bytes of u32 array storing third SHA-256 hash into result buffer
    r[r_offset_third_sha256 + 0] = (third_sha256_hash[0] >> 24) & 0xFF;
    r[r_offset_third_sha256 + 1] = (third_sha256_hash[0] >> 16) & 0xFF;
    r[r_offset_third_sha256 + 2] = (third_sha256_hash[0] >> 8) & 0xFF;
    r[r_offset_third_sha256 + 3] = (third_sha256_hash[0] >> 0) & 0xFF;

    r[r_offset_third_sha256 + 4] = (third_sha256_hash[1] >> 24) & 0xFF;
    r[r_offset_third_sha256 + 5] = (third_sha256_hash[1] >> 16) & 0xFF;
    r[r_offset_third_sha256 + 6] = (third_sha256_hash[1] >> 8) & 0xFF;
    r[r_offset_third_sha256 + 7] = (third_sha256_hash[1] >> 0) & 0xFF;

    r[r_offset_third_sha256 + 8] = (third_sha256_hash[2] >> 24) & 0xFF;
    r[r_offset_third_sha256 + 9] = (third_sha256_hash[2] >> 16) & 0xFF;
    r[r_offset_third_sha256 + 10] = (third_sha256_hash[2] >> 8) & 0xFF;
    r[r_offset_third_sha256 + 11] = (third_sha256_hash[2] >> 0) & 0xFF;

    r[r_offset_third_sha256 + 12] = (third_sha256_hash[3] >> 24) & 0xFF;
    r[r_offset_third_sha256 + 13] = (third_sha256_hash[3] >> 16) & 0xFF;
    r[r_offset_third_sha256 + 14] = (third_sha256_hash[3] >> 8) & 0xFF;
    r[r_offset_third_sha256 + 15] = (third_sha256_hash[3] >> 0) & 0xFF;

    r[r_offset_third_sha256 + 16] = (third_sha256_hash[4] >> 24) & 0xFF;
    r[r_offset_third_sha256 + 17] = (third_sha256_hash[4] >> 16) & 0xFF;
    r[r_offset_third_sha256 + 18] = (third_sha256_hash[4] >> 8) & 0xFF;
    r[r_offset_third_sha256 + 19] = (third_sha256_hash[4] >> 0) & 0xFF;

    r[r_offset_third_sha256 + 20] = (third_sha256_hash[5] >> 24) & 0xFF;
    r[r_offset_third_sha256 + 21] = (third_sha256_hash[5] >> 16) & 0xFF;
    r[r_offset_third_sha256 + 22] = (third_sha256_hash[5] >> 8) & 0xFF;
    r[r_offset_third_sha256 + 23] = (third_sha256_hash[5] >> 0) & 0xFF;

    r[r_offset_third_sha256 + 24] = (third_sha256_hash[6] >> 24) & 0xFF;
    r[r_offset_third_sha256 + 25] = (third_sha256_hash[6] >> 16) & 0xFF;
    r[r_offset_third_sha256 + 26] = (third_sha256_hash[6] >> 8) & 0xFF;
    r[r_offset_third_sha256 + 27] = (third_sha256_hash[6] >> 0) & 0xFF;

    r[r_offset_third_sha256 + 28] = (third_sha256_hash[7] >> 24) & 0xFF;
    r[r_offset_third_sha256 + 29] = (third_sha256_hash[7] >> 16) & 0xFF;
    r[r_offset_third_sha256 + 30] = (third_sha256_hash[7] >> 8) & 0xFF;
    r[r_offset_third_sha256 + 31] = (third_sha256_hash[7] >> 0) & 0xFF;

    // write bytes of uchar array storing RIPEMD-160 hash with version byte into address array
    address[0] = version[0];

    address[1] = version[1];
    address[2] = version[2];
    address[3] = version[3];
    address[4] = version[4];

    address[5] = version[5];
    address[6] = version[6];
    address[7] = version[7];
    address[8] = version[8];

    address[9] = version[9];
    address[10] = version[10];
    address[11] = version[11];
    address[12] = version[12];

    address[13] = version[13];
    address[14] = version[14];
    address[15] = version[15];
    address[16] = version[16];

    address[17] = version[17];
    address[18] = version[18];
    address[19] = version[19];
    address[20] = version[20];

    // write first four bytes of uchar array storing third SHA-256 hash into address array
    address[21] = (third_sha256_hash[0] >> 24) & 0xFF;
    address[22] = (third_sha256_hash[0] >> 16) & 0xFF;
    address[23] = (third_sha256_hash[0] >> 8) & 0xFF;
    address[24] = (third_sha256_hash[0] >> 0) & 0xFF;

    int r_offset_address = r_offset_third_sha256 + SHA256_HASH_BYTES_LEN;

    // write bytes of uchar array storing address bytes into result buffer
    r[r_offset_address + 0] = address[0];
    r[r_offset_address + 1] = address[1];
    r[r_offset_address + 2] = address[2];
    r[r_offset_address + 3] = address[3];
    r[r_offset_address + 4] = address[4];

    r[r_offset_address + 5] = address[5];
    r[r_offset_address + 6] = address[6];
    r[r_offset_address + 7] = address[7];
    r[r_offset_address + 8] = address[8];
    r[r_offset_address + 9] = address[9];

    r[r_offset_address + 10] = address[10];
    r[r_offset_address + 11] = address[11];
    r[r_offset_address + 12] = address[12];
    r[r_offset_address + 13] = address[13];
    r[r_offset_address + 14] = address[14];

    r[r_offset_address + 15] = address[15];
    r[r_offset_address + 16] = address[16];
    r[r_offset_address + 17] = address[17];
    r[r_offset_address + 18] = address[18];
    r[r_offset_address + 19] = address[19];

    r[r_offset_address + 20] = address[20];
    r[r_offset_address + 21] = address[21];
    r[r_offset_address + 22] = address[22];
    r[r_offset_address + 23] = address[23];
    r[r_offset_address + 24] = address[24];
}

/*
 * "Creates" a new private key from a single private key and then calculates the public key,
 * hashes it with SHA-256, RIPEMD-160, adds version byte and then hashes it again
 * with SHA-256 two times. Then assembles the address and stores it in the given result buffer.
 *
 * OUTPUT uchar *r: Pointer to the result buffer storing all private keys and their addresses
 * INPUT u32 *k:    Pointer to the private key buffer storing a single private key
 */
__kernel void generate_address_chunk(__global uchar *r, __global const u32 *k){

    u32 k_local_u32[PRIVATE_KEY_LENGTH];
    u32 x_local_u32[PUBLIC_KEY_ONE_COORDINATE_LENGTH];
    u32 y_local_u32[PUBLIC_KEY_ONE_COORDINATE_LENGTH];
    uchar public_key_bytes[PUBLIC_KEY_BYTES_WITH_PARITY];
    secp256k1_t g_xy_local;

    // to store the results of the SHA-256 and RIPEMD-160 hashes
    u32 sha256_hash[SHA256_HASH_U32_LEN];
    u32 ripemd160_hash[RIPEMD160_HASH_U32_LEN];
    uchar version[RIPEMD160_HASH_WITH_VERSION_BYTES];
    u32 second_sha256_hash[SHA256_HASH_U32_LEN];
    u32 third_sha256_hash[SHA256_HASH_U32_LEN];
    uchar address[ADDRESS_BYTES_LEN];

    // id of current work item
    int work_item_id = get_global_id(0);

    // get first private key from private key grid and "create" a new one
    k_local_u32[0] = k[0] | work_item_id;
    k_local_u32[1] = k[1];
    k_local_u32[2] = k[2];
    k_local_u32[3] = k[3];
    k_local_u32[4] = k[4];
    k_local_u32[5] = k[5];
    k_local_u32[6] = k[6];
    k_local_u32[7] = k[7];

    // calculating the public key coordinates
    set_precomputed_basepoint_g(&g_xy_local);
    point_mul_xy(x_local_u32, y_local_u32, k_local_u32, &g_xy_local);

    // calculating offset to write results in byte buffer
    int r_offset_bytes_private_key = (PRIVATE_KEY_BYTES + ADDRESS_BYTES_LEN) * work_item_id;

    // write bytes of u32 array storing private key into result buffer
    r[r_offset_bytes_private_key + 0] = (k_local_u32[7] >> 24) & 0xFF;
    r[r_offset_bytes_private_key + 1] = (k_local_u32[7] >> 16) & 0xFF;
    r[r_offset_bytes_private_key + 2] = (k_local_u32[7] >> 8) & 0xFF;
    r[r_offset_bytes_private_key + 3] = (k_local_u32[7] >> 0) & 0xFF;

    r[r_offset_bytes_private_key + 4] = (k_local_u32[6] >> 24) & 0xFF;
    r[r_offset_bytes_private_key + 5] = (k_local_u32[6] >> 16) & 0xFF;
    r[r_offset_bytes_private_key + 6] = (k_local_u32[6] >> 8) & 0xFF;
    r[r_offset_bytes_private_key + 7] = (k_local_u32[6] >> 0) & 0xFF;

    r[r_offset_bytes_private_key + 8] = (k_local_u32[5] >> 24) & 0xFF;
    r[r_offset_bytes_private_key + 9] = (k_local_u32[5] >> 16) & 0xFF;
    r[r_offset_bytes_private_key + 10] = (k_local_u32[5] >> 8) & 0xFF;
    r[r_offset_bytes_private_key + 11] = (k_local_u32[5] >> 0) & 0xFF;

    r[r_offset_bytes_private_key + 12] = (k_local_u32[4] >> 24) & 0xFF;
    r[r_offset_bytes_private_key + 13] = (k_local_u32[4] >> 16) & 0xFF;
    r[r_offset_bytes_private_key + 14] = (k_local_u32[4] >> 8) & 0xFF;
    r[r_offset_bytes_private_key + 15] = (k_local_u32[4] >> 0) & 0xFF;

    r[r_offset_bytes_private_key + 16] = (k_local_u32[3] >> 24) & 0xFF;
    r[r_offset_bytes_private_key + 17] = (k_local_u32[3] >> 16) & 0xFF;
    r[r_offset_bytes_private_key + 18] = (k_local_u32[3] >> 8) & 0xFF;
    r[r_offset_bytes_private_key + 19] = (k_local_u32[3] >> 0) & 0xFF;

    r[r_offset_bytes_private_key + 20] = (k_local_u32[2] >> 24) & 0xFF;
    r[r_offset_bytes_private_key + 21] = (k_local_u32[2] >> 16) & 0xFF;
    r[r_offset_bytes_private_key + 22] = (k_local_u32[2] >> 8) & 0xFF;
    r[r_offset_bytes_private_key + 23] = (k_local_u32[2] >> 0) & 0xFF;

    r[r_offset_bytes_private_key + 24] = (k_local_u32[1] >> 24) & 0xFF;
    r[r_offset_bytes_private_key + 25] = (k_local_u32[1] >> 16) & 0xFF;
    r[r_offset_bytes_private_key + 26] = (k_local_u32[1] >> 8) & 0xFF;
    r[r_offset_bytes_private_key + 27] = (k_local_u32[1] >> 0) & 0xFF;

    r[r_offset_bytes_private_key + 28] = (k_local_u32[0] >> 24) & 0xFF;
    r[r_offset_bytes_private_key + 29] = (k_local_u32[0] >> 16) & 0xFF;
    r[r_offset_bytes_private_key + 30] = (k_local_u32[0] >> 8) & 0xFF;
    r[r_offset_bytes_private_key + 31] = (k_local_u32[0] >> 0) & 0xFF;

    // creating the public key from coordinates and parity byte for hashing
    create_public_key_from_coordinates(public_key_bytes, x_local_u32, y_local_u32);

    // hash the public key with SHA-256
    calculate_sha256_from_public_key(public_key_bytes, sha256_hash);

    // hash the SHA-256 result with RIPEMD-160
    calculate_ripemd160_from_u32(sha256_hash, ripemd160_hash);

    // version = 0x00 + RIPEMD-160 hash
    version[0] = RIPEMD160_HASH_VERSION_BYTE;

    version[1] = (ripemd160_hash[0] >> 0) & 0xFF;
    version[2] = (ripemd160_hash[0] >> 8) & 0xFF;
    version[3] = (ripemd160_hash[0] >> 16) & 0xFF;
    version[4] = (ripemd160_hash[0] >> 24) & 0xFF;

    version[5] = (ripemd160_hash[1] >> 0) & 0xFF;
    version[6] = (ripemd160_hash[1] >> 8) & 0xFF;
    version[7] = (ripemd160_hash[1] >> 16) & 0xFF;
    version[8] = (ripemd160_hash[1] >> 24) & 0xFF;

    version[9] = (ripemd160_hash[2] >> 0) & 0xFF;
    version[10] = (ripemd160_hash[2] >> 8) & 0xFF;
    version[11] = (ripemd160_hash[2] >> 16) & 0xFF;
    version[12] = (ripemd160_hash[2] >> 24) & 0xFF;

    version[13] = (ripemd160_hash[3] >> 0) & 0xFF;
    version[14] = (ripemd160_hash[3] >> 8) & 0xFF;
    version[15] = (ripemd160_hash[3] >> 16) & 0xFF;
    version[16] = (ripemd160_hash[3] >> 24) & 0xFF;

    version[17] = (ripemd160_hash[4] >> 0) & 0xFF;
    version[18] = (ripemd160_hash[4] >> 8) & 0xFF;
    version[19] = (ripemd160_hash[4] >> 16) & 0xFF;
    version[20] = (ripemd160_hash[4] >> 24) & 0xFF;

    // hash the RIPEMD-160 hash incl version byte with SHA-256
    calculate_sha256_from_version(version, second_sha256_hash);

    // hash the SHA-256 hash with SHA-256
    calculate_sha256_from_sha256(second_sha256_hash, third_sha256_hash);

    int r_offset_address = r_offset_bytes_private_key + PRIVATE_KEY_BYTES;

    // write bytes of uchar array storing address bytes into result buffer
    r[r_offset_address + 0] = version[0];
    r[r_offset_address + 1] = version[1];
    r[r_offset_address + 2] = version[2];
    r[r_offset_address + 3] = version[3];
    r[r_offset_address + 4] = version[4];

    r[r_offset_address + 5] = version[5];
    r[r_offset_address + 6] = version[6];
    r[r_offset_address + 7] = version[7];
    r[r_offset_address + 8] = version[8];
    r[r_offset_address + 9] = version[9];

    r[r_offset_address + 10] = version[10];
    r[r_offset_address + 11] = version[11];
    r[r_offset_address + 12] = version[12];
    r[r_offset_address + 13] = version[13];
    r[r_offset_address + 14] = version[14];

    r[r_offset_address + 15] = version[15];
    r[r_offset_address + 16] = version[16];
    r[r_offset_address + 17] = version[17];
    r[r_offset_address + 18] = version[18];
    r[r_offset_address + 19] = version[19];

    r[r_offset_address + 20] = version[20];
    r[r_offset_address + 21] = (third_sha256_hash[0] >> 24) & 0xFF;
    r[r_offset_address + 22] = (third_sha256_hash[0] >> 16) & 0xFF;
    r[r_offset_address + 23] = (third_sha256_hash[0] >> 8) & 0xFF;
    r[r_offset_address + 24] = (third_sha256_hash[0] >> 0) & 0xFF;
}