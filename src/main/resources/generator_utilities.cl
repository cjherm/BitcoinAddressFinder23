/**
 * Author......: Bernard Ladenthin & Christoph Hermann, 2023
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

__attribute__((always_inline)) void storeU32ToByteArray(const u32 *u32Array, const int numU32Elements, uchar *byteArray, const int byteArrayOffset);
__attribute__((always_inline)) void storeByteArrayToU32Array(const uchar *byteArray, u32 *u32Array, const uint arrayLength);
__attribute__((always_inline)) void create_public_key_from_coordinates(uchar *public_key_byte_array, const u32 *x_coordinate, const u32 *y_coordinate);
__attribute__((always_inline)) void sha256_padding(const uchar *input, const int numInputBytes, uchar *output, int *numOutputBytes);
__attribute__((always_inline)) void calculate_sha256_from_public_key(PRIVATE_AS const uchar *digest_bytes, u32 *sha256_hash);
__attribute__((always_inline)) void calculate_sha256_from_sha256(PRIVATE_AS const u32 *unpadded_digest_u32, u32 *sha256_hash);
__attribute__((always_inline)) void calculate_ripemd160_from_u32(u32 *sha256_hash, u32 *ripemd160_hash);

 /*
  * Calculates the RIPEMD-160 hash from a given digest.
  *
  * INPUT u32 *unpadded_digest_u32: Pointer to the digest as u32 array to be hashed
  * OUTPUT u32 *ripemd160_hash:     Pointer to the resulting hash as an u32 array
  */
__attribute__((always_inline)) void calculate_ripemd160_from_u32(u32 *unpadded_digest_u32, u32 *ripemd160_hash){

    // padded digest as u32 array (16x 32bit words or 512 bits)
    u32 padded_digest_u32[SINGLE_SIZED_SHA256_INPUT_U32];

    padded_digest_u32[0] = unpadded_digest_u32[0];
    padded_digest_u32[1] = unpadded_digest_u32[1];
    padded_digest_u32[2] = unpadded_digest_u32[2];
    padded_digest_u32[3] = unpadded_digest_u32[3];

    padded_digest_u32[4] = unpadded_digest_u32[4];
    padded_digest_u32[5] = unpadded_digest_u32[5];
    padded_digest_u32[6] = unpadded_digest_u32[6];
    padded_digest_u32[7] = unpadded_digest_u32[7];

    // begin of padding bits:
    // 2147483648 is in binary = 10000000 00000000 00000000 00000000
    padded_digest_u32[8] = 2147483648;
    padded_digest_u32[9] = 0;
    padded_digest_u32[10] = 0;
    padded_digest_u32[11] = 0;

    padded_digest_u32[12] = 0;
    padded_digest_u32[13] = 0;

    // begin of 64 length bits:
    // 65536 is in binary = 00000000 00000001 00000000 00000000
    // (little endian for 256 decimal length of initial digest)
    padded_digest_u32[14] = 65536;
    padded_digest_u32[15] = 0;

    ripemd160_ctx_t ctx;
    ripemd160_init(&ctx);
    ripemd160_update_swap(&ctx, padded_digest_u32, SINGLE_SIZED_SHA256_INPUT_BYTES);

    // store hash in output
    ripemd160_hash[0] = ctx.h[0];
    ripemd160_hash[1] = ctx.h[1];
    ripemd160_hash[2] = ctx.h[2];
    ripemd160_hash[3] = ctx.h[3];
    ripemd160_hash[4] = ctx.h[4];
}

 /*
  * Calculates the SHA-256 hash from a given digest.
  *
  * INPUT uchar *digest_bytes:  Pointer to the digest as byte array to be hashed
  * OUTPUT u32 *sha256_hash:     Pointer to the resulting hash as an u32 array
  */
__attribute__((always_inline)) void calculate_sha256_from_public_key(PRIVATE_AS const uchar *digest_bytes, u32 *sha256_hash) {

    // digest to be hashed
    u32 digest_u32[SHA256_HASH_BYTES_LEN];

    // padded byte array for correct sha256 digest length
    uchar padded_digest_bytes[DOUBLE_SIZED_SHA256_INPUT_BYTES];

    // size in bytes of the input to be hashed
    int padded_digest_size;

    // prepare hash
    sha256_padding(digest_bytes, PUBLIC_KEY_BYTES_WITH_PARITY, padded_digest_bytes, &padded_digest_size);
    storeByteArrayToU32Array(padded_digest_bytes, digest_u32, padded_digest_size);

    // perform hash
    sha256_ctx_t ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, digest_u32, padded_digest_size);

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
__attribute__((always_inline)) void calculate_sha256_from_sha256(PRIVATE_AS const u32 *unpadded_digest_u32, u32 *sha256_hash){

    // unpadded digest as byte array (needed for bytewise padding)
    uchar unpadded_digest_bytes[SHA256_HASH_BYTES_LEN];

    // padded digest as byte array
    uchar padded_digest_bytes[SINGLE_SIZED_SHA256_INPUT_BYTES];

    // padded digest as u32 array
    u32 padded_digest_u32[SINGLE_SIZED_SHA256_INPUT_U32];

    // size in bytes of the input to be hashed
    int padded_digest_size;

    storeU32ToByteArray(unpadded_digest_u32, SHA256_HASH_U32_LEN, unpadded_digest_bytes, 0);

    sha256_padding(unpadded_digest_bytes, SHA256_HASH_BYTES_LEN, padded_digest_bytes, &padded_digest_size);

    storeByteArrayToU32Array(padded_digest_bytes, padded_digest_u32, padded_digest_size);

    // perform hash
    sha256_ctx_t ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, padded_digest_u32, padded_digest_size);

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
  * OUTPUT int *numOutputBytes: Pointer to a int to store the size of the output in bytes
  */
__attribute__((always_inline)) void sha256_padding(const uchar *input, const int numInputBytes, uchar *output, int *numOutputBytes) {

    int multiples_of_64 = 0;
    int temp = numInputBytes;
    while(temp > 0){
        multiples_of_64 = multiples_of_64 + 1;
        temp = temp - SINGLE_SIZED_SHA256_INPUT_BYTES;
    }

    int output_size = multiples_of_64 * SINGLE_SIZED_SHA256_INPUT_BYTES;
    *numOutputBytes = output_size;

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