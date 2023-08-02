/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef _INC_ECC_SECP256K1_H
#define _INC_ECC_SECP256K1_H

// y^2 = x^3 + ax + b with a = 0 and b = 7 => y^2 = x^3 + 7:

#define SECP256K1_B 7

// finite field Fp
// p = FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE FFFFFC2F
#define SECP256K1_P0 0xfffffc2f
#define SECP256K1_P1 0xfffffffe
#define SECP256K1_P2 0xffffffff
#define SECP256K1_P3 0xffffffff
#define SECP256K1_P4 0xffffffff
#define SECP256K1_P5 0xffffffff
#define SECP256K1_P6 0xffffffff
#define SECP256K1_P7 0xffffffff

// prime order N
// n = FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE BAAEDCE6 AF48A03B BFD25E8C D0364141
#define SECP256K1_N0 0xd0364141
#define SECP256K1_N1 0xbfd25e8c
#define SECP256K1_N2 0xaf48a03b
#define SECP256K1_N3 0xbaaedce6
#define SECP256K1_N4 0xfffffffe
#define SECP256K1_N5 0xffffffff
#define SECP256K1_N6 0xffffffff
#define SECP256K1_N7 0xffffffff

// the base point G in compressed form for transform_public
// G = 02 79BE667E F9DCBBAC 55A06295 CE870B07 029BFCDB 2DCE28D9 59F2815B 16F81798
#define SECP256K1_G_PARITY 0x00000002
#define SECP256K1_G0 0x16f81798
#define SECP256K1_G1 0x59f2815b
#define SECP256K1_G2 0x2dce28d9
#define SECP256K1_G3 0x029bfcdb
#define SECP256K1_G4 0xce870b07
#define SECP256K1_G5 0x55a06295
#define SECP256K1_G6 0xf9dcbbac
#define SECP256K1_G7 0x79be667e

// the base point G in compressed form for parse_public
// parity and reversed byte/char (8 bit) byte order
// G = 02 79BE667E F9DCBBAC 55A06295 CE870B07 029BFCDB 2DCE28D9 59F2815B 16F81798
#define SECP256K1_G_STRING0 0x66be7902
#define SECP256K1_G_STRING1 0xbbdcf97e
#define SECP256K1_G_STRING2 0x62a055ac
#define SECP256K1_G_STRING3 0x0b87ce95
#define SECP256K1_G_STRING4 0xfc9b0207
#define SECP256K1_G_STRING5 0x28ce2ddb
#define SECP256K1_G_STRING6 0x81f259d9
#define SECP256K1_G_STRING7 0x17f8165b
#define SECP256K1_G_STRING8 0x00000098

// pre computed values, can be verified using private keys for
// x1 is the same as the basepoint g
// x1 WIF: KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn
// x3 WIF: KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU74sHUHy8S
// x5 WIF: KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU75s2EPgZf
// x7 WIF: KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU76rnZwVdz

// x1: 79BE667E F9DCBBAC 55A06295 CE870B07 029BFCDB 2DCE28D9 59F2815B 16F81798
// x1: 79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
#define SECP256K1_G_PRE_COMPUTED_00 0x16f81798
#define SECP256K1_G_PRE_COMPUTED_01 0x59f2815b
#define SECP256K1_G_PRE_COMPUTED_02 0x2dce28d9
#define SECP256K1_G_PRE_COMPUTED_03 0x029bfcdb
#define SECP256K1_G_PRE_COMPUTED_04 0xce870b07
#define SECP256K1_G_PRE_COMPUTED_05 0x55a06295
#define SECP256K1_G_PRE_COMPUTED_06 0xf9dcbbac
#define SECP256K1_G_PRE_COMPUTED_07 0x79be667e

// y1: 483ADA77 26A3C465 5DA4FBFC 0E1108A8 FD17B448 A6855419 9C47D08F FB10D4B8
// y1: 483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
#define SECP256K1_G_PRE_COMPUTED_08 0xfb10d4b8
#define SECP256K1_G_PRE_COMPUTED_09 0x9c47d08f
#define SECP256K1_G_PRE_COMPUTED_10 0xa6855419
#define SECP256K1_G_PRE_COMPUTED_11 0xfd17b448
#define SECP256K1_G_PRE_COMPUTED_12 0x0e1108a8
#define SECP256K1_G_PRE_COMPUTED_13 0x5da4fbfc
#define SECP256K1_G_PRE_COMPUTED_14 0x26a3c465
#define SECP256K1_G_PRE_COMPUTED_15 0x483ada77

// -y1: B7C52588 D95C3B9A A25B0403 F1EEF757 02E84BB7 597AABE6 63B82F6F 04EF2777
// -y1: B7C52588D95C3B9AA25B0403F1EEF75702E84BB7597AABE663B82F6F04EF2777
#define SECP256K1_G_PRE_COMPUTED_16 0x04ef2777
#define SECP256K1_G_PRE_COMPUTED_17 0x63b82f6f
#define SECP256K1_G_PRE_COMPUTED_18 0x597aabe6
#define SECP256K1_G_PRE_COMPUTED_19 0x02e84bb7
#define SECP256K1_G_PRE_COMPUTED_20 0xf1eef757
#define SECP256K1_G_PRE_COMPUTED_21 0xa25b0403
#define SECP256K1_G_PRE_COMPUTED_22 0xd95c3b9a
#define SECP256K1_G_PRE_COMPUTED_23 0xb7c52588

// x3: F9308A01 9258C310 49344F85 F89D5229 B531C845 836F99B0 8601F113 BCE036F9
// x3: F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9
#define SECP256K1_G_PRE_COMPUTED_24 0xbce036f9
#define SECP256K1_G_PRE_COMPUTED_25 0x8601f113
#define SECP256K1_G_PRE_COMPUTED_26 0x836f99b0
#define SECP256K1_G_PRE_COMPUTED_27 0xb531c845
#define SECP256K1_G_PRE_COMPUTED_28 0xf89d5229
#define SECP256K1_G_PRE_COMPUTED_29 0x49344f85
#define SECP256K1_G_PRE_COMPUTED_30 0x9258c310
#define SECP256K1_G_PRE_COMPUTED_31 0xf9308a01

// y3: 388F7B0F 632DE814 0FE337E6 2A37F356 6500A999 34C2231B 6CB9FD75 84B8E672
// y3: 388F7B0F632DE8140FE337E62A37F3566500A99934C2231B6CB9FD7584B8E672
#define SECP256K1_G_PRE_COMPUTED_32 0x84b8e672
#define SECP256K1_G_PRE_COMPUTED_33 0x6cb9fd75
#define SECP256K1_G_PRE_COMPUTED_34 0x34c2231b
#define SECP256K1_G_PRE_COMPUTED_35 0x6500a999
#define SECP256K1_G_PRE_COMPUTED_36 0x2a37f356
#define SECP256K1_G_PRE_COMPUTED_37 0x0fe337e6
#define SECP256K1_G_PRE_COMPUTED_38 0x632de814
#define SECP256K1_G_PRE_COMPUTED_39 0x388f7b0f

// -y3: C77084F0 9CD217EB F01CC819 D5C80CA9 9AFF5666 CB3DDCE4 93460289 7B4715BD
// -y3: C77084F09CD217EBF01CC819D5C80CA99AFF5666CB3DDCE4934602897B4715BD
#define SECP256K1_G_PRE_COMPUTED_40 0x7b4715bd
#define SECP256K1_G_PRE_COMPUTED_41 0x93460289
#define SECP256K1_G_PRE_COMPUTED_42 0xcb3ddce4
#define SECP256K1_G_PRE_COMPUTED_43 0x9aff5666
#define SECP256K1_G_PRE_COMPUTED_44 0xd5c80ca9
#define SECP256K1_G_PRE_COMPUTED_45 0xf01cc819
#define SECP256K1_G_PRE_COMPUTED_46 0x9cd217eb
#define SECP256K1_G_PRE_COMPUTED_47 0xc77084f0

// x5: 2F8BDE4D 1A072093 55B4A725 0A5C5128 E88B84BD DC619AB7 CBA8D569 B240EFE4
// x5: 2F8BDE4D1A07209355B4A7250A5C5128E88B84BDDC619AB7CBA8D569B240EFE4
#define SECP256K1_G_PRE_COMPUTED_48 0xb240efe4
#define SECP256K1_G_PRE_COMPUTED_49 0xcba8d569
#define SECP256K1_G_PRE_COMPUTED_50 0xdc619ab7
#define SECP256K1_G_PRE_COMPUTED_51 0xe88b84bd
#define SECP256K1_G_PRE_COMPUTED_52 0x0a5c5128
#define SECP256K1_G_PRE_COMPUTED_53 0x55b4a725
#define SECP256K1_G_PRE_COMPUTED_54 0x1a072093
#define SECP256K1_G_PRE_COMPUTED_55 0x2f8bde4d

// y5: D8AC2226 36E5E3D6 D4DBA9DD A6C9C426 F788271B AB0D6840 DCA87D3A A6AC62D6
// y5: D8AC222636E5E3D6D4DBA9DDA6C9C426F788271BAB0D6840DCA87D3AA6AC62D6
#define SECP256K1_G_PRE_COMPUTED_56 0xa6ac62d6
#define SECP256K1_G_PRE_COMPUTED_57 0xdca87d3a
#define SECP256K1_G_PRE_COMPUTED_58 0xab0d6840
#define SECP256K1_G_PRE_COMPUTED_59 0xf788271b
#define SECP256K1_G_PRE_COMPUTED_60 0xa6c9c426
#define SECP256K1_G_PRE_COMPUTED_61 0xd4dba9dd
#define SECP256K1_G_PRE_COMPUTED_62 0x36e5e3d6
#define SECP256K1_G_PRE_COMPUTED_63 0xd8ac2226

// -y5: 2753DDD9 C91A1C29 2B245622 59363BD9 0877D8E4 54F297BF 235782C4 59539959
// -y5: 2753DDD9C91A1C292B24562259363BD90877D8E454F297BF235782C459539959
#define SECP256K1_G_PRE_COMPUTED_64 0x59539959
#define SECP256K1_G_PRE_COMPUTED_65 0x235782c4
#define SECP256K1_G_PRE_COMPUTED_66 0x54f297bf
#define SECP256K1_G_PRE_COMPUTED_67 0x0877d8e4
#define SECP256K1_G_PRE_COMPUTED_68 0x59363bd9
#define SECP256K1_G_PRE_COMPUTED_69 0x2b245622
#define SECP256K1_G_PRE_COMPUTED_70 0xc91a1c29
#define SECP256K1_G_PRE_COMPUTED_71 0x2753ddd9

// x7: 5CBDF064 6E5DB4EA A398F365 F2EA7A0E 3D419B7E 0330E39C E92BDDED CAC4F9BC
// x7: 5CBDF0646E5DB4EAA398F365F2EA7A0E3D419B7E0330E39CE92BDDEDCAC4F9BC
#define SECP256K1_G_PRE_COMPUTED_72 0xcac4f9bc
#define SECP256K1_G_PRE_COMPUTED_73 0xe92bdded
#define SECP256K1_G_PRE_COMPUTED_74 0x0330e39c
#define SECP256K1_G_PRE_COMPUTED_75 0x3d419b7e
#define SECP256K1_G_PRE_COMPUTED_76 0xf2ea7a0e
#define SECP256K1_G_PRE_COMPUTED_77 0xa398f365
#define SECP256K1_G_PRE_COMPUTED_78 0x6e5db4ea
#define SECP256K1_G_PRE_COMPUTED_79 0x5cbdf064

// y7: 6AEBCA40 BA255960 A3178D6D 861A54DB A813D0B8 13FDE7B5 A5082628 087264DA
// y7: 6AEBCA40BA255960A3178D6D861A54DBA813D0B813FDE7B5A5082628087264DA
#define SECP256K1_G_PRE_COMPUTED_80 0x087264da
#define SECP256K1_G_PRE_COMPUTED_81 0xa5082628
#define SECP256K1_G_PRE_COMPUTED_82 0x13fde7b5
#define SECP256K1_G_PRE_COMPUTED_83 0xa813d0b8
#define SECP256K1_G_PRE_COMPUTED_84 0x861a54db
#define SECP256K1_G_PRE_COMPUTED_85 0xa3178d6d
#define SECP256K1_G_PRE_COMPUTED_86 0xba255960
#define SECP256K1_G_PRE_COMPUTED_87 0x6aebca40

// -y7: 951435BF 45DAA69F 5CE87292 79E5AB24 57EC2F47 EC02184A 5AF7D9D6 F78D9755
// -y7: 951435BF45DAA69F5CE8729279E5AB2457EC2F47EC02184A5AF7D9D6F78D9755
#define SECP256K1_G_PRE_COMPUTED_88 0xf78d9755
#define SECP256K1_G_PRE_COMPUTED_89 0x5af7d9d6
#define SECP256K1_G_PRE_COMPUTED_90 0xec02184a
#define SECP256K1_G_PRE_COMPUTED_91 0x57ec2f47
#define SECP256K1_G_PRE_COMPUTED_92 0x79e5ab24
#define SECP256K1_G_PRE_COMPUTED_93 0x5ce87292
#define SECP256K1_G_PRE_COMPUTED_94 0x45daa69f
#define SECP256K1_G_PRE_COMPUTED_95 0x951435bf

#define SECP256K1_PRE_COMPUTED_XY_SIZE 96
#define SECP256K1_NAF_SIZE 33 // 32+1, we need one extra slot

#define PUBLIC_KEY_LENGTH_WITHOUT_PARITY 8
#define PUBLIC_KEY_ONE_COORDINATE_LENGTH 8
#define PUBLIC_KEY_PARITY_BYTE 4
#define PUBLIC_KEY_LENGTH_X_Y_WITHOUT_PARITY 16
#define PUBLIC_KEY_LENGTH 17
#define PUBLIC_KEY_BYTES_WITH_PARITY 65
#define PUBKEY_LEN_WITHOUT_PARITY_WITH_SHA256 32
#define RESULT_U32_LEN_WITH_RIPEMD160 29
#define SHA256_HASH_U32_LEN 8
#define SHA256_HASH_BYTES_LEN 32
#define RIPEMD160_HASH_U32_LEN 5
#define RIPEMD160_HASH_BYTES 20
#define RIPEMD160_HASH_WITH_VERSION_BYTES 21
#define SINGLE_SIZED_SHA256_INPUT_BYTES 64
#define SINGLE_SIZED_SHA256_INPUT_U32 16
#define DOUBLE_SIZED_SHA256_INPUT_BYTES 128
#define RIPEMD160_HASH_VERSION_BYTE 0
#define ADDRESS_BYTES_LEN 25
// 8+1 to make room for the parity
#define PUBLIC_KEY_LENGTH_WITH_PARITY 9

// (32*8 == 256)
#define PRIVATE_KEY_LENGTH 8
#define PRIVATE_KEY_BYTES 32

typedef struct secp256k1
{
  u32 xy[SECP256K1_PRE_COMPUTED_XY_SIZE]; // pre-computed points: (x1,y1,-y1),(x3,y3,-y3),(x5,y5,-y5),(x7,y7,-y7)

} secp256k1_t;


DECLSPEC u32  transform_public (secp256k1_t *r, const u32 *x, const u32 first_byte);
DECLSPEC u32  parse_public (secp256k1_t *r, const u32 *k);

DECLSPEC void point_mul_xy (u32 *x1, u32 *y1, const u32 *k, GLOBAL_AS const secp256k1_t *tmps);
DECLSPEC void point_mul (u32 *r, const u32 *k, GLOBAL_AS const secp256k1_t *tmps);

DECLSPEC void set_precomputed_basepoint_g (secp256k1_t *r);

#endif // _INC_ECC_SECP256K1_H
