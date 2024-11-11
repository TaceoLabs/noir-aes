global REDUCTION_POLY: u8 = 0x1b;

unconstrained fn get_bits_uc(byte: u8) -> [u1; 8] {
    let mut out: [u1; 8] = [0; 8];
    for i in 0..8 {
        out[i] = (byte >> i) as u1;
    }
    out
}
fn get_bits(byte: u8) -> [u1; 8] {
    let b_bits = unsafe { get_bits_uc(byte) };

    // reconstrain b
    assert(byte == recombine_bits(b_bits));
    b_bits
}

fn recombine_bits(bits: [u1; 8]) -> u8 {
    bits[0] as u8 * 1
        + bits[1] as u8 * 2
        + bits[2] as u8 * 4
        + bits[3] as u8 * 8
        + bits[4] as u8 * 16
        + bits[5] as u8 * 32
        + bits[6] as u8 * 64
        + bits[7] as u8 * 128
}

fn multiply(mut a: u8, mut b: u8) -> u8 {
    let mut result: u8 = 0;

    let b_bits = get_bits(b);

    for i in 0..8 {
        result ^= (a * b_bits[i] as u8);
        let mask2_bit: u8 = (a >> 7) & 1;
        a = a << 1;
        a ^= REDUCTION_POLY * mask2_bit;
    }
    result
}

/// multiply by 2 in finite field
fn xtime(a: u8) -> u8 {
    let mut result: u8 = a << 1;
    let mask: u8 = (a >> 7) & 1;
    result ^= REDUCTION_POLY * mask;
    result
}

/// squaring in finite field, naive
fn square(b: u8) -> u8 {
    multiply(b, b)
}

/// squaring in finite field, using explicit squaring formula with coefficients
// fn square_explicit(b: u8) -> u8 {
//   let b_bits = get_bits(b);
//   let result_bits = [                             // b^2
//     b_bits[0] ^ b_bits[4] ^ b_bits[6],            // (b0 + b4 + b6) +
//     b_bits[4] ^ b_bits[6] ^ b_bits[7],            // (b4 + b6 + b7)X +
//     b_bits[1] ^ b_bits[5],                        // (b1 + b5)X^2 +
//     b_bits[4] ^ b_bits[5] ^ b_bits[6] ^ b_bits[7],// (b4 + b5 + b6 + b7)X^3 +
//     b_bits[2] ^ b_bits[4] ^ b_bits[7],            // (b2 + b4 + b7)X^4 +
//     b_bits[5] ^ b_bits[6],                        // (b5 + b6)X^5 +
//     b_bits[3] ^ b_bits[5],                        // (b3 + b5)X^6 +
//     b_bits[6] ^ b_bits[7],                        // (b6 + b7)X^7
//   ];
//     recombine_bits(result_bits)
// }
unconstrained fn inverse_uc(c: u8) -> u8 {
    let c3 = multiply(square(c), c);
    let c7 = multiply(square(c3), c);
    let c63 = multiply(square(square(square(c7))), c7);
    let c127 = multiply(square(c63), c);
    let c254 = square(c127);
    c254
}

fn inverse(c: u8) -> u8 {
    let c_is_zero = (c == 0) as u8;

    // we can use + and - here instead of ^, as we know the values are just 0 or 1
    let c_inv = unsafe { inverse_uc(c + c_is_zero) };

    // for this check to always work, we map 0 to 1 for the injected inverse (1^-1 = 1)
    assert(multiply(c + c_is_zero, c_inv) == 1);

    // and then map it back from 1 to 0, if needed
    c_inv - c_is_zero
}

global AES_SBOX_AFFINE_CONST: u8 = 0x63;

fn rotl8_1(s: u8) -> u8 {
    // we use the wrapping function here since we shift out stuff of the u8
    // we can use addition since the two parts are not overlapping and add is cheaper than or
    (s << 1) + (s >> 7)
}
fn rotl8_2(s: u8) -> u8 {
    (s << 2) + (s >> 6)
}
fn rotl8_3(s: u8) -> u8 {
    (s << 3) + (s >> 5)
}
fn rotl8_4(s: u8) -> u8 {
    (s << 4) + (s >> 4)
}

fn aes_sbox(s: u8) -> u8 {
    let c = inverse(s);

    c ^ rotl8_1(c) ^ rotl8_2(c) ^ rotl8_3(c) ^ rotl8_4(c) ^ AES_SBOX_AFFINE_CONST
}

fn aes_sbox_layer(state: [u8; 16]) -> [u8; 16] {
    // todo: check if this is inefficient and we should modify state instead
    let mut result: [u8; 16] = [0; 16];
    for i in 0..16 {
        result[i] = aes_sbox(state[i]);
    }
    result
}
fn aes_shift_rows_layer(state: [u8; 16]) -> [u8; 16] {
    [
        state[0], state[5], state[10], state[15], state[4], state[9], state[14], state[3], state[8],
        state[13], state[2], state[7], state[12], state[1], state[6], state[11],
    ]
}
fn aes_mix_column_layer(state: [u8; 16]) -> [u8; 16] {
    let mut result: [u8; 16] = [0; 16];

    // column 0:
    let s0 = state[0];
    let s1 = state[1];
    let s2 = state[2];
    let s3 = state[3];
    result[0] = xtime(s0 ^ s1) ^ s1 ^ s2 ^ s3;
    result[1] = xtime(s1 ^ s2) ^ s2 ^ s3 ^ s0;
    result[2] = xtime(s2 ^ s3) ^ s3 ^ s0 ^ s1;
    result[3] = xtime(s3 ^ s0) ^ s0 ^ s1 ^ s2;

    // column 1:
    let s0 = state[4];
    let s1 = state[5];
    let s2 = state[6];
    let s3 = state[7];
    result[4] = xtime(s0 ^ s1) ^ s1 ^ s2 ^ s3;
    result[5] = xtime(s1 ^ s2) ^ s2 ^ s3 ^ s0;
    result[6] = xtime(s2 ^ s3) ^ s3 ^ s0 ^ s1;
    result[7] = xtime(s3 ^ s0) ^ s0 ^ s1 ^ s2;

    // column 2:
    let s0 = state[8];
    let s1 = state[9];
    let s2 = state[10];
    let s3 = state[11];
    result[8] = xtime(s0 ^ s1) ^ s1 ^ s2 ^ s3;
    result[9] = xtime(s1 ^ s2) ^ s2 ^ s3 ^ s0;
    result[10] = xtime(s2 ^ s3) ^ s3 ^ s0 ^ s1;
    result[11] = xtime(s3 ^ s0) ^ s0 ^ s1 ^ s2;

    // column 3:
    let s0 = state[12];
    let s1 = state[13];
    let s2 = state[14];
    let s3 = state[15];
    result[12] = xtime(s0 ^ s1) ^ s1 ^ s2 ^ s3;
    result[13] = xtime(s1 ^ s2) ^ s2 ^ s3 ^ s0;
    result[14] = xtime(s2 ^ s3) ^ s3 ^ s0 ^ s1;
    result[15] = xtime(s3 ^ s0) ^ s0 ^ s1 ^ s2;

    result
}

fn aes_add_key_layer(state: [u8; 16], round_key: [u8; 16]) -> [u8; 16] {
    let mut result: [u8; 16] = [0; 16];
    for i in 0..16 {
        result[i] = state[i] ^ round_key[i];
    }
    result
}

global RCON: [u8; 10] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36];
fn aes_128_key_schedule(key: [u8; 16]) -> [[u8; 16]; 11] {
    let mut result: [[u8; 16]; 11] = [[0; 16]; 11];

    // copy key into first 16 bytes of result
    for i in 0..16 {
        result[0][i] = key[i];
    }

    // do the key schedule
    for j in 1..11 {
        // copy last word into temp, with RotWords, SubWords and Rcon already applied
        let mut temp: [u8; 4] = [
            aes_sbox(result[j - 1][13]) ^ RCON[j - 1],
            aes_sbox(result[j - 1][14]),
            aes_sbox(result[j - 1][15]),
            aes_sbox(result[j - 1][12]),
        ];

        // first word
        result[j][0] = result[j - 1][0] ^ temp[0];
        result[j][1] = result[j - 1][1] ^ temp[1];
        result[j][2] = result[j - 1][2] ^ temp[2];
        result[j][3] = result[j - 1][3] ^ temp[3];

        // second column
        result[j][4] = result[j - 1][4] ^ result[j][0];
        result[j][5] = result[j - 1][5] ^ result[j][1];
        result[j][6] = result[j - 1][6] ^ result[j][2];
        result[j][7] = result[j - 1][7] ^ result[j][3];

        // third column
        result[j][8] = result[j - 1][8] ^ result[j][4];
        result[j][9] = result[j - 1][9] ^ result[j][5];
        result[j][10] = result[j - 1][10] ^ result[j][6];
        result[j][11] = result[j - 1][11] ^ result[j][7];

        // fourth column
        result[j][12] = result[j - 1][12] ^ result[j][8];
        result[j][13] = result[j - 1][13] ^ result[j][9];
        result[j][14] = result[j - 1][14] ^ result[j][10];
        result[j][15] = result[j - 1][15] ^ result[j][11];
    }

    result
}

pub fn aes_128_enc(pt: [u8; 16], key: [u8; 16]) -> [u8; 16] {
    let mut state = pt;
    let key_schedule = aes_128_key_schedule(key);

    // initial key add
    state = aes_add_key_layer(state, key_schedule[0]);

    // 9 rounds
    for i in 0..9 {
        state = aes_sbox_layer(state);
        state = aes_shift_rows_layer(state);
        state = aes_mix_column_layer(state);
        state = aes_add_key_layer(state, key_schedule[i + 1]);
    }

    // final round
    state = aes_sbox_layer(state);
    state = aes_shift_rows_layer(state);
    state = aes_add_key_layer(state, key_schedule[10]);
    state
}

#[test]
fn test_multiply() {
    // test some KATS in the Rinjdael finite field
    assert(multiply(0, 0) == 0);
    assert(multiply(0, 1) == 0);
    assert(multiply(1, 0) == 0);
    assert(multiply(255, 169) == 241);
    assert(multiply(255, 170) == 235);
    assert(multiply(255, 171) == 20);
    assert(multiply(255, 172) == 223);
    assert(multiply(255, 173) == 32);
    assert(multiply(255, 174) == 58);
    assert(multiply(255, 175) == 197);
    assert(multiply(255, 176) == 222);
}

#[test]
fn test_square() {
    for i in 0..255 {
        assert(square(i) == multiply(i, i));
    }
}

#[test]
fn test_inverse() {
    for i in 1..255 {
        assert(multiply(i, inverse(i)) == 1);
    }
    assert(inverse(0) == 0);
}

#[test]
fn test_aes_sbox() {
    // test some KATs for AES Sbox
    assert(aes_sbox(0) == 99);
    assert(aes_sbox(1) == 124);
    assert(aes_sbox(2) == 119);
    assert(aes_sbox(3) == 123);
}
#[test]
fn test_aes_shift_rows() {
    assert(
        aes_shift_rows_layer([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15])
            == [0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11],
    );
}
#[test]
fn test_aes_mix_columns() {
    assert(
        aes_mix_column_layer(
            [219, 19, 83, 69, 219, 19, 83, 69, 219, 19, 83, 69, 219, 19, 83, 69],
        )
            == [142, 77, 161, 188, 142, 77, 161, 188, 142, 77, 161, 188, 142, 77, 161, 188],
    );
    assert(
        aes_mix_column_layer([1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1])
            == [1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1],
    );
    assert(
        aes_mix_column_layer([
            198, 198, 198, 198, 198, 198, 198, 198, 198, 198, 198, 198, 198, 198, 198, 198,
        ])
            == [198, 198, 198, 198, 198, 198, 198, 198, 198, 198, 198, 198, 198, 198, 198, 198],
    );
    assert(
        aes_mix_column_layer([45, 38, 49, 76, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
            == [77, 126, 189, 248, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    );
}

#[test]
fn test_aes_key_schedule() {
    let expanded = [
        [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00,
        ],
        [
            0x62, 0x63, 0x63, 0x63, 0x62, 0x63, 0x63, 0x63, 0x62, 0x63, 0x63, 0x63, 0x62, 0x63,
            0x63, 0x63,
        ],
        [
            0x9b, 0x98, 0x98, 0xc9, 0xf9, 0xfb, 0xfb, 0xaa, 0x9b, 0x98, 0x98, 0xc9, 0xf9, 0xfb,
            0xfb, 0xaa,
        ],
        [
            0x90, 0x97, 0x34, 0x50, 0x69, 0x6c, 0xcf, 0xfa, 0xf2, 0xf4, 0x57, 0x33, 0x0b, 0x0f,
            0xac, 0x99,
        ],
        [
            0xee, 0x06, 0xda, 0x7b, 0x87, 0x6a, 0x15, 0x81, 0x75, 0x9e, 0x42, 0xb2, 0x7e, 0x91,
            0xee, 0x2b,
        ],
        [
            0x7f, 0x2e, 0x2b, 0x88, 0xf8, 0x44, 0x3e, 0x09, 0x8d, 0xda, 0x7c, 0xbb, 0xf3, 0x4b,
            0x92, 0x90,
        ],
        [
            0xec, 0x61, 0x4b, 0x85, 0x14, 0x25, 0x75, 0x8c, 0x99, 0xff, 0x09, 0x37, 0x6a, 0xb4,
            0x9b, 0xa7,
        ],
        [
            0x21, 0x75, 0x17, 0x87, 0x35, 0x50, 0x62, 0x0b, 0xac, 0xaf, 0x6b, 0x3c, 0xc6, 0x1b,
            0xf0, 0x9b,
        ],
        [
            0x0e, 0xf9, 0x03, 0x33, 0x3b, 0xa9, 0x61, 0x38, 0x97, 0x06, 0x0a, 0x04, 0x51, 0x1d,
            0xfa, 0x9f,
        ],
        [
            0xb1, 0xd4, 0xd8, 0xe2, 0x8a, 0x7d, 0xb9, 0xda, 0x1d, 0x7b, 0xb3, 0xde, 0x4c, 0x66,
            0x49, 0x41,
        ],
        [
            0xb4, 0xef, 0x5b, 0xcb, 0x3e, 0x92, 0xe2, 0x11, 0x23, 0xe9, 0x51, 0xcf, 0x6f, 0x8f,
            0x18, 0x8e,
        ],
    ];
    assert(aes_128_key_schedule([0; 16]) == expanded);

    let expanded2 = [
        [
            0x49, 0x20, 0xe2, 0x99, 0xa5, 0x20, 0x52, 0x61, 0x64, 0x69, 0x6f, 0x47, 0x61, 0x74,
            0x75, 0x6e,
        ],
        [
            0xda, 0xbd, 0x7d, 0x76, 0x7f, 0x9d, 0x2f, 0x17, 0x1b, 0xf4, 0x40, 0x50, 0x7a, 0x80,
            0x35, 0x3e,
        ],
        [
            0x15, 0x2b, 0xcf, 0xac, 0x6a, 0xb6, 0xe0, 0xbb, 0x71, 0x42, 0xa0, 0xeb, 0x0b, 0xc2,
            0x95, 0xd5,
        ],
        [
            0x34, 0x01, 0xcc, 0x87, 0x5e, 0xb7, 0x2c, 0x3c, 0x2f, 0xf5, 0x8c, 0xd7, 0x24, 0x37,
            0x19, 0x02,
        ],
        [
            0xa6, 0xd5, 0xbb, 0xb1, 0xf8, 0x62, 0x97, 0x8d, 0xd7, 0x97, 0x1b, 0x5a, 0xf3, 0xa0,
            0x02, 0x58,
        ],
        [
            0x56, 0xa2, 0xd1, 0xbc, 0xae, 0xc0, 0x46, 0x31, 0x79, 0x57, 0x5d, 0x6b, 0x8a, 0xf7,
            0x5f, 0x33,
        ],
        [
            0x1e, 0x6d, 0x12, 0xc2, 0xb0, 0xad, 0x54, 0xf3, 0xc9, 0xfa, 0x09, 0x98, 0x43, 0x0d,
            0x56, 0xab,
        ],
        [
            0x89, 0xdc, 0x70, 0xd8, 0x39, 0x71, 0x24, 0x2b, 0xf0, 0x8b, 0x2d, 0xb3, 0xb3, 0x86,
            0x7b, 0x18,
        ],
        [
            0x4d, 0xfd, 0xdd, 0xb5, 0x74, 0x8c, 0xf9, 0x9e, 0x84, 0x07, 0xd4, 0x2d, 0x37, 0x81,
            0xaf, 0x35,
        ],
        [
            0x5a, 0x84, 0x4b, 0x2f, 0x2e, 0x08, 0xb2, 0xb1, 0xaa, 0x0f, 0x66, 0x9c, 0x9d, 0x8e,
            0xc9, 0xa9,
        ],
        [
            0x75, 0x59, 0x98, 0x71, 0x5b, 0x51, 0x2a, 0xc0, 0xf1, 0x5e, 0x4c, 0x5c, 0x6c, 0xd0,
            0x85, 0xf5,
        ],
    ];
    let key2 = [
        0x49, 0x20, 0xe2, 0x99, 0xa5, 0x20, 0x52, 0x61, 0x64, 0x69, 0x6f, 0x47, 0x61, 0x74, 0x75,
        0x6e,
    ];
    assert(aes_128_key_schedule(key2) == expanded2);
}

#[test]
fn test_aes_block_encrypt() {
    let pt1 = [0; 16];
    let key1 = [0; 16];
    let ct1 = [
        0x66, 0xe9, 0x4b, 0xd4, 0xef, 0x8a, 0x2c, 0x3b, 0x88, 0x4c, 0xfa, 0x59, 0xca, 0x34, 0x2b,
        0x2e,
    ];
    assert(aes_128_enc(pt1, key1) == ct1);
    let pt2 = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
        0xff,
    ];
    let key2 = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f,
    ];
    let ct2 = [
        0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5,
        0x5a,
    ];
    assert(aes_128_enc(pt2, key2) == ct2);
}
