
fn multiply(mut a: u8, mut b: u8) -> u8 {
  let mut result: u8 = 0;

  for _ in 0..8 {
    let mask_bit: u8 = b & 1;
    result ^= (a * mask_bit);
    let mask2_bit: u8 = (a >> 7) & 1;
    a <<= 1;
    a ^= 27 * mask2_bit; // 27 = 1b; the lower 8 bits of the reduction poly
    b >>= 1;
  }
  result
}

fn square(c: u8) -> u8 { multiply(c, c) }

fn inverse(c: u8) -> u8{
  let c3 = multiply(square(c), c);
  let c7 = multiply(square(c3), c);
  let c63 = multiply(square(square(square(c7))), c7);
  let c127 = multiply(square(c63), c);
  let c254 = square(c127); 
  c254
}

global AES_SBOX_AFFINE_CONST: u8 = 0x63;

fn rotl8_1(s: u8) -> u8 {
  (s << 1) | (s >> 7)
}
fn rotl8_2(s: u8) -> u8 {
  (s << 2) | (s >> 6)
}
fn rotl8_3(s: u8) -> u8 {
  (s << 3) | (s >> 5)
}
fn rotl8_4(s: u8) -> u8 {
  (s << 4) | (s >> 4)
}

fn aes_sbox(s: u8) -> u8 {
  let c = inverse(s);

  c ^ rotl8_1(c) ^ rotl8_2(c) ^
      rotl8_3(c) ^ rotl8_4(c) ^
      AES_SBOX_AFFINE_CONST
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
    state[0], state[1], state[2], state[3],
    state[5], state[6], state[7], state[4],
    state[10], state[11], state[8], state[9],
    state[15], state[12], state[13], state[14]
  ]
}
fn aes_mix_column_layer(state: [u8; 16]) -> [u8;16] {
  let mut result: [u8; 16] = [0; 16];
  // column 0:
  let s0 = state[0];
  let s1 = state[4];
  let s2 = state[8];
  let s3 = state[12];
  result[0] = multiply(s0 ^ s1, 2) ^ s1 ^ s2 ^ s3;
  result[4] = multiply(s1 ^ s2, 2) ^ s2 ^ s3 ^ s0;
  result[8] = multiply(s2 ^ s3, 2) ^ s3 ^ s0 ^ s1;
  result[12] = multiply(s3 ^ s0, 2) ^ s0 ^ s1 ^ s2;
  // column 1:
  let s0 = state[1];
  let s1 = state[5];
  let s2 = state[9];
  let s3 = state[13];
  result[1] = multiply(s0 ^ s1, 2) ^ s1 ^ s2 ^ s3;
  result[5] = multiply(s1 ^ s2, 2) ^ s2 ^ s3 ^ s0;
  result[9] = multiply(s2 ^ s3, 2) ^ s3 ^ s0 ^ s1;
  result[13] = multiply(s3 ^ s0, 2) ^ s0 ^ s1 ^ s2;
  // column 2:
  let s0 = state[2];
  let s1 = state[6];
  let s2 = state[10];
  let s3 = state[14];
  result[2] = multiply(s0 ^ s1, 2) ^ s1 ^ s2 ^ s3;
  result[6] = multiply(s1 ^ s2, 2) ^ s2 ^ s3 ^ s0;
  result[10] = multiply(s2 ^ s3, 2) ^ s3 ^ s0 ^ s1;
  result[14] = multiply(s3 ^ s0, 2) ^ s0 ^ s1 ^ s2;
  // column 2:
  let s0 = state[3];
  let s1 = state[7];
  let s2 = state[11];
  let s3 = state[15];
  result[3] = multiply(s0 ^ s1, 2) ^ s1 ^ s2 ^ s3;
  result[7] = multiply(s1 ^ s2, 2) ^ s2 ^ s3 ^ s0;
  result[11] = multiply(s2 ^ s3, 2) ^ s3 ^ s0 ^ s1;
  result[15] = multiply(s3 ^ s0, 2) ^ s0 ^ s1 ^ s2;

  result
}

fn aes_add_key_layer(state: [u8; 16], key: [u8; 16]) -> [u8; 16] {
  let mut result: [u8; 16] = [0; 16];
  for i in 0..16 {
    result[i] = state[i] ^ key[i];
  }
  result
}

fn aes_128_key_schedule(key: [u8;16]) -> [u8; 176] {
  let mut result: [u8; 176] = [0; 176];
  // copy key into first 16 bytes of result
  for i in 0..16 {
    result[i] = key[i];
  }
  // do the key schedule
   roundconstant = 1;
  for (j = 4; j < 44; ++j) {
    unsigned char temp[4];
    if (j % 4)
      for (i = 0; i < 4; ++i)
        temp[i] = expanded[i][j - 1];
    else {
      for (i = 0; i < 4; ++i) {
        unsigned char s = expanded[(i + 1) % 4][j - 1];
        if (s == 0)
          return false;
        temp[i] = bytesub(s);
      }
      temp[0] ^= roundconstant;
      roundconstant = xtime(roundconstant);
    }
    for (i = 0; i < 4; ++i)
      expanded[i][j] = temp[i] ^ expanded[i][j - 4];
  }

  result
}

fn aes_128(pt: [u8;16], key: [u8;16]) -> [u8;16] {
  let mut state = pt;
  // TODO: key schedule
  let mut key_schedule = key;
  // initial key add
  state = aes_add_key_layer(state, key_schedule);
  // 9 rounds
  for _ in 0..9 {
    state = aes_sbox_layer(state);
    state = aes_shift_rows_layer(state);
    state = aes_mix_column_layer(state);
    state = aes_add_key_layer(state, key_schedule);
  }
  // final round
  state = aes_sbox_layer(state);
  state = aes_shift_rows_layer(state);
  state = aes_add_key_layer(state, key_schedule);
  state
}


#[test]
fn test_multiply() {
  // test some KATS in the Rinjdael finite field
  assert(multiply(0,0) == 0);
  assert(multiply(0,1) == 0);
  assert(multiply(1,0) == 0);
  assert(multiply(255,169) == 241);
  assert(multiply(255,170) == 235);
  assert(multiply(255,171) == 20);
  assert(multiply(255,172) == 223);
  assert(multiply(255,173) == 32);
  assert(multiply(255,174) == 58);
  assert(multiply(255,175) == 197);
  assert(multiply(255,176) == 222);
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
  assert(aes_shift_rows_layer([0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15]) == [0,1,2,3,5,6,7,4,10,11,8,9,15,12,13,14]);
}
#[test]
fn test_aes_mix_columns() {
  assert(aes_mix_column_layer([219,219,219,219,19,19,19,19,83,83,83,83,69,69,69,69]) == [142,142,142,142,77,77,77,77,161,161,161,161,188,188,188,188]);
  assert(aes_mix_column_layer([1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1]) == [1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1]);
  assert(aes_mix_column_layer([198,198,198,198,198,198,198,198,198,198,198,198,198,198,198,198]) == [198,198,198,198,198,198,198,198,198,198,198,198,198,198,198,198]);
  assert(aes_mix_column_layer([45,0,0,0, 38,0,0,0, 49,0,0,0, 76,0,0,0]) == [77,0,0,0, 126,0,0,0, 189,0,0,0, 248,0,0,0]);
}
