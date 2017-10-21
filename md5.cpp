#include <cstdio>
#include <string>
#include <cstring>
#include "md5.h"

using std::string;

/* static variable start */
const function<uint32(uint32, uint32, uint32)> MD5::g_funcs[4] = {
  [](uint32 b, uint32 c, uint32 d) -> uint32 {    /* function F */
    return (b & c) | (~b & d);
  },
  [](uint32 b, uint32 c, uint32 d) -> uint32 {    /* function G */
    return (b & d) | (c & ~d);
  },
  [](uint32 b, uint32 c, uint32 d) -> uint32 {    /* function H */
    return b ^ c ^ d;
  },
  [](uint32 b, uint32 c, uint32 d) -> uint32 {    /* function I */
    return c ^ (b | ~d);
  }
};

const uint32 MD5::Xs[4][16] = {
  {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
  {1, 6, 11, 0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12},
  {5, 8, 11, 14, 1, 4, 7, 10, 13, 0, 3, 6, 9, 12, 15, 2},
  {0, 7, 14, 5, 12, 3, 10, 1, 8, 15, 6, 13, 4, 11, 2, 9}
};

const uint32 MD5::Ts[64] = {
  0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
  0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
  0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
  0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
  0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
  0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
  0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
  0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
  0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
  0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
  0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
  0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
  0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
  0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
  0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
  0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
};

const uint32 MD5::Ss[64] = {
   7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,
   5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,
   4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,
   6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21
};

const unsigned char MD5::PADDING[64] = {
  0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
     0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
     0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
     0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

/* static variables end */

MD5::MD5() {
  memset(count, 0, sizeof(count));
  memset(buffer, 0, sizeof(buffer));
}

MD5::MD5(const string& input) {
  memset(count, 0, sizeof(count));
  memset(buffer, 0, sizeof(buffer));
  update(input);
}

MD5& MD5::update(const string& input, UPDATE_TYPE type) {
  if (type == UPDATE_STRING) {
    int inputLen = input.length();
    update(input.c_str(), inputLen);
  } else if (type == UPDATE_FILE) {
    FILE *f = fopen(input.c_str(), "rb");
    if (f == NULL) throw "NO SUCH FILE EXCEPTION";
    char data_buffer[FILE_READ_BLOCK_SIZE] = {};
    while (!feof(f)) {
      int inputLen = fread(data_buffer, 1, FILE_READ_BLOCK_SIZE, f);
      update(data_buffer, inputLen);
    }
  } else {
    throw "UNKNOWN UPDATE_TYPE EXCEPTION";
  }
  return *this;
}

MD5& MD5::update(const char* data, uint32 dataLen) {
  count[0] += dataLen;
  if (dataLen + count[1] < 64) {
    memcpy(buffer + count[1], data, dataLen);
    count[1] += dataLen;
    return *this; /* unnecessary to process */
  }

  int offset = 64 - count[1];
  memcpy(buffer + count[1], data, offset);
  process();
  int restBlockCount = (dataLen - offset) >> 6;   // num / 64
  int restLength = (dataLen - offset) & 0x3f;     // num % 64

  /* process except the final block */
  for (int i = 0; i < restBlockCount; ++i) {
    memcpy(buffer, data + offset + i * 64, 64);
    process();
  }
  /* save the final block */
  memcpy(buffer, data + offset + restBlockCount * 64, restLength);
  count[1] = restLength;

  return *this;
}

MD5& MD5::digest() {
  /* process the final block */
  char new_buffer[64];
  int res = appendPaddingAndLength(new_buffer);
  process();
  if (res == 1) { // new block
    memcpy(buffer, new_buffer, 64);
    process();
  }
  return *this;
}

string MD5::getHexResult() {
  string ret;
  char buffer[4];
  /* Output in Big-Endian
     For a value 0x6789abcd
     Output as    "cdab8967"
  */
  for (int i = 0; i < 4; ++i) {
    for (int j = 0; j < 4; ++j) {
      snprintf(buffer, 4, "%02x", registers[i] >> j*8 & 0xff);
      ret += buffer;
    }
  }
  return ret;
}

/* 
  This step may create a new block (when the length of rest message is greater than 56)
  When a new block is created, the rest message will be written in restMessage. And 1 will be returned.
  Otherwise, no data will be written to restMessage. And 0 will be returned.
*/
int MD5::appendPaddingAndLength(char *restMessage) {
  if (count[1] < 56) {
    // Append Padding
    memcpy(buffer + count[1], PADDING, 56 - count[1]);
    // Append Length
    uint64 length = uint64(count[0]) * 8;
    memcpy(buffer + 56, &length, 8);
    return 0;
  } else {
    // Append Padding
    char extendedBuffer[128] = {};
    memcpy(extendedBuffer, buffer, count[1]);
    memcpy(extendedBuffer + count[1], PADDING, 120 - count[1]);
    // Append Length
    uint64 length = uint64(count[0]) * 8;
    memcpy(extendedBuffer + 120, &length, 8);
    // first part in buffer, second part in restMessage
    memcpy(buffer, extendedBuffer, 64);
    memcpy(restMessage, extendedBuffer + 64, 64);
    return 1;
  }
}

/* Step 4. Process Message in 16-Word Blocks */
void MD5::process() {
  uint32 a = registers[0], b = registers[1], c = registers[2], d = registers[3];
  for (int i = 0; i < 4; ++i) {
    for (int j = 0; j < 16; ++j) {
      // a = b + ((a + g(b,c,d) + X[k] + T[i]) <<<s)
      a = b + (leftRotate(a + g_funcs[i](b, c, d) + *(uint32*)(buffer + Xs[i][j] * 4) + Ts[i * 16 + j], Ss[i * 16 + j]));
      uint32 tempD = d;
      /* 
      a   b   c   d
      |   |   |   |
      |   |   |  /
       \   \   \/
        \   \  /\
         \   \/  \
          \  /\   \
           \/  \   \
           /\   \   \
          /  \   \   \
         a    b   c   d
      */
      d = c;
      c = b;
      b = a;
      a = tempD;
    }
  }
  registers[0] += a;
  registers[1] += b;
  registers[2] += c;
  registers[3] += d;
}

uint32 MD5::leftRotate(uint32 num, uint32 n) {
  return (num << n) | (num >> (32 - n));
}