#include <string>
#include <functional>

using std::string;
using std::function;

typedef unsigned int uint32;
typedef unsigned long long int uint64;

constexpr uint32 FILE_READ_BLOCK_SIZE = 256;

class MD5 {
public:
  MD5();
  MD5(const string& input);

  enum UPDATE_TYPE {
    UPDATE_STRING,
    UPDATE_FILE
  };

  MD5& update(const string& input, UPDATE_TYPE type = UPDATE_STRING);
  MD5& update(const char* data, uint32 dataLen);
  MD5& digest();
  string getHexResult();  /* Step 5. Output */

private:
  int appendPaddingAndLength(char *restMessage); /* Step 1. Append Padding Bits & Step 2. Append Length */
  void process();         /* Process one block in buffer */
  
  static uint32 leftRotate(uint32 num, uint32 n);
  
  const static function<uint32(uint32, uint32, uint32)> g_funcs[4];
  const static uint32 Xs[4][16];
  const static uint32 Ts[64];
  const static uint32 Ss[64];
  const static unsigned char PADDING[64];

  uint32 registers[4] = {   /* Step 3. Initialize MD Buffer */
    0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476
  };
  /* count[0] is the total length of the data, count[1] is the data length in the buffer */
  /* count[0] is used in appending length, count[1] is used in updating buffer */
  /* Because of the data type unsigned int can only represent 32 bits, the max message size is 4 Gigabytes */
  uint32 count[2];
  unsigned char buffer[64];
};