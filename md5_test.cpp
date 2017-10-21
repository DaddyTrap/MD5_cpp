#include <cstdio>
#include "md5.h"
#include <map>
#include <utility>

using std::map;
using std::pair;

bool test_one(const pair<string, string> &plain_to_res) {
  // printf("%s : %s\n", plain_to_res.first.c_str(), plain_to_res.second.c_str());
  MD5 md5(plain_to_res.first);
  auto res = md5.digest().getHexResult();

  printf("ORIGIN: \"%s\"\nANSWER: %s\nEXPECT: %s\n", plain_to_res.first.c_str(), res.c_str(), plain_to_res.second.c_str());
  return res == plain_to_res.second;
}

map<string, string> test_case = {
  {"", "d41d8cd98f00b204e9800998ecf8427e"},
  {"a", "0cc175b9c0f1b6a831c399e269772661"},
  {"abc", "900150983cd24fb0d6963f7d28e17f72"},
  {"message digest", "f96b697d7cb7938d525a2f31aaf161d0"},
  {"abcdefghijklmnopqrstuvwxyz", "c3fcd3d76192e4007dfb496cca67e13b"},
  {"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", "d174ab98d277d9f5a5611c2c9f419d9f"},
  {"12345678901234567890123456789012345678901234567890123456789012345678901234567890", "57edf4a22be3c955ac49da2e2107b67a"},
  {"1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890", "268c7919189d85e276d74b8c60b2f84f"}
};

void simpleTest() {
  printf("[Simple Test]\n");
  for (auto &p : test_case) {
    printf(test_one(p) ? "OK\n\n" : "FAILED\n\n");
  }
}

void multiUpdatesTest() {
  printf("[Multiple Updates Test]\n");
  MD5 md5;
  md5.update("message");
  md5.update(" digest");
  md5.digest();
  auto hexResult = md5.getHexResult();
  auto expectResult = test_case["message digest"];
  auto res = (hexResult == expectResult);
  printf("ORIGIN: \"%s\"\nANSWER: %s\nEXPECT: %s\n", "message digest", hexResult.c_str(), expectResult.c_str());
  printf(hexResult == expectResult ? "OK\n\n" : "FAILED\n\n");
}

void fileMD5Test() {
  printf("[File MD5 Test]\n");
  MD5 md5;
  md5.update(string("favicon.png"), MD5::UPDATE_TYPE::UPDATE_FILE);
  md5.digest();
  auto hexResult = md5.getHexResult();
  printf("ANSWER: %s\nEXPECT: %s\n", hexResult.c_str(), "58359783ee49041096c6484732468659");
  printf(hexResult == "58359783ee49041096c6484732468659" ? "OK\n\n" : "FAILED\n\n");
}

int main() {
  simpleTest();
  multiUpdatesTest();
  fileMD5Test();
  return 0;
}
