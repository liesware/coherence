#include <iostream>
#include "cryptopp/oids.h"
#include "libntru/src/ntru.h"

#define _sha3
#define _sha2
#define _whirlpool
#define _blake2b
#define _poly1305
#define _hmac
#define _cmac
#define _vmac
#define _sosemanuk
#define _salsa20
#define _argon2
#define _rand
#define _dsa
#define _dh
#define _aes
#define _rc6
#define _mars
#define _serpent
#define _twofish
#define _cast256
#define _camellia
#define _speck128
#define _simeck64
#define _rsa
#define _ecc
#define _ntru
#define _qtesla
#define _dilithium


using namespace  std;
using namespace CryptoPP;

typedef struct info_log{
  string ip;
  int timestamp;
  float exec_time;
  string req;
  string answ;
  string error;
  string tag;
} stru_info_log;

typedef struct params{
  int version;
  string algorithm;
  string payload;
  string plaintext;
  string adata;
  int hex;
  string file;
  string type;
  string family;
  string mode;
  string hash;
  string rands;
  int length;
  int entropy;
  string mac;
  string key;
  string iv;
  string nonce;
  string operation;
  string sign;
  string result;
  //argon2
  int t_cost;
  int m_cost;
  int parallelism;
  string salt;
  string pwd;
  string verify;
  int hashlen;
  //public crypt
  string pubkey;
  string privkey;
  string sharedkey;
  string sharedpub;
  string hash_sign;
  //DH
  string p;
  string g;
  string q;
  //ECC
  string curve;
  string field;
  OID CURVE;
  //NTRU
  string parameter;
  string paramsq_;
  struct NtruEncParams params_;
  //json
  string tag;
  string value;
  //log
  string error;
}stru_param;
