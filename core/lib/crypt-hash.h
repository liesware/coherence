#include "rapidjson/document.h"
#include "rapidjson/writer.h"
#include "rapidjson/stringbuffer.h"
#include "rapidjson/error/en.h"
#include <iostream>
#include <fstream>

#include "cryptopp/sha3.h"
#include "cryptopp/sha.h"
#include "cryptopp/whrlpool.h"
#include "cryptopp/blake2.h"
#include "cryptopp/siphash.h"
#include "cryptopp/filters.h"
#include "cryptopp/hex.h"
#include "cryptopp/files.h"
#include "cryptopp/cryptlib.h"

using namespace CryptoPP;
using namespace  std;

int hash_anws(stru_param& req_val, string& answ_js){

  req_val.tag.clear();
  req_val.tag="algorithm";
  Addstr2json(answ_js, req_val.tag, req_val.algorithm);
  req_val.tag.clear();
  req_val.tag="hash";
  Addstr2json(answ_js, req_val.tag, req_val.hash);
  req_val.tag.clear();
  req_val.tag="error";
  Addstr2json(answ_js, req_val.tag, req_val.error);

  return 0;
}

////////////////////////////////////////////////////////////////////////

//Poly1305//////////////////////////////////////////////////////////////
int SIPHASH_(string& type ,string& payload, string& digest, int& binary, string& error){
  error.clear();
  digest.clear();
  try{
    SipHash<2,4,true> hash;
    if (strncmp(type.c_str(), "string",sizeof("string")) == 0){
      if(binary==0)
      StringSource(payload, true, new HashFilter(hash,new HexEncoder(new StringSink(digest))));
      else if(binary==1)
      StringSource(payload, true, new HexDecoder( new HashFilter(hash,new HexEncoder(new StringSink(digest)))));
      else{
        error+="Bad binary bool ";
        return 1;
      }
    }
    else if (strncmp(type.c_str(), "file",sizeof("file")) == 0){
      error="Bad type file not supported";
    }
    else{
      error="Bad type";
      return 1;
    }

  }
  catch(const CryptoPP::Exception& e){
    error=e.what();
    #ifdef DEBUG
    cerr << error << endl;
    #endif
    return 1;
  }
  return 0;
}

//HASHING///////////////////////////////////////////////////////////////
template <typename T>
int HASHING(string& type ,string& payload, string& digest, int& binary, string& error){
  error.clear();
  digest.clear();
  try{
    T hash;
    if (strncmp(type.c_str(), "string",sizeof("string")) == 0){
      if(binary==0)
      StringSource(payload, true, new HashFilter(hash,new HexEncoder(new StringSink(digest))));
      else if(binary==1)
      StringSource(payload, true, new HexDecoder( new HashFilter(hash,new HexEncoder(new StringSink(digest)))));
      else{
        error+="Bad binary bool ";
        return 1;
      }
    }
    else{
      error="Bad type";
      return 1;
    }

  }
  catch(const CryptoPP::Exception& e){
    error=e.what();
    #ifdef DEBUG
    cerr << error << endl;
    #endif
    return 1;
  }
  return 0;
}

////////////////////////////////////////////////////////////////////////
//HASH_STRING///////////////////////////////////////////////////////////
int parse_hash(Document& d, stru_param& req_val, string& answ_js){
  if(d.HasMember("type") ){
    if(check_type(d,req_val,answ_js)!=0)
    return 1;
  }
  else{
    req_val.error="Not type tag ";
    answ_error(req_val,answ_js);
    return 1;
  }


  if (strncmp(req_val.type.c_str(), "string",sizeof("string")) == 0){
    if(d.HasMember("plaintext") ){
      if(check_plain(d,req_val,answ_js)!=0)
      return 1;
      if(check_bin(d,req_val,answ_js)!=0)
      return 1;

      req_val.payload=req_val.plaintext;
    }
    else{
      req_val.error="Not plaintext tag ";
      answ_error(req_val,answ_js);
      return 1;
    }
  }
  else{
    req_val.error="Bad tye ";
    answ_error(req_val,answ_js);
    return 1;
  }

  if(strncmp(req_val.algorithm.c_str(), "SHA3_512",sizeof("SHA3_512")) == 0){
    HASHING<SHA3_512>(req_val.type, req_val.payload, req_val.hash, req_val.hex,req_val.error);
  }
  else if(strncmp(req_val.algorithm.c_str(), "SHA3_384",sizeof("SHA3_384")) == 0){
    HASHING<SHA3_384>(req_val.type, req_val.payload, req_val.hash, req_val.hex,req_val.error);
  }
  else if(strncmp(req_val.algorithm.c_str(), "SHA3_256",sizeof("SHA3_256")) == 0){
    HASHING<SHA3_256>(req_val.type, req_val.payload, req_val.hash, req_val.hex,req_val.error);
  }
  else if(strncmp(req_val.algorithm.c_str(), "SHA3_224",sizeof("SHA3_224")) == 0){
    HASHING<SHA3_224>(req_val.type, req_val.payload, req_val.hash, req_val.hex,req_val.error);
  }
  else if(strncmp(req_val.algorithm.c_str(), "SHA_512",sizeof("SHA_512")) == 0){
    HASHING<SHA512>(req_val.type, req_val.payload, req_val.hash, req_val.hex,req_val.error);
  }
  else if(strncmp(req_val.algorithm.c_str(), "SHA_384",sizeof("SHA_384")) == 0){
    HASHING<SHA384>(req_val.type, req_val.payload, req_val.hash, req_val.hex,req_val.error);
  }
  else if(strncmp(req_val.algorithm.c_str(), "SHA_256",sizeof("SHA_256")) == 0){
    HASHING<SHA256>(req_val.type, req_val.payload, req_val.hash, req_val.hex,req_val.error);
  }
  else if(strncmp(req_val.algorithm.c_str(), "SHA_224",sizeof("SHA_224")) == 0){
    HASHING<SHA224>(req_val.type, req_val.payload, req_val.hash, req_val.hex,req_val.error);
  }
  else if(strncmp(req_val.algorithm.c_str(), "SHA_1",sizeof("SHA_1")) == 0){
    HASHING<SHA1>(req_val.type, req_val.payload, req_val.hash, req_val.hex,req_val.error);
  }
  else if(strncmp(req_val.algorithm.c_str(), "WHIRLPOOL",sizeof("WHIRLPOOL")) == 0){
    HASHING<Whirlpool>(req_val.type, req_val.payload, req_val.hash, req_val.hex,req_val.error);
  }
  else if(strncmp(req_val.algorithm.c_str(), "BLAKE2B",sizeof("BLAKE2B")) == 0){
    HASHING<BLAKE2b>(req_val.type, req_val.payload, req_val.hash, req_val.hex,req_val.error);
  }
  else if(strncmp(req_val.algorithm.c_str(), "SIPHASH",sizeof("SIPHASH")) == 0){
    SIPHASH_(req_val.type, req_val.payload, req_val.hash, req_val.hex,req_val.error);
  }
  else{
    req_val.error="Bad Hash algorithm ";
    answ_error(req_val,answ_js);
    return 1;
  }

  hash_anws(req_val,answ_js);
  return 0;
}
