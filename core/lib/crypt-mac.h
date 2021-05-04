#include "rapidjson/document.h"
#include "rapidjson/writer.h"
#include "rapidjson/stringbuffer.h"
#include "rapidjson/error/en.h"
#include <iostream>
#include <fstream>

#include "cryptopp/hmac.h"
#include "cryptopp/cmac.h"
#include "cryptopp/vmac.h"
#include "cryptopp/poly1305.h"
#include "cryptopp/sha3.h"
#include "cryptopp/sha.h"
#include "cryptopp/whrlpool.h"
#include "cryptopp/blake2.h"
#include "cryptopp/aes.h"
#include "cryptopp/rc6.h"
#include "cryptopp/mars.h"
#include "cryptopp/serpent.h"
#include "cryptopp/twofish.h"
#include "cryptopp/cast.h"
#include "cryptopp/camellia.h"

#include "cryptopp/filters.h"
#include "cryptopp/hex.h"
#include "cryptopp/files.h"
#include "cryptopp/osrng.h"

using namespace CryptoPP;
using namespace  std;


int mac_anws(stru_param& req_val, string& answ_js){

  req_val.tag.clear();
  req_val.tag="algorithm";
  Addstr2json(answ_js, req_val.tag, req_val.algorithm);
  req_val.tag.clear();
  req_val.tag="family";
  Addstr2json(answ_js, req_val.tag, req_val.family);
  req_val.tag.clear();
  req_val.tag="mac";
  Addstr2json(answ_js, req_val.tag, req_val.mac);
  req_val.tag.clear();
  req_val.tag="error";
  Addstr2json(answ_js, req_val.tag, req_val.error);

  return 0;
}

int check_poly(Document& d, stru_param& req_val, string& answ_js){
  if(d.HasMember("nonce") && d["nonce"].IsString()&&d.HasMember("key") && d["key"].IsString()){
    req_val.nonce=d["nonce"].GetString();
    req_val.key=d["key"].GetString();
    if(Isb16(req_val.nonce,req_val.error)!=0){
      req_val.error+=" nonce no hex ";
      req_val.tag="error";
      Addstr2json(answ_js, req_val.tag, req_val.error);
      #ifdef DEBUG
      cerr << req_val.error;
      #endif
      return 1;
    }
    if(Isb16(req_val.key,req_val.error)!=0){
      req_val.error+=" key no hex ";
      req_val.tag="error";
      Addstr2json(answ_js, req_val.tag, req_val.error);
      #ifdef DEBUG
      cerr << req_val.error;
      #endif
      return 1;
    }
    if(req_val.nonce.size()!=32 || req_val.key.size()!=64){
      req_val.error+=" nonce/key size not 16/32 ";
      req_val.tag="error";
      Addstr2json(answ_js, req_val.tag, req_val.error);
      #ifdef DEBUG
      cerr << req_val.error;
      #endif
      return 1;
    }
  }
  return 0;
}

////////////////////////////////////////////////////////////////////////
//HMACING///////////////////////////////////////////////////////////////
template <typename T>
int HMACING(string& payload, string& type, string& mac, string& key , int& binary,string& error){
  mac.clear();
  error.clear();
  SecByteBlock key_b(key.size()/2);
  string key_e;
  StringSource(key, true, new HexDecoder(new StringSink(key_e)));
  memcpy( key_b, key_e.data(),key_b.size());

  try{
    HMAC< T > hmac(key_b, key_b.size());
    if (strncmp(type.c_str(), "string",sizeof("string")) == 0){
      if(binary==0)
      StringSource(payload, true, new HashFilter(hmac,new HexEncoder(new StringSink(mac))));
      else if(binary==1)
      StringSource(payload, true, new HexDecoder( new HashFilter(hmac,new HexEncoder(new StringSink(mac)))));
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

//CMACING///////////////////////////////////////////////////////////////
template <typename T>
int CMACING(string& payload, string& type, string& mac, string& key , int& binary,string& error){
  mac.clear();
  error.clear();
  SecByteBlock key_b(key.size()/2);
  string key_e;
  StringSource (key, true, new HexDecoder(new StringSink(key_e)));
  memcpy( key_b, key_e.data(),key_b.size());

  try{
    CMAC< T > cmac(key_b, key_b.size());
    if (strncmp(type.c_str(), "string",sizeof("string")) == 0){
      if(binary==0)
      StringSource(payload, true, new HashFilter(cmac,new HexEncoder(new StringSink(mac))));
      else if(binary==1)
      StringSource(payload, true, new HexDecoder( new HashFilter(cmac,new HexEncoder(new StringSink(mac)))));
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

//VMACING///////////////////////////////////////////////////////////////
template <typename T>
int VMACING(string& payload, string& type, string& mac, string& key, string& iv , int& binary,string& error){
  mac.clear();
  error.clear();
  SecByteBlock key_b(key.size()/2),iv_b(iv.size()/2);
  string key_e,iv_e;
  StringSource (key, true, new HexDecoder(new StringSink(key_e)));
  memcpy( key_b, key_e.data(),key_b.size());
  StringSource (iv, true, new HexDecoder(new StringSink(iv_e)));
  memcpy( iv_b, iv_e.data(),iv_b.size());

  try{
    VMAC< T > vmac;
    vmac.SetKeyWithIV(key_b, key_b.size(),iv_b, iv_b.size());
    if (strncmp(type.c_str(), "string",sizeof("string")) == 0){
      if(binary==0)
      StringSource(payload, true, new HashFilter(vmac,new HexEncoder(new StringSink(mac))));
      else if(binary==1)
      StringSource(payload, true, new HexDecoder( new HashFilter(vmac,new HexEncoder(new StringSink(mac)))));
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

//Poly1305//////////////////////////////////////////////////////////////
int POLY1305_(string& payload, string& type, string& mac, string& key, string& nonce, int& binary, string& error){
  mac.clear();
  error.clear();
  SecByteBlock key_b(key.size()/2),nonce_b(nonce.size()/2);
  string key_e,nonce_e;
  StringSource (key, true, new HexDecoder(new StringSink(key_e)));
  memcpy( key_b, key_e.data(),key_b.size());
  StringSource (nonce, true, new HexDecoder(new StringSink(nonce_e)));
  memcpy( nonce_b, nonce_e.data(),nonce_b.size());

  try{
    Poly1305<AES> poly(key_b, key_b.size(), nonce_b, nonce_b.size());
    if (strncmp(type.c_str(), "string",sizeof("string")) == 0){
      if(binary==0)
      StringSource(payload, true, new HashFilter(poly,new HexEncoder(new StringSink(mac))));
      else if(binary==1)
      StringSource(payload, true, new HexDecoder( new HashFilter(poly,new HexEncoder(new StringSink(mac)))));
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

//PARSE_HMAC_///////////////////////////////////////////////////////////
int parse_hmac(Document& d, stru_param& req_val, string& answ_js){
  if(d.HasMember("type") ){
    if(check_type(d,req_val,answ_js)!=0)
    return 1;
  }
  else{
    req_val.error="Not type tag ";
    answ_error(req_val,answ_js);
    return 1;
  }

  if(d.HasMember("family") ){
    if(check_fam(d,req_val,answ_js)!=0)
    return 1;
  }
  else{
    req_val.error="Not family tag ";
    answ_error(req_val,answ_js);
    return 1;
  }

  if (strncmp(req_val.type.c_str(), "string",sizeof("string")) == 0){
    if(d.HasMember("plaintext") && d.HasMember("key") ){
      if(check_plain(d,req_val,answ_js)!=0)
      return 1;
      if(check_bin(d,req_val,answ_js)!=0)
      return 1;
      if(check_key(d,req_val,answ_js)!=0)
      return 1;

      req_val.payload=req_val.plaintext;
    }
    else{
      req_val.error="Not plaintext/key tag ";
      answ_error(req_val,answ_js);
      return 1;
    }
  }
  else{
    req_val.error="Bad tye ";
    answ_error(req_val,answ_js);
    return 1;
  }

  if(strncmp(req_val.family.c_str(), "sha3_512",sizeof("sha3_512")) == 0){
    HMACING<SHA3_512>(req_val.payload, req_val.type, req_val.mac, req_val.key , req_val.hex,req_val.error);
  }
  else if(strncmp(req_val.family.c_str(), "sha3_384",sizeof("sha3_384")) == 0){
    HMACING<SHA3_384>(req_val.payload, req_val.type, req_val.mac, req_val.key , req_val.hex,req_val.error);
  }
  else if(strncmp(req_val.family.c_str(), "sha3_256",sizeof("sha3_256")) == 0){
    HMACING<SHA3_256>(req_val.payload, req_val.type, req_val.mac, req_val.key , req_val.hex,req_val.error);
  }
  else if(strncmp(req_val.family.c_str(), "sha3_224",sizeof("sha3_224")) == 0){
    HMACING<SHA3_224>(req_val.payload, req_val.type, req_val.mac, req_val.key , req_val.hex,req_val.error);
  }
  else if(strncmp(req_val.family.c_str(), "sha_512",sizeof("sha_512")) == 0){
    HMACING<SHA512>(req_val.payload, req_val.type, req_val.mac, req_val.key , req_val.hex,req_val.error);
  }
  else if(strncmp(req_val.family.c_str(), "sha_384",sizeof("sha_384")) == 0){
    HMACING<SHA384>(req_val.payload, req_val.type, req_val.mac, req_val.key , req_val.hex,req_val.error);
  }
  else if(strncmp(req_val.family.c_str(), "sha_256",sizeof("sha_256")) == 0){
    HMACING<SHA256>(req_val.payload, req_val.type, req_val.mac, req_val.key , req_val.hex,req_val.error);
  }
  else if(strncmp(req_val.family.c_str(), "sha_224",sizeof("sha_224")) == 0){
    HMACING<SHA224>(req_val.payload, req_val.type, req_val.mac, req_val.key , req_val.hex,req_val.error);
  }
  else if(strncmp(req_val.family.c_str(), "sha_1",sizeof("sha_1")) == 0){
    HMACING<SHA1>(req_val.payload, req_val.type, req_val.mac, req_val.key , req_val.hex,req_val.error);
  }
  else if(strncmp(req_val.family.c_str(), "whirlpool",sizeof("whirlpool")) == 0){
    HMACING<Whirlpool>(req_val.payload, req_val.type, req_val.mac, req_val.key , req_val.hex,req_val.error);
  }
  /* HMAC: can only be used with a block-based hash function
  else if(strncmp(req_val.family.c_str(), "blake2b",sizeof("blake2")) == 0){
  HMACING<BLAKE2b>(req_val.payload, req_val.type, req_val.mac, req_val.key , req_val.hex,req_val.error);
}*/
else{
  req_val.error="Bad Hmac algorithm ";
  answ_error(req_val,answ_js);
  return 1;
}

mac_anws(req_val,answ_js);

return 0;
}

//PARSE_CMAC////////////////////////////////////////////////////////////
int parse_cmac(Document& d, stru_param& req_val, string& answ_js){
  if(d.HasMember("type") ){
    if(check_type(d,req_val,answ_js)!=0)
    return 1;
  }
  else{
    req_val.error="Not type tag ";
    answ_error(req_val,answ_js);
    return 1;
  }

  if(d.HasMember("family") ){
    if(check_fam(d,req_val,answ_js)!=0)
    return 1;
  }
  else{
    req_val.error="Not family tag ";
    answ_error(req_val,answ_js);
    return 1;
  }

  if (strncmp(req_val.type.c_str(), "string",sizeof("string")) == 0){
    if(d.HasMember("plaintext") && d.HasMember("key") ){
      if(check_plain(d,req_val,answ_js)!=0)
      return 1;
      if(check_bin(d,req_val,answ_js)!=0)
      return 1;
      if(check_key(d,req_val,answ_js)!=0)
      return 1;

      req_val.payload=req_val.plaintext;
    }
    else{
      req_val.error="Not plaintext/key tag ";
      answ_error(req_val,answ_js);
      return 1;
    }
  }
  else{
    req_val.error="Bad tye ";
    answ_error(req_val,answ_js);
    return 1;
  }


  if(strncmp(req_val.family.c_str(), "aes",sizeof("aes")) == 0){
    CMACING<AES>(req_val.payload, req_val.type, req_val.mac, req_val.key , req_val.hex,req_val.error);
  }
  else if(strncmp(req_val.family.c_str(), "rc6",sizeof("rc6")) == 0){
    CMACING<RC6>(req_val.payload, req_val.type, req_val.mac, req_val.key , req_val.hex,req_val.error);
  }
  else if(strncmp(req_val.family.c_str(), "mars",sizeof("mars")) == 0){
    CMACING<MARS>(req_val.payload, req_val.type, req_val.mac, req_val.key , req_val.hex,req_val.error);
  }
  else if(strncmp(req_val.family.c_str(), "serpent",sizeof("serpent")) == 0){
    CMACING<Serpent>(req_val.payload, req_val.type, req_val.mac, req_val.key , req_val.hex,req_val.error);
  }
  else if(strncmp(req_val.family.c_str(), "twofish",sizeof("twofish")) == 0){
    CMACING<Twofish>(req_val.payload, req_val.type, req_val.mac, req_val.key , req_val.hex,req_val.error);
  }
  else if(strncmp(req_val.family.c_str(), "cast256",sizeof("cast256")) == 0){
    CMACING<CAST256>(req_val.payload, req_val.type, req_val.mac, req_val.key , req_val.hex,req_val.error);
  }
  else if(strncmp(req_val.family.c_str(), "camellia",sizeof("camellia")) == 0){
    CMACING<Camellia>(req_val.payload, req_val.type, req_val.mac, req_val.key , req_val.hex,req_val.error);
  }
  else{
    req_val.error="Bad Cmac algorithm ";
    answ_error(req_val,answ_js);
    return 1;
  }
  mac_anws(req_val,answ_js);

  return 0;
}

//PARSE_VMAC_STRING//////////////////////////////////////////////////////
int parse_vmac(Document& d, stru_param& req_val, string& answ_js){
  if(d.HasMember("type") ){
    if(check_type(d,req_val,answ_js)!=0)
    return 1;
  }
  else{
    req_val.error="Not type tag ";
    answ_error(req_val,answ_js);
    return 1;
  }

  if(d.HasMember("family") ){
    if(check_fam(d,req_val,answ_js)!=0)
    return 1;
  }
  else{
    req_val.error="Not family tag ";
    answ_error(req_val,answ_js);
    return 1;
  }


  if (strncmp(req_val.type.c_str(), "string",sizeof("string")) == 0){
    if(d.HasMember("plaintext") && d.HasMember("key")&&d.HasMember("iv") ){
      if(check_plain(d,req_val,answ_js)!=0)
      return 1;
      if(check_bin(d,req_val,answ_js)!=0)
      return 1;
      if(check_key(d,req_val,answ_js)!=0)
      return 1;
      if(check_iv(d,req_val,answ_js)!=0)
      return 1;

      req_val.payload=req_val.plaintext;
    }
    else{
      req_val.error="Not plaintext/key/iv tag ";
      answ_error(req_val,answ_js);
      return 1;
    }
  }
  else{
    req_val.error="Bad tye ";
    answ_error(req_val,answ_js);
    return 1;
  }


  if(strncmp(req_val.family.c_str(), "aes",sizeof("aes")) == 0){
    VMACING<AES>(req_val.payload, req_val.type, req_val.mac, req_val.key , req_val.iv, req_val.hex,req_val.error);
  }
  else if(strncmp(req_val.family.c_str(), "rc6",sizeof("rc6")) == 0){
    VMACING<RC6>(req_val.payload, req_val.type, req_val.mac, req_val.key , req_val.iv, req_val.hex,req_val.error);
  }
  else if(strncmp(req_val.family.c_str(), "mars",sizeof("mars")) == 0){
    VMACING<MARS>(req_val.payload, req_val.type, req_val.mac, req_val.key , req_val.iv, req_val.hex,req_val.error);
  }
  else if(strncmp(req_val.family.c_str(), "serpent",sizeof("serpent")) == 0){
    VMACING<Serpent>(req_val.payload, req_val.type, req_val.mac, req_val.key , req_val.iv, req_val.hex,req_val.error);
  }
  else if(strncmp(req_val.family.c_str(), "twofish",sizeof("twofish")) == 0){
    VMACING<Twofish>(req_val.payload, req_val.type, req_val.mac, req_val.key , req_val.iv, req_val.hex,req_val.error);
  }
  else if(strncmp(req_val.family.c_str(), "cast256",sizeof("cast256")) == 0){
    VMACING<CAST256>(req_val.payload, req_val.type, req_val.mac, req_val.key , req_val.iv, req_val.hex,req_val.error);
  }
  else if(strncmp(req_val.family.c_str(), "camellia",sizeof("camellia")) == 0){
    VMACING<Camellia>(req_val.payload, req_val.type, req_val.mac, req_val.key , req_val.iv, req_val.hex,req_val.error);
  }
  else{
    req_val.error="Bad Vmac algorithm ";
    answ_error(req_val,answ_js);
    return 1;
  }
  mac_anws(req_val,answ_js);

  return 0;
}

//PARSE_POLY////////////////////////////////////////////////////////////
int parse_poly(Document& d, stru_param& req_val, string& answ_js){
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
    if(d.HasMember("plaintext") && d.HasMember("key")&&d.HasMember("nonce") ){

      if(check_plain(d,req_val,answ_js)!=0)
      return 1;
      if(check_bin(d,req_val,answ_js)!=0)
      return 1;
      if(check_poly(d,req_val,answ_js)!=0)
      return 1;

      req_val.payload=req_val.plaintext;
    }
    else{
      req_val.error="Not plaintext/key/nonce tag ";
      answ_error(req_val,answ_js);
      return 1;
    }
  }
  else{
    req_val.error="Bad tye ";
    answ_error(req_val,answ_js);
    return 1;
  }


  POLY1305_(req_val.payload, req_val.type, req_val.mac, req_val.key , req_val.nonce, req_val.hex,req_val.error);
  mac_anws(req_val,answ_js);

  return 0;
}
