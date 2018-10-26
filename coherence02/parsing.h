#include "rapidjson/document.h"
#include "rapidjson/writer.h"
#include "rapidjson/stringbuffer.h"
#include "rapidjson/error/en.h"
#include <iostream>
#include <fstream>
#include <sstream>

#include "params.h"

#include "parse-func.h"
#include "crypt-hash.h"
#include "crypt-mac.h"
#include "crypt-stream.h"
#include "crypt-argon2.h"
#include "crypt-rand.h"
#include "crypt-dsa.h"
#include "crypt-dh.h"
#include "crypt-block.h"
#include "crypt-rsa.h"
#include "crypt-ecc.h"
#include "crypt-ntru.h"

extern "C" {
#include "crypt-oqs.h"
}

#include <stdio.h>

using namespace rapidjson;
using namespace  std;




int parse_log(stru_info_log& log_info,string& log_js){
  Clear2json(log_info.req);
  Clear2json(log_info.answ);

  stringstream stream;
  stream<<"{ \"ip\":\""<<log_info.ip<<"\",";
  stream<<"\"timestamp\":"<<log_info.timestamp<<",";
  stream<<"\"exec_time\":"<<log_info.exec_time<<",";
  stream<<"\"req\":"<<log_info.req<<",";
  stream<<"\"answ\":"<<log_info.answ<<"}";

  #ifdef DEBUG
  cout<<"Log: "<<stream.str()<<endl;
  #endif

  log_js=stream.str();
  return 0;
}


int PARSING(string& str_json, string& answ_js ){
  Document d;
  stru_param req_val;
  answ_js.clear();
  answ_js="{}";

  if(Parsingjson(d, str_json,req_val,answ_js)!=0)
  return 1;

  if(check_ver(d,req_val,answ_js)!=0)
  return 1;

  if(d.HasMember("algorithm") && d["algorithm"].IsString()){
    req_val.algorithm=d["algorithm"].GetString();
  }
  else{
    req_val.error.clear();
    req_val.error="No algorithm tag or bad algorithm data type ";
    req_val.tag="error";
    Addstr2json(answ_js, req_val.tag, req_val.error);
    #ifdef DEBUG
    cerr << req_val.error;
    #endif
    return 1;
  }

  //STRING//////////////////////////////////////////////////////////////////
  if(strncmp(req_val.algorithm.c_str(), "SHA3_512",sizeof("SHA3_512")) == 0){
    parse_hash(d,req_val,answ_js);
  }
  else if(strncmp(req_val.algorithm.c_str(), "SHA3_384",sizeof("SHA3_384")) == 0){
    parse_hash(d,req_val,answ_js);
  }
  else if(strncmp(req_val.algorithm.c_str(), "SHA3_256",sizeof("SHA3_256")) == 0){
    parse_hash(d,req_val,answ_js);
  }
  else if(strncmp(req_val.algorithm.c_str(), "SHA3_224",sizeof("SHA3_224")) == 0){
    parse_hash(d,req_val,answ_js);
  }
  else if(strncmp(req_val.algorithm.c_str(), "SHA_512",sizeof("SHA_512")) == 0){
    parse_hash(d,req_val,answ_js);
  }
  else if(strncmp(req_val.algorithm.c_str(), "SHA_384",sizeof("SHA_384")) == 0){
    parse_hash(d,req_val,answ_js);
  }
  else if(strncmp(req_val.algorithm.c_str(), "SHA_256",sizeof("SHA_256")) == 0){
    parse_hash(d,req_val,answ_js);
  }
  else if(strncmp(req_val.algorithm.c_str(), "SHA_224",sizeof("SHA_224")) == 0){
    parse_hash(d,req_val,answ_js);
  }
  else if(strncmp(req_val.algorithm.c_str(), "SHA_1",sizeof("SHA_1")) == 0){
    parse_hash(d,req_val,answ_js);
  }
  else if(strncmp(req_val.algorithm.c_str(), "WHIRLPOOL",sizeof("WHIRLPOOL")) == 0){
    parse_hash(d,req_val,answ_js);
  }
  else if(strncmp(req_val.algorithm.c_str(), "BLAKE2B",sizeof("BLAKE2B")) == 0){
    parse_hash(d,req_val,answ_js);
  }
  else if(strncmp(req_val.algorithm.c_str(), "POLY1305",sizeof("POLY1305")) == 0){
    parse_poly(d,req_val,answ_js);
  }
  else if(strncmp(req_val.algorithm.c_str(), "HMAC",sizeof("HMAC")) == 0){
    parse_hmac(d,req_val,answ_js);
  }
  else if(strncmp(req_val.algorithm.c_str(), "CMAC",sizeof("CMAC")) == 0){
    parse_cmac(d,req_val,answ_js);
  }
  else if(strncmp(req_val.algorithm.c_str(), "VMAC",sizeof("VMAC")) == 0){
    parse_vmac(d,req_val,answ_js);
  }
  else if(strncmp(req_val.algorithm.c_str(), "POLY1305",sizeof("POLY1305")) == 0){
    parse_poly(d,req_val,answ_js);
  }
  else if(strncmp(req_val.algorithm.c_str(), "SOSEMANUK",sizeof("SOSEMANUK")) == 0){
    parse_stream(d,req_val,answ_js);
  }
  else if(strncmp(req_val.algorithm.c_str(), "SALSA20",sizeof("SALSA20")) == 0){
    parse_stream(d,req_val,answ_js);
  }
  else if(strncmp(req_val.algorithm.c_str(), "ARGON2",sizeof("ARGON2")) == 0){
    parse_argon2(d,req_val,answ_js);
  }
  else if(strncmp(req_val.algorithm.c_str(), "RAND_RP",sizeof("RAND_RP")) == 0){
    parse_rand(d,req_val,answ_js);
  }
  else if(strncmp(req_val.algorithm.c_str(), "RAND_AUTO",sizeof("RAND_AUTO")) == 0){
    parse_rand(d,req_val,answ_js);
  }
  else if(strncmp(req_val.algorithm.c_str(), "RAND_RDRAND",sizeof("RAND_RDRAND")) == 0){
    parse_rand(d,req_val,answ_js);
  }
  else if(strncmp(req_val.algorithm.c_str(), "DSA",sizeof("DSA")) == 0){
    parse_dsa(d,req_val,answ_js);
  }
  else if(strncmp(req_val.algorithm.c_str(), "DH",sizeof("DH")) == 0){
    parse_dh(d,req_val,answ_js);
  }
  else if(strncmp(req_val.algorithm.c_str(), "AES",sizeof("AES")) == 0){
    parse_block(d,req_val,answ_js);
  }
  else if(strncmp(req_val.algorithm.c_str(), "RC6",sizeof("RC6")) == 0){
    parse_block(d,req_val,answ_js);
  }
  else if(strncmp(req_val.algorithm.c_str(), "MARS",sizeof("MARS")) == 0){
    parse_block(d,req_val,answ_js);
  }
  else if(strncmp(req_val.algorithm.c_str(), "SERPENT",sizeof("SERPENT")) == 0){
    parse_block(d,req_val,answ_js);
  }
  else if(strncmp(req_val.algorithm.c_str(), "TWOFISH",sizeof("TWOFISH")) == 0){
    parse_block(d,req_val,answ_js);
  }
  else if(strncmp(req_val.algorithm.c_str(), "CAST256",sizeof("CAST256")) == 0){
    parse_block(d,req_val,answ_js);
  }
  else if(strncmp(req_val.algorithm.c_str(), "CAMELLIA",sizeof("CAMELLIA")) == 0){
    parse_block(d,req_val,answ_js);
  }
  else if(strncmp(req_val.algorithm.c_str(), "SPECK128",sizeof("SPECK128")) == 0){
    parse_block(d,req_val,answ_js);
  }
  else if(strncmp(req_val.algorithm.c_str(), "SIMECK64",sizeof("SIMECK64")) == 0){
    parse_block(d,req_val,answ_js);
  }
  else if(strncmp(req_val.algorithm.c_str(), "RSA",sizeof("RSA")) == 0){
    parse_rsa(d,req_val,answ_js);
  }
  else if(strncmp(req_val.algorithm.c_str(), "ECC_GEN",sizeof("ECC_GEN")) == 0){
    parse_ec_gen(d,req_val,answ_js);
  }
  else if(strncmp(req_val.algorithm.c_str(), "ECIES",sizeof("ECIES")) == 0){
    parse_ecies(d,req_val,answ_js);
  }
  else if(strncmp(req_val.algorithm.c_str(), "ECDSA",sizeof("ECDSA")) == 0){
    parse_ecdsa(d,req_val,answ_js);
  }
  else if(strncmp(req_val.algorithm.c_str(), "ECDH",sizeof("ECDH")) == 0){
    parse_ecdh(d,req_val,answ_js);
  }
  else if(strncmp(req_val.algorithm.c_str(), "NTRU",sizeof("NTRU")) == 0){
    parse_ntru(d,req_val,answ_js);
  }
  else if(strncmp(req_val.algorithm.c_str(), "QTESLA",sizeof("QTESLA")) == 0){
    parse_qtesla(d,req_val,answ_js);
  }
  else{
    req_val.error="Bad algorithm";
    req_val.tag="error";
    Addstr2json(answ_js, req_val.tag, req_val.error);
    #ifdef DEBUG
    cerr << req_val.error;
    #endif
    return 1;
  }

  return 0;
}
