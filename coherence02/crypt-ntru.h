#include "rapidjson/document.h"
#include "rapidjson/writer.h"
#include "rapidjson/stringbuffer.h"
#include "rapidjson/error/en.h"
#include <iostream>
#include <fstream>

#include "libntru/src/ntru.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>
#include <time.h>

#include "cryptopp/filters.h"
#include "cryptopp/hex.h"
#include "cryptopp/files.h"
#include "cryptopp/cryptlib.h"

using namespace CryptoPP;
using namespace  std;

int check_error(int& i, string& error){
  error.clear();

  if(i==0)
  return 0;
  else if(i==1)
  error="NTRU_ERR_OUT_OF_MEMORY";
  else if(i==2)
  error="NTRU_ERR_PRNG";
  else if(i==3)
  error="NTRU_ERR_MSG_TOO_LONG";
  else if(i==4)
  error="NTRU_ERR_INVALID_MAX_LEN";
  else if(i==5)
  error="NTRU_ERR_DM0_VIOLATION";
  else if(i==6)
  error="NTRU_ERR_NO_ZERO_PAD";
  else if(i==7)
  error="NTRU_ERR_INVALID_ENCODING";
  else if(i==8)
  error="NTRU_ERR_NULL_ARG";
  else if(i==9)
  error="NTRU_ERR_UNKNOWN_PARAM_SET";
  else if(i==10)
  error="NTRU_ERR_INVALID_PARAM";
  else if(i==11)
  error="NTRU_ERR_INVALID_KEY";
  else
  error="NTRU_ERR_UNKNOWN";

  return 0;
}

int search_ntru_param_(Document& d, stru_param& req_val, string& answ_js){
  if(d.HasMember("parameter")){
    if(check_params(d,req_val,answ_js)!=0)
    return 1;

    if(strncmp(req_val.parameter.c_str(), "EES449EP1",sizeof("EES449EP1")) == 0){
      req_val.params_=EES449EP1;
    }
    else if(strncmp(req_val.parameter.c_str(), "EES613EP1",sizeof("EES613EP1")) == 0){
      req_val.params_=EES613EP1;
    }
    else if(strncmp(req_val.parameter.c_str(), "EES761EP1",sizeof("EES761EP1")) == 0){
      req_val.params_=EES761EP1;
    }
    else if(strncmp(req_val.parameter.c_str(), "EES677EP1",sizeof("EES677EP1")) == 0){
      req_val.params_=EES677EP1;
    }
    else if(strncmp(req_val.parameter.c_str(), "EES887EP1",sizeof("EES887EP1")) == 0){
      req_val.params_=EES887EP1;
    }
    else if(strncmp(req_val.parameter.c_str(), "EES1087EP1",sizeof("EES1087EP1")) == 0){
      req_val.params_=EES1087EP1;
    }
    else if(strncmp(req_val.parameter.c_str(), "EES1087EP2",sizeof("EES1087EP2")) == 0){
      req_val.params_=EES1087EP2;
    }
    else if(strncmp(req_val.parameter.c_str(), "EES1171EP1",sizeof("EES1171EP1")) == 0){
      req_val.params_=EES1171EP1;
    }
    else if(strncmp(req_val.parameter.c_str(), "EES1499EP1",sizeof("EES1499EP1")) == 0){
      req_val.params_=EES1499EP1;
    }
    else{
      req_val.error="Bad parameter ";
      answ_error(req_val,answ_js);
      return 1;
    }
  }
  else{
    req_val.error.clear();
    req_val.error="Not parameter to NTRU";
    req_val.tag="error";
    Addstr2json(answ_js, req_val.tag, req_val.error);
    #ifdef DEBUG
    cerr << req_val.error;
    #endif
    return 1;
  }
  return 0;
}

////////////////////////////////////////////////////////////////////////
int NTRU_GEN(struct NtruEncParams& params_,string& privkey, string& pubkey,string& error){
  error.clear();

  NtruRandGen rng_def = NTRU_RNG_DEFAULT;
  NtruRandContext rand_ctx_def;
  if (ntru_rand_init(&rand_ctx_def, &rng_def) != NTRU_SUCCESS){
    error="rng fail";
    #ifdef DEBUG
    cerr << error << endl;
    #endif
    return 1;
  }

  NtruEncKeyPair kp;
  if (ntru_gen_key_pair(&params_, &kp, &rand_ctx_def) != NTRU_SUCCESS){
    error="keygen fail";
    #ifdef DEBUG
    cerr << error << endl;
    #endif
    return 1;
  }

  if (ntru_rand_release(&rand_ctx_def) != NTRU_SUCCESS){
    error="rng release fail";
    #ifdef DEBUG
    cerr << error << endl;
    #endif
    return 1;
  }

  int i=0;

  /* export key to uint8_t array */
  uint8_t pub_arr[ntru_pub_len(&params_)];
  char pub_hex[4];
  char priv_hex[4];

  ntru_export_pub(&kp.pub, pub_arr);

  //printf("%d %#x\n",sizeof(pub_arr), pub_arr);
  for (i = 0; i < ntru_pub_len(&params_); i++){
    //printf("%02X", pub_arr[i]);
    snprintf(pub_hex,4,"%02X", pub_arr[i]);
    pubkey+=pub_hex;
  }

  /* export key to uint8_t array */
  uint8_t priv_arr[ntru_priv_len(&params_)];
  ntru_export_priv(&kp.priv, priv_arr);

  //printf("%d %#x\n",sizeof(priv_arr), priv_arr);
  for (i = 0; i < ntru_priv_len(&params_); i++){
    //printf("%02X", priv_arr[i]);
    snprintf(priv_hex,4,"%02X", priv_arr[i]);
    privkey+=priv_hex;
  }

  return 0;
}

int NTRU_GEN_PUB(struct NtruEncParams& params_,string& privkey, string& pubkey,string& error){
  error.clear();

  string priv_bin;
  int i;

  StringSource(privkey, true, new HexDecoder(new StringSink(priv_bin)));

  NtruRandGen rng_def = NTRU_RNG_DEFAULT;
  NtruRandContext rand_ctx_def;
  uint8_t priv_arr[ntru_priv_len(&params_)];
  memcpy(priv_arr, priv_bin.data(),ntru_priv_len(&params_));
  NtruEncKeyPair kp;
  NtruEncPrivKey priv;
  ntru_import_priv(priv_arr, &priv);
  kp.priv=priv;

  if (ntru_rand_init(&rand_ctx_def, &rng_def) != NTRU_SUCCESS){
    error="rng fail";
    #ifdef DEBUG
    cerr << error << endl;
    #endif
    return 1;
  }

  NtruEncPubKey pub2;
  if (ntru_gen_pub(&params_, &kp.priv, &pub2, &rand_ctx_def) != NTRU_SUCCESS){
    error="pub gen fail";
    #ifdef DEBUG
    cerr << error << endl;
    #endif
    return 1;
  }


  if (ntru_rand_release(&rand_ctx_def) != NTRU_SUCCESS){
    error="rng release fail";
    #ifdef DEBUG
    cerr << error << endl;
    #endif
    return 1;
  }

  uint8_t pub_arr[ntru_pub_len(&params_)];
  char pub_hex[4];
  ntru_export_pub(&pub2, pub_arr);

  for (i = 0; i < ntru_pub_len(&params_); i++){
    snprintf(pub_hex,4,"%02X", pub_arr[i]);
    pubkey+=pub_hex;
  }


  return 0;
}

int NTRU_ENC(struct NtruEncParams& params_,string& payload,string& pubkey, string& result, int& binary,string& error){
  error.clear();
  result.clear();

  string pub_bin, payload_e;
  int i;

  StringSource(pubkey, true, new HexDecoder(new StringSink(pub_bin)));

  NtruRandGen rng_def = NTRU_RNG_DEFAULT;
  NtruRandContext rand_ctx_def;
  uint8_t pub_arr[ntru_pub_len(&params_)];
  memcpy(pub_arr, pub_bin.data(),ntru_pub_len(&params_));
  NtruEncKeyPair kp;
  NtruEncPubKey pub;
  ntru_import_pub(pub_arr, &pub);
  kp.pub=pub;

  int msg_mx=ntru_max_msg_len(&params_);
  i=ntru_rand_init(&rand_ctx_def, &rng_def);

  if(i!=0){
    check_error(i,error);
    return 1;
  }

  if(binary==0)
  payload_e=payload;
  else if(binary==1)
  StringSource(payload, true, new HexDecoder( new StringSink(payload_e)));
  else{
    error+="Bad binary bool ";
    return 1;
  }

  if(payload_e.size()>msg_mx){
    error="NTRU_ERR_MSG_TOO_LONG";
    return 1;
  }

  uint8_t msg[msg_mx];
  memcpy(msg, payload_e.c_str(),payload_e.size());
  uint8_t enc[ntru_enc_len(&params_)];
  i=ntru_encrypt(msg,payload_e.size(), &kp.pub, &params_, &rand_ctx_def, enc);
  if (i!=0){
    check_error(i,error);
    #ifdef DEBUG
    cerr << error << endl;
    #endif
    return 1;
  }

  if (ntru_rand_release(&rand_ctx_def) != NTRU_SUCCESS){
    error="rng release fail";
    #ifdef DEBUG
    cerr << error << endl;
    #endif
    return 1;
  }

  char enc_hex[4];

  for(i = 0; i < ntru_enc_len(&params_); i++){
    snprintf(enc_hex,4,"%02X", enc[i]);
    result+=enc_hex;
  }

  return 0;
}

int NTRU_DEC(struct NtruEncParams& params_,string& payload,string& privkey, string& pubkey, string& result,string& error){
  error.clear();
  result.clear();

  string pub_bin,priv_bin,payload_e;
  int i;

  StringSource(privkey, true, new HexDecoder(new StringSink(priv_bin)));
  StringSource(pubkey, true, new HexDecoder(new StringSink(pub_bin)));

  uint8_t priv_arr[ntru_priv_len(&params_)];
  memcpy(priv_arr, priv_bin.data(),ntru_priv_len(&params_));
  uint8_t pub_arr[ntru_pub_len(&params_)];
  memcpy(pub_arr, pub_bin.data(),ntru_pub_len(&params_));
  NtruEncKeyPair kp;
  NtruEncPubKey pub;
  ntru_import_pub(pub_arr, &pub);
  NtruEncPrivKey priv;
  ntru_import_priv(priv_arr, &priv);
  kp.pub=pub;
  kp.priv=priv;

  if(payload_e.size()>ntru_enc_len(&params_)){
    error="NTRU_ERR_MSG_TOO_LONG";
    return 1;
  }

  StringSource(payload, true, new HexDecoder( new StringSink(payload_e)));

  uint8_t enc[ntru_enc_len(&params_)];
  memcpy(enc, payload_e.c_str(),payload_e.size());

  uint8_t dec[ntru_max_msg_len(&params_)];
  uint16_t dec_len;
  i=ntru_decrypt((uint8_t*)&enc, &kp, &params_, (uint8_t*)&dec, &dec_len);

  if (i!=0){
    check_error(i,error);
    #ifdef DEBUG
    cerr << error << endl;
    #endif
    return 1;
  }
  char dec_hex[4];

  for(i = 0; i < dec_len; i++){
    snprintf(dec_hex,4,"%c", dec[i]);
    result+=dec_hex;
  }
  if(Isjson(result,error)!=0){
    string result_tmp=result;
    result.clear();
    error.clear();
    StringSource(result_tmp, true,new HexEncoder(new StringSink( result )));
  }

  return 0;
}

////////////////////////////////////////////////////////////////////////
int parse_ntru_gen(Document& d, stru_param& req_val, string& answ_js){

  NTRU_GEN(req_val.params_, req_val.privkey, req_val.pubkey, req_val.error);

  req_val.tag.clear();
  req_val.tag="algorithm";
  Addstr2json(answ_js, req_val.tag, req_val.algorithm);
  req_val.tag.clear();
  req_val.tag="parameter";
  Addstr2json(answ_js, req_val.tag, req_val.parameter);
  req_val.tag.clear();
  req_val.tag="privkey";
  Addstr2json(answ_js, req_val.tag, req_val.privkey);
  req_val.tag.clear();
  req_val.tag="pubkey";
  Addstr2json(answ_js, req_val.tag, req_val.pubkey);
  req_val.tag.clear();
  req_val.tag="error";
  Addstr2json(answ_js, req_val.tag, req_val.error);

  return 0;
}


int parse_ntru_gen_pub(Document& d, stru_param& req_val, string& answ_js){

  if(!(d.HasMember("privkey"))){
    req_val.error+="Not privkey tag ";
    answ_error(req_val,answ_js);
    return 1;
  }
  if(check_keys(d,req_val,answ_js)!=0)
  return 1;

  NTRU_GEN_PUB(req_val.params_, req_val.privkey, req_val.pubkey, req_val.error);

  req_val.tag.clear();
  req_val.tag="algorithm";
  Addstr2json(answ_js, req_val.tag, req_val.algorithm);
  req_val.tag.clear();
  req_val.tag="parameter";
  Addstr2json(answ_js, req_val.tag, req_val.parameter);
  req_val.tag.clear();
  req_val.tag="pubkey";
  Addstr2json(answ_js, req_val.tag, req_val.pubkey);
  req_val.tag.clear();
  req_val.tag="error";
  Addstr2json(answ_js, req_val.tag, req_val.error);

  return 0;
}



int parse_ntru_cipher(Document& d, stru_param& req_val, string& answ_js){
  if(d.HasMember("type") ){
    if(check_type(d,req_val,answ_js)!=0)
    return 1;

    if(strncmp(req_val.type.c_str(), "file",sizeof("file")) == 0){
      req_val.error="NTRU file encryption not supported ";
      answ_error(req_val,answ_js);
      return 1;
    }
  }
  else{
    req_val.error="Not type tag ";
    answ_error(req_val,answ_js);
    return 1;
  }

  if(d.HasMember("operation")){
    if(check_ops(d,req_val,answ_js)!=0)
    return 1;

    if(strncmp(req_val.operation.c_str(), "enc",sizeof("enc")) == 0){
      if(!(d.HasMember("plaintext") && d.HasMember("pubkey"))){
        req_val.error+="Not plaintext/pubkey tag ";
        answ_error(req_val,answ_js);
        return 1;
      }
      if(check_plain(d,req_val,answ_js)!=0)
      return 1;
      if(check_bin(d,req_val,answ_js)!=0)
      return 1;
      if(check_keys(d,req_val,answ_js)!=0)
      return 1;

      req_val.payload=req_val.plaintext;

      NTRU_ENC(req_val.params_,req_val.payload, req_val.pubkey, req_val.result, req_val.hex ,req_val.error);
      cipher_anws(req_val,answ_js);
    }
    else if(strncmp(req_val.operation.c_str(), "dec",sizeof("dec")) == 0){
      if(!(d.HasMember("plaintext") && d.HasMember("privkey")&& d.HasMember("pubkey"))){
        req_val.error+="Not plaintext/privkey/pubkey tag ";
        answ_error(req_val,answ_js);
        return 1;
      }
      if(check_plain(d,req_val,answ_js)!=0)
      return 1;
      if(check_bin(d,req_val,answ_js)!=0)
      return 1;
      if(check_keys(d,req_val,answ_js)!=0)
      return 1;

      req_val.payload=req_val.plaintext;

      NTRU_DEC(req_val.params_,req_val.payload, req_val.privkey, req_val.pubkey, req_val.result,req_val.error);
      cipher_anws(req_val,answ_js);
    }
    else{
      req_val.error="Not plaintext/pubkey/privkey tag ";
      answ_error(req_val,answ_js);
      return 1;
    }


  }
  else{
    req_val.error="Not ops tag ";
    answ_error(req_val,answ_js);
    return 1;
  }

  return 0;
}

////////////////////////////////////////////////////////////////////////
int parse_ntru(Document& d, stru_param& req_val, string& answ_js){
  #ifdef DEBUG
  printf("Good algorithm NTRU ");
  #endif

  if(d.HasMember("parameter")){
    if(check_params(d,req_val,answ_js)!=0)
    return 1;
    if(search_ntru_param_(d, req_val, answ_js)!=0)
    return 1;
  }
  else{
    req_val.error.clear();
    req_val.error="Not parameter tag";
    req_val.tag="error";
    Addstr2json(answ_js, req_val.tag, req_val.error);
    #ifdef DEBUG
    cerr << req_val.error;
    #endif
    return 1;
  }

  if(d.HasMember("operation")){
    if(check_ops(d,req_val,answ_js)!=0)
    return 1;

    if(strncmp(req_val.operation.c_str(), "gen",sizeof("gen")) == 0){
      parse_ntru_gen(d, req_val, answ_js);
    }
    else if (strncmp(req_val.operation.c_str(), "gen_pub",sizeof("gen_pub")) == 0){
      parse_ntru_gen_pub(d, req_val, answ_js);
    }
    else if (strncmp(req_val.operation.c_str(), "enc",sizeof("enc")) == 0){
      parse_ntru_cipher(d, req_val, answ_js);
    }
    else if (strncmp(req_val.operation.c_str(), "dec",sizeof("dec")) == 0){
      parse_ntru_cipher(d, req_val, answ_js);
    }
    else {
      req_val.error="Bad ntru operation ";
      answ_error(req_val,answ_js);
      return 1;
    }
  }
  else{
    req_val.error.clear();
    req_val.error="Not operation ";
    req_val.tag="error";
    Addstr2json(answ_js, req_val.tag, req_val.error);
    #ifdef DEBUG
    cerr << req_val.error;
    #endif
    return 1;
  }

  return 0;
}
