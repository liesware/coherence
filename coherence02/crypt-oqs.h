#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "oqs/oqs.h"


int search_qtesla_param_(Document& d, stru_param& req_val, string& answ_js){
  if(d.HasMember("parameter")){
    if(check_params(d,req_val,answ_js)!=0)
    return 1;

    if(strncmp(req_val.parameter.c_str(), "qteslai",sizeof("qteslai")) == 0){
      req_val.paramsq_="qTESLA_I";
    }
    else if(strncmp(req_val.parameter.c_str(), "qteslaiiisize",sizeof("qteslaiiisize")) == 0){
      req_val.paramsq_="qTESLA_III_size";
    }
    else if(strncmp(req_val.parameter.c_str(), "qteslaiiispeed",sizeof("qteslaiiispeed")) == 0){
      req_val.paramsq_="qTESLA_III_speed";
    }
    else{
      req_val.error="Bad parameter ";
      answ_error(req_val,answ_js);
      return 1;
    }
  }
  else{
    req_val.error.clear();
    req_val.error="Not parameter for QTESLA";
    req_val.tag="error";
    Addstr2json(answ_js, req_val.tag, req_val.error);
    #ifdef DEBUG
    cerr << req_val.error;
    #endif
    return 1;
  }
  return 0;
}
////////////////////////////////////////////////////////////////////////////////
int QTESLA_V(string& payload,string& pubkey, string& sign, string& verify,int& binary, string& paramsq_ ,string& error ){
  error.clear();
  string pub_bin, payload_e, sign_bin;
  int i=0;


  OQS_SIG *sig = NULL;
  uint8_t *public_key = NULL;
  uint8_t *message = NULL;
  uint8_t *signature = NULL;
  size_t signature_len;
  OQS_STATUS rc;
  OQS_STATUS ret = OQS_ERROR;

  sig = OQS_SIG_new(paramsq_.c_str());
  if (sig == NULL) {
    return OQS_SUCCESS;
  }

  if(binary==0)
  payload_e=payload;
  else if(binary==1)
  StringSource(payload, true, new HexDecoder( new StringSink(payload_e)));
  else{
    error+="Bad binary bool ";
    return 1;
  }

  public_key = static_cast<uint8_t *>(malloc(sig->length_public_key));
  signature = static_cast<uint8_t *>(malloc(sig->length_signature));
  message = static_cast<uint8_t *>(malloc(payload_e.size()));
  size_t message_len = payload_e.size();
  signature_len=sig->length_signature;

  if ((signature == NULL) || (public_key == NULL)|| (message == NULL)) {
    error="ERROR: malloc failed";
    return 1;
  }

  StringSource(pubkey, true, new HexDecoder(new StringSink(pub_bin)));
  if(pub_bin.size()!=sig->length_public_key){
    error="Bad pubkey size";
    return 1;
  }
  StringSource(sign, true, new HexDecoder(new StringSink(sign_bin)));
  if(sign_bin.size()!=sig->length_signature){
    error="Bad sign size";
    return 1;
  }
  memcpy(public_key, pub_bin.data(),sig->length_public_key);
  memcpy(signature, sign_bin.data(),sig->length_signature);
  memcpy(message,payload_e.data(),sizeof message );

  rc = OQS_SIG_verify(sig, message, message_len, signature, signature_len, public_key);
  //rc= OQS_SIG_qTESLA_I_verify(message, message_len, signature, signature_len, public_key);
  if (rc != OQS_SUCCESS) {
    error+="ERROR: OQS_SIG_verify failed";
    return 1;
  }
  //printf("%s",signature);
  verify="QTESLA_OK" ;

  OQS_MEM_insecure_free(public_key);
  OQS_MEM_insecure_free(message);
  OQS_MEM_insecure_free(signature);
  OQS_SIG_free(sig);

 return 0;
}

int QTESLA_SIGN(string& payload,string& privkey, string& sign, int& binary, string& paramsq_ ,string& error ){
  error.clear();
  sign.clear();
  string priv_bin, payload_e;
  int i=0;


  OQS_SIG *sig = NULL;
  uint8_t *secret_key = NULL;
  uint8_t *message = NULL;
  uint8_t *signature = NULL;
  size_t signature_len;
  OQS_STATUS rc;
  OQS_STATUS ret = OQS_ERROR;

  sig = OQS_SIG_new(paramsq_.c_str());
  if (sig == NULL) {
    return OQS_SUCCESS;
  }

  if(binary==0)
  payload_e=payload;
  else if(binary==1)
  StringSource(payload, true, new HexDecoder( new StringSink(payload_e)));
  else{
    error+="Bad binary bool ";
    return 1;
  }

  secret_key = static_cast<uint8_t *>(malloc(sig->length_secret_key));
  signature = static_cast<uint8_t *>(malloc(sig->length_signature));
  message = static_cast<uint8_t *>(malloc(payload_e.size()));
  size_t message_len = payload_e.size();

  if ((signature == NULL) || (secret_key == NULL)|| (message == NULL)) {
    error="ERROR: malloc failed";
    return 1;
  }

  StringSource(privkey, true, new HexDecoder(new StringSink(priv_bin)));
  if(priv_bin.size()!=sig->length_secret_key){
    error="Bad privkey size";
    return 1;
  }
  memcpy(secret_key, priv_bin.data(),sig->length_secret_key);
  memcpy(message,payload_e.data(),sizeof message );

  rc = OQS_SIG_sign(sig, signature, &signature_len, message, message_len, secret_key);
  if (rc != OQS_SUCCESS) {
    error+="ERROR: OQS_SIG_sign failed";
    return 1;
  }

  char sign_hex[4];
  for (i = 0; i < signature_len; i++){
    snprintf(sign_hex,4,"%02X", signature[i]);
    sign+=sign_hex;
  }

  if (sig != NULL) {
    OQS_MEM_secure_free(secret_key, sig->length_secret_key);
  }
  OQS_MEM_insecure_free(message);
  OQS_MEM_insecure_free(signature);
  OQS_SIG_free(sig);

  return 0;
}


int QTESLA_GEN(string& paramsq_,string& privkey, string& pubkey,string& error){
  privkey.clear();
  pubkey.clear();
  error.clear();

  OQS_SIG *sig = NULL;
  uint8_t *public_key = NULL;
  uint8_t *secret_key = NULL;
  OQS_STATUS rc, ret = OQS_ERROR;

  sig = OQS_SIG_new(paramsq_.c_str());
  if (sig == NULL) {
    return OQS_SUCCESS;
  }

  public_key =  static_cast<uint8_t *>(malloc(sig->length_public_key));
  secret_key =  static_cast<uint8_t *>(malloc(sig->length_secret_key));

  //#ifdef DEBUG
  printf("length_public_key %d\n",sig->length_public_key );
  printf("length_secret_key %d\n",sig->length_secret_key );
  //#endif

  if ((public_key == NULL) || (secret_key == NULL)) {
    error="ERROR: malloc failed";
    return 1;
  }

  rc = OQS_SIG_keypair(sig, public_key, secret_key);
  if (rc != OQS_SUCCESS) {
    error="ERROR: OQS_SIG_keypair failed";
    return 1;
  }

  int i=0;
  char key_hex[4];
  char pub_key_ex[sig->length_public_key*2];
  //memset(pub_key_ex, 0, sizeof pub_key_ex);
  char priv_key_ex[sig->length_secret_key*2];
  //memset(priv_key_ex,0,sizeof priv_key_ex);

  for (i = 0; i < sig->length_public_key; i++){
    snprintf(key_hex,4,"%02X", public_key[i]);
    //strcat(pub_key_ex, key_hex);
    pubkey+=key_hex;
  }
  //pubkey=pub_key_ex;

  for (i = 0; i < sig->length_secret_key; i++){
    //printf("%02X", secret_key[i]);
    snprintf(key_hex,4,"%02X", secret_key[i]);
    //strcat(priv_key_ex, key_hex);
    privkey+=key_hex;
  }
  //privkey=priv_key_ex;

  if (sig != NULL) {
    OQS_MEM_secure_free(secret_key, sig->length_secret_key);
  }
  OQS_MEM_insecure_free(public_key);
  OQS_SIG_free(sig);

  return 0;
}

////////////////////////////////////////////////////////////////////////////////
int parse_qtesla_v(Document& d, stru_param& req_val, string& answ_js){
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
    if(d.HasMember("plaintext")  && d.HasMember("pubkey")&& d.HasMember("sign")){
      if(check_plain(d,req_val,answ_js)!=0)
      return 1;
      if(check_keys(d,req_val,answ_js)!=0)
      return 1;
      if(check_bin(d,req_val,answ_js)!=0)
      return 1;
      if(check_signs(d,req_val,answ_js)!=0)
      return 1;

      req_val.payload=req_val.plaintext;
    }
    else{
      req_val.error="Not plaintext/pubkey/sign tag ";
      answ_error(req_val,answ_js);
      return 1;
    }
  }
  else if (strncmp(req_val.type.c_str(), "file",sizeof("file")) == 0){
    req_val.error="Qtesla file sign not supported ";
    answ_error(req_val,answ_js);
    return 1;
  }
  else{
    req_val.error="Bad type ";
    answ_error(req_val,answ_js);
    return 1;
  }

  QTESLA_V(req_val.payload, req_val.pubkey, req_val.sign,req_val.verify, req_val.hex, req_val.paramsq_,req_val.error);
  verify_anws(req_val,answ_js);
  return 0;
}

int parse_qtesla_sign(Document& d, stru_param& req_val, string& answ_js){
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
    if(d.HasMember("plaintext")  && d.HasMember("privkey")){
      if(check_plain(d,req_val,answ_js)!=0)
      return 1;
      if(check_keys(d,req_val,answ_js)!=0)
      return 1;
      if(check_bin(d,req_val,answ_js)!=0)
      return 1;

      req_val.payload=req_val.plaintext;
    }
    else{
      req_val.error="Not plaintext/privkey/pubkey tag ";
      answ_error(req_val,answ_js);
      return 1;
    }
  }
  else if (strncmp(req_val.type.c_str(), "file",sizeof("file")) == 0){
    req_val.error="Qtesla file sign not supported ";
    answ_error(req_val,answ_js);
    return 1;
  }
  else{
    req_val.error="Bad type ";
    answ_error(req_val,answ_js);
    return 1;
  }

  QTESLA_SIGN(req_val.payload, req_val.privkey, req_val.sign, req_val.hex, req_val.paramsq_,req_val.error);
  sign_anws(req_val,answ_js);

  return 0;
}

int parse_qtesla_gen(Document& d, stru_param& req_val, string& answ_js){
  QTESLA_GEN(req_val.paramsq_, req_val.privkey, req_val.pubkey, req_val.error);

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

////////////////////////////////////////////////////////////////////////////////
int parse_qtesla(Document& d, stru_param& req_val, string& answ_js) {
  #ifdef DEBUG
  printf("Good algorithm QTESLA ");
  #endif

  if(d.HasMember("operation")){
    if(check_ops(d,req_val,answ_js)!=0)
      return 1;
    }
    else{
      req_val.error="Not ops tag ";
      answ_error(req_val,answ_js);
      return 1;
  }

  if(d.HasMember("parameter")){
    if(check_params(d,req_val,answ_js)!=0)
    return 1;
    if(search_qtesla_param_(d,req_val,answ_js)!=0)
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

  OQS_randombytes_switch_algorithm(OQS_RAND_alg_system);

  if(strncmp(req_val.operation.c_str(), "gen",sizeof("gen")) == 0)
  parse_qtesla_gen(d, req_val,answ_js);
  else if(strncmp(req_val.operation.c_str(), "sign",sizeof("sign")) == 0)
  parse_qtesla_sign(d, req_val,answ_js);
  else if(strncmp(req_val.operation.c_str(), "verify",sizeof("verify")) == 0)
  parse_qtesla_v(d, req_val,answ_js);
  else{
    req_val.error="Not ops valid ";
    answ_error(req_val,answ_js);
    return 1;
  }

  return 0;
}
