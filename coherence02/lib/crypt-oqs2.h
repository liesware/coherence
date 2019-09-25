#include "oqs_cpp.h"

using namespace oqs;

////////////////////////////////////////////////////////////////////////////////
int search_oqs_param_(Document& d, stru_param& req_val, string& answ_js){
  if(d.HasMember("parameter")){
    if(check_params(d,req_val,answ_js)!=0)
    return 1;

    if(strncmp(req_val.algorithm.c_str(), "QTESLA",sizeof("QTESLA"))== 0){
      if(strncmp(req_val.parameter.c_str(), "qtesla1",sizeof("qtesla1")) == 0){
        req_val.paramsq_="qTesla-p-I";
      }
      else if(strncmp(req_val.parameter.c_str(), "qtesla3",sizeof("qtesla3")) == 0){
        req_val.paramsq_="qTesla-p-III";
      }
      else{
        req_val.error="Bad parameter Qtesla ";
        answ_error(req_val,answ_js);
        return 1;
      }
    }
    else if(strncmp(req_val.algorithm.c_str(), "DILITHIUM",sizeof("DILITHIUM"))== 0){
      if(strncmp(req_val.parameter.c_str(), "dilithium2",sizeof("dilithium2")) == 0){
        req_val.paramsq_="DILITHIUM_2";
      }
      else if(strncmp(req_val.parameter.c_str(), "dilithium3",sizeof("dilithium3")) == 0){
        req_val.paramsq_="DILITHIUM_3";
      }
      else if(strncmp(req_val.parameter.c_str(), "dilithium4",sizeof("dilithium4")) == 0){
        req_val.paramsq_="DILITHIUM_4";
      }
      else{
        req_val.error="Bad parameter Dilithium ";
        answ_error(req_val,answ_js);
        return 1;
      }
    }
    else{
      req_val.error="Bad parameter ";
      answ_error(req_val,answ_js);
      return 1;
    }
  }
  else{
    req_val.error.clear();
    req_val.error="Not parameter for OQS";
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
int OQS_V(string& payload,string& pubkey, string& sign, string& verify,int& binary, string& paramsq_ ,string& error ){
  error.clear();
  string pub_bin, payload_e, sign_bin;
  int i=0;

  Signature signer_tmp{paramsq_};

  if(binary==0)
  payload_e=payload;
  else if(binary==1)
  StringSource(payload, true, new HexDecoder( new StringSink(payload_e)));
  else{
    error+="Bad binary bool ";
    return 1;
  }

  StringSource(pubkey, true, new HexDecoder(new StringSink(pub_bin)));
  if(pub_bin.size()!=signer_tmp.get_details().length_public_key){
    error="Bad privkey size";
    return 1;
  }
  StringSource(sign, true, new HexDecoder(new StringSink(sign_bin)));
  if(sign_bin.size()!=signer_tmp.get_details().max_length_signature){
    error="Bad sign size";
    return 1;
  }

  oqs::bytes message = bytes(payload_e.begin(),payload_e.end());
  oqs::bytes signature = bytes(sign_bin.begin(),sign_bin.end());
  oqs::bytes public_key = bytes(pub_bin.begin(),pub_bin.end());

  oqs::Signature verifier{paramsq_};
  bool is_valid = verifier.verify(message, signature, public_key);

  if (!is_valid){
    error+="ERROR: OQS_SIG_verify failed";
    return 1;
  }

  verify="OQS_OK";
  return 0;
}

int OQS_SIGN(string& payload,string& privkey, string& sign, int& binary, string& paramsq_ ,string& error ){
  error.clear();
  sign.clear();
  string priv_bin, payload_e;
  int i=0;

  Signature signer_tmp{paramsq_};

  if(binary==0)
  payload_e=payload;
  else if(binary==1)
  StringSource(payload, true, new HexDecoder( new StringSink(payload_e)));
  else{
    error+="Bad binary bool ";
    return 1;
  }

  StringSource(privkey, true, new HexDecoder(new StringSink(priv_bin)));
  if(priv_bin.size()!=signer_tmp.get_details().length_secret_key){
    error="Bad privkey size";
    return 1;
  }

  //oqs::bytes signer_secret_key=bytes(signer_tmp.get_details().length_secret_key, 0);
  //memcpy(signer_secret_key, priv_bin.data(),signer_tmp.get_details().length_secret_key);
  oqs::bytes message = bytes(payload_e.begin(),payload_e.end());
  oqs::bytes signer_secret_key=bytes(priv_bin.begin(),priv_bin.end());
  Signature signer{paramsq_,signer_secret_key};
  oqs::bytes signature = signer.sign(message);

  char key_hex[4];
  for (i = 0; i < signer.get_details().max_length_signature; i++){
    snprintf(key_hex,4,"%02X", signature[i]);
    sign+=key_hex;
  }

  return 0;
}

int OQS_GEN(string& paramsq_,string& privkey, string& pubkey,string& error){
  privkey.clear();
  pubkey.clear();
  error.clear();
  int i=0;
  char key_hex[4];
  bool is_valid;

  do{
    Signature signer{paramsq_};
    oqs::bytes signer_public_key = signer.generate_keypair();
    oqs::bytes signer_secret_key = signer.export_secret_key();
    oqs::bytes message = "The things you used to own, now they own you"_bytes;
    oqs::bytes signature = signer.sign(message);
    oqs::Signature verifier{paramsq_};
    is_valid = verifier.verify(message, signature, signer_public_key);
    if(is_valid){
      for (i = 0; i < signer.get_details().length_public_key; i++){
        snprintf(key_hex,4,"%02X", signer_public_key[i]);
        pubkey+=key_hex;
      }

      for (i = 0; i < signer.get_details().length_secret_key; i++){
        snprintf(key_hex,4,"%02X", signer_secret_key[i]);
        privkey+=key_hex;
      }
    }
  }while(!is_valid);

  return 0;
}

////////////////////////////////////////////////////////////////////////////////
int parse_oqs_v(Document& d, stru_param& req_val, string& answ_js){
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

  OQS_V(req_val.payload, req_val.pubkey, req_val.sign,req_val.verify, req_val.hex, req_val.paramsq_,req_val.error);
  verify_anws(req_val,answ_js);
  return 0;
}

int parse_oqs_sign(Document& d, stru_param& req_val, string& answ_js){
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
    req_val.error="OQS file sign not supported ";
    answ_error(req_val,answ_js);
    return 1;
  }
  else{
    req_val.error="Bad type ";
    answ_error(req_val,answ_js);
    return 1;
  }

  OQS_SIGN(req_val.payload, req_val.privkey, req_val.sign, req_val.hex, req_val.paramsq_,req_val.error);
  sign_anws(req_val,answ_js);

  return 0;
}

int parse_oqs_gen(Document& d, stru_param& req_val, string& answ_js){
  OQS_GEN(req_val.paramsq_, req_val.privkey, req_val.pubkey, req_val.error);

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
int parse_oqs(Document& d, stru_param& req_val, string& answ_js) {
  #ifdef DEBUG
  printf("Good algorithm OQS ");
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
    if(search_oqs_param_(d,req_val,answ_js)!=0)
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

  if(strncmp(req_val.operation.c_str(), "gen",sizeof("gen")) == 0)
  parse_oqs_gen(d, req_val,answ_js);
  else if(strncmp(req_val.operation.c_str(), "sign",sizeof("sign")) == 0)
  parse_oqs_sign(d, req_val,answ_js);
  else if(strncmp(req_val.operation.c_str(), "verify",sizeof("verify")) == 0)
  parse_oqs_v(d, req_val,answ_js);
  else{
    req_val.error="Not ops valid ";
    answ_error(req_val,answ_js);
    return 1;
  }

  return 0;
}
