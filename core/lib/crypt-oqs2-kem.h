#include "oqs_cpp.hpp"

using namespace oqs;

int search_oqs_param_k(Document& d, stru_param& req_val, string& answ_js){
  if(d.HasMember("parameter")){
    if(check_params(d,req_val,answ_js)!=0)
    return 1;

    if(strncmp(req_val.algorithm.c_str(), "KYBER",sizeof("KYBER"))== 0){

      if(strncmp(req_val.parameter.c_str(), "kyber512",sizeof("kyber512")) == 0){
        req_val.paramsq_="Kyber512";
      }
      else if(strncmp(req_val.parameter.c_str(), "kyber768",sizeof("kyber768")) == 0){
        req_val.paramsq_="Kyber768";
      }
      else if(strncmp(req_val.parameter.c_str(), "kyber1024",sizeof("kyber1024")) == 0){
        req_val.paramsq_="Kyber1024";
      }
      else{
        req_val.error="Bad parameter Kyber ";
        answ_error(req_val,answ_js);
        return 1;
      }
    }

    else if(strncmp(req_val.algorithm.c_str(), "NTRU_KEM",sizeof("NTRU_KEM"))== 0){

      if(strncmp(req_val.parameter.c_str(), "sntrup761",sizeof("sntrup761")) == 0){
        req_val.paramsq_="sntrup761";
      }
      else{
        req_val.error="Bad parameter Newhope ";
        answ_error(req_val,answ_js);
        return 1;
      }
    }

    else{
      req_val.error.clear();
      req_val.error="Bad algorithm";
      req_val.tag="error";
      Addstr2json(answ_js, req_val.tag, req_val.error);
      #ifdef DEBUG
      cerr << req_val.error;
      #endif
      return 1;
    }

  }
  else{
    req_val.error.clear();
    req_val.error="Not parameter for algorithm";
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
int OQS_KEM_DECAP(string& paramsq_ ,string& privkey, string& sharedtext, string& sharedkey ,string& error){
  sharedkey.clear();
  error.clear();
  string priv_bin, shared_bin;
  char key_hex[4];
  int i=0;

  KeyEncapsulation server_tmp{paramsq_};
  StringSource(privkey, true, new HexDecoder(new StringSink(priv_bin)));
  if(priv_bin.size()!=server_tmp.get_details().length_secret_key){
    error="Bad privkey size";
    return 1;
  }
  oqs::bytes server_secret_key=bytes(priv_bin.begin(),priv_bin.end());

  StringSource(sharedtext, true, new HexDecoder(new StringSink(shared_bin)));
  if(shared_bin.size()!=server_tmp.get_details().length_ciphertext){
    error="Bad ciphertext size";
    return 1;
  }
  oqs::bytes server_ciphertext=bytes(shared_bin.begin(),shared_bin.end());

  KeyEncapsulation server{paramsq_,server_secret_key};
  oqs::bytes shared_secret_client = server.decap_secret(server_ciphertext);

  for (i = 0; i < server.get_details().length_shared_secret; i++){
    snprintf(key_hex,4,"%02X", shared_secret_client[i]);
    sharedkey+=key_hex;
  }

  return 0;
}



int OQS_KEM_ENCAP(string& paramsq_ ,string& pubkey, string& sharedtext, string& sharedkey ,string& error){
  sharedtext.clear();
  sharedkey.clear();
  error.clear();
  string pub_bin;
  char key_hex[4];
  int i=0;

  KeyEncapsulation server{paramsq_};

  StringSource(pubkey, true, new HexDecoder(new StringSink(pub_bin)));
  if(pub_bin.size()!=server.get_details().length_public_key){
    error="Bad privkey size";
    return 1;
  }

  oqs::bytes client_public_key = bytes(pub_bin.begin(),pub_bin.end());
  oqs::bytes ciphertext, shared_secret_server;
  tie(ciphertext, shared_secret_server) = server.encap_secret(client_public_key);

  for (i = 0; i < server.get_details().length_ciphertext; i++){
    snprintf(key_hex,4,"%02X", ciphertext[i]);
    sharedtext+=key_hex;
  }

  for (i = 0; i < server.get_details().length_shared_secret; i++){
    snprintf(key_hex,4,"%02X", shared_secret_server[i]);
    sharedkey+=key_hex;
  }

  return 0;
}

int OQS_KEM_GEN(string& paramsq_ ,string& privkey, string& pubkey, string& error){
  privkey.clear();
  pubkey.clear();
  error.clear();
  int i=0;
  char key_hex[4];
  bool is_valid;

  KeyEncapsulation user{paramsq_};
  oqs::bytes user_public_key = user.generate_keypair();
  oqs::bytes user_secret_key = user.export_secret_key();

  for (i = 0; i < user.get_details().length_public_key; i++){
    snprintf(key_hex,4,"%02X", user_public_key[i]);
    pubkey+=key_hex;
  }

  for (i = 0; i < user.get_details().length_secret_key; i++){
    snprintf(key_hex,4,"%02X", user_secret_key[i]);
    privkey+=key_hex;
  }
  return 0;
}

////////////////////////////////////////////////////////////////////////////////
int parse_oqs_kem_decap(Document& d, stru_param& req_val, string& answ_js) {
  if(d.HasMember("privkey")&&d.HasMember("sharedtext")){
    if(check_keys(d,req_val,answ_js)!=0)
    return 1;
  }
  else{
    req_val.error="Not pubkey tag ";
    answ_error(req_val,answ_js);
    return 1;
  }

  OQS_KEM_DECAP(req_val.paramsq_,req_val.privkey ,req_val.sharedtext, req_val.sharedkey, req_val.error);

  req_val.tag.clear();
  req_val.tag="algorithm";
  Addstr2json(answ_js, req_val.tag, req_val.algorithm);
  req_val.tag.clear();
  req_val.tag="parameter";
  Addstr2json(answ_js, req_val.tag, req_val.parameter);
  req_val.tag.clear();
  req_val.tag="sharedkey";
  Addstr2json(answ_js, req_val.tag, req_val.sharedkey);
  req_val.tag.clear();
  req_val.tag="error";
  Addstr2json(answ_js, req_val.tag, req_val.error);

  return 0;
}



int parse_oqs_kem_encap(Document& d, stru_param& req_val, string& answ_js) {
  if(d.HasMember("pubkey")){
    if(check_keys(d,req_val,answ_js)!=0)
    return 1;
  }
  else{
    req_val.error="Not pubkey tag ";
    answ_error(req_val,answ_js);
    return 1;
  }

  OQS_KEM_ENCAP(req_val.paramsq_,req_val.pubkey ,req_val.sharedtext, req_val.sharedkey, req_val.error);

  req_val.tag.clear();
  req_val.tag="algorithm";
  Addstr2json(answ_js, req_val.tag, req_val.algorithm);
  req_val.tag.clear();
  req_val.tag="parameter";
  Addstr2json(answ_js, req_val.tag, req_val.parameter);
  req_val.tag.clear();
  req_val.tag="sharedkey";
  Addstr2json(answ_js, req_val.tag, req_val.sharedkey);
  req_val.tag.clear();
  req_val.tag="sharedtext";
  Addstr2json(answ_js, req_val.tag, req_val.sharedtext);
  req_val.tag.clear();
  req_val.tag="error";
  Addstr2json(answ_js, req_val.tag, req_val.error);

  return 0;
}

int parse_oqs_kem_gen(Document& d, stru_param& req_val, string& answ_js){
  OQS_KEM_GEN(req_val.paramsq_,req_val.privkey, req_val.pubkey, req_val.error);
  keys_anws(req_val,answ_js);

  return 0;
}

int parse_oqs_kem(Document& d, stru_param& req_val, string& answ_js) {
  #ifdef DEBUG
  printf("Good algorithm OQS KEM ");
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
    if(search_oqs_param_k(d,req_val,answ_js)!=0)
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
    parse_oqs_kem_gen(d, req_val,answ_js);
  else if(strncmp(req_val.operation.c_str(), "encap",sizeof("encap")) == 0)
    parse_oqs_kem_encap(d, req_val,answ_js);
  else if(strncmp(req_val.operation.c_str(), "decap",sizeof("decap")) == 0)
    parse_oqs_kem_decap(d, req_val,answ_js);
  else{
    req_val.error="Not ops valid ";
    answ_error(req_val,answ_js);
    return 1;
  }

  return 0;
}
