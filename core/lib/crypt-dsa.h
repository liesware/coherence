#include "rapidjson/document.h"
#include "rapidjson/writer.h"
#include "rapidjson/stringbuffer.h"
#include "rapidjson/error/en.h"
#include <iostream>
#include <fstream>

#include "cryptopp/filters.h"
#include "cryptopp/hex.h"
#include "cryptopp/files.h"
#include "cryptopp/cryptlib.h"
#include "cryptopp/osrng.h"
#include "cryptopp/dsa.h"


using namespace CryptoPP;
using namespace  std;

////////////////////////////////////////////////////////////////////////
int DSA_GEN(string& privkey ,string& pubkey,int& dsalen,string& error ){
  error.clear();
  privkey.clear();
  pubkey.clear();
  string key,keyp;

  try{
    AutoSeededRandomPool rng;
    DSA::PrivateKey PrivateKey;
    PrivateKey.GenerateRandomWithKeySize(rng, dsalen);
    if (!PrivateKey.Validate(rng, 3)){
      error="Fail DSA gen";
      #ifdef DEBUG
      cerr << error << endl;
      #endif
      return 1;
    }

    DSA::PublicKey PublicKey;
    PublicKey.AssignFrom(PrivateKey);

    StringSink p_key(key);
    PrivateKey.Save(p_key);
    StringSink e_key(keyp);
    PublicKey.Save(e_key);
    StringSource(key,true, new HexEncoder(new StringSink(privkey)));
    StringSource(keyp,true, new HexEncoder(new StringSink(pubkey)));
  }
  catch(const CryptoPP::Exception& e){
    error=e.what();;
    #ifdef DEBUG
    cerr << error << endl;
    #endif
    return 1;
  }
  return 0;
}

int DSA_SIGN(string& type, string& payload,string& privkey, string& sign, int& binary,string& error ){
  error.clear();
  sign.clear();
  DSA::PrivateKey PrivateKey;
  string key;
  AutoSeededRandomPool prng;

  try{
    StringSource(privkey,true,new HexDecoder( new StringSink(key)));
    StringSource source(key, true);
    PrivateKey.Load(source);

    if(false == PrivateKey.Validate (prng, 3)){
      error="Private key validation failed";
      #ifdef DEBUG
      cerr << error << endl;
      #endif
      return 1;
    }

    DSA::Signer signer(PrivateKey);
    if (strncmp(type.c_str(), "string",sizeof("string")) == 0){
      if(binary==0)
      StringSource( payload, true, new SignerFilter( prng, signer,new HexEncoder(new StringSink(sign))));
      else if(binary==1)
      StringSource(payload, true, new HexDecoder( new SignerFilter( prng, signer,new HexEncoder(new StringSink(sign)))));
      else{
        error+="Bad binary bool ";
        return 1;
      }
    }
    else if (strncmp(type.c_str(), "file",sizeof("file")) == 0){
      FileSource( payload.c_str(), true, new SignerFilter( prng, signer,new HexEncoder(new StringSink(sign))));
      payload+=".sign";
      StringSource(sign, true, new HexDecoder(new FileSink(payload.c_str())));
    }
    else
    error="Bad type";
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

int DSA_V(string& type, string& payload,string& pubkey, string& sign, string& verify, int& binary,string& error ){
  error.clear();
  DSA::PublicKey PublicKey;
  string key,dsasign;
  AutoSeededRandomPool prng;

  try{
    StringSource(pubkey,true,new HexDecoder( new StringSink(key)));
    StringSource source(key, true);
    PublicKey.Load(source);

    StringSource(sign,true,new HexDecoder( new StringSink(dsasign)));

    if(false == PublicKey.Validate (prng, 3)){
      error="Public key validation failed";
      #ifdef DEBUG
      cerr << error << endl;
      #endif
      return 1;
    }

    DSA::Verifier verifier( PublicKey );
    string payload_e;

    if(binary==0)
    payload_e=payload;
    else if(binary==1)
    StringSource(payload, true, new HexDecoder( new StringSink(payload_e)));
    else{
      error+="Bad binary bool ";
      return 1;
    }

    if (strncmp(type.c_str(), "string",sizeof("string")) == 0)
    StringSource( payload_e+dsasign, true,new SignatureVerificationFilter(verifier, NULL , SignatureVerificationFilter::THROW_EXCEPTION| SignatureVerificationFilter::SIGNATURE_AT_END ));
    else if (strncmp(type.c_str(), "file",sizeof("file")) == 0){
      FileSource( payload.c_str(), true,new SignatureVerificationFilter(verifier, NULL, SignatureVerificationFilter::THROW_EXCEPTION | SignatureVerificationFilter::SIGNATURE_AT_END ));
    }
    verify="DSA_OK" ;

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
//PARSE DSA/////////////////////////////////////////////////////////////
int parse_dsa_gen(Document& d, stru_param& req_val, string& answ_js){
  if(d.HasMember("length")){
    if(check_length(d,req_val,answ_js,4096)!=0)
    return 1;

    DSA_GEN(req_val.privkey, req_val.pubkey, req_val.length, req_val.error);
    keys_anws(req_val,answ_js);
  }
  else{
    req_val.error.clear();
    req_val.error="Not length tag ";
    req_val.tag="error";
    Addstr2json(answ_js, req_val.tag, req_val.error);
    #ifdef DEBUG
    cerr << req_val.error;
    #endif
    return 1;
  }
  return 0;
}

//DSASIGN////////////////////////////////////////////////////////////////
int parse_dsa_sign(Document& d, stru_param& req_val, string& answ_js){
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
      req_val.error="Not plaintext/privkey tag ";
      answ_error(req_val,answ_js);
      return 1;
    }
  }
  else if (strncmp(req_val.type.c_str(), "file",sizeof("file")) == 0){
    if(d.HasMember("file")  && d.HasMember("privkey")){
      if(check_file(d,req_val,answ_js)!=0)
      return 1;
      if(check_keys(d,req_val,answ_js)!=0)
      return 1;

      req_val.hex=0;
      req_val.payload=req_val.file;
    }
    else{
      req_val.error="Not file/privkey tag ";
      answ_error(req_val,answ_js);
      return 1;
    }
  }
  else{
    req_val.error="Bad tye ";
    answ_error(req_val,answ_js);
    return 1;
  }

  DSA_SIGN(req_val.type, req_val.payload, req_val.privkey, req_val.sign, req_val.hex, req_val.error);
  sign_anws(req_val,answ_js);

  return 0;
}


int parse_dsa_v(Document& d, stru_param& req_val, string& answ_js){
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
      req_val.error="Not plaintext/pubkey tag ";
      answ_error(req_val,answ_js);
      return 1;
    }
  }
  else if (strncmp(req_val.type.c_str(), "file",sizeof("file")) == 0){
    if(d.HasMember("file")  && d.HasMember("pubkey")){
      if(check_file(d,req_val,answ_js)!=0)
      return 1;
      if(check_keys(d,req_val,answ_js)!=0)
      return 1;

      req_val.hex=0;
      req_val.payload=req_val.file;
    }
    else{
      req_val.error="Not file/pubkey tag ";
      answ_error(req_val,answ_js);
      return 1;
    }
  }
  else{
    req_val.error="Bad tye ";
    answ_error(req_val,answ_js);
    return 1;
  }

  DSA_V(req_val.type, req_val.payload, req_val.pubkey, req_val.sign,req_val.verify, req_val.hex,req_val.error);
  verify_anws(req_val,answ_js);

  return 0;
}

int parse_dsa(Document& d, stru_param& req_val, string& answ_js){
  if(d.HasMember("operation")){
    if(check_ops(d,req_val,answ_js)!=0)
    return 1;
  }
  else{
    req_val.error="Not ops tag ";
    answ_error(req_val,answ_js);
    return 1;
  }

  if(strncmp(req_val.operation.c_str(), "gen",sizeof("gen")) == 0)
  parse_dsa_gen(d, req_val,answ_js);
  else if(strncmp(req_val.operation.c_str(), "sign",sizeof("sign")) == 0)
  parse_dsa_sign(d, req_val,answ_js);
  else if(strncmp(req_val.operation.c_str(), "verify",sizeof("verify")) == 0)
  parse_dsa_v(d, req_val,answ_js);
  else{
    req_val.error="Not ops valid ";
    answ_error(req_val,answ_js);
    return 1;
  }

  return 0;
}
