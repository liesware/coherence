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
#include "cryptopp/oids.h"
#include "cryptopp/osrng.h"
#include "cryptopp/eccrypto.h"
#include "cryptopp/xed25519.h"



int Ed25519_GEN(string& privkey ,string& pubkey,string& error ){
  error.clear();
  privkey.clear();
  pubkey.clear();
  string key,keyp;

  try{
    AutoSeededRandomPool rng;

    ed25519::Signer signer;
    signer.AccessPrivateKey().GenerateRandom(rng);

    ed25519::Verifier verifier(signer);


    if (false==signer.GetPrivateKey().Validate(rng, 3)){
      error="Private key validation failed";
      return 1;
    }
    if (false==verifier.GetPublicKey().Validate(rng, 3)){
      error="Public key validation failed";
      return 1;
    }

    StringSink p_key(key);
    signer.GetPrivateKey().Save(p_key);
    StringSink e_key(keyp);
    verifier.GetPublicKey().Save(e_key);
    StringSource(key,true, new HexEncoder(new StringSink(privkey)));
    StringSource(keyp,true, new HexEncoder(new StringSink(pubkey)));

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


int Ed25519_SIGN(string& type, string& payload,string& privkey, string& sign, int& binary,string& error ){
  error.clear();
  sign.clear();
  ed25519::Signer signer;
  string key;
  AutoSeededRandomPool prng;

  try{
    StringSource(privkey,true,new HexDecoder( new StringSink(key)));
    StringSource source(key, true);
    signer.AccessPrivateKey().Load(source);

    if(false == signer.GetPrivateKey().Validate(prng, 3)){
      error="Private key validation failed";
      #ifdef DEBUG
      cerr << error << endl;
      #endif
      return 1;
    }

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


int Ed25519_V(string& type, string& payload,string& pubkey, string& sign, string& verify, int& binary,string& error ){
  error.clear();
  ed25519::Verifier verifier;
  string key,edsign;
  AutoSeededRandomPool prng;

  try{
    StringSource(pubkey,true,new HexDecoder( new StringSink(key)));
    StringSource source(key, true);
    verifier.AccessPublicKey().Load(source);

    StringSource(sign,true,new HexDecoder( new StringSink(edsign)));

    if(false == verifier.GetPublicKey().Validate(prng, 3)){
      error="Public key validation failed ";
      #ifdef DEBUG
      cerr << error << endl;
      #endif
      return 1;
    }

    string payload_e;

    if(binary==0)
    payload_e=payload;
    else if(binary==1)
    StringSource(payload, true, new HexDecoder( new StringSink(payload_e)));
    else{
      error+="Bad binary bool ";
      return 1;
    }

    if (strncmp(type.c_str(), "string",sizeof("string")) == 0){
      StringSource(payload_e+edsign, true,new SignatureVerificationFilter(verifier, NULL, SignatureVerificationFilter::THROW_EXCEPTION| SignatureVerificationFilter::SIGNATURE_AT_END));
    }
    else
    error="Bad type ";

    verify="Ed25519_OK" ;
  }
  catch(const CryptoPP::Exception& e){
    error=e.what();
    #ifdef DEBUG
    cerr << e.what() << endl;
    #endif
    return 1;
  }

  return 0;
}



int parse_ed25519_gen(Document& d, stru_param& req_val, string& answ_js){
  Ed25519_GEN(req_val.privkey, req_val.pubkey, req_val.error);
  keys_anws(req_val,answ_js);

  return 0;
}

int parse_ed25519_sign(Document& d, stru_param& req_val, string& answ_js){
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
    req_val.error="Not support file tag";
    answ_error(req_val,answ_js);
    return 1;
  }
  else{
    req_val.error="Bad tye ";
    answ_error(req_val,answ_js);
    return 1;
  }

  Ed25519_SIGN(req_val.type, req_val.payload, req_val.privkey, req_val.sign, req_val.hex, req_val.error);
  sign_anws(req_val,answ_js);

  return 0;
}

int parse_ed25519_v(Document& d, stru_param& req_val, string& answ_js){
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
    req_val.error="Not support file tag";
    answ_error(req_val,answ_js);
    return 1;
  }
  else{
    req_val.error="Bad tye ";
    answ_error(req_val,answ_js);
    return 1;
  }

  Ed25519_V(req_val.type, req_val.payload, req_val.pubkey, req_val.sign,req_val.verify, req_val.hex,req_val.error);
  verify_anws(req_val,answ_js);

  return 0;
}


int parse_ed25519(Document& d, stru_param& req_val, string& answ_js){
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
  parse_ed25519_gen(d, req_val,answ_js);
  else if(strncmp(req_val.operation.c_str(), "sign",sizeof("sign")) == 0)
  parse_ed25519_sign(d, req_val,answ_js);
  else if(strncmp(req_val.operation.c_str(), "verify",sizeof("verify")) == 0)
  parse_ed25519_v(d, req_val,answ_js);
  else{
    req_val.error="Not ops valid ";
    answ_error(req_val,answ_js);
    return 1;
  }

  return 0;

}

///////////////////////////////////////////////////////////////////////////////
int X25519_A(string& privkey, string& sharedpub, string& sharedkey,string& error){
  AutoSeededRandomPool rnd;

  try{
    x25519 keys;

    SecByteBlock priv_key(keys.PrivateKeyLength());
    SecByteBlock pub_shared(keys.PublicKeyLength());
    SecByteBlock shared(keys.AgreedValueLength());

    string priv,spub;

    StringSource k(privkey, true, new HexDecoder(new StringSink(priv)));
    memcpy( priv_key, priv.data(),priv_key.size());
    StringSource k1(sharedpub, true, new HexDecoder(new StringSink(spub)));
    memcpy( pub_shared, spub.data(),pub_shared.size());

    if(!keys.Agree(shared, priv_key, pub_shared)){
      error="Failed to reach shared secret";
      return 1;
    }

    string key;
    HexEncoder hex(new StringSink(key));
    key = "";
    hex.Put(shared.BytePtr(), shared.SizeInBytes());
    hex.MessageEnd();
    //cout << "Private key: " << key << endl;
    sharedkey=key;
  }
  catch(const CryptoPP::Exception& e){
    error=e.what();
    #ifdef DEBUG
    cerr << error << endl;
    cerr << "Fail AGREE" << endl;
    #endif
    return 1;
  }

  return 0;
}



int X25519_GEN(string& privkey ,string& pubkey,string& error ){
  error.clear();
  privkey.clear();
  pubkey.clear();
  string key,keyp;

  try{
    AutoSeededRandomPool rng;

    x25519 keys;
    SecByteBlock priv(keys.PrivateKeyLength()), pub(keys.PublicKeyLength());
    keys.GenerateKeyPair(rng, priv, pub);


    string key;
    HexEncoder hex(new StringSink(key));
    key = "";
    hex.Put(priv.BytePtr(), priv.SizeInBytes());
    hex.MessageEnd();
    privkey=key;

    key = "";
    hex.Put(pub.BytePtr(), pub.SizeInBytes());
    hex.MessageEnd();
    pubkey=key;


  }
  catch(const CryptoPP::Exception& e){
    error=e.what();
    #ifdef DEBUG
    cerr << error << endl;
    cerr << "Fail ECDH GEN" << endl;
    #endif
    return 1;
  }

  return 0;
}


int parse_x25519_agree(Document& d, stru_param& req_val, string& answ_js){
  if(d.HasMember("privkey") && d.HasMember("sharedpub")){
    if(check_a_keys(d,req_val,answ_js)!=0)
    return 1;

    X25519_A(req_val.privkey, req_val.sharedpub, req_val.sharedkey, req_val.error);

    req_val.tag.clear();
    req_val.tag="algorithm";
    Addstr2json(answ_js, req_val.tag, req_val.algorithm);
    req_val.tag.clear();
    req_val.tag="sharedkey";
    Addstr2json(answ_js, req_val.tag, req_val.sharedkey);
    req_val.tag.clear();
    req_val.tag="error";
    Addstr2json(answ_js, req_val.tag, req_val.error);

  }
  else{
    req_val.error.clear();
    req_val.error="Not privkey/sharedpub tag ";
    req_val.tag="error";
    Addstr2json(answ_js, req_val.tag, req_val.error);
    #ifdef DEBUG
    cerr << req_val.error;
    #endif
    return 1;
  }
  return 0;
}

int parse_x25519_gen(Document& d, stru_param& req_val, string& answ_js){
  X25519_GEN(req_val.privkey, req_val.pubkey, req_val.error);
  keys_anws(req_val,answ_js);

  return 0;
}


int parse_x25519(Document& d, stru_param& req_val, string& answ_js){
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
  parse_x25519_gen(d, req_val,answ_js);
  else if(strncmp(req_val.operation.c_str(), "agree",sizeof("agree")) == 0)
  parse_x25519_agree(d, req_val,answ_js);
  else{
    req_val.error="Not ops valid ";
    answ_error(req_val,answ_js);
    return 1;
  }

  return 0;

}
