#include "rapidjson/document.h"
#include "rapidjson/writer.h"
#include "rapidjson/stringbuffer.h"
#include "rapidjson/error/en.h"
//https://tools.ietf.org/rfc/rfc4492.txt
#include <iostream>
#include <fstream>

#include "cryptopp/filters.h"
#include "cryptopp/hex.h"
#include "cryptopp/files.h"
#include "cryptopp/cryptlib.h"
#include <iostream>

#include "cryptopp/asn.h"
#include "cryptopp/ecp.h"
#include "cryptopp/ec2n.h"
#include "cryptopp/oids.h"
#include "cryptopp/osrng.h"
#include "cryptopp/eccrypto.h"
#include "cryptopp/sha3.h"
#include "cryptopp/sha.h"
#include "cryptopp/whrlpool.h"

using namespace CryptoPP;
using namespace  std;

int check_curve(Document& d, stru_param& req_val, string& answ_js){
  if(d.HasMember("curve") && d["curve"].IsString()){
    req_val.curve=d["curve"].GetString();
    if(Isalphnum(req_val.curve,req_val.error)!=0){
      req_val.error+=" curve no ascii ";
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


int check_field(Document& d, stru_param& req_val, string& answ_js){
  if(d.HasMember("field") && d["field"].IsString()){
    req_val.field=d["field"].GetString();
    if(strncmp(req_val.field.c_str(), "ecp",sizeof("ecp")) !=0 && strncmp(req_val.field.c_str(), "ec2n",sizeof("ec2n"))!=0){
      req_val.error+=" not valid field ";
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

int search_field_curve(Document& d, stru_param& req_val, string& answ_js){
  if(d.HasMember("curve")){
    if(check_curve(d,req_val,answ_js)!=0)
    return 1;

    if(strncmp(req_val.curve.c_str(), "secp256k1",sizeof("secp256k1")) == 0){
      req_val.CURVE=CryptoPP::ASN1::secp256k1();
      req_val.field="ecp";

    }
    else if(strncmp(req_val.curve.c_str(), "brainpoolP256r1",sizeof("brainpoolP256r1")) == 0){
      req_val.CURVE=CryptoPP::ASN1::brainpoolP256r1();
      req_val.field="ecp";
    }
    else if(strncmp(req_val.curve.c_str(), "brainpoolP320r1",sizeof("brainpoolP320r1")) == 0){
      req_val.CURVE=CryptoPP::ASN1::brainpoolP320r1();
      req_val.field="ecp";
    }
    else if(strncmp(req_val.curve.c_str(), "secp384r1",sizeof("secp384r1")) == 0){
      req_val.CURVE=CryptoPP::ASN1::secp384r1();
      req_val.field="ecp";
    }
    else if(strncmp(req_val.curve.c_str(), "brainpoolP384r1",sizeof("brainpoolP384r1")) == 0){
      req_val.CURVE=CryptoPP::ASN1::brainpoolP384r1();
      req_val.field="ecp";
    }
    else if(strncmp(req_val.curve.c_str(), "secp521r1",sizeof("secp521r1")) == 0){
      req_val.CURVE=CryptoPP::ASN1::secp521r1();
      req_val.field="ecp";
    }
    else if(strncmp(req_val.curve.c_str(), "brainpoolP512r1",sizeof("brainpoolP512r1")) == 0){
      req_val.CURVE=CryptoPP::ASN1::brainpoolP512r1();
      req_val.field="ecp";
    }
    else if(strncmp(req_val.curve.c_str(), "sect283k1",sizeof("sect283k1")) == 0){
      req_val.CURVE=CryptoPP::ASN1::sect283k1();
      req_val.field="ec2n";
    }
    else if(strncmp(req_val.curve.c_str(), "sect283r1",sizeof("sect283r1")) == 0){
      req_val.CURVE=CryptoPP::ASN1::sect283r1();
      req_val.field="ec2n";
    }
    else if(strncmp(req_val.curve.c_str(), "sect409k1",sizeof("sect409k1")) == 0){
      req_val.CURVE=CryptoPP::ASN1::sect409k1();
      req_val.field="ec2n";
    }
    else if(strncmp(req_val.curve.c_str(), "sect409r1",sizeof("sect409r1")) == 0){
      req_val.CURVE=CryptoPP::ASN1::sect409r1();
      req_val.field="ec2n";
    }
    else if(strncmp(req_val.curve.c_str(), "sect571k1",sizeof("sect571k1")) == 0){
      req_val.CURVE=CryptoPP::ASN1::sect571k1();
      req_val.field="ec2n";
    }
    else if(strncmp(req_val.curve.c_str(), "sect571r1",sizeof("sect571r1")) == 0){
      req_val.CURVE=CryptoPP::ASN1::sect571r1();
      req_val.field="ec2n";
    }
    else{
      req_val.error="Bad curve ";
      answ_error(req_val,answ_js);
      return 1;
    }
  }
  else{
    req_val.error.clear();
    req_val.error="Not curve to ECC";
    req_val.tag="error";
    Addstr2json(answ_js, req_val.tag, req_val.error);
    #ifdef DEBUG
    cerr << req_val.error;
    #endif
    return 1;
  }
  return 0;
}


int LoadPrivateKey(PrivateKey& key,string& privkey, string& error){
  AutoSeededRandomPool prng;
  string key0;
  StringSource(privkey,true,new HexDecoder( new StringSink(key0)));
  StringSource source(key0, true);
  key.Load(source);
  if(false == key.Validate (prng, 3)){
    error="Private key validation failed";
    return 1;
  }
  return 0;
}

int LoadPublicKey(PublicKey& key,string& pubkey,string& error){

  AutoSeededRandomPool prng;
  string key0;
  StringSource(pubkey,true,new HexDecoder( new StringSink(key0)));
  StringSource source(key0, true);
  key.Load(source);
  if(false == key.Validate (prng, 3)){
    error="Public key validation failed";
    return 1;
  }
  return 0;
}
////////////////////////////////////////////////////////////////////////

template <typename T,typename T2>
int EC_GEN(OID& CURVE, string& privkey, string& pubkey, string& error){
  try{
    T privateKey;
    T2 publicKey;
    AutoSeededRandomPool rng;

    privateKey.Initialize (rng, CURVE);
    privateKey.MakePublicKey (publicKey);

    if (false == privateKey.Validate (rng, 3)){
      error="Private key validation failed";
      return 1;
    }
    if (false == publicKey.Validate (rng, 3)){
      error="Public key validation failed";
      return 1;
    }

    string priv_e;
    StringSink priv_s(priv_e);
    privateKey.Save(priv_s);
    StringSource (priv_e,true, new HexEncoder(new StringSink(privkey)));

    string pub_e;
    StringSink pub_s(pub_e);
    publicKey.Save(pub_s);
    StringSource (pub_e,true, new HexEncoder(new StringSink(pubkey)));
  }
  catch(const CryptoPP::Exception& e){
    error=e.what();
    #ifdef DEBUG
    cerr << error << endl;
    cerr << "Fail EC GEN" << endl;
    #endif
    return 1;
  }
  return 0;
}

template <typename T>
int ECIES_ENC(string& payload,string& pubkey, string& result, int& binary, string& field, string& error ){
  error.clear();
  string key;
  AutoSeededRandomPool prng;
  T Encryptor;
  LoadPublicKey(Encryptor.AccessPublicKey(), pubkey,error);
  Encryptor.GetPublicKey(). ThrowIfInvalid(prng, 3);

  try{
    if(binary==0)
    StringSource( payload, true,new PK_EncryptorFilter( prng, Encryptor,new HexEncoder(new StringSink(result))));
    else if(binary==1)
    StringSource( payload, true,new HexDecoder(new PK_EncryptorFilter( prng, Encryptor,new HexEncoder(new StringSink(result)))));
    else{
      error+="Bad binary bool ";
      return 1;
    }
  }
  catch(const CryptoPP::Exception& e){
    error=e.what() ;
    #ifdef DEBUG
    cerr << error << endl;
    #endif
    return 1;
  }
  return 0;
}

template <typename T>
int ECIES_DEC(string& payload,string& privkey, string& result, string& field, string& error ){
  error.clear();
  string key;
  AutoSeededRandomPool prng;
  T Decryptor;
  try{
    LoadPrivateKey(Decryptor.AccessPrivateKey(), privkey, error);
    Decryptor.GetPrivateKey(). ThrowIfInvalid(prng, 3);
    StringSource( payload, true,new HexDecoder(new PK_DecryptorFilter( prng, Decryptor,new StringSink( result ))));
    if(Isjson(result,error)!=0){
      result.clear();
      error.clear();
      StringSource( payload, true,new HexDecoder(new PK_DecryptorFilter( prng, Decryptor,new HexEncoder(new StringSink( result )))));
    }
  }
  catch(const CryptoPP::Exception& e){
    error=e.what() ;
    #ifdef DEBUG
    cerr << error << endl;
    #endif
    return 1;
  }
  return 0;
}

////////////////////////////////////////////////////////////////////////
template <typename T,typename T2>
int ECDSA_SIGN(string& type, string& payload,string& privkey, string& sign, int& binary, string field,string& error ){
  error.clear();
  sign.clear();

  T PrivateKey;
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

    T2 signer( PrivateKey );
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
    // else if (strncmp(type.c_str(), "file",sizeof("file")) == 0){
    //   FileSource( payload.c_str(), true, new SignerFilter( prng, signer,new HexEncoder(new StringSink(sign))));
    //   payload+=".sign";
    //   StringSource(sign, true, new HexDecoder(new FileSink(payload.c_str())));
    // }
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

template <typename T,typename T2>
int ECDSA_V(string& type, string& payload,string& pubkey, string& sign, string& verify, int& binary, string& field,string& error ){
  error.clear();
  string key,ecdsasign;
  AutoSeededRandomPool prng;

  T PublicKey;
  try{
    StringSource(pubkey,true,new HexDecoder( new StringSink(key)));
    StringSource source(key, true);
    PublicKey.Load(source);

    StringSource(sign,true,new HexDecoder( new StringSink(ecdsasign)));

    if(false == PublicKey.Validate (prng, 3)){
      error="Public key validation failed";
      #ifdef DEBUG
      cerr << error << endl;
      #endif
      return 1;
    }

    T2 verifier( PublicKey );
    string payload_e;

    if(binary==0)
    payload_e=payload;
    else if(binary==1)
    StringSource(payload, true, new HexDecoder( new StringSink(payload_e)));
    else{
      error+="Bad binary bool ";
      return 1;
    }

    if(strncmp(type.c_str(), "string",sizeof("string")) == 0)
    StringSource( payload_e+ecdsasign, true,new SignatureVerificationFilter(verifier, NULL , SignatureVerificationFilter::THROW_EXCEPTION| SignatureVerificationFilter::SIGNATURE_AT_END ));
    // else if(strncmp(type.c_str(), "file",sizeof("file")) == 0){
    //   FileSource( payload.c_str(), true,new SignatureVerificationFilter(verifier, NULL, SignatureVerificationFilter::THROW_EXCEPTION | SignatureVerificationFilter::SIGNATURE_AT_END ));
    // }

    verify="ECDSA_OK" ;
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
template <typename T>
int ECDH_GEN(OID& CURVE, string& privkey, string& pubkey, string&field ,string& error){
  AutoSeededRandomPool rng;

  try{
    T ecdh(CURVE);
    SecByteBlock priv(ecdh.PrivateKeyLength()), pub(ecdh.PublicKeyLength());
    ecdh.GenerateKeyPair(rng, priv, pub);

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

template <typename T>
int ECDH_A(OID& CURVE, string& privkey, string& sharedpub, string& sharedkey, string&field  ,string& error){
  AutoSeededRandomPool rnd;

  try{
    T dh(CURVE);

    SecByteBlock priv_key(privkey.size()/2);
    SecByteBlock pub_shared(sharedpub.size()/2);
    SecByteBlock shared(dh.AgreedValueLength());

    string priv,spub;

    StringSource k(privkey, true, new HexDecoder(new StringSink(priv)));
    memcpy( priv_key, priv.data(),priv_key.size());
    StringSource k1(sharedpub, true, new HexDecoder(new StringSink(spub)));
    memcpy( pub_shared, spub.data(),pub_shared.size());

    if(!dh.Agree(shared, priv_key, pub_shared)){
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
    cerr << "Fail DHAGREE" << endl;
    #endif
    return 1;
  }

  return 0;
}


////////////////////////////////////////////////////////////////////////
int parse_ec_gen(Document& d, stru_param& req_val, string& answ_js){
  if(d.HasMember("curve")){
    if(check_curve(d,req_val,answ_js)!=0)
    return 1;
    if(search_field_curve(d, req_val, answ_js)!=0)
    return 1;

    if(strncmp(req_val.field.c_str(), "ecp",sizeof("ecp")) == 0){
      EC_GEN <CryptoPP::ECIES < ECP >::PrivateKey,CryptoPP::ECIES < ECP >::PublicKey>
      (req_val.CURVE, req_val.privkey, req_val.pubkey, req_val.error);
    }
    else if(strncmp(req_val.field.c_str(), "ec2n",sizeof("ec2n")) == 0){
      EC_GEN <CryptoPP::ECIES < EC2N >::PrivateKey,CryptoPP::ECIES < EC2N >::PublicKey>
      (req_val.CURVE, req_val.privkey, req_val.pubkey, req_val.error);
    }

    req_val.tag.clear();
    req_val.tag="algorithm";
    Addstr2json(answ_js, req_val.tag, req_val.algorithm);
    req_val.tag.clear();
    req_val.tag="curve";
    Addstr2json(answ_js, req_val.tag, req_val.curve);
    req_val.tag.clear();
    req_val.tag="privkey";
    Addstr2json(answ_js, req_val.tag, req_val.privkey);
    req_val.tag.clear();
    req_val.tag="pubkey";
    Addstr2json(answ_js, req_val.tag, req_val.pubkey);
    req_val.tag.clear();
    req_val.tag="error";
    Addstr2json(answ_js, req_val.tag, req_val.error);

  }
  else{
    req_val.error.clear();
    req_val.error="Not curve tag";
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
int parse_ecies(Document& d, stru_param& req_val, string& answ_js){
  if(d.HasMember("type") ){
    if(check_type(d,req_val,answ_js)!=0)
    return 1;

    if(strncmp(req_val.type.c_str(), "file",sizeof("file")) == 0){
      req_val.error="ECIES file encryption not supported ";
      answ_error(req_val,answ_js);
      return 1;
    }
  }
  else{
    req_val.error="Not type tag ";
    answ_error(req_val,answ_js);
    return 1;
  }

  if(d.HasMember("curve")){
    if(check_curve(d,req_val,answ_js)!=0)
    return 1;
    if(search_field_curve(d, req_val, answ_js)!=0)
    return 1;
  }
  else{
    req_val.error="Not curve tag ";
    answ_error(req_val,answ_js);
    return 1;
  }

  if(d.HasMember("operation")){
    if(check_ops(d,req_val,answ_js)!=0)
    return 1;
    if(check_field(d,req_val,answ_js)!=0)
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


      if(strncmp(req_val.field.c_str(), "ecp",sizeof("ecp")) == 0){
        ECIES_ENC <ECIES<ECP>::Encryptor>
        (req_val.payload, req_val.pubkey, req_val.result, req_val.hex ,req_val.field, req_val.error);
      }
      else if(strncmp(req_val.field.c_str(), "ec2n",sizeof("ec2n")) == 0){
        ECIES_ENC <ECIES<EC2N>::Encryptor>
        (req_val.payload, req_val.pubkey, req_val.result, req_val.hex ,req_val.field, req_val.error);
      }
      cipher_anws(req_val,answ_js);


    }
    else if(strncmp(req_val.operation.c_str(), "dec",sizeof("dec")) == 0){
      if(!(d.HasMember("plaintext") && d.HasMember("privkey"))){
        req_val.error+="Not plaintext/privkey tag ";
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

      if(strncmp(req_val.field.c_str(), "ecp",sizeof("ecp")) == 0){
        ECIES_DEC <ECIES<ECP>::Decryptor>
        (req_val.payload, req_val.privkey, req_val.result, req_val.field,req_val.error);
      }
      else if(strncmp(req_val.field.c_str(), "ec2n",sizeof("ec2n")) == 0){
        ECIES_DEC <ECIES<EC2N>::Decryptor>
        (req_val.payload, req_val.privkey, req_val.result, req_val.field,req_val.error);
      }
      cipher_anws(req_val,answ_js);
    }
    else{
      req_val.error="Not payload/pubkey/privkey tag ";
      answ_error(req_val,answ_js);
      return 1;
    }


  }
  else{
    req_val.error="Not ops/field tag ";
    answ_error(req_val,answ_js);
    return 1;
  }

  return 0;
}

////////////////////////////////////////////////////////////////////////
int parse_ecdsa_sign(Document& d, stru_param& req_val, string& answ_js){
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
      if(check_field(d,req_val,answ_js)!=0)
      return 1;
      if(check_hash_sign(d,req_val,answ_js)!=0)
      return 1;

      req_val.payload=req_val.plaintext;
    }
    else{
      req_val.error="Not plaintext/privkey tag ";
      answ_error(req_val,answ_js);
      return 1;
    }
  }
  // else if (strncmp(req_val.type.c_str(), "file",sizeof("file")) == 0){
  //   if(d.HasMember("file")  && d.HasMember("privkey")){
  //     if(check_file(d,req_val,answ_js)!=0)
  //     return 1;
  //     if(check_keys(d,req_val,answ_js)!=0)
  //     return 1;
  //     if(check_field(d,req_val,answ_js)!=0)
  //     return 1;
  //     if(check_hash_sign(d,req_val,answ_js)!=0)
  //     return 1;
  //
  //     req_val.hex=0;
  //     req_val.payload=req_val.file;
  //   }
  //   else{
  //     req_val.error="Not file/privkey tag ";
  //     answ_error(req_val,answ_js);
  //     return 1;
  //   }
  // }
  else{
    req_val.error="Bad type ";
    answ_error(req_val,answ_js);
    return 1;
  }


  if(strncmp(req_val.field.c_str(), "ecp",sizeof("ecp")) == 0){
    if(strncmp(req_val.hash_sign.c_str(), "sha3_512",sizeof("sha3_512")) == 0){
      ECDSA_SIGN <ECDSA<ECP, SHA3_512>::PrivateKey, ECDSA<ECP,SHA3_512>::Signer>
      (req_val.type, req_val.payload, req_val.privkey, req_val.sign, req_val.hex, req_val.field,req_val.error);
    }
    else if(strncmp(req_val.hash_sign.c_str(), "sha3_384",sizeof("sha3_384")) == 0){
      ECDSA_SIGN <ECDSA<ECP, SHA3_384>::PrivateKey, ECDSA<ECP,SHA3_384>::Signer>
      (req_val.type, req_val.payload, req_val.privkey, req_val.sign, req_val.hex, req_val.field,req_val.error);
    }
    else if(strncmp(req_val.hash_sign.c_str(), "sha3_256",sizeof("sha3_256")) == 0){
      ECDSA_SIGN <ECDSA<ECP, SHA3_256>::PrivateKey, ECDSA<ECP,SHA3_256>::Signer>
      (req_val.type, req_val.payload, req_val.privkey, req_val.sign, req_val.hex, req_val.field,req_val.error);
    }
    else if(strncmp(req_val.hash_sign.c_str(), "sha3_224",sizeof("sha3_224")) == 0){
      ECDSA_SIGN <ECDSA<ECP, SHA3_224>::PrivateKey, ECDSA<ECP,SHA3_224>::Signer>
      (req_val.type, req_val.payload, req_val.privkey, req_val.sign, req_val.hex, req_val.field,req_val.error);
    }
    else if(strncmp(req_val.hash_sign.c_str(), "sha_512",sizeof("sha_512")) == 0){
      ECDSA_SIGN <ECDSA<ECP, SHA512>::PrivateKey, ECDSA<ECP,SHA512>::Signer>
      (req_val.type, req_val.payload, req_val.privkey, req_val.sign, req_val.hex, req_val.field,req_val.error);
    }
    else if(strncmp(req_val.hash_sign.c_str(), "sha_384",sizeof("sha_384")) == 0){
      ECDSA_SIGN <ECDSA<ECP, SHA384>::PrivateKey, ECDSA<ECP,SHA384>::Signer>
      (req_val.type, req_val.payload, req_val.privkey, req_val.sign, req_val.hex, req_val.field,req_val.error);
    }
    else if(strncmp(req_val.hash_sign.c_str(), "sha_256",sizeof("sha_256")) == 0){
      ECDSA_SIGN <ECDSA<ECP, SHA256>::PrivateKey, ECDSA<ECP,SHA256>::Signer>
      (req_val.type, req_val.payload, req_val.privkey, req_val.sign, req_val.hex, req_val.field,req_val.error);
    }
    else if(strncmp(req_val.hash_sign.c_str(), "sha_224",sizeof("sha_224")) == 0){
      ECDSA_SIGN <ECDSA<ECP, SHA224>::PrivateKey, ECDSA<ECP,SHA224>::Signer>
      (req_val.type, req_val.payload, req_val.privkey, req_val.sign, req_val.hex, req_val.field,req_val.error);
    }
    else if(strncmp(req_val.hash_sign.c_str(), "sha_1",sizeof("sha_1")) == 0){
      ECDSA_SIGN <ECDSA<ECP, SHA1>::PrivateKey, ECDSA<ECP,SHA1>::Signer>
      (req_val.type, req_val.payload, req_val.privkey, req_val.sign, req_val.hex, req_val.field,req_val.error);
    }
    else if(strncmp(req_val.hash_sign.c_str(), "whirlpool",sizeof("whirlpool")) == 0){
      ECDSA_SIGN <ECDSA<ECP, Whirlpool>::PrivateKey, ECDSA<ECP,Whirlpool>::Signer>
      (req_val.type, req_val.payload, req_val.privkey, req_val.sign, req_val.hex, req_val.field,req_val.error);
    }
    else{
      req_val.error="Bad hash sign algorithm ";
      answ_error(req_val,answ_js);
      return 1;
    }
  }
  else if(strncmp(req_val.field.c_str(), "ec2n",sizeof("ec2n")) == 0){
    if(strncmp(req_val.hash_sign.c_str(), "sha3_512",sizeof("sha3_512")) == 0){
      ECDSA_SIGN <ECDSA<EC2N, SHA3_512>::PrivateKey, ECDSA<EC2N,SHA3_512>::Signer>
      (req_val.type, req_val.payload, req_val.privkey, req_val.sign, req_val.hex, req_val.field,req_val.error);
    }
    else if(strncmp(req_val.hash_sign.c_str(), "sha3_384",sizeof("sha3_384")) == 0){
      ECDSA_SIGN <ECDSA<EC2N, SHA3_384>::PrivateKey, ECDSA<EC2N,SHA3_384>::Signer>
      (req_val.type, req_val.payload, req_val.privkey, req_val.sign, req_val.hex, req_val.field,req_val.error);
    }
    else if(strncmp(req_val.hash_sign.c_str(), "sha3_256",sizeof("sha3_256")) == 0){
      ECDSA_SIGN <ECDSA<EC2N, SHA3_256>::PrivateKey, ECDSA<EC2N,SHA3_256>::Signer>
      (req_val.type, req_val.payload, req_val.privkey, req_val.sign, req_val.hex, req_val.field,req_val.error);
    }
    else if(strncmp(req_val.hash_sign.c_str(), "sha3_224",sizeof("sha3_224")) == 0){
      ECDSA_SIGN <ECDSA<EC2N, SHA3_224>::PrivateKey, ECDSA<EC2N,SHA3_224>::Signer>
      (req_val.type, req_val.payload, req_val.privkey, req_val.sign, req_val.hex, req_val.field,req_val.error);
    }
    else if(strncmp(req_val.hash_sign.c_str(), "sha_512",sizeof("sha_512")) == 0){
      ECDSA_SIGN <ECDSA<EC2N, SHA512>::PrivateKey, ECDSA<EC2N,SHA512>::Signer>
      (req_val.type, req_val.payload, req_val.privkey, req_val.sign, req_val.hex, req_val.field,req_val.error);
    }
    else if(strncmp(req_val.hash_sign.c_str(), "sha_384",sizeof("sha_384")) == 0){
      ECDSA_SIGN <ECDSA<EC2N, SHA384>::PrivateKey, ECDSA<EC2N,SHA384>::Signer>
      (req_val.type, req_val.payload, req_val.privkey, req_val.sign, req_val.hex, req_val.field,req_val.error);
    }
    else if(strncmp(req_val.hash_sign.c_str(), "sha_256",sizeof("sha_256")) == 0){
      ECDSA_SIGN <ECDSA<EC2N, SHA256>::PrivateKey, ECDSA<EC2N,SHA256>::Signer>
      (req_val.type, req_val.payload, req_val.privkey, req_val.sign, req_val.hex, req_val.field,req_val.error);
    }
    else if(strncmp(req_val.hash_sign.c_str(), "sha_224",sizeof("sha_224")) == 0){
      ECDSA_SIGN <ECDSA<EC2N, SHA224>::PrivateKey, ECDSA<EC2N,SHA224>::Signer>
      (req_val.type, req_val.payload, req_val.privkey, req_val.sign, req_val.hex, req_val.field,req_val.error);
    }
    else if(strncmp(req_val.hash_sign.c_str(), "sha_1",sizeof("sha_1")) == 0){
      ECDSA_SIGN <ECDSA<EC2N, SHA1>::PrivateKey, ECDSA<EC2N,SHA1>::Signer>
      (req_val.type, req_val.payload, req_val.privkey, req_val.sign, req_val.hex, req_val.field,req_val.error);
    }
    else if(strncmp(req_val.hash_sign.c_str(), "whirlpool",sizeof("whirlpool")) == 0){
      ECDSA_SIGN <ECDSA<EC2N, Whirlpool>::PrivateKey, ECDSA<EC2N,Whirlpool>::Signer>
      (req_val.type, req_val.payload, req_val.privkey, req_val.sign, req_val.hex, req_val.field,req_val.error);
    }
    else{
      req_val.error="Bad hash sign algorithm ";
      answ_error(req_val,answ_js);
      return 1;
    }

  }

  sign_anws(req_val,answ_js);

  return 0;
}

int parse_ecdsa_v(Document& d, stru_param& req_val, string& answ_js){
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
      if(check_hash_sign(d,req_val,answ_js)!=0)
      return 1;


      req_val.payload=req_val.plaintext;
    }
    else{
      req_val.error="Not plaintext/pubkey/sign tag ";
      answ_error(req_val,answ_js);
      return 1;
    }
  }
  // else if (strncmp(req_val.type.c_str(), "file",sizeof("file")) == 0){
  //   if(d.HasMember("file")  && d.HasMember("pubkey")){
  //     if(check_file(d,req_val,answ_js)!=0)
  //     return 1;
  //     if(check_keys(d,req_val,answ_js)!=0)
  //     return 1;
  //     if(check_field(d,req_val,answ_js)!=0)
  //     return 1;
  //     if(check_hash_sign(d,req_val,answ_js)!=0)
  //     return 1;
  //
  //     req_val.hex=0;
  //     req_val.payload=req_val.file;
  //   }
  //   else{
  //     req_val.error="Not file/pubkey tag ";
  //     answ_error(req_val,answ_js);
  //     return 1;
  //   }
  // }
  else{
    req_val.error="Bad type ";
    answ_error(req_val,answ_js);
    return 1;
  }

  if(strncmp(req_val.field.c_str(), "ecp",sizeof("ecp")) == 0){
    if(strncmp(req_val.hash_sign.c_str(), "sha3_512",sizeof("sha3_512")) == 0){
      ECDSA_V<ECDSA<ECP, SHA3_512>::PublicKey, ECDSA<ECP,SHA3_512>::Verifier>
      (req_val.type, req_val.payload, req_val.pubkey, req_val.sign,req_val.verify, req_val.hex, req_val.field,req_val.error);
    }
    else if(strncmp(req_val.hash_sign.c_str(), "sha3_384",sizeof("sha3_384")) == 0){
      ECDSA_V<ECDSA<ECP, SHA3_384>::PublicKey, ECDSA<ECP,SHA3_384>::Verifier>
      (req_val.type, req_val.payload, req_val.pubkey, req_val.sign,req_val.verify, req_val.hex, req_val.field,req_val.error);
    }
    else if(strncmp(req_val.hash_sign.c_str(), "sha3_256",sizeof("sha3_256")) == 0){
      ECDSA_V<ECDSA<ECP, SHA3_256>::PublicKey, ECDSA<ECP,SHA3_256>::Verifier>
      (req_val.type, req_val.payload, req_val.pubkey, req_val.sign,req_val.verify, req_val.hex, req_val.field,req_val.error);
    }
    else if(strncmp(req_val.hash_sign.c_str(), "sha3_224",sizeof("sha3_224")) == 0){
      ECDSA_V<ECDSA<ECP, SHA3_224>::PublicKey, ECDSA<ECP,SHA3_224>::Verifier>
      (req_val.type, req_val.payload, req_val.pubkey, req_val.sign,req_val.verify, req_val.hex, req_val.field,req_val.error);
    }
    else if(strncmp(req_val.hash_sign.c_str(), "sha_512",sizeof("sha_512")) == 0){
      ECDSA_V<ECDSA<ECP, SHA512>::PublicKey, ECDSA<ECP,SHA512>::Verifier>
      (req_val.type, req_val.payload, req_val.pubkey, req_val.sign,req_val.verify, req_val.hex, req_val.field,req_val.error);
    }
    else if(strncmp(req_val.hash_sign.c_str(), "sha_384",sizeof("sha_384")) == 0){
      ECDSA_V<ECDSA<ECP, SHA384>::PublicKey, ECDSA<ECP,SHA384>::Verifier>
      (req_val.type, req_val.payload, req_val.pubkey, req_val.sign,req_val.verify, req_val.hex, req_val.field,req_val.error);
    }
    else if(strncmp(req_val.hash_sign.c_str(), "sha_256",sizeof("sha_256")) == 0){
      ECDSA_V<ECDSA<ECP, SHA256>::PublicKey, ECDSA<ECP,SHA256>::Verifier>
      (req_val.type, req_val.payload, req_val.pubkey, req_val.sign,req_val.verify, req_val.hex, req_val.field,req_val.error);
    }
    else if(strncmp(req_val.hash_sign.c_str(), "sha_224",sizeof("sha_224")) == 0){
      ECDSA_V<ECDSA<ECP, SHA224>::PublicKey, ECDSA<ECP,SHA224>::Verifier>
      (req_val.type, req_val.payload, req_val.pubkey, req_val.sign,req_val.verify, req_val.hex, req_val.field,req_val.error);
    }
    else if(strncmp(req_val.hash_sign.c_str(), "sha_1",sizeof("sha_1")) == 0){
      ECDSA_V<ECDSA<ECP, SHA1>::PublicKey, ECDSA<ECP,SHA1>::Verifier>
      (req_val.type, req_val.payload, req_val.pubkey, req_val.sign,req_val.verify, req_val.hex, req_val.field,req_val.error);
    }
    else if(strncmp(req_val.hash_sign.c_str(), "whirlpool",sizeof("whirlpool")) == 0){
      ECDSA_V<ECDSA<ECP, Whirlpool>::PublicKey, ECDSA<ECP,Whirlpool>::Verifier>
      (req_val.type, req_val.payload, req_val.pubkey, req_val.sign,req_val.verify, req_val.hex, req_val.field,req_val.error);
    }
    else{
      req_val.error="Bad hash sign algorithm ";
      answ_error(req_val,answ_js);
      return 1;
    }

  }
  else if(strncmp(req_val.field.c_str(), "ec2n",sizeof("ec2n")) == 0){
    if(strncmp(req_val.hash_sign.c_str(), "sha3_512",sizeof("sha3_512")) == 0){
      ECDSA_V<ECDSA<EC2N, SHA3_512>::PublicKey, ECDSA<EC2N,SHA3_512>::Verifier>
      (req_val.type, req_val.payload, req_val.pubkey, req_val.sign,req_val.verify, req_val.hex, req_val.field,req_val.error);
    }
    else if(strncmp(req_val.hash_sign.c_str(), "sha3_384",sizeof("sha3_384")) == 0){
      ECDSA_V<ECDSA<EC2N, SHA3_384>::PublicKey, ECDSA<EC2N,SHA3_384>::Verifier>
      (req_val.type, req_val.payload, req_val.pubkey, req_val.sign,req_val.verify, req_val.hex, req_val.field,req_val.error);
    }
    else if(strncmp(req_val.hash_sign.c_str(), "sha3_256",sizeof("sha3_256")) == 0){
      ECDSA_V<ECDSA<EC2N, SHA3_256>::PublicKey, ECDSA<EC2N,SHA3_256>::Verifier>
      (req_val.type, req_val.payload, req_val.pubkey, req_val.sign,req_val.verify, req_val.hex, req_val.field,req_val.error);
    }
    else if(strncmp(req_val.hash_sign.c_str(), "sha3_224",sizeof("sha3_224")) == 0){
      ECDSA_V<ECDSA<EC2N, SHA3_224>::PublicKey, ECDSA<EC2N,SHA3_224>::Verifier>
      (req_val.type, req_val.payload, req_val.pubkey, req_val.sign,req_val.verify, req_val.hex, req_val.field,req_val.error);
    }
    else if(strncmp(req_val.hash_sign.c_str(), "sha_512",sizeof("sha_512")) == 0){
      ECDSA_V<ECDSA<EC2N, SHA512>::PublicKey, ECDSA<EC2N,SHA512>::Verifier>
      (req_val.type, req_val.payload, req_val.pubkey, req_val.sign,req_val.verify, req_val.hex, req_val.field,req_val.error);
    }
    else if(strncmp(req_val.hash_sign.c_str(), "sha_384",sizeof("sha_384")) == 0){
      ECDSA_V<ECDSA<EC2N, SHA384>::PublicKey, ECDSA<EC2N,SHA384>::Verifier>
      (req_val.type, req_val.payload, req_val.pubkey, req_val.sign,req_val.verify, req_val.hex, req_val.field,req_val.error);
    }
    else if(strncmp(req_val.hash_sign.c_str(), "sha_256",sizeof("sha_256")) == 0){
      ECDSA_V<ECDSA<EC2N, SHA256>::PublicKey, ECDSA<EC2N,SHA256>::Verifier>
      (req_val.type, req_val.payload, req_val.pubkey, req_val.sign,req_val.verify, req_val.hex, req_val.field,req_val.error);
    }
    else if(strncmp(req_val.hash_sign.c_str(), "sha_224",sizeof("sha_224")) == 0){
      ECDSA_V<ECDSA<EC2N, SHA224>::PublicKey, ECDSA<EC2N,SHA224>::Verifier>
      (req_val.type, req_val.payload, req_val.pubkey, req_val.sign,req_val.verify, req_val.hex, req_val.field,req_val.error);
    }
    else if(strncmp(req_val.hash_sign.c_str(), "sha_1",sizeof("sha_1")) == 0){
      ECDSA_V<ECDSA<EC2N, SHA1>::PublicKey, ECDSA<EC2N,SHA1>::Verifier>
      (req_val.type, req_val.payload, req_val.pubkey, req_val.sign,req_val.verify, req_val.hex, req_val.field,req_val.error);
    }
    else if(strncmp(req_val.hash_sign.c_str(), "whirlpool",sizeof("whirlpool")) == 0){
      ECDSA_V<ECDSA<EC2N, Whirlpool>::PublicKey, ECDSA<EC2N,Whirlpool>::Verifier>
      (req_val.type, req_val.payload, req_val.pubkey, req_val.sign,req_val.verify, req_val.hex, req_val.field,req_val.error);
    }
    else{
      req_val.error="Bad hash sign algorithm ";
      answ_error(req_val,answ_js);
      return 1;
    }
  }

  verify_anws(req_val,answ_js);
  return 0;

}

int parse_ecdsa(Document& d, stru_param& req_val, string& answ_js){
  if(d.HasMember("operation")){
    if(check_ops(d,req_val,answ_js)!=0)
    return 1;
  }
  else{
    req_val.error="Not ops tag ";
    answ_error(req_val,answ_js);
    return 1;
  }

  if(d.HasMember("curve")){
    if(check_curve(d,req_val,answ_js)!=0)
    return 1;
    if(search_field_curve(d, req_val, answ_js)!=0)
    return 1;
  }
  else{
    req_val.error="Not curve tag ";
    answ_error(req_val,answ_js);
    return 1;
  }

  if(strncmp(req_val.operation.c_str(), "sign",sizeof("sign")) == 0)
  parse_ecdsa_sign(d, req_val,answ_js);
  else if(strncmp(req_val.operation.c_str(), "verify",sizeof("verify")) == 0)
  parse_ecdsa_v(d, req_val,answ_js);
  else{
    req_val.error="Not ops valid ";
    answ_error(req_val,answ_js);
    return 1;
  }

  return 0;

}

////////////////////////////////////////////////////////////////////////
int parse_ecnr_sign(Document& d, stru_param& req_val, string& answ_js){
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
      if(check_field(d,req_val,answ_js)!=0)
      return 1;
      if(check_hash_sign(d,req_val,answ_js)!=0)
      return 1;

      req_val.payload=req_val.plaintext;
    }
    else{
      req_val.error="Not plaintext/privkey tag ";
      answ_error(req_val,answ_js);
      return 1;
    }
  }
  // else if (strncmp(req_val.type.c_str(), "file",sizeof("file")) == 0){
  //   if(d.HasMember("file")  && d.HasMember("privkey")){
  //     if(check_file(d,req_val,answ_js)!=0)
  //     return 1;
  //     if(check_keys(d,req_val,answ_js)!=0)
  //     return 1;
  //     if(check_field(d,req_val,answ_js)!=0)
  //     return 1;
  //     if(check_hash_sign(d,req_val,answ_js)!=0)
  //     return 1;
  //
  //     req_val.hex=0;
  //     req_val.payload=req_val.file;
  //   }
  //   else{
  //     req_val.error="Not file/privkey tag ";
  //     answ_error(req_val,answ_js);
  //     return 1;
  //   }
  // }
  else{
    req_val.error="Bad type ";
    answ_error(req_val,answ_js);
    return 1;
  }


  if(strncmp(req_val.field.c_str(), "ecp",sizeof("ecp")) == 0){
    if(strncmp(req_val.hash_sign.c_str(), "sha3_512",sizeof("sha3_512")) == 0){
      ECDSA_SIGN <ECNR<ECP, SHA3_512>::PrivateKey, ECNR<ECP,SHA3_512>::Signer>
      (req_val.type, req_val.payload, req_val.privkey, req_val.sign, req_val.hex, req_val.field,req_val.error);
    }
    else if(strncmp(req_val.hash_sign.c_str(), "sha3_384",sizeof("sha3_384")) == 0){
      ECDSA_SIGN <ECNR<ECP, SHA3_384>::PrivateKey, ECNR<ECP,SHA3_384>::Signer>
      (req_val.type, req_val.payload, req_val.privkey, req_val.sign, req_val.hex, req_val.field,req_val.error);
    }
    else if(strncmp(req_val.hash_sign.c_str(), "sha3_256",sizeof("sha3_256")) == 0){
      ECDSA_SIGN <ECNR<ECP, SHA3_256>::PrivateKey, ECNR<ECP,SHA3_256>::Signer>
      (req_val.type, req_val.payload, req_val.privkey, req_val.sign, req_val.hex, req_val.field,req_val.error);
    }
    else if(strncmp(req_val.hash_sign.c_str(), "sha3_224",sizeof("sha3_224")) == 0){
      ECDSA_SIGN <ECNR<ECP, SHA3_224>::PrivateKey, ECNR<ECP,SHA3_224>::Signer>
      (req_val.type, req_val.payload, req_val.privkey, req_val.sign, req_val.hex, req_val.field,req_val.error);
    }
    else if(strncmp(req_val.hash_sign.c_str(), "sha_512",sizeof("sha_512")) == 0){
      ECDSA_SIGN <ECNR<ECP, SHA512>::PrivateKey, ECNR<ECP,SHA512>::Signer>
      (req_val.type, req_val.payload, req_val.privkey, req_val.sign, req_val.hex, req_val.field,req_val.error);
    }
    else if(strncmp(req_val.hash_sign.c_str(), "sha_384",sizeof("sha_384")) == 0){
      ECDSA_SIGN <ECNR<ECP, SHA384>::PrivateKey, ECNR<ECP,SHA384>::Signer>
      (req_val.type, req_val.payload, req_val.privkey, req_val.sign, req_val.hex, req_val.field,req_val.error);
    }
    else if(strncmp(req_val.hash_sign.c_str(), "sha_256",sizeof("sha_256")) == 0){
      ECDSA_SIGN <ECNR<ECP, SHA256>::PrivateKey, ECNR<ECP,SHA256>::Signer>
      (req_val.type, req_val.payload, req_val.privkey, req_val.sign, req_val.hex, req_val.field,req_val.error);
    }
    else if(strncmp(req_val.hash_sign.c_str(), "sha_224",sizeof("sha_224")) == 0){
      ECDSA_SIGN <ECNR<ECP, SHA224>::PrivateKey, ECNR<ECP,SHA224>::Signer>
      (req_val.type, req_val.payload, req_val.privkey, req_val.sign, req_val.hex, req_val.field,req_val.error);
    }
    else if(strncmp(req_val.hash_sign.c_str(), "sha_1",sizeof("sha_1")) == 0){
      ECDSA_SIGN <ECNR<ECP, SHA1>::PrivateKey, ECNR<ECP,SHA1>::Signer>
      (req_val.type, req_val.payload, req_val.privkey, req_val.sign, req_val.hex, req_val.field,req_val.error);
    }
    else if(strncmp(req_val.hash_sign.c_str(), "whirlpool",sizeof("whirlpool")) == 0){
      ECDSA_SIGN <ECNR<ECP, Whirlpool>::PrivateKey, ECNR<ECP,Whirlpool>::Signer>
      (req_val.type, req_val.payload, req_val.privkey, req_val.sign, req_val.hex, req_val.field,req_val.error);
    }
    else{
      req_val.error="Bad hash sign algorithm ";
      answ_error(req_val,answ_js);
      return 1;
    }
  }
  else{
    req_val.error="Bad curve ECP";
    answ_error(req_val,answ_js);
    return 1;
  }


  if(req_val.error.size()>0)
     req_val.error="Fail ECNR sign";

  sign_anws(req_val,answ_js);

  return 0;
}

int parse_ecnr_v(Document& d, stru_param& req_val, string& answ_js){
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
      if(check_hash_sign(d,req_val,answ_js)!=0)
      return 1;


      req_val.payload=req_val.plaintext;
    }
    else{
      req_val.error="Not plaintext/pubkey/sign tag ";
      answ_error(req_val,answ_js);
      return 1;
    }
  }
  // else if (strncmp(req_val.type.c_str(), "file",sizeof("file")) == 0){
  //   if(d.HasMember("file")  && d.HasMember("pubkey")){
  //     if(check_file(d,req_val,answ_js)!=0)
  //     return 1;
  //     if(check_keys(d,req_val,answ_js)!=0)
  //     return 1;
  //     if(check_field(d,req_val,answ_js)!=0)
  //     return 1;
  //     if(check_hash_sign(d,req_val,answ_js)!=0)
  //     return 1;
  //
  //     req_val.hex=0;
  //     req_val.payload=req_val.file;
  //   }
  //   else{
  //     req_val.error="Not file/pubkey tag ";
  //     answ_error(req_val,answ_js);
  //     return 1;
  //   }
  // }
  else{
    req_val.error="Bad type ";
    answ_error(req_val,answ_js);
    return 1;
  }

  if(strncmp(req_val.field.c_str(), "ecp",sizeof("ecp")) == 0){
    if(strncmp(req_val.hash_sign.c_str(), "sha3_512",sizeof("sha3_512")) == 0){
      ECDSA_V<ECNR<ECP, SHA3_512>::PublicKey, ECNR<ECP,SHA3_512>::Verifier>
      (req_val.type, req_val.payload, req_val.pubkey, req_val.sign,req_val.verify, req_val.hex, req_val.field,req_val.error);
    }
    else if(strncmp(req_val.hash_sign.c_str(), "sha3_384",sizeof("sha3_384")) == 0){
      ECDSA_V<ECNR<ECP, SHA3_384>::PublicKey, ECNR<ECP,SHA3_384>::Verifier>
      (req_val.type, req_val.payload, req_val.pubkey, req_val.sign,req_val.verify, req_val.hex, req_val.field,req_val.error);
    }
    else if(strncmp(req_val.hash_sign.c_str(), "sha3_256",sizeof("sha3_256")) == 0){
      ECDSA_V<ECNR<ECP, SHA3_256>::PublicKey, ECNR<ECP,SHA3_256>::Verifier>
      (req_val.type, req_val.payload, req_val.pubkey, req_val.sign,req_val.verify, req_val.hex, req_val.field,req_val.error);
    }
    else if(strncmp(req_val.hash_sign.c_str(), "sha3_224",sizeof("sha3_224")) == 0){
      ECDSA_V<ECNR<ECP, SHA3_224>::PublicKey, ECNR<ECP,SHA3_224>::Verifier>
      (req_val.type, req_val.payload, req_val.pubkey, req_val.sign,req_val.verify, req_val.hex, req_val.field,req_val.error);
    }
    else if(strncmp(req_val.hash_sign.c_str(), "sha_512",sizeof("sha_512")) == 0){
      ECDSA_V<ECNR<ECP, SHA512>::PublicKey, ECNR<ECP,SHA512>::Verifier>
      (req_val.type, req_val.payload, req_val.pubkey, req_val.sign,req_val.verify, req_val.hex, req_val.field,req_val.error);
    }
    else if(strncmp(req_val.hash_sign.c_str(), "sha_384",sizeof("sha_384")) == 0){
      ECDSA_V<ECNR<ECP, SHA384>::PublicKey, ECNR<ECP,SHA384>::Verifier>
      (req_val.type, req_val.payload, req_val.pubkey, req_val.sign,req_val.verify, req_val.hex, req_val.field,req_val.error);
    }
    else if(strncmp(req_val.hash_sign.c_str(), "sha_256",sizeof("sha_256")) == 0){
      ECDSA_V<ECNR<ECP, SHA256>::PublicKey, ECNR<ECP,SHA256>::Verifier>
      (req_val.type, req_val.payload, req_val.pubkey, req_val.sign,req_val.verify, req_val.hex, req_val.field,req_val.error);
    }
    else if(strncmp(req_val.hash_sign.c_str(), "sha_224",sizeof("sha_224")) == 0){
      ECDSA_V<ECNR<ECP, SHA224>::PublicKey, ECNR<ECP,SHA224>::Verifier>
      (req_val.type, req_val.payload, req_val.pubkey, req_val.sign,req_val.verify, req_val.hex, req_val.field,req_val.error);
    }
    else if(strncmp(req_val.hash_sign.c_str(), "sha_1",sizeof("sha_1")) == 0){
      ECDSA_V<ECNR<ECP, SHA1>::PublicKey, ECNR<ECP,SHA1>::Verifier>
      (req_val.type, req_val.payload, req_val.pubkey, req_val.sign,req_val.verify, req_val.hex, req_val.field,req_val.error);
    }
    else if(strncmp(req_val.hash_sign.c_str(), "whirlpool",sizeof("whirlpool")) == 0){
      ECDSA_V<ECNR<ECP, Whirlpool>::PublicKey, ECNR<ECP,Whirlpool>::Verifier>
      (req_val.type, req_val.payload, req_val.pubkey, req_val.sign,req_val.verify, req_val.hex, req_val.field,req_val.error);
    }
    else{
      req_val.error="Bad hash sign algorithm ";
      answ_error(req_val,answ_js);
      return 1;
    }

  }
  else{
    req_val.error="Bad curve ECP";
    answ_error(req_val,answ_js);
    return 1;
  }

  if(req_val.error.size()>0)
     req_val.error="Fail ECNR verify";
  else
    req_val.verify="ENCR_OK";

  verify_anws(req_val,answ_js);
  return 0;

}


int parse_ecnr(Document& d, stru_param& req_val, string& answ_js){
  if(d.HasMember("operation")){
    if(check_ops(d,req_val,answ_js)!=0)
    return 1;
  }
  else{
    req_val.error="Not ops tag ";
    answ_error(req_val,answ_js);
    return 1;
  }

  if(d.HasMember("curve")){
    if(check_curve(d,req_val,answ_js)!=0)
    return 1;
    if(search_field_curve(d, req_val, answ_js)!=0)
    return 1;
  }
  else{
    req_val.error="Not curve tag ";
    answ_error(req_val,answ_js);
    return 1;
  }

  if(strncmp(req_val.operation.c_str(), "sign",sizeof("sign")) == 0)
  parse_ecnr_sign(d, req_val,answ_js);
  else if(strncmp(req_val.operation.c_str(), "verify",sizeof("verify")) == 0)
  parse_ecnr_v(d, req_val,answ_js);
  else{
    req_val.error="Not ops valid ";
    answ_error(req_val,answ_js);
    return 1;
  }

  return 0;

}


////////////////////////////////////////////////////////////////////////
int parse_ecdh_a(Document& d, stru_param& req_val, string& answ_js){
  if(d.HasMember("curve")&&d.HasMember("privkey") && d.HasMember("sharedpub")){
    if(check_curve(d,req_val,answ_js)!=0)
    return 1;
    if(search_field_curve(d, req_val, answ_js)!=0)
    return 1;
    if(check_a_keys(d,req_val,answ_js)!=0)
    return 1;


    if(strncmp(req_val.field.c_str(), "ecp",sizeof("ecp")) == 0){
      ECDH_A<ECDH <ECP>::Domain>
      (req_val.CURVE,req_val.privkey, req_val.sharedpub, req_val.sharedkey, req_val.field, req_val.error);

    }
    else if(strncmp(req_val.field.c_str(), "ec2n",sizeof("ec2n")) == 0){
      ECDH_A<ECDH <EC2N>::Domain>
      (req_val.CURVE,req_val.privkey, req_val.sharedpub, req_val.sharedkey, req_val.field, req_val.error);
    }

    req_val.tag.clear();
    req_val.tag="algorithm";
    Addstr2json(answ_js, req_val.tag, req_val.algorithm);
    req_val.tag.clear();
    req_val.tag="curve";
    Addstr2json(answ_js, req_val.tag, req_val.curve);
    req_val.tag.clear();
    req_val.tag="sharedkey";
    Addstr2json(answ_js, req_val.tag, req_val.sharedkey);
    req_val.tag.clear();
    req_val.tag="error";
    Addstr2json(answ_js, req_val.tag, req_val.error);

  }
  else{
    req_val.error.clear();
    req_val.error="Not curve/privkey/sharedpub tag ";
    req_val.tag="error";
    Addstr2json(answ_js, req_val.tag, req_val.error);
    #ifdef DEBUG
    cerr << req_val.error;
    #endif
    return 1;
  }
  return 0;
}

int parse_ecdh_gen(Document& d, stru_param& req_val, string& answ_js){
  if(d.HasMember("curve")){
    if(check_curve(d,req_val,answ_js)!=0)
    return 1;
    if(search_field_curve(d, req_val, answ_js)!=0)
    return 1;

    if(strncmp(req_val.field.c_str(), "ecp",sizeof("ecp")) == 0){
      ECDH_GEN<ECDH <ECP>::Domain>
      (req_val.CURVE, req_val.privkey, req_val.pubkey, req_val.field, req_val.error);

    }
    else if(strncmp(req_val.field.c_str(), "ec2n",sizeof("ec2n")) == 0){
      ECDH_GEN<ECDH <EC2N>::Domain>
      (req_val.CURVE, req_val.privkey, req_val.pubkey, req_val.field, req_val.error);
    }

    req_val.tag.clear();
    req_val.tag="algorithm";
    Addstr2json(answ_js, req_val.tag, req_val.algorithm);
    req_val.tag.clear();
    req_val.tag="curve";
    Addstr2json(answ_js, req_val.tag, req_val.curve);
    req_val.tag.clear();
    req_val.tag="privkey";
    Addstr2json(answ_js, req_val.tag, req_val.privkey);
    req_val.tag.clear();
    req_val.tag="pubkey";
    Addstr2json(answ_js, req_val.tag, req_val.pubkey);
    req_val.tag.clear();
    req_val.tag="error";
    Addstr2json(answ_js, req_val.tag, req_val.error);

  }
  else{
    req_val.error.clear();
    req_val.error="Not curve tag ";
    req_val.tag="error";
    Addstr2json(answ_js, req_val.tag, req_val.error);
    #ifdef DEBUG
    cerr << req_val.error;
    #endif
    return 1;
  }
  return 0;
}

int parse_ecdh(Document& d, stru_param& req_val, string& answ_js){
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
  parse_ecdh_gen(d, req_val,answ_js);
  else if(strncmp(req_val.operation.c_str(), "agree",sizeof("agree")) == 0)
  parse_ecdh_a(d, req_val,answ_js);
  else{
    req_val.error="Not ops valid ";
    answ_error(req_val,answ_js);
    return 1;
  }
  return 0;
}
