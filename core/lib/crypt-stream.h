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
#include "cryptopp/sosemanuk.h"
#include "cryptopp/salsa.h"

using namespace CryptoPP;
using namespace  std;

int stream_anws(stru_param& req_val, string& answ_js){

  req_val.tag.clear();
  req_val.tag="algorithm";
  Addstr2json(answ_js, req_val.tag, req_val.algorithm);
  req_val.tag.clear();
  req_val.tag="result";
  Addstr2json(answ_js, req_val.tag, req_val.result);
  req_val.tag.clear();
  req_val.tag="error";
  Addstr2json(answ_js, req_val.tag, req_val.error);

  return 0;
}

template <typename T>
int STREAM_ENC(string& payload, string& type, string& result, string& key, string& iv ,int& binary, string& error){
  result.clear();
  error.clear();
  SecByteBlock key_b(key.size()/2),iv_b(iv.size()/2);
  string key_e,iv_e;
  StringSource (key, true, new HexDecoder(new StringSink(key_e)));
  memcpy( key_b, key_e.data(),key_b.size());
  StringSource (iv, true, new HexDecoder(new StringSink(iv_e)));
  memcpy( iv_b, iv_e.data(),iv_b.size());

  try{
    //Sosemanuk::Encryption stream;
    T stream;
    stream.SetKeyWithIV(key_b, key_b.size(), iv_b, iv_b.size());
    if (strncmp(type.c_str(), "string",sizeof("string")) == 0){
      if(binary==0)
      StringSource(payload, true, new StreamTransformationFilter(stream,new HexEncoder(new StringSink(result))));
      else if(binary==1)
      StringSource(payload, true, new HexDecoder( new StreamTransformationFilter(stream,new HexEncoder(new StringSink(result)))));
      else{
        error+="Bad binary bool ";
        return 1;
      }
    }
    // else if (strncmp(type.c_str(), "file",sizeof("file")) == 0){
    //   result=payload;
    //   result+=".enc";
    //   FileSource(payload.c_str(), true, new StreamTransformationFilter(stream,new FileSink(result.c_str())));
    // }
    else{
      error="Bad type";
      return 1;
    }
  }
  catch(const CryptoPP::Exception& e){
    error=e.what();
    #ifdef DEBUG
    cerr << error << endl;
    cerr << "Fail stream " << endl;
    #endif
    return 1;
  }
  return 0;

}

template <typename T>
int STREAM_DEC(string& payload, string& type, string& result, string& key, string& iv ,int& binary, string& error){
  result.clear();
  error.clear();
  SecByteBlock key_b(key.size()/2),iv_b(iv.size()/2);
  string key_e,iv_e;
  StringSource (key, true, new HexDecoder(new StringSink(key_e)));
  memcpy( key_b, key_e.data(),key_b.size());
  StringSource (iv, true, new HexDecoder(new StringSink(iv_e)));
  memcpy( iv_b, iv_e.data(),iv_b.size());

  try{
    //Sosemanuk::Decryption stream;
    T stream;
    stream.SetKeyWithIV(key_b, key_b.size(), iv_b, iv_b.size());
    if (strncmp(type.c_str(), "string",sizeof("string")) == 0){
      StringSource(payload, true,new HexDecoder(new StreamTransformationFilter(stream,new StringSink(result))));
      if(Isjson(result,error)!=0){
        result.clear();
        error.clear();
        StringSource(payload, true, new StreamTransformationFilter(stream,new HexEncoder(new StringSink(result))));
      }
    }
    // else if (strncmp(type.c_str(), "file",sizeof("file")) == 0){
    //   result=payload;
    //   result+=".dec";
    //   FileSource(payload.c_str(), true, new StreamTransformationFilter(stream,new FileSink(result.c_str())));
    // }
    else{
      error="Bad type";
      return 1;
    }
  }
  catch(const CryptoPP::Exception& e){
    error=e.what();
    #ifdef DEBUG
    cerr << error << endl;
    cerr << "Fail stream " << endl;
    #endif
    return 1;
  }
  return 0;

}

//PARSE_STREAM//////////////////////////////////////////////////////////
int parse_stream(Document& d, stru_param& req_val, string& answ_js){
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
    if(d.HasMember("plaintext") && d.HasMember("key")&&d.HasMember("iv")&&d.HasMember("operation") ){
      if(check_plain(d,req_val,answ_js)!=0)
      return 1;
      if(check_bin(d,req_val,answ_js)!=0)
      return 1;
      if(check_key(d,req_val,answ_js)!=0)
      return 1;
      if(check_ops(d,req_val,answ_js)!=0)
      return 1;
      if(strncmp(req_val.algorithm.c_str(), "SOSEMANUK",sizeof("SOSEMANUK")) == 0){
        if(check_iv(d,req_val,answ_js)!=0)
        return 1;
      }
      else if(strncmp(req_val.algorithm.c_str(), "SALSA20",sizeof("SALSA20")) == 0){
        if(check_iv(d,req_val,answ_js,16)!=0)
        return 1;
      }
      else{
        req_val.error="Bad Stream algorithm ";
        answ_error(req_val,answ_js);
        return 1;
      }

      req_val.payload=req_val.plaintext;
    }
    else{
      req_val.error="Not plaintext/key/iv/ops tag ";
      answ_error(req_val,answ_js);
      return 1;
    }
  }
  // else if (strncmp(req_val.type.c_str(), "file",sizeof("file")) == 0){
  //   if(d.HasMember("file")&&d.HasMember("key")&&d.HasMember("iv") &&d.HasMember("operation")){
  //     if(check_file(d,req_val,answ_js)!=0)
  //     return 1;
  //     if(check_key(d,req_val,answ_js)!=0)
  //     return 1;
  //     if(check_ops(d,req_val,answ_js)!=0)
  //     return 1;
  //     if(strncmp(req_val.algorithm.c_str(), "SOSEMANUK",sizeof("SOSEMANUK")) == 0){
  //       if(check_iv(d,req_val,answ_js)!=0)
  //       return 1;
  //     }
  //     else if(strncmp(req_val.algorithm.c_str(), "SALSA20",sizeof("SALSA20")) == 0){
  //       if(check_iv(d,req_val,answ_js,16)!=0)
  //       return 1;
  //     }
  //     else{
  //       req_val.error="Bad Stream algorithm ";
  //       answ_error(req_val,answ_js);
  //       return 1;
  //     }
  //
  //     req_val.hex=0;
  //     req_val.payload=req_val.file;
  //   }
  //   else{
  //     req_val.error="Not file/key/iv/ops tag ";
  //     answ_error(req_val,answ_js);
  //     return 1;
  //   }
  // }
  else{
    req_val.error="Bad type ";
    answ_error(req_val,answ_js);
    return 1;
  }

  if(strncmp(req_val.operation.c_str(), "enc",sizeof("enc")) == 0){
    if(strncmp(req_val.algorithm.c_str(), "SOSEMANUK",sizeof("SOSEMANUK")) == 0){
      STREAM_ENC<Sosemanuk::Encryption>(req_val.payload, req_val.type, req_val.result, req_val.key , req_val.iv, req_val.hex, req_val.error);
    }
    else if(strncmp(req_val.algorithm.c_str(), "SALSA20",sizeof("SALSA20")) == 0){
      STREAM_ENC<Salsa20::Encryption>(req_val.payload, req_val.type, req_val.result, req_val.key , req_val.iv, req_val.hex, req_val.error);
    }
    else{
      req_val.error="Bad Algorithm ";
      answ_error(req_val,answ_js);
      return 1;
    }
  }
  else if (strncmp(req_val.operation.c_str(), "dec",sizeof("dec")) == 0){
    if(strncmp(req_val.algorithm.c_str(), "SOSEMANUK",sizeof("SOSEMANUK")) == 0){
      STREAM_DEC<Sosemanuk::Decryption>(req_val.payload, req_val.type, req_val.result, req_val.key , req_val.iv, req_val.hex, req_val.error);
    }
    else if(strncmp(req_val.algorithm.c_str(), "SALSA20",sizeof("SALSA20")) == 0){
      STREAM_DEC<Salsa20::Decryption>(req_val.payload, req_val.type, req_val.result, req_val.key , req_val.iv, req_val.hex, req_val.error);
    }
    else{
      req_val.error="Bad Algorithm ";
      answ_error(req_val,answ_js);
      return 1;
    }
  }
  else{
    req_val.error="Bad ops ";
    answ_error(req_val,answ_js);
    return 1;
  }
  stream_anws(req_val,answ_js);

  return 0;
}
