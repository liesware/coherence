#include "rapidjson/document.h"
#include "rapidjson/writer.h"
#include "rapidjson/stringbuffer.h"
#include "rapidjson/error/en.h"
#include <iostream>
#include <fstream>

#include "argon2/include/argon2.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "cryptopp/filters.h"
#include "cryptopp/hex.h"
#include "cryptopp/files.h"
#include "cryptopp/cryptlib.h"

using namespace CryptoPP;
using namespace  std;

int check_argon2(Document& d, stru_param& req_val, string& answ_js){
  if(d.HasMember("t_cost") && d["t_cost"].IsNumber() &&
  d.HasMember("m_cost") && d["m_cost"].IsNumber() &&
  d.HasMember("parallelism") && d["parallelism"].IsNumber() &&
  d.HasMember("hashlen") && d["hashlen"].IsNumber()&&
  d.HasMember("salt") && d["salt"].IsString()){

    if(Isb16(req_val.salt,req_val.error)!=0){
      req_val.error+=" salt no hex ";
      req_val.tag="error";
      Addstr2json(answ_js, req_val.tag, req_val.error);
      #ifdef DEBUG
      cerr << req_val.error;
      #endif
      return 1;
    }

    req_val.t_cost=d["t_cost"].GetInt();
    req_val.m_cost=d["m_cost"].GetInt();
    req_val.parallelism=d["parallelism"].GetInt();
    req_val.hashlen=d["hashlen"].GetInt();
    req_val.salt=d["salt"].GetString();

    #ifdef DEBUG
    cout<< "Good Argon parameters";
    #endif
  }
  else{
    req_val.error.clear();
    req_val.error="Problem with Argon parameters ";
    req_val.tag="error";
    Addstr2json(answ_js, req_val.tag, req_val.error);
    #ifdef DEBUG
    cerr<<req_val.error;
    #endif
    return 1;
  }
  return 0;
}

int check_pwd(Document& d, stru_param& req_val, string& answ_js){
  if(d.HasMember("pwd") && d["pwd"].IsString()){
    req_val.pwd=d["pwd"].GetString();
    if(Isb16(req_val.key,req_val.error)!=0){
      req_val.error+=" pwd no hex  ";
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
int ARGON2_h(string& payload, string& digest, string& family, int t_cost,
  int m_cost, int parallelism, string& salt, int hashlen, int& binary, string& error){

    error.clear();
    digest.clear();
    char encoded[2048];
    int ok;
    memset(encoded,'\0',2048);
    m_cost=(1<<m_cost);

    string pwd;
    if(binary==0)
    pwd=payload;
    else if(binary==1)
    StringSource(payload, true, new HexDecoder(new StringSink(pwd)));
    else{
      error+="Bad binary bool ";
      return 1;
    }

    if(strncmp(family.c_str(), "argon2i",sizeof("argon2i")) == 0){
      ok=argon2i_hash_encoded(t_cost, m_cost, parallelism, pwd.c_str(), pwd.size(), salt.c_str(), salt.size(), hashlen, encoded,2048);
      if(ok!=ARGON2_OK)
      error="Fail argon2i";
      else
      StringSource h1(encoded, true, new HexEncoder(new StringSink(digest)));
    }
    else if(strncmp(family.c_str(), "argon2d",sizeof("argon2d")) == 0){
      ok=argon2d_hash_encoded(t_cost, m_cost, parallelism, pwd.c_str(), pwd.size(), salt.c_str(), salt.size(), hashlen, encoded,2048);
      if(ok!=ARGON2_OK)
      error="Fail argon2d";
      else
      StringSource h1(encoded, true, new HexEncoder(new StringSink(digest)));
    }
    else if(strncmp(family.c_str(), "argon2id",sizeof("argon2id")) == 0){
      ok=argon2id_hash_encoded(t_cost, m_cost, parallelism, pwd.c_str(), pwd.size(), salt.c_str(), salt.size(), hashlen, encoded,2048);
      if(ok!=ARGON2_OK)
      error="Fail argon2id";
      else
      StringSource h1(encoded, true, new HexEncoder(new StringSink(digest)));
    }
    else{
      error="bad family ";
    }

    if(ok!=ARGON2_OK){
      error="Fail Argon ";
      #ifdef DEBUG
      cerr << error << endl;
      #endif
      return 1;
    }

    #ifdef DEBUG
    cout <<"Argon encoded: " <<encoded << endl;
    #endif

    return 0;
  }

  int ARGON2_V(string& payload, string& family, string& pwd, string& verify,int& binary,string& error){
    error.clear();
    verify.clear();
    string digest;
    int ok;

    string key;
    if(binary==0)
    key=pwd;
    else if(binary==1)
    StringSource(pwd, true, new HexDecoder(new StringSink(key)));
    else{
      error+="Bad binary bool ";
      return 1;
    }

    if(strncmp(family.c_str(), "argon2i",sizeof("argon2i")) == 0){
      StringSource h1(payload, true, new HexDecoder(new StringSink(digest)));
      ok=argon2i_verify(digest.c_str(),key.c_str(), key.size());
      if(ok!=ARGON2_OK)
      error="Fail argon2i";
      else
      verify="ARGON2_OK";
    }
    else if(strncmp(family.c_str(), "argon2d",sizeof("argon2d")) == 0){
      StringSource h1(payload, true, new HexDecoder(new StringSink(digest)));
      ok=argon2d_verify(digest.c_str(),key.c_str(), key.size());
      if(ok!=ARGON2_OK)
      error="Fail argon2d";
      else
      verify="ARGON2_OK";
    }
    else if(strncmp(family.c_str(), "argon2id",sizeof("argon2id")) == 0){
      StringSource h1(payload, true, new HexDecoder(new StringSink(digest)));
      ok=argon2id_verify(digest.c_str(),key.c_str(), key.size());
      if(ok!=ARGON2_OK)
      error="Fail argon2id";
      else
      verify="ARGON2_OK";
    }
    else{
      error="bad family ";
    }

    if(ok!=ARGON2_OK){
      #ifdef DEBUG
      cerr << error << endl;
      cerr << "Fail Argon" << endl;
      #endif
      return 1;
    }

    return 0;
  }

  //PARSE ARGON2////////////////////////////////////////////////////////////////
  int parse_argon2h(Document& d, stru_param& req_val, string& answ_js){
    if(d.HasMember("plaintext")&&d.HasMember("family")&&d.HasMember("t_cost")&&d.HasMember("m_cost")
    &&d.HasMember("parallelism")&&d.HasMember("salt")&&d.HasMember("hashlen")){

      if(check_argon2(d,req_val,answ_js)!=0)
      return 1;
      if(check_plain(d,req_val,answ_js)!=0)
      return 1;
      if(check_fam(d,req_val,answ_js)!=0)
      return 1;
      if(check_bin(d,req_val,answ_js)!=0)
      return 1;

      req_val.payload=req_val.plaintext;

      ARGON2_h(req_val.payload, req_val.hash,req_val.family,req_val.t_cost,
        req_val.m_cost,req_val.parallelism,req_val.salt,req_val.hashlen,req_val.hex,req_val.error);

        req_val.tag.clear();
        req_val.tag="algorithm";
        Addstr2json(answ_js, req_val.tag, req_val.algorithm);
        req_val.tag.clear();
        req_val.tag="family";
        Addstr2json(answ_js, req_val.tag, req_val.family);
        req_val.tag.clear();
        req_val.tag="hash";
        Addstr2json(answ_js, req_val.tag, req_val.hash);
        req_val.tag.clear();
        req_val.tag="error";
        Addstr2json(answ_js, req_val.tag, req_val.error);
      }
      else{
        req_val.error.clear();
        req_val.error="Not enought parameters to argon2 ";
        req_val.tag="error";
        Addstr2json(answ_js, req_val.tag, req_val.error);
        #ifdef DEBUG
        cerr << req_val.error;
        #endif
        return 1;
      }
      return 0;
    }

    //ARGONV////////////////////////////////////////////////////////////////
    int parse_argon2v(Document& d, stru_param& req_val, string& answ_js){
      #ifdef DEBUG
      printf("Good algorithm ARGON2_V ");
      #endif

      if(d.HasMember("plaintext")&&d.HasMember("family")&&d.HasMember("pwd")){
        if(check_plain(d,req_val,answ_js)!=0)
        return 1;
        if(check_pwd(d,req_val,answ_js)!=0)
        return 1;
        if(check_fam(d,req_val,answ_js)!=0)
        return 1;
        if(check_bin(d,req_val,answ_js)!=0)
        return 1;

        req_val.payload=req_val.pwd;

        ARGON2_V(req_val.payload, req_val.family, req_val.plaintext, req_val.verify,req_val.hex, req_val.error);

        req_val.tag.clear();
        req_val.tag="algorithm";
        Addstr2json(answ_js, req_val.tag, req_val.algorithm);
        req_val.tag.clear();
        req_val.tag="family";
        Addstr2json(answ_js, req_val.tag, req_val.family);
        req_val.tag.clear();
        req_val.tag="verify";
        Addstr2json(answ_js, req_val.tag, req_val.verify);
        req_val.tag.clear();
        req_val.tag="error";
        Addstr2json(answ_js, req_val.tag, req_val.error);
      }
      else{
        req_val.error.clear();
        req_val.error="Not plaintext/family/pwd  ";
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
    int parse_argon2(Document& d, stru_param& req_val, string& answ_js){
      #ifdef DEBUG
      printf("Good algorithm ARGON2 ");
      #endif

      if(d.HasMember("operation")){
        if(check_ops(d,req_val,answ_js)!=0)
        return 1;

        if(strncmp(req_val.operation.c_str(), "hash",sizeof("hash")) == 0){
          parse_argon2h(d, req_val, answ_js);
        }
        else if (strncmp(req_val.operation.c_str(), "verify",sizeof("verify")) == 0){
          parse_argon2v(d, req_val, answ_js);
        }
        else{
          req_val.error="Bad argon2 operation ";
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
