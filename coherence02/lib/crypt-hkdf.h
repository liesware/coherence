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
#include "cryptopp/hkdf.h"
#include "cryptopp/sha3.h"
#include "cryptopp/sha.h"


using namespace CryptoPP;
using namespace  std;

int HKDF_GEN(string& payload, string& key ,int& keylen,string& errors ){
  SecByteBlock key_b(SHA3_256::DIGESTSIZE);
  SecByteBlock payload_b(payload.size()/2);
  string payload_e;
  StringSource(payload, true, new HexDecoder(new StringSink(payload_e)));
  memcpy( payload_b, payload_e.data(),payload_b.size());

  try{  
    HKDF<SHA3_256> kdf;
    kdf.DeriveKey(key_b, key_b.size(), payload_b, payload_b.size(), NULL, 0, NULL, 0);
    StringSource(key_b, true, new HexEncoder(new StringSink(key)));
    cout<< key;

  }
  catch(const CryptoPP::Exception& e){ 
	errors="Fail HKDF ";
#ifdef DEBUG					 
	cerr << errors << endl;
#endif					
    return 1;
  }       
          
  return 0;    
}    

int parse_hkfh(Document& d, stru_param& req_val, string& answ_js){
   if(d.HasMember("length")&&d.HasMember("key")&& d["key"].IsString()){     
     if(check_length(d,req_val,answ_js,4096)!=0)
       return 1;
    
    req_val.key=d["key"].GetString();   
	if(Isb16(req_val.key,req_val.error)!=0){
	  req_val.error+=" Key no hex  ";
	  req_val.tag="error";  
	  Addstr2json(answ_js, req_val.tag, req_val.error); 	  
#ifdef DEBUG	    
      cerr << req_val.error;
#endif
      return 1;		  
	}
	
	req_val.payload=req_val.key;
	req_val.key.clear(); 
	HKDF_GEN(req_val.payload,req_val.key, req_val.length,req_val.error);
	
	req_val.tag.clear();
    req_val.tag="algorithm";  
    Addstr2json(answ_js, req_val.tag, req_val.algorithm); 
    req_val.tag.clear();
    req_val.tag="key";  
    Addstr2json(answ_js, req_val.tag, req_val.key);	  
    req_val.tag.clear();	 
    req_val.tag="error";  
    Addstr2json(answ_js, req_val.tag, req_val.error);       
	  	 	 
   }
   else{
	req_val.error.clear();    
	req_val.error="not enought/bad parameters to HKDF gen ";
	req_val.tag="error";  
	Addstr2json(answ_js, req_val.tag, req_val.error); 	  
#ifdef DEBUG	    
    cerr << req_val.error;
#endif
    return 1;	   
   } 	

	
}
