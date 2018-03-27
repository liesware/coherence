#include "rapidjson/document.h"
#include "rapidjson/writer.h"
#include "rapidjson/stringbuffer.h"
#include "rapidjson/error/en.h"
#include <iostream>
#include <fstream>

#include "cryptopp/osrng.h"
#include "cryptopp/randpool.h"
#include "cryptopp/rdrand.h"
#include "cryptopp/secblock.h"

#include "cryptopp/filters.h"
#include "cryptopp/hex.h"
#include "cryptopp/files.h"
#include "cryptopp/cryptlib.h"


using namespace CryptoPP;
using namespace  std;

int rand_anws(stru_param& req_val, string& answ_js){
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

int check_entropy(Document& d, stru_param& req_val, string& answ_js){
  if(d.HasMember("entropy")&&(d["entropy"].GetInt()==0 || d["entropy"].GetInt()==1 ||d["entropy"].GetInt()==2)){
    req_val.entropy=d["entropy"].GetInt();    
  }
  else
    req_val.entropy=0;  
     
  return 0;
}

////////////////////////////////////////////////////////////////////////

int entropy_gen(string& str_entropy, int& device , string& error){	
  error.clear();
  str_entropy.clear();
  try{
    SecByteBlock dev_entropy(128);
	if(device == 1) 	
      OS_GenerateRandomBlock(true, dev_entropy,dev_entropy.size());
    else if (device == 0) 	
      OS_GenerateRandomBlock(false, dev_entropy,dev_entropy.size());
    else{
      error="Bad entropy ";
      return 1;
    }
          
	StringSource(dev_entropy, sizeof(dev_entropy), true, new HexEncoder(new StringSink(str_entropy) )); 
        
  }
  catch(const CryptoPP::Exception& d){
    error=d.what();
    error+="Fail OS_GenerateRandomBlock ";		
#ifdef DEBUG					 
	cerr << error << endl;
#endif					
    return 1;
  }
  return 0;
}


template <typename T>
int RANDING(string& rand_numbers, int& entropy, int& len,  string& error ){	
  error.clear();
  rand_numbers.clear();
 
  try{
    T prng;      
    const unsigned int BLOCKSIZE = len;
	SecByteBlock gen_numbers(len);
	string seed;
	
	if(entropy==0 || entropy==1){
		if(entropy==0)
	      if(entropy_gen(seed, entropy, error)!=0)
	        return 1;

		if(entropy==1)
	      if(entropy_gen(seed, entropy, error)!=0)
	        return 1;
      SecByteBlock seed_b(seed.size()/2);
      string seed_e;
      StringSource (seed, true, new HexDecoder(new StringSink(seed_e)));
      memcpy( seed_b, seed_e.data(),seed_b.size()); 	     
	  prng.IncorporateEntropy(seed_b, seed_b.size());
	}

	prng.GenerateBlock(gen_numbers, gen_numbers.size());		
	StringSource(gen_numbers, gen_numbers.size(), true, new HexEncoder(new StringSink(rand_numbers) )); 
  }
  catch(const CryptoPP::Exception& d){
    error=d.what();		
#ifdef DEBUG					 
	cerr << error << endl;
	cerr << "Fail rdrand auto " << endl;
#endif					
    return 1;
  }
  return 0;
}

////////////////////////////////////////////////////////////////////////
int parse_rand(Document& d, stru_param& req_val, string& answ_js){
  if(d.HasMember("length") ){
  	 if(check_length(d,req_val,answ_js,16384)!=0)
       return 1; 
  }
  else{
	req_val.error="Not randlen tag ";  
    answ_error(req_val,answ_js); 
    return 1;	   
  } 
  if(check_entropy(d,req_val,answ_js)!=0)
    return 1;
  
  if(strncmp(req_val.algorithm.c_str(), "RAND_RP",sizeof("RAND_RP")) == 0){
    RANDING<RandomPool>(req_val.result, req_val.entropy,req_val.length, req_val.error);     
  }
  else if(strncmp(req_val.algorithm.c_str(), "RAND_AUTO",sizeof("RAND_AUTO")) == 0){
    RANDING<AutoSeededRandomPool>(req_val.result, req_val.entropy,req_val.length, req_val.error);     
  }
  else if(strncmp(req_val.algorithm.c_str(), "RAND_RDRAND",sizeof("RAND_RDRAND")) == 0){
    RANDING<RDRAND>(req_val.result, req_val.entropy,req_val.length, req_val.error);     
  }     
  else{
    req_val.error="Bad Rand algorithm ";  
    answ_error(req_val,answ_js); 
    return 1;	   
  } 
	   	
  rand_anws(req_val,answ_js); 

  return 0;
}
