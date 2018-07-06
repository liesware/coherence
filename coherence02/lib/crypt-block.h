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
#include "cryptopp/aes.h"
#include "cryptopp/ccm.h"
#include "cryptopp/gcm.h"
#include "cryptopp/camellia.h"



using namespace CryptoPP;
using namespace  std;

int block_anws(stru_param& req_val, string& answ_js){

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

int check_mode_block(Document& d, stru_param& req_val, string& answ_js){           
  if(d.HasMember("mode") && d["mode"].IsString()){
    req_val.mode= d["mode"].GetString();
    if(strncmp(req_val.mode.c_str(), "ctr",sizeof("ctr")) !=0 && strncmp(req_val.mode.c_str(), "gcm",sizeof("gcm"))!=0){
    req_val.error.clear();    
	req_val.error="Bad mode ctr/gcm ";
	req_val.tag="error";  
	Addstr2json(answ_js, req_val.tag, req_val.error); 	  
#ifdef DEBUG	    
    cerr << req_val.error;
#endif
    return 1;	      
    }     
  }
  else{
    req_val.error=" no mode ctr/gcm ";
    return 1;
  }
     
  return 0;
}

int check_adata(Document& d, stru_param& req_val, string& answ_js){
  if(!d.HasMember("adata")){
    req_val.error=" no adata tag ";
    req_val.tag="error"; 
	Addstr2json(answ_js, req_val.tag, req_val.error); 
    return 1;	
  }  
  req_val.adata= d["adata"].GetString();      	  
  if(req_val.hex==1)  
    if(Isb16(req_val.adata,req_val.error)!=0 ){
	  req_val.tag="error"; 
	  Addstr2json(answ_js, req_val.tag, req_val.error); 
      return 1 ;
    }       
  
  return 0;
}

////////////////////////////////////////////////////////////////////////

template <typename T>
int BLOCK_ENC_CTR(string& payload, string& type, string& result, string& key, string& iv ,int& binary, string& error){		
  result.clear();
  error.clear();
  SecByteBlock key_b(key.size()/2),iv_b(iv.size()/2);
  string key_e,iv_e;
  StringSource (key, true, new HexDecoder(new StringSink(key_e)));
  memcpy( key_b, key_e.data(),key_b.size()); 
  StringSource (iv, true, new HexDecoder(new StringSink(iv_e)));
  memcpy( iv_b, iv_e.data(),iv_b.size());         
	
  try{
    T block;
    block.SetKeyWithIV(key_b, key_b.size(), iv_b, iv_b.size());
    if (strncmp(type.c_str(), "string",sizeof("string")) == 0){
      if(binary==0)	 
        StringSource(payload, true, new StreamTransformationFilter(block,new HexEncoder(new StringSink(result))));
      else if(binary==1)
        StringSource(payload, true, new HexDecoder( new StreamTransformationFilter(block,new HexEncoder(new StringSink(result)))));
	  else{
	    error+="Bad binary bool ";
	    return 1;
	  }	  
	}
	else if (strncmp(type.c_str(), "file",sizeof("file")) == 0){
      result=payload;
	  result+=".enc";
	  FileSource(payload.c_str(), true, new StreamTransformationFilter(block,new FileSink(result.c_str())));
    }	
	else{
	  error="Bad type";			  
	  return 1;
	} 	 	 	    		    
  }
  catch(const CryptoPP::Exception& d){
       error=d.what();
#ifdef DEBUG					 
		cerr << error << endl;
		cerr << "Fail stream " << endl;
#endif					
        return 1;
	}
	return 0;
	
}

template <typename T>
int BLOCK_DEC_CTR(string& payload, string& type, string& result, string& key, string& iv ,int& binary, string& error){		
  result.clear();
  error.clear();
  SecByteBlock key_b(key.size()/2),iv_b(iv.size()/2);
  string key_e,iv_e;
  StringSource (key, true, new HexDecoder(new StringSink(key_e)));
  memcpy( key_b, key_e.data(),key_b.size()); 
  StringSource (iv, true, new HexDecoder(new StringSink(iv_e)));
  memcpy( iv_b, iv_e.data(),iv_b.size());         
	
  try{
    T block;
    block.SetKeyWithIV(key_b, key_b.size(), iv_b, iv_b.size());       
    if (strncmp(type.c_str(), "string",sizeof("string")) == 0){
	  StringSource(payload, true,new HexDecoder(new StreamTransformationFilter(block,new StringSink(result))));
	  if(Isjson(result,error)!=0){
        result.clear();
        error.clear();
        StringSource(payload, true, new StreamTransformationFilter(block,new HexEncoder(new StringSink(result))));	      
	  }
	}
	else if (strncmp(type.c_str(), "file",sizeof("file")) == 0){
      result=payload;
	  result+=".dec";
	  FileSource(payload.c_str(), true, new StreamTransformationFilter(block,new FileSink(result.c_str())));            
    }	      
	else{
	  error="Bad type";			  
	  return 1;
	} 	 	 	    		    
  }
  catch(const CryptoPP::Exception& d){
       error=d.what();
#ifdef DEBUG					 
		cerr << error << endl;
		cerr << "Fail stream " << endl;
#endif					
        return 1;
	}
	return 0;
	
}

////////////////////////////////////////////////////////////////////////
template <typename T>
int BLOCK_ENC_GCM(string& payload, string& adata, string& result, string& key, string& iv ,int& binary, string& error){		
  result.clear();
  error.clear();
  SecByteBlock key_b(key.size()/2),iv_b(iv.size()/2);
  string key_e,iv_e;
  StringSource (key, true, new HexDecoder(new StringSink(key_e)));
  memcpy( key_b, key_e.data(),key_b.size()); 
  StringSource (iv, true, new HexDecoder(new StringSink(iv_e)));
  memcpy( iv_b, iv_e.data(),iv_b.size());         
  
  const int TAG_SIZE = 16;
  	
  try{
    T block;
    string result_e;
    block.SetKeyWithIV(key_b, key_b.size(), iv_b, iv_b.size());    
    AuthenticatedEncryptionFilter ef( block,new StringSink( result_e ), false, TAG_SIZE); 
    
      if(binary==0){	 
        ef.ChannelPut( "AAD", (const byte*)adata.data(), adata.size() );
        ef.ChannelMessageEnd("AAD");
        ef.ChannelPut( "", (const byte*)payload.data(), payload.size() );
        ef.ChannelMessageEnd("");                
      }
      else if(binary==1){
        string payload_e,adata_e;
        StringSource(payload, true, new HexDecoder(new StringSink(payload_e)));
        StringSource(adata, true, new HexDecoder(new StringSink(adata_e)));
        
        ef.ChannelPut( "AAD", (const byte*)adata_e.data(), adata_e.size() );
        ef.ChannelMessageEnd("AAD");
        ef.ChannelPut( "", (const byte*)payload_e.data(), payload_e.size() );
        ef.ChannelMessageEnd(""); 	  
      }
	  else{
	    error+="Bad binary bool ";
	    return 1;
	  }	
	  
	  StringSource( result_e, true,new HexEncoder( new StringSink( result )));
	    	 	    		    
  }
  catch(const CryptoPP::Exception& d){
       error=d.what();
#ifdef DEBUG					 
		cerr << error << endl;
		cerr << "Fail stream " << endl;
#endif					
        return 1;
	}
	return 0;
	
}


template <typename T>
int BLOCK_DEC_GCM(string& payload, string& adata, string& result, string& key, string& iv ,int& binary, string& error){		
  result.clear();
  error.clear();
  SecByteBlock key_b(key.size()/2),iv_b(iv.size()/2);
  string key_e,iv_e;
  StringSource (key, true, new HexDecoder(new StringSink(key_e)));
  memcpy( key_b, key_e.data(),key_b.size()); 
  StringSource (iv, true, new HexDecoder(new StringSink(iv_e)));
  memcpy( iv_b, iv_e.data(),iv_b.size());         
  
  const int TAG_SIZE = 16;
  	
  try{
    T block;
    block.SetKeyWithIV(key_b, key_b.size(), iv_b, iv_b.size());    
       
    string payload_b;
    StringSource(payload, true,new HexDecoder(new StringSink(payload_b)));
       
    string enc = payload_b.substr( 0, payload_b.length()-TAG_SIZE );
    string mac = payload_b.substr( payload_b.length()-TAG_SIZE );
    
    string adata_e;
    if(binary==0)
      adata_e=adata;
    else if(binary==1){     
        StringSource(adata, true, new HexDecoder(new StringSink(adata_e)));
     }
     else
       return 1;

     if(payload_b.size() != (enc.size() + mac.size())){
       error="Bad size enc + mac ";
	   return 1 ; 
	 }

     AuthenticatedDecryptionFilter df( block, NULL,
       AuthenticatedDecryptionFilter::MAC_AT_BEGIN | 
       AuthenticatedDecryptionFilter::THROW_EXCEPTION, TAG_SIZE );
          
     df.ChannelPut( "", (const byte*)mac.data(), mac.size() ); 
     df.ChannelPut( "AAD", (const byte*)adata_e.data(), adata_e.size() );      
     df.ChannelPut( "", (const byte*)enc.data(), enc.size() );              

     df.ChannelMessageEnd( "AAD" );
     df.ChannelMessageEnd( "" );

     bool b = false;
     b = df.GetLastResult();
     if(true != b){
	   error="Bad data intehrity " ;
	   return 1;
	 }
	 
     string retrieved;
     size_t n = (size_t)-1;

     df.SetRetrievalChannel( "" );
     n = (size_t)df.MaxRetrievable();
     retrieved.resize( n );

     if( n > 0 ) { df.Get( (byte*)retrieved.data(), n ); }
     string rpdata = retrieved;
      
     result=rpdata;
        
     if(Isjson(result,error)!=0){
       result.clear();
       error.clear();
       StringSource(rpdata, true,new HexEncoder(new StringSink(result)));	      
     }               	    		   
     	  
  }
  catch(const CryptoPP::Exception& d){
       error=d.what();
#ifdef DEBUG					 
		cerr << error << endl;
		cerr << "Fail Block " << endl;
#endif					
        return 1;
	}
	return 0;
	
}




//PARSE_BLOCK//////////////////////////////////////////////////////////    
int parse_block(Document& d, stru_param& req_val, string& answ_js){	
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
    if(d.HasMember("plaintext") && d.HasMember("key")&&d.HasMember("iv")&&d.HasMember("operation")&&d.HasMember("mode")){  
      if(check_plain(d,req_val,answ_js)!=0)
        return 1;          
      if(check_bin(d,req_val,answ_js)!=0)
        return 1;
      if(check_key(d,req_val,answ_js)!=0)
        return 1; 
      if(check_ops(d,req_val,answ_js)!=0)
        return 1;      
      if(check_iv(d,req_val,answ_js)!=0)
        return 1;   
      if(check_mode_block(d,req_val,answ_js)!=0)
        return 1;              
      
      req_val.payload=req_val.plaintext;  
    }
    else{
	  req_val.error="Not plaintext/key/iv/ops/mode tag ";  
      answ_error(req_val,answ_js); 
      return 1;	   
    }      
  }
  else if (strncmp(req_val.type.c_str(), "file",sizeof("file")) == 0){
    if(d.HasMember("file")&&d.HasMember("key")&&d.HasMember("iv") &&d.HasMember("operation")&&d.HasMember("mode")){  
      if(check_file(d,req_val,answ_js)!=0)
        return 1;
      if(check_bin(d,req_val,answ_js)!=0)
        return 1;
      if(check_key(d,req_val,answ_js)!=0)
        return 1; 
      if(check_ops(d,req_val,answ_js)!=0)
        return 1;      
      if(check_iv(d,req_val,answ_js)!=0)
        return 1;   
      if(check_mode_block(d,req_val,answ_js)!=0)
        return 1;                         
                                        
      req_val.hex=0;
	  req_val.payload=req_val.file;         
    }
    else{
	  req_val.error="Not file/key/iv/ops tag ";  
      answ_error(req_val,answ_js); 
      return 1;	   
    }      
  } 
  else{
    req_val.error="Bad tye ";  
    answ_error(req_val,answ_js); 
    return 1;	   
  }                   
  if(strncmp(req_val.operation.c_str(), "enc",sizeof("enc")) == 0){
    if(strncmp(req_val.mode.c_str(), "ctr",sizeof("ctr")) == 0){
      if(strncmp(req_val.algorithm.c_str(), "AES",sizeof("AES")) == 0){
        BLOCK_ENC_CTR<CTR_Mode< AES >::Encryption>(req_val.payload, req_val.type, req_val.result, req_val.key , req_val.iv, req_val.hex, req_val.error); 	 	
	  }	  
      else if(strncmp(req_val.algorithm.c_str(), "RC6",sizeof("RC6")) == 0){
        BLOCK_ENC_CTR<CTR_Mode< RC6 >::Encryption>(req_val.payload, req_val.type, req_val.result, req_val.key , req_val.iv, req_val.hex, req_val.error); 	 	
	  } 
      else if(strncmp(req_val.algorithm.c_str(), "MARS",sizeof("MARS")) == 0){
        BLOCK_ENC_CTR<CTR_Mode< MARS >::Encryption>(req_val.payload, req_val.type, req_val.result, req_val.key , req_val.iv, req_val.hex, req_val.error); 	 	
	  }
      else if(strncmp(req_val.algorithm.c_str(), "SERPENT",sizeof("SERPENT")) == 0){
        BLOCK_ENC_CTR<CTR_Mode< Serpent >::Encryption>(req_val.payload, req_val.type, req_val.result, req_val.key , req_val.iv, req_val.hex, req_val.error); 	 	
	  } 
      else if(strncmp(req_val.algorithm.c_str(), "TWOFISH",sizeof("TWOFISH")) == 0){
        BLOCK_ENC_CTR<CTR_Mode< Twofish >::Encryption>(req_val.payload, req_val.type, req_val.result, req_val.key , req_val.iv, req_val.hex, req_val.error); 	 	
	  } 	 	
      else if(strncmp(req_val.algorithm.c_str(), "CAST256",sizeof("CAST256")) == 0){
        BLOCK_ENC_CTR<CTR_Mode< CAST256 >::Encryption>(req_val.payload, req_val.type, req_val.result, req_val.key , req_val.iv, req_val.hex, req_val.error); 	 	
	  }
      else if(strncmp(req_val.algorithm.c_str(), "CAMELLIA",sizeof("CAMELLIA")) == 0){
        BLOCK_ENC_CTR<CTR_Mode< Camellia >::Encryption>(req_val.payload, req_val.type, req_val.result, req_val.key , req_val.iv, req_val.hex, req_val.error); 	 	
	  }		  	
      else{
        req_val.error="Bad Block algorithm ";  
        answ_error(req_val,answ_js); 
        return 1;	   
      }
    }       
    else if(strncmp(req_val.mode.c_str(), "gcm",sizeof("gcm")) == 0){ 
      if(check_adata(d,req_val,answ_js)!=0){
        return 1; 
	  }
	  			   
      if(strncmp(req_val.algorithm.c_str(), "AES",sizeof("AES")) == 0){
        BLOCK_ENC_GCM<GCM< AES >::Encryption>(req_val.payload, req_val.adata,  req_val.result, req_val.key , req_val.iv, req_val.hex, req_val.error); 	 	
	  }	  
      else if(strncmp(req_val.algorithm.c_str(), "RC6",sizeof("RC6")) == 0){
        BLOCK_ENC_GCM<GCM< RC6 >::Encryption>(req_val.payload, req_val.adata,  req_val.result, req_val.key , req_val.iv, req_val.hex, req_val.error); 	 	
	  } 
      else if(strncmp(req_val.algorithm.c_str(), "MARS",sizeof("MARS")) == 0){
        BLOCK_ENC_GCM<GCM< MARS >::Encryption>(req_val.payload, req_val.adata,  req_val.result, req_val.key , req_val.iv, req_val.hex, req_val.error); 	 	
	  }
      else if(strncmp(req_val.algorithm.c_str(), "SERPENT",sizeof("SERPENT")) == 0){
        BLOCK_ENC_GCM<GCM< Serpent >::Encryption>(req_val.payload, req_val.adata,  req_val.result, req_val.key , req_val.iv, req_val.hex, req_val.error); 	 	
	  } 
      else if(strncmp(req_val.algorithm.c_str(), "TWOFISH",sizeof("TWOFISH")) == 0){
        BLOCK_ENC_GCM<GCM< Twofish >::Encryption>(req_val.payload, req_val.adata,  req_val.result, req_val.key , req_val.iv, req_val.hex, req_val.error); 	 	
	  } 	 	
      else if(strncmp(req_val.algorithm.c_str(), "CAST256",sizeof("CAST256")) == 0){
        BLOCK_ENC_GCM<GCM< CAST256 >::Encryption>(req_val.payload, req_val.adata,  req_val.result, req_val.key , req_val.iv, req_val.hex, req_val.error); 	 	
	  }
      else if(strncmp(req_val.algorithm.c_str(), "CAMELLIA",sizeof("CAMELLIA")) == 0){
        BLOCK_ENC_GCM<GCM< Camellia >::Encryption>(req_val.payload, req_val.adata,  req_val.result, req_val.key , req_val.iv, req_val.hex, req_val.error); 	 	
	  }		  	
      else{
        req_val.error="Bad Block algorithm ";  
        answ_error(req_val,answ_js); 
        return 1;	   
      }
    }          	 		
  }
  
  else if (strncmp(req_val.operation.c_str(), "dec",sizeof("dec")) == 0){ 
    if(strncmp(req_val.mode.c_str(), "ctr",sizeof("ctr")) == 0){
      if(strncmp(req_val.algorithm.c_str(), "AES",sizeof("AES")) == 0){
        BLOCK_DEC_CTR<CTR_Mode< AES >::Decryption>(req_val.payload, req_val.type, req_val.result, req_val.key , req_val.iv, req_val.hex, req_val.error); 	 	
	  }	  
      else if(strncmp(req_val.algorithm.c_str(), "RC6",sizeof("RC6")) == 0){
        BLOCK_DEC_CTR<CTR_Mode< RC6 >::Decryption>(req_val.payload, req_val.type, req_val.result, req_val.key , req_val.iv, req_val.hex, req_val.error); 	 	
	  } 
      else if(strncmp(req_val.algorithm.c_str(), "MARS",sizeof("MARS")) == 0){
        BLOCK_DEC_CTR<CTR_Mode< MARS >::Decryption>(req_val.payload, req_val.type, req_val.result, req_val.key , req_val.iv, req_val.hex, req_val.error); 	 	
	  }
      else if(strncmp(req_val.algorithm.c_str(), "SERPENT",sizeof("SERPENT")) == 0){
        BLOCK_DEC_CTR<CTR_Mode< Serpent >::Decryption>(req_val.payload, req_val.type, req_val.result, req_val.key , req_val.iv, req_val.hex, req_val.error); 	 	
	  } 
      else if(strncmp(req_val.algorithm.c_str(), "TWOFISH",sizeof("TWOFISH")) == 0){
        BLOCK_DEC_CTR<CTR_Mode< Twofish >::Decryption>(req_val.payload, req_val.type, req_val.result, req_val.key , req_val.iv, req_val.hex, req_val.error); 	 	
	  } 	 	
      else if(strncmp(req_val.algorithm.c_str(), "CAST256",sizeof("CAST256")) == 0){
        BLOCK_DEC_CTR<CTR_Mode< CAST256 >::Decryption>(req_val.payload, req_val.type, req_val.result, req_val.key , req_val.iv, req_val.hex, req_val.error); 	 	
	  }	
      else if(strncmp(req_val.algorithm.c_str(), "CAMELLIA",sizeof("CAMELLIA")) == 0){
        BLOCK_DEC_CTR<CTR_Mode< Camellia >::Decryption>(req_val.payload, req_val.type, req_val.result, req_val.key , req_val.iv, req_val.hex, req_val.error); 	 	
	  }		  
      else{
        req_val.error="Bad Block algorithm ";  
        answ_error(req_val,answ_js); 
        return 1;	   
      }
    }       
    else if(strncmp(req_val.mode.c_str(), "gcm",sizeof("gcm")) == 0){ 
      if(check_adata(d,req_val,answ_js)!=0){
        return 1; 
	  }

      if(strncmp(req_val.algorithm.c_str(), "AES",sizeof("AES")) == 0){
        BLOCK_DEC_GCM<GCM< AES >::Decryption>(req_val.payload, req_val.adata,  req_val.result, req_val.key , req_val.iv, req_val.hex, req_val.error); 	 	
	  }	  
      else if(strncmp(req_val.algorithm.c_str(), "RC6",sizeof("RC6")) == 0){
        BLOCK_DEC_GCM<GCM< RC6 >::Decryption>(req_val.payload, req_val.adata,  req_val.result, req_val.key , req_val.iv, req_val.hex, req_val.error); 	 	
	  } 
      else if(strncmp(req_val.algorithm.c_str(), "MARS",sizeof("MARS")) == 0){
        BLOCK_DEC_GCM<GCM< MARS >::Decryption>(req_val.payload, req_val.adata,  req_val.result, req_val.key , req_val.iv, req_val.hex, req_val.error); 	 	
	  }
      else if(strncmp(req_val.algorithm.c_str(), "SERPENT",sizeof("SERPENT")) == 0){
        BLOCK_DEC_GCM<GCM< Serpent >::Decryption>(req_val.payload, req_val.adata,  req_val.result, req_val.key , req_val.iv, req_val.hex, req_val.error); 	 	
	  } 
      else if(strncmp(req_val.algorithm.c_str(), "TWOFISH",sizeof("TWOFISH")) == 0){
        BLOCK_DEC_GCM<GCM< Twofish >::Decryption>(req_val.payload, req_val.adata,  req_val.result, req_val.key , req_val.iv, req_val.hex, req_val.error); 	 	
	  } 	 	
      else if(strncmp(req_val.algorithm.c_str(), "CAST256",sizeof("CAST256")) == 0){
        BLOCK_DEC_GCM<GCM< CAST256 >::Decryption>(req_val.payload, req_val.adata,  req_val.result, req_val.key , req_val.iv, req_val.hex, req_val.error); 	 	
	  }	
      else if(strncmp(req_val.algorithm.c_str(), "CAMELLIA",sizeof("CAMELLIA")) == 0){
        BLOCK_DEC_GCM<GCM< Camellia >::Decryption>(req_val.payload, req_val.adata,  req_val.result, req_val.key , req_val.iv, req_val.hex, req_val.error); 	 	
	  }	  
      else{
        req_val.error="Bad Block algorithm ";  
        answ_error(req_val,answ_js); 
        return 1;	   
      }
    }          	 		 
  }   
  
  cipher_anws(req_val,answ_js);

  return 0;                	      		  	 	 
}

