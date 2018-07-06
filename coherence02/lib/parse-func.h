#include "rapidjson/document.h"
#include "rapidjson/writer.h"
#include "rapidjson/stringbuffer.h"
#include "rapidjson/error/en.h"
#include <iostream>
#include <fstream>

//#include "params.h"


#include <stdio.h>

using namespace rapidjson;
using namespace  std;

//Isb16/////////////////////////////////////////////////////////////////
int Isb16(string &str,string& error_str){	
	int i,k,i2,k2;
	k=0, k2=0;
	for(i=0;i<str.size();i++){
		if (strchr("0123456789ABCDEF",str[i])|| strchr("0123456789abcdef",str[i]))
		  k++;
		else{						
		  error_str.clear();    
	      error_str="Bad String hex, character is ";
	      error_str+=str[i]; 		  		      	
#ifdef DEBUG			
			cerr << error_str;
#endif			
			return 1;		
		}
	}
	if(str.size()!=k){
	  error_str.clear();    
	  error_str="Bad String hex size ";	
#ifdef DEBUG		
	  cerr << error_str;
#endif
        return 1;
	}

#ifdef DEBUG			
  cout<<"God hex string ";
#endif	
	
	return 0;
}

//Isalphnum/////////////////////////////////////////////////////////////
int Isalphnum(string &str,string& error_str)
{	
	int i,k;
	k=0;
	for(i=0;i<str.size();i++){
		if (isalnum(str[i]))
		  k++;
		else{
	      error_str.clear();    
	      error_str="Bad String alphanum, character is  ";
	      error_str+=str[i]; 		  	
#ifdef DEBUG						
		  cerr << error_str;
#endif			
			return 1;		
		}
	}
	if(str.size()!=k){
	error_str.clear();    
	error_str="Bad Size alphanum "; 		
#ifdef DEBUG					
	cerr << error_str;
#endif		
        return 1;
	}
	
	return 0;
}


//Isjson////////////////////////////////////////////////////////////////
int Isjson(string &str,string& error_str){		
	int i,k;
	k=0;
	for(i=0;i<str.size();i++){
//      if (strchr("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ01234567890{}\"/:,_.-",str[i]) ||str[i]==' ')
	  if(strchr(" !\"#$%&\'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~",str[i]) ||str[i]==' ')
		k++;
	  else{
	    error_str.clear();    
	    error_str="Bad Character Json, character is ";
	    error_str+=str[i]; 		  	
#ifdef DEBUG						
		cerr << error_str;
#endif			
		return 1;		
		}
	}
	
	if(str.size()!=k){
	error_str.clear();    
	error_str="Bad Size Json "; 		
#ifdef DEBUG					
	cerr << error_str;
#endif		
        return 1;
	}
	
	return 0;
}

//addstr2json///////////////////////////////////////////////////////////
int Addstr2json(string& json, string& tag, string& value){
  Document d;
  ParseResult ok = d.Parse<rapidjson::kParseStopWhenDoneFlag>(json.c_str());  
  Document::AllocatorType& alloc = d.GetAllocator();
  //d.SetObject();
  Value tagjs, valjs;
  tagjs.SetString(tag.c_str(), alloc);
  valjs.SetString(value.c_str(), alloc);
  d.AddMember(tagjs, valjs, alloc);
  StringBuffer buffer;
  Writer<StringBuffer> writer(buffer);
  d.Accept(writer);
  json.clear();            
  json=buffer.GetString();
#ifdef DEBUG		      
  //cout<<json<<endl;
#endif
  return 0; 
}	

//cleardata/////////////////////////////////////////////////////////////
int Clear2json(string& json){
  Document d;
  ParseResult ok = d.Parse<rapidjson::kParseStopWhenDoneFlag>(json.c_str());  
  if (!ok) {	            
    return 1;
  }  
  if(d.HasMember("key")){
    d["key"]="";
  }
  if(d.HasMember("iv")){
    d["iv"]="";
  }
  if(d.HasMember("payload")){
    d["payload"]="";
  } 
  if(d.HasMember("plaintext")){
    d["plaintext"]="";
  } 
  if(d.HasMember("adata")){
    d["adata"]="";
  }
  if(d.HasMember("hash")){
    d["hash"]="";
  }
  if(d.HasMember("rands")){
    d["rands"]="";
  }
  if(d.HasMember("mac")){
    d["mac"]="";
  } 
  if(d.HasMember("nonce")){
    d["nonce"]="";
  } 
  if(d.HasMember("sign")){
    d["sign"]="";
  }    
  if(d.HasMember("result")){
    d["result"]="";
  }
  if(d.HasMember("salt")){
    d["salt"]="";
  }
  if(d.HasMember("pwd")){
    d["pwd"]="";
  } 
  if(d.HasMember("pubkey")){
    d["pubkey"]="";
  } 
  if(d.HasMember("privkey")){
    d["privkey"]="";
  }
  if(d.HasMember("sharedkey")){
    d["sharedkey"]="";
  }
  if(d.HasMember("sharedpub")){
    d["sharedpub"]="";
  }
  if(d.HasMember("p")){
    d["p"]="";
  } 
  if(d.HasMember("q")){
    d["q"]="";
  } 
  if(d.HasMember("g")){
    d["g"]="";
  } 
  StringBuffer buffer;
  Writer<StringBuffer> writer(buffer);
  d.Accept(writer);
  json.clear();            
  json=buffer.GetString();  
     
#ifdef DEBUG		      
  //cout<<json<<endl;
#endif
  return 0; 
}



//Parsingjson///////////////////////////////////////////////////////////  
int Parsingjson(Document& d,string& str_json, stru_param& req_val, string& answ_js){	
  if(Isjson(str_json, req_val.error)!=0){
    req_val.tag="error";  
	Addstr2json(answ_js, req_val.tag, req_val.error); 
#ifdef DEBUG	  
    cerr<< req_val.error;
#endif		            
    return 1;
  }
  else{        
    ParseResult ok = d.Parse<rapidjson::kParseStopWhenDoneFlag>(str_json.c_str());
    if (!ok) {
	  req_val.error.clear();    
      req_val.error="JSON parse error: ";
      req_val.tag="error";  
	  Addstr2json(answ_js, req_val.tag, req_val.error); 
#ifdef DEBUG	  
      cerr<< req_val.error;
#endif		            
      return 1;
    }  
  }
  return 0;
}

//Version///////////////////////////////////////////////////////////////
int check_ver(Document& d, stru_param& req_val, string& answ_js){    
  if(d.HasMember("version") && d["version"].IsNumber() && d["version"].GetInt()==1){ 
#ifdef DEBUG	  
    cout<< "Good  Version and Number ";
#endif		    
  }
  else{
	req_val.error.clear();    
	req_val.error="Problem with version, NO version tag or bad version number ";
	req_val.tag="error";  
	Addstr2json(answ_js, req_val.tag, req_val.error); 
#ifdef DEBUG
    cerr<<req_val.error;
#endif		    
    return 1;
  }
  return 0;      
}

//Plaintext///////////////////////////////////////////////////////////////
int check_plain(Document& d, stru_param& req_val, string& answ_js){ 
  if(d.HasMember("plaintext") && d["plaintext"].IsString()){
	req_val.plaintext=d["plaintext"].GetString();
	if(Isjson(req_val.plaintext,req_val.error)!=0){
	  req_val.error+=" plaintext no ascii ";
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

//File///////////////////////////////////////////////////////////////
int check_file(Document& d, stru_param& req_val, string& answ_js){ 
  if(d.HasMember("file") && d["file"].IsString()){
	req_val.file=d["file"].GetString();  	  
    ifstream f(req_val.file.c_str());
    if(f.good()==false){
     req_val.error.clear();  
     req_val.error="Problem to access the file";
     req_val.tag="error";  
     Addstr2json(answ_js, req_val.tag, req_val.error); 	  
#ifdef DEBUG	    
     cerr << req_val.error;
#endif
        return 1;	
  }           
#ifdef DEBUG      
    cout<< "Good  file: " << req_val.file ;
#endif		    
    return 0;
  }
  return 1;  
}	

//Key/////////////////////////////////////////////////////////////////
int check_key(Document& d, stru_param& req_val, string& answ_js){       
  if(d.HasMember("key") && d["key"].IsString()){
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
	if(req_val.key.size() <0 && req_val.key.size() >64){
	  req_val.error+=" Key size bad 16/24/32 bytes  ";
	  req_val.tag="error";  
	  Addstr2json(answ_js, req_val.tag, req_val.error); 	  
#ifdef DEBUG	    
      cerr << req_val.error;
      cerr << "key size: " << req_val.key.size();
#endif
      return 1;		  
	}	 		  
  }
  return 0;
}

//Iv/////////////////////////////////////////////////////////////////
int check_iv(Document& d, stru_param& req_val, string& answ_js){       
  if(d.HasMember("iv") && d["iv"].IsString()){
	req_val.iv=d["iv"].GetString();
	if(Isb16(req_val.iv,req_val.error)!=0){
	  req_val.error+=" Iv no hex ";
	  req_val.tag="error";  
	  Addstr2json(answ_js, req_val.tag, req_val.error); 	  
#ifdef DEBUG	    
      cerr << req_val.error;
#endif
      return 1;		  
	}
	//if(req_val.iv.size()!=32 ){
	  if(req_val.iv.size() <0 && req_val.iv.size() >32){
	  req_val.error+=" Iv size bad 16 bytes  ";
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

//Hex///////////////////////////////////////////////////////////////
int check_hex(Document& d, stru_param& req_val, string& answ_js){    
  if(d.HasMember("hex")){
	if(d["hex"].IsNumber()&&(d["hex"].GetInt()==1||d["hex"].GetInt()==0)){  
      req_val.hex=d["hex"].GetInt();
#ifdef DEBUG	  
      cout<< "Hex bool ok ";
#endif	  
    }
    else{
	  req_val.error.clear();    
	  req_val.error="Problem with hex, bad hex bool ";
	  req_val.tag="error";  
	  Addstr2json(answ_js, req_val.tag, req_val.error); 
#ifdef DEBUG
      cerr<<req_val.error;
#endif		    
    return 1;
    }
  }      	       
  else 
    req_val.hex=0;	
      
  return 0;      
}

//Bin///////////////////////////////////////////////////////////////////
int check_bin(Document& d, stru_param& req_val, string& answ_js){
  if(d.HasMember("hex")){
    if(check_hex(d,req_val,answ_js)!=0 )
      return 1;
    if(req_val.hex==1)  
      if(Isb16(req_val.plaintext,req_val.error)!=0 ){
	    req_val.tag="error";  
	    Addstr2json(answ_js, req_val.tag, req_val.error); 
        return 1 ;
      }       
  }
  else
    req_val.hex=0;  
  
  return 0;
}

//Error answ////////////////////////////////////////////////////////////
int answ_error(stru_param& req_val, string& answ_js){
  req_val.error+="Not enought parameters to ";
  req_val.error+=req_val.algorithm;
  req_val.tag="error";  
  Addstr2json(answ_js, req_val.tag, req_val.error); 	  
#ifdef DEBUG	    
    cerr << req_val.error;
#endif   

  return 0;
}

//check_ops/////////////////////////////////////////////////////////////
int check_ops(Document& d, stru_param& req_val, string& answ_js){           
  if(d.HasMember("operation") && d["operation"].IsString()){
    req_val.operation= d["operation"].GetString();
    if(strncmp(req_val.operation.c_str(), "enc",sizeof("enc")) !=0 && strncmp(req_val.operation.c_str(), "dec",sizeof("dec"))!=0
      &&strncmp(req_val.operation.c_str(), "sign",sizeof("sign")) !=0 && strncmp(req_val.operation.c_str(), "verify",sizeof("verify"))!=0
      &&strncmp(req_val.operation.c_str(), "gen",sizeof("gen")) !=0 && strncmp(req_val.operation.c_str(), "agree",sizeof("agree")) !=0
      &&strncmp(req_val.operation.c_str(), "hash",sizeof("hash")) !=0 &&strncmp(req_val.operation.c_str(), "gen_pub",sizeof("gen_pub")) !=0){
    req_val.error.clear();    
	req_val.error="Bad operation enc/dec/sign/very ";
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

//Type//////////////////////////////////////////////////////////////////
int check_type(Document& d, stru_param& req_val, string& answ_js){        
  if(d.HasMember("type") && d["type"].IsString()){
    req_val.type= d["type"].GetString();
    if(strncmp(req_val.type.c_str(), "string",sizeof("string")) !=0 && strncmp(req_val.type.c_str(), "file",sizeof("file"))!=0){
    req_val.error.clear();    
	req_val.error="Bad Type ";
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

//Family////////////////////////////////////////////////////////////////
int check_fam(Document& d, stru_param& req_val, string& answ_js){    
  if(d.HasMember("family") && d["family"].IsString()){
    req_val.family= d["family"].GetString();
    if(Isjson(req_val.family, req_val.error)!=0){
    req_val.error.clear();    
	req_val.error="Bad Family Name ";
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
int check_keys(Document& d, stru_param& req_val, string& answ_js){
  if(d.HasMember("privkey") && d["privkey"].IsString()){
	req_val.privkey=d["privkey"].GetString();
	if(Isb16(req_val.privkey,req_val.error)!=0){
	  req_val.error+=" Key no hex  ";
	  req_val.tag="error";  
	  Addstr2json(answ_js, req_val.tag, req_val.error); 	  
#ifdef DEBUG	    
      cerr << req_val.error;
#endif
       return 1;
	}
  }	
  if(d.HasMember("pubkey") && d["pubkey"].IsString()){
	req_val.pubkey=d["pubkey"].GetString();
	if(Isb16(req_val.pubkey,req_val.error)!=0){
	  req_val.error+=" Key no hex  ";
	  req_val.tag="error";  
	  Addstr2json(answ_js, req_val.tag, req_val.error); 	  
#ifdef DEBUG	    
      cerr << req_val.error;
#endif
      return 1;		  
	}
  }
/*  	
  else{
	  req_val.error+="No Key";
	  req_val.tag="error";  
	  Addstr2json(answ_js, req_val.tag, req_val.error); 	  
#ifdef DEBUG	    
      cerr << req_val.error;
#endif
      return 1;		  
  }
*/ 
#ifdef DEBUG	    
      cout << "Good keys ";
#endif 
  return 0;
}

////////////////////////////////////////////////////////////////////////
int check_signs(Document& d, stru_param& req_val, string& answ_js){
  if(d.HasMember("sign") && d["sign"].IsString()){
	req_val.sign=d["sign"].GetString();
	if(Isb16(req_val.sign,req_val.error)!=0){
	  req_val.error+=" sign no hex  ";
	  req_val.tag="error";  
	  Addstr2json(answ_js, req_val.tag, req_val.error); 	  
#ifdef DEBUG	    
      cerr << req_val.error;
#endif
      return 1;
	}
  }	
  else{
	  req_val.error+="Bad sign";
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
int check_a_keys(Document& d, stru_param& req_val, string& answ_js){
  if(d.HasMember("privkey") && d["privkey"].IsString() ){
	req_val.privkey=d["privkey"].GetString();	
	if(Isb16(req_val.privkey,req_val.error)!=0){
	  req_val.error+=" Type string, but privkey no hex ";
	  req_val.tag="error";  
	  Addstr2json(answ_js, req_val.tag, req_val.error); 	  
#ifdef DEBUG	    
      cerr << req_val.error;
#endif
      return 1;		  
	}
  }	
  if(d.HasMember("sharedpub") && d["sharedpub"].IsString() ){
	req_val.sharedpub=d["sharedpub"].GetString();	
	if(Isb16(req_val.sharedpub,req_val.error)!=0){
	  req_val.error+=" Type string, but sharedpub no hex ";
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

int check_length(Document& d, stru_param& req_val, string& answ_js, int length){   
  if(d.HasMember("length")){	    
    if(d["length"].IsNumber() && d["length"].GetInt()<=length){
	  req_val.length=d["length"].GetInt();   
#ifdef DEBUG	  
      cout<< "Good length ";
#endif		
	}
    else{
      req_val.error.clear();    
	  req_val.error="Bad int/len ";
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
int cipher_anws(stru_param& req_val, string& answ_js){

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

////////////////////////////////////////////////////////////////////////
int sign_anws(stru_param& req_val, string& answ_js){

  req_val.tag.clear();
  req_val.tag="algorithm";  
  Addstr2json(answ_js, req_val.tag, req_val.algorithm); 
  req_val.tag.clear();
  req_val.tag="sign";  
  Addstr2json(answ_js, req_val.tag, req_val.sign); 
  req_val.tag.clear();	 
  req_val.tag="error";  
  Addstr2json(answ_js, req_val.tag, req_val.error); 

  return 0;
}

////////////////////////////////////////////////////////////////////////
int verify_anws(stru_param& req_val, string& answ_js){

  req_val.tag.clear();
  req_val.tag="algorithm";  
  Addstr2json(answ_js, req_val.tag, req_val.algorithm); 
  req_val.tag.clear();
  req_val.tag="verify";  
  Addstr2json(answ_js, req_val.tag, req_val.verify); 
  req_val.tag.clear();	 
  req_val.tag="error";  
  Addstr2json(answ_js, req_val.tag, req_val.error); 

  return 0;
}

////////////////////////////////////////////////////////////////////////
int keys_anws(stru_param& req_val, string& answ_js){

  req_val.tag.clear();
  req_val.tag="algorithm";  
  Addstr2json(answ_js, req_val.tag, req_val.algorithm); 
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
////////////////////////////////////////////////////////////////////////
int check_hash_sign(Document& d, stru_param& req_val, string& answ_js){    
  if(d.HasMember("hash_sign") && d["hash_sign"].IsString() ){
	req_val.hash_sign=d["hash_sign"].GetString();
	if(Isjson(req_val.hash_sign,req_val.error)!=0){
	  req_val.error+=" hash_sign no ascii ";
	  req_val.tag="error";  
	  Addstr2json(answ_js, req_val.tag, req_val.error); 	  
#ifdef DEBUG	    
      cerr << req_val.error;
#endif
      return 1;		  
	} 	
  }
  else
    req_val.hash_sign="sha3_256";
      
  return 0;      
}
