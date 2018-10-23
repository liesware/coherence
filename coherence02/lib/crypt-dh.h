#include "rapidjson/document.h"
#include "rapidjson/writer.h"
#include "rapidjson/stringbuffer.h"
#include "rapidjson/error/en.h"
#include <iostream>
#include <fstream>
#include <sstream>


#include "cryptopp/osrng.h"
#include "cryptopp/integer.h"
#include "cryptopp/nbtheory.h"
#include "cryptopp/dh.h"
#include "cryptopp/secblock.h"

#include "cryptopp/filters.h"
#include "cryptopp/hex.h"
#include "cryptopp/files.h"
#include "cryptopp/cryptlib.h"
#include <iostream>

using namespace CryptoPP;
using namespace  std;

////////////////////////////////////////////////////////////////////////
Integer modp160_p("0xB10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C6"
"9A6A9DCA52D23B616073E28675A23D189838EF1E2EE652C0"
"13ECB4AEA906112324975C3CD49B83BFACCBDD7D90C4BD70"
"98488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0"
"A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708"
"DF1FB2BC2E4A4371");
Integer modp160_g("0xA4D1CBD5C3FD34126765A442EFB99905F8104DD258AC507F"
"D6406CFF14266D31266FEA1E5C41564B777E690F5504F213"
"160217B4B01B886A5E91547F9E2749F4D7FBD7D3B9A92EE1"
"909D0D2263F80A76A6A24C087A091F531DBF0A0169B6A28A"
"D662A4D18E73AFA32D779D5918D08BC8858F4DCEF97C2A24"
"855E6EEB22B3B2E5");
Integer modp160_q("0xF518AA8781A8DF278ABA4E7D64B7CB9D49462353");

////////////////////////////////////////////////////////////////////////
Integer modp224_p("0xAD107E1E9123A9D0D660FAA79559C51FA20D64E5683B9FD1"
"B54B1597B61D0A75E6FA141DF95A56DBAF9A3C407BA1DF15"
"EB3D688A309C180E1DE6B85A1274A0A66D3F8152AD6AC212"
"9037C9EDEFDA4DF8D91E8FEF55B7394B7AD5B7D0B6C12207"
"C9F98D11ED34DBF6C6BA0B2C8BBC27BE6A00E0A0B9C49708"
"B3BF8A317091883681286130BC8985DB1602E714415D9330"
"278273C7DE31EFDC7310F7121FD5A07415987D9ADC0A486D"
"CDF93ACC44328387315D75E198C641A480CD86A1B9E587E8"
"BE60E69CC928B2B9C52172E413042E9B23F10B0E16E79763"
"C9B53DCF4BA80A29E3FB73C16B8E75B97EF363E2FFA31F71"
"CF9DE5384E71B81C0AC4DFFE0C10E64F");
Integer modp224_g("0xAC4032EF4F2D9AE39DF30B5C8FFDAC506CDEBE7B89998CAF"
"74866A08CFE4FFE3A6824A4E10B9A6F0DD921F01A70C4AFA"
"AB739D7700C29F52C57DB17C620A8652BE5E9001A8D66AD7"
"C17669101999024AF4D027275AC1348BB8A762D0521BC98A"
"E247150422EA1ED409939D54DA7460CDB5F6C6B250717CBE"
"F180EB34118E98D119529A45D6F834566E3025E316A330EF"
"BB77A86F0C1AB15B051AE3D428C8F8ACB70A8137150B8EEB"
"10E183EDD19963DDD9E263E4770589EF6AA21E7F5F2FF381"
"B539CCE3409D13CD566AFBB48D6C019181E1BCFE94B30269"
"EDFE72FE9B6AA4BD7B5A0F1C71CFFF4C19C418E1F6EC0179"
"81BC087F2A7065B384B890D3191F2BFA");
Integer modp224_q("0x801C0D34C58D93FE997177101F80535A4738CEBCBF389A99"
"B36371EB");

////////////////////////////////////////////////////////////////////////
Integer modp256_p("0x87A8E61DB4B6663CFFBBD19C651959998CEEF608660DD0F2"
"5D2CEED4435E3B00E00DF8F1D61957D4FAF7DF4561B2AA30"
"16C3D91134096FAA3BF4296D830E9A7C209E0C6497517ABD"
"5A8A9D306BCF67ED91F9E6725B4758C022E0B1EF4275BF7B"
"6C5BFC11D45F9088B941F54EB1E59BB8BC39A0BF12307F5C"
"4FDB70C581B23F76B63ACAE1CAA6B7902D52526735488A0E"
"F13C6D9A51BFA4AB3AD8347796524D8EF6A167B5A41825D9"
"67E144E5140564251CCACB83E6B486F6B3CA3F7971506026"
"C0B857F689962856DED4010ABD0BE621C3A3960A54E710C3"
"75F26375D7014103A4B54330C198AF126116D2276E11715F"
"693877FAD7EF09CADB094AE91E1A1597");
Integer modp256_g("0x3FB32C9B73134D0B2E77506660EDBD484CA7B18F21EF2054"
"07F4793A1A0BA12510DBC15077BE463FFF4FED4AAC0BB555"
"BE3A6C1B0C6B47B1BC3773BF7E8C6F62901228F8C28CBB18"
"A55AE31341000A650196F931C77A57F2DDF463E5E9EC144B"
"777DE62AAAB8A8628AC376D282D6ED3864E67982428EBC83"
"1D14348F6F2F9193B5045AF2767164E1DFC967C1FB3F2E55"
"A4BD1BFFE83B9C80D052B985D182EA0ADB2A3B7313D3FE14"
"C8484B1E052588B9B7D2BBD2DF016199ECD06E1557CD0915"
"B3353BBB64E0EC377FD028370DF92B52C7891428CDC67EB6"
"184B523D1DB246C32F63078490F00EF8D647D148D4795451"
"5E2327CFEF98C582664B4C0F6CC41659");
Integer modp256_q("0x8CF83642A709A097B447997640129DA299B1A47D1EB3750B"
"A308B0FE64F5FBD3");


////////////////////////////////////////////////////////////////////////
int check_ops_dh(Document& d, stru_param& req_val, string& answ_js){
  if(d.HasMember("operation") && d["operation"].IsString()){
    req_val.operation= d["operation"].GetString();
    if(strncmp(req_val.operation.c_str(), "gen_rfc",sizeof("gen_rfc")) !=0 && strncmp(req_val.operation.c_str(), "gen_n_rfc",sizeof("gen_n_rfc"))!=0
    &&strncmp(req_val.operation.c_str(), "a_rfc",sizeof("a_rfc")) !=0 && strncmp(req_val.operation.c_str(), "a_n_rfc",sizeof("a_n_rfc"))!=0
    &&strncmp(req_val.operation.c_str(), "a_n_rfc_gen",sizeof("a_n_rfc_gen")) !=0){
      req_val.error.clear();
      req_val.error="Bad operation dh ";
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



int check_dh_params(string &str,string& error_str){
  if (str.compare(0,2,"0x") != 0){
    error_str=" Type string, but no int hex 0x ";
    #ifdef DEBUG
    cerr << error_str;
    #endif
    return 1;
  }

  if (str.compare(str.size()-1,1,"h") != 0){
    error_str=" Type string, but no int hex h ";
    #ifdef DEBUG
    cerr << error_str;
    #endif
    return 1;
  }

  string hex=str;
  hex.erase(0,2);
  hex.erase(hex.size()-1,1);

  if(Isb16(hex,error_str)!=0){
    error_str=" Type string, but  no int hex ";
    #ifdef DEBUG
    cerr << error_str;
    #endif
    return 1;
  }
  return 0;
}


int check_dh_shares(Document& d, stru_param& req_val, string& answ_js){
  if(d["p"].IsString() ){
    req_val.p=d["p"].GetString();
    if(check_dh_params(req_val.p,req_val.error)!=0){
      req_val.error+=" Bad p parameter format ";
      req_val.tag="error";
      Addstr2json(answ_js, req_val.tag, req_val.error);
      #ifdef DEBUG
      cerr << req_val.error;
      #endif
      return 1;
    }
  }

  if(d["q"].IsString() ){
    req_val.q=d["q"].GetString();
    if(check_dh_params(req_val.q,req_val.error)!=0){
      req_val.error+=" Bad q parameter format ";
      req_val.tag="error";
      Addstr2json(answ_js, req_val.tag, req_val.error);
      #ifdef DEBUG
      cerr << req_val.error;
      #endif
      return 1;
    }
  }

  if(d["g"].IsString() ){
    req_val.g=d["g"].GetString();
    if(check_dh_params(req_val.g,req_val.error)!=0){
      req_val.error+=" Bad q parameter format ";
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

int DH_GEN_RFC(string& family,string& privkey, string& pubkey ,string& error){
  error.clear();
  privkey.clear();
  pubkey.clear();
  AutoSeededRandomPool rnd;
  try{
    Integer p;
    Integer g;
    Integer q;

    if(strncmp(family.c_str(), "modp256",sizeof("modp256")) == 0){
      p=modp256_p;
      g=modp256_g;
      q=modp256_q;
    }
    else if(strncmp(family.c_str(), "modp224",sizeof("modp224")) == 0){
      p=modp224_p;
      g=modp224_g;
      q=modp224_q;
    }
    else if(strncmp(family.c_str(), "modp160",sizeof("modp160")) == 0){
      p=modp160_p;
      g=modp160_g;
      q=modp160_q;
    }
    else{
      error="Bad family";
      return 1;
    }


    DH dh;
    dh.AccessGroupParameters().Initialize(p, q, g);
    if(!dh.GetGroupParameters().ValidateGroup(rnd, 3)){
      error="Failed to validate prime and generator";
      return 1;
    }

    p = dh.GetGroupParameters().GetModulus();
    q = dh.GetGroupParameters().GetSubgroupOrder();
    g = dh.GetGroupParameters().GetGenerator();
    Integer v = ModularExponentiation(g, q, p);
    if(v != Integer::One()){
      error="Failed to verify order of the subgroup";
      return 1;
    }

    SecByteBlock priv_key(dh.PrivateKeyLength());
    SecByteBlock pub_key(dh.PublicKeyLength());
    dh.GenerateKeyPair(rnd, priv_key, pub_key);

    string key;
    HexEncoder hex(new StringSink(key));
    key = "";
    hex.Put(priv_key.BytePtr(), priv_key.SizeInBytes());
    hex.MessageEnd();
    //cout << "Private key: " << key << endl;
    privkey=key;

    key = "";
    hex.Put(pub_key.BytePtr(), pub_key.SizeInBytes());
    hex.MessageEnd();
    //cout << "Pub key: " << key << endl;
    pubkey=key;


    //StringSource s1(priv_key, sizeof(priv_key), true, new HexEncoder(new StringSink(privkey)));
    //StringSource s2(pub_key, sizeof(pub_key), true, new HexEncoder(new StringSink(pubkey)));

  }
  catch(const CryptoPP::Exception& d){
    error=d.what();
    #ifdef DEBUG
    cerr << error << endl;
    cerr << "Fail DHGEN" << endl;
    #endif
    return 1;
  }
  return 0;
}

int DH_GEN_N_RFC(int& dhlen, string& privkey, string& pubkey, string& P,string& Q,string& G ,string& error){
  AutoSeededRandomPool rnd;
  DH dh;
  dh.AccessGroupParameters().GenerateRandomWithKeySize(rnd, dhlen);

  if(!dh.GetGroupParameters().ValidateGroup(rnd, 3)){
    error="Failed to validate prime and generator";
    return 1;
  }
  try{
    Integer p = dh.GetGroupParameters().GetModulus();
    Integer q = dh.GetGroupParameters().GetSubgroupOrder();
    Integer g = dh.GetGroupParameters().GetGenerator();

    Integer v = ModularExponentiation(g, q, p);
    if(v != Integer::One()){
      error="Failed to verify order of the subgroup";
      return 1;
    }
    SecByteBlock priv_key(dh.PrivateKeyLength());
    SecByteBlock pub_key(dh.PublicKeyLength());
    dh.GenerateKeyPair(rnd, priv_key, pub_key);

    string key;
    HexEncoder hex(new StringSink(key));
    key = "";
    hex.Put(priv_key.BytePtr(), priv_key.SizeInBytes());
    hex.MessageEnd();
    //cout << "Private key: " << key << endl;
    privkey=key;

    key = "";
    hex.Put(pub_key.BytePtr(), pub_key.SizeInBytes());
    hex.MessageEnd();
    //cout << "Pub key: " << key << endl;
    pubkey=key;

    stringstream stream;
    stream.str("");
    stream << "0x"<< std::hex << p;
    P=stream.str();

    stream.str("");
    stream << "0x"<< std::hex << q;
    Q=stream.str();

    stream.str("");
    stream << "0x"<< std::hex << g;
    G=stream.str();

    //StringSource s1(priv_key, sizeof(priv_key), true, new HexEncoder(new StringSink(privkey)));
    //StringSource s2(pub_key, sizeof(pub_key), true, new HexEncoder(new StringSink(pubkey)));
  }


  catch(const CryptoPP::Exception& d){
    error=d.what();
    #ifdef DEBUG
    cerr << error << endl;
    cerr << "Fail DHGEN" << endl;
    #endif
    return 1;
  }
  return 0;
}

int DH_A_RFC(string& family, string& privkey, string& sharedpub, string& sharedkey ,string& error){
  DH dh;
  AutoSeededRandomPool rnd;
  if(strncmp(family.c_str(), "modp256",sizeof("modp256")) == 0)
  dh.AccessGroupParameters().Initialize(modp256_p, modp256_q, modp256_g);
  else if(strncmp(family.c_str(), "modp224",sizeof("modp224")) == 0)
  dh.AccessGroupParameters().Initialize(modp224_p, modp224_q, modp224_g);
  else if(strncmp(family.c_str(), "modp160",sizeof("modp160")) == 0)
  dh.AccessGroupParameters().Initialize(modp160_p, modp160_q, modp160_g);
  else{
    error="Bad family";
    return 1;
  }
  if(!dh.GetGroupParameters().ValidateGroup(rnd, 3)){
    error="Failed to validate prime and generator";
    return 1;
  }
  try{
    SecByteBlock priv_key(dh.PrivateKeyLength());
    SecByteBlock pub_shared(dh.PublicKeyLength());
    SecByteBlock shared(dh.AgreedValueLength());

    string priv,spub;

    StringSource k(privkey, true, new HexDecoder(new StringSink(priv)));
    memcpy( priv_key, priv.data(),dh.PrivateKeyLength());
    StringSource k1(sharedpub, true, new HexDecoder(new StringSink(spub)));
    memcpy( pub_shared, spub.data(),dh.PublicKeyLength());

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
  catch(const CryptoPP::Exception& d){
    error=d.what();
    #ifdef DEBUG
    cerr << error << endl;
    cerr << "Fail DHAGREE" << endl;
    #endif
    return 1;
  }
  return 0;
}

int DH_A_N_RFC_GEN(string& privkey, string& pubkey, string& sharedpub, string& sharedkey ,string& P,string& Q,string& G ,string& error){
  AutoSeededRandomPool rnd;
  try{
    Integer p(P.c_str());
    Integer q(Q.c_str());
    Integer g(G.c_str());

    string spub;
    StringSource k(sharedpub, true, new HexDecoder(new StringSink(spub)));
    SecByteBlock pub_shared(spub.size());
    memcpy( pub_shared, spub.data(),spub.size());

    DH dh;
    dh.AccessGroupParameters().Initialize(p, q, g);
    if(!dh.GetGroupParameters().ValidateGroup(rnd, 3)){
      error="Failed to validate prime and generator";
      return 1;
    }

    p = dh.GetGroupParameters().GetModulus();
    q = dh.GetGroupParameters().GetSubgroupOrder();
    g = dh.GetGroupParameters().GetGenerator();
    Integer v = ModularExponentiation(g, q, p);
    if(v != Integer::One()){
      error="Failed to verify order of the subgroup";
      return 1;
    }

    SecByteBlock priv_key(dh.PrivateKeyLength());
    SecByteBlock pub_key(dh.PublicKeyLength());
    dh.GenerateKeyPair(rnd, priv_key, pub_key);

    SecByteBlock shared(dh.AgreedValueLength());
    if(!dh.Agree(shared, priv_key, pub_shared)){
      error="Failed to reach shared secret";
      return 1;
    }

    string key;
    HexEncoder hex(new StringSink(key));
    key = "";
    hex.Put(priv_key.BytePtr(), priv_key.SizeInBytes());
    hex.MessageEnd();
    privkey=key;

    key = "";
    hex.Put(pub_key.BytePtr(), pub_key.SizeInBytes());
    hex.MessageEnd();
    pubkey=key;

    key = "";
    hex.Put(shared.BytePtr(), shared.SizeInBytes());
    hex.MessageEnd();
    sharedkey=key;
  }
  catch(const CryptoPP::Exception& d){
    error=d.what();
    #ifdef DEBUG
    cerr << error << endl;
    cerr << "Fail DHAGREE" << endl;
    #endif
    return 1;
  }
  return 0;
}

int DH_A_N_RFC(string& privkey,string& sharedpub, string& sharedkey ,string& P,string& Q,string& G ,string& error){
  AutoSeededRandomPool rnd;
  try{
    Integer p(P.c_str());
    Integer q(Q.c_str());
    Integer g(G.c_str());

    DH dh;
    dh.AccessGroupParameters().Initialize(p, q, g);
    if(!dh.GetGroupParameters().ValidateGroup(rnd, 3)){
      error="Failed to validate prime and generator";
      return 1;
    }

    p = dh.GetGroupParameters().GetModulus();
    q = dh.GetGroupParameters().GetSubgroupOrder();
    g = dh.GetGroupParameters().GetGenerator();
    Integer v = ModularExponentiation(g, q, p);
    if(v != Integer::One()){
      error="Failed to verify order of the subgroup";
      return 1;
    }

    string priv,spub;

    SecByteBlock priv_key(dh.PrivateKeyLength());
    SecByteBlock pub_shared(dh.PublicKeyLength());

    StringSource k(privkey, true, new HexDecoder(new StringSink(priv)));
    memcpy( priv_key, priv.data(),dh.PrivateKeyLength());
    StringSource k1(sharedpub, true, new HexDecoder(new StringSink(spub)));
    memcpy( pub_shared, spub.data(),dh.PublicKeyLength());


    SecByteBlock shared(dh.AgreedValueLength());
    if(!dh.Agree(shared, priv_key, pub_shared)){
      error="Failed to reach shared secret";
      return 1;
    }

    string key;
    HexEncoder hex(new StringSink(key));
    key = "";
    hex.Put(shared.BytePtr(), shared.SizeInBytes());
    hex.MessageEnd();
    sharedkey=key;
  }
  catch(const CryptoPP::Exception& d){
    error=d.what();
    #ifdef DEBUG
    cerr << error << endl;
    cerr << "Fail DHAGREE" << endl;
    #endif
    return 1;
  }
  return 0;
}


////////////////////////////////////////////////////////////////////////
int parse_dh_gen_rfc(Document& d, stru_param& req_val, string& answ_js){
  if(d.HasMember("family")){
    if(check_fam(d,req_val,answ_js)!=0)
    return 1;

    DH_GEN_RFC(req_val.family,req_val.privkey, req_val.pubkey, req_val.error);
    req_val.tag.clear();
    req_val.tag="algorithm";
    Addstr2json(answ_js, req_val.tag, req_val.algorithm);
    req_val.tag.clear();
    req_val.tag="family";
    Addstr2json(answ_js, req_val.tag, req_val.family);
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
    req_val.error="Not family tag ";
    req_val.tag="error";
    Addstr2json(answ_js, req_val.tag, req_val.error);
    #ifdef DEBUG
    cerr << req_val.error;
    #endif
    return 1;
  }
  return 0;
}

int parse_dh_gen_n_rfc(Document& d, stru_param& req_val, string& answ_js){
  if(d.HasMember("length")){
    if(check_length(d,req_val,answ_js,15360)!=0)
    return 1;

    DH_GEN_N_RFC(req_val.length,req_val.privkey, req_val.pubkey, req_val.p,req_val.q,req_val.g ,req_val.error);
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
    req_val.tag="p";
    Addstr2json(answ_js, req_val.tag, req_val.p);
    req_val.tag.clear();
    req_val.tag="q";
    Addstr2json(answ_js, req_val.tag, req_val.q);
    req_val.tag.clear();
    req_val.tag="g";
    Addstr2json(answ_js, req_val.tag, req_val.g);
    req_val.tag.clear();
    req_val.tag="error";
    Addstr2json(answ_js, req_val.tag, req_val.error);
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

int parse_dh_a_rfc(Document& d, stru_param& req_val, string& answ_js){
  if(d.HasMember("family") && d.HasMember("privkey") && d.HasMember("sharedpub")){
    if(check_a_keys(d,req_val,answ_js)!=0)
    return 1;
    if(check_fam(d,req_val,answ_js)!=0)
    return 1;

    DH_A_RFC(req_val.family,req_val.privkey, req_val.sharedpub, req_val.sharedkey, req_val.error);
    req_val.tag.clear();
    req_val.tag="algorithm";
    Addstr2json(answ_js, req_val.tag, req_val.algorithm);
    req_val.tag.clear();
    req_val.tag="family";
    Addstr2json(answ_js, req_val.tag, req_val.family);
    req_val.tag.clear();
    req_val.tag="sharedkey";
    Addstr2json(answ_js, req_val.tag, req_val.sharedkey);
    req_val.tag.clear();
    req_val.tag="error";
    Addstr2json(answ_js, req_val.tag, req_val.error);

  }
  else{
    req_val.error.clear();
    req_val.error="Not gamily/privkey/sharepub tag ";
    req_val.tag="error";
    Addstr2json(answ_js, req_val.tag, req_val.error);
    #ifdef DEBUG
    cerr << req_val.error;
    #endif
    return 1;
  }
  return 0;
}

int parse_dh_a_n_rfc_gen(Document& d, stru_param& req_val, string& answ_js){
  if(d.HasMember("sharedpub") && d.HasMember("p") && d.HasMember("q") && d.HasMember("g")){
    if(check_dh_shares(d,req_val,answ_js)!=0)
    return 1;
    if(check_a_keys(d,req_val,answ_js)!=0)
    return 1;

    DH_A_N_RFC_GEN(req_val.privkey, req_val.pubkey, req_val.sharedpub, req_val.sharedkey, req_val.p,req_val.q, req_val.g, req_val.error);
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
    req_val.tag="sharedkey";
    Addstr2json(answ_js, req_val.tag, req_val.sharedkey);
    req_val.tag.clear();
    req_val.tag="error";
    Addstr2json(answ_js, req_val.tag, req_val.error);

  }
  else{
    req_val.error.clear();
    req_val.error="Not sharepub/p/q/g tag ";
    req_val.tag="error";
    Addstr2json(answ_js, req_val.tag, req_val.error);
    #ifdef DEBUG
    cerr << req_val.error;
    #endif
    return 1;
  }
  return 0;
}

int parse_dh_a_n_rfc(Document& d, stru_param& req_val, string& answ_js){
  if(d.HasMember("privkey") &&  d.HasMember("sharedpub") && d.HasMember("p") && d.HasMember("q") && d.HasMember("g")){
    if(check_dh_shares(d,req_val,answ_js)!=0)
    return 1;
    if(check_a_keys(d,req_val,answ_js)!=0)
    return 1;

    DH_A_N_RFC(req_val.privkey,req_val.sharedpub, req_val.sharedkey, req_val.p,req_val.q, req_val.g, req_val.error);
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
    req_val.error="Not privkey/sharepub/p/q/g tag";
    req_val.tag="error";
    Addstr2json(answ_js, req_val.tag, req_val.error);
    #ifdef DEBUG
    cerr << req_val.error;
    #endif
    return 1;
  }
  return 0;
}

int parse_dh(Document& d, stru_param& req_val, string& answ_js){
  if(d.HasMember("operation")){
    if(check_ops_dh(d,req_val,answ_js)!=0)
    return 1;
  }
  else{
    req_val.error="Not ops tag ";
    answ_error(req_val,answ_js);
    return 1;
  }

  if(strncmp(req_val.operation.c_str(), "gen_rfc",sizeof("gen_rfc")) == 0)
  parse_dh_gen_rfc(d, req_val,answ_js);
  else if(strncmp(req_val.operation.c_str(), "gen_n_rfc",sizeof("gen_n_rfc")) == 0)
  parse_dh_gen_n_rfc(d, req_val,answ_js);
  else if(strncmp(req_val.operation.c_str(), "a_rfc",sizeof("a_rfc")) == 0)
  parse_dh_a_rfc(d, req_val,answ_js);
  else if(strncmp(req_val.operation.c_str(), "a_n_rfc",sizeof("a_n_rfc")) == 0)
  parse_dh_a_n_rfc(d, req_val,answ_js);
  else if(strncmp(req_val.operation.c_str(), "a_n_rfc_gen",sizeof("a_n_rfc_gen")) == 0)
  parse_dh_a_n_rfc_gen(d, req_val,answ_js);
  else{
    req_val.error="Not ops valid ";
    answ_error(req_val,answ_js);
    return 1;
  }
  return 0;
}
