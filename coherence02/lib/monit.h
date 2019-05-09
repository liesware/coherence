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

int status_anws(string& answ_js){
  string tag,val;
  tag= "algorithm";
  val= "MONIT";
  Addstr2json(answ_js, tag, val);
  tag= "operation";
  val= "status";
  Addstr2json(answ_js, tag, val);
  tag= "result";
  val= "OK";
  Addstr2json(answ_js, tag, val);

  return 0;
}


////////////////////////////////////////////////////////////////////////////////

int parse_monit(Document& d, stru_param& req_val, string& answ_js){
  if(!d.HasMember("operation")){
    req_val.error="Not ops tag ";
    answ_error(req_val,answ_js);
    return 1;
  }

  req_val.operation= d["operation"].GetString();
  if(strncmp(req_val.operation.c_str(), "status",sizeof("status")) == 0){
    status_anws(answ_js);
  }
  else{
    req_val.error="Monitor metric ";
    answ_error(req_val,answ_js);
    return 1;
  }

  return 0;
}
