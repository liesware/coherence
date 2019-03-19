#include <sstream>
#include <fstream>
#include <memory>
#include <iostream>
#include <string>
#include <thread>

#include <time.h>
#include <arpa/inet.h>

#include <grpcpp/grpcpp.h>
#include <grpc/support/log.h>
#include "coherence.grpc.pb.h"

#include "lib/parsing.h"

using grpc::Server;
using grpc::ServerAsyncResponseWriter;
using grpc::ServerBuilder;
using grpc::ServerContext;
using grpc::ServerCompletionQueue;
using grpc::Status;
using coherence::coherence_req;
using coherence::coherence_answ;
using coherence::coherence_offload;


void banner(){
  cout<<"Welcome to Cryptoserver\n";
  cout<<" _______  _____  _     _ _______  ______ _______ __   _ _______ _______\n";
  cout<<" |       |     | |_____| |______ |_____/ |______ | \\  | |       |______\n";
  cout<<" |_____  |_____| |     | |______ |    \\_ |______ |  \\_| |_____  |______\n";
  cout<<"\n";
  cout<<"\"Privacy is the power to selectively reveal oneself to the world.\" \n";
  cout<<"https://www.activism.net/cypherpunk/manifesto.html\n";
  cout<<"\n";
}


int ok_buff(string& buf){
  int len_buff=buf.length();
  char cp_buff[len_buff];
  memcpy( cp_buff, buf.c_str(), len_buff );
  if((strchr("{",cp_buff[0]) && strchr("}",cp_buff[len_buff-1]))==NULL)
  return 1;
  int i,k=0;
  for(i=0;i<len_buff;i++){
    if (!(isalnum(cp_buff[i]) || cp_buff[i]==' '|| strchr("!\"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~",cp_buff[i]) || cp_buff[i]=='\n')){
      #ifdef DEBUG
      printf("Bad buffer character is %c \n", cp_buff[i]);
      #endif
      return 1;
    }
  }
  return 0;
}


void read_fs ( const std::string& filename, std::string& data ){
  std::ifstream file ( filename.c_str (), std::ios::in );
	if ( file.is_open () ){
		std::stringstream ss;
		ss << file.rdbuf ();
		file.close ();
		data = ss.str ();
	}
	return;
}


void coherence_start(string& request, string& answer){
  stru_info_log log_info;
  log_info.req=request;

  clock_t t;
  t = clock();

  log_info.timestamp=(int)time(NULL);
  log_info.ip="working";

    if(ok_buff(log_info.req)!=0){
      log_info.answ="{\"error\":\"Bad Buffer, plase see https://github.com/liesware/coherence  and report bugs\"}";
      t = clock()-t;
      log_info.exec_time=(float)t/CLOCKS_PER_SEC;
      log_info.total_read=log_info.req.length();
      log_info.total_write=log_info.answ.length();
      string log_js="{}";
      log_info.req="{\"error\":\"Bad json string format request\"}";
      parse_log(log_info, log_js);
      cout<<log_js<<endl;
      return;
    }

  PARSING(log_info.req , log_info.answ);
  answer=log_info.answ;
  t = clock()-t;
  log_info.exec_time=(float)t/CLOCKS_PER_SEC;
  log_info.total_read=log_info.req.length();
  log_info.total_write=log_info.answ.length();
  string log_js="{}";
  parse_log(log_info, log_js);
  cout<<log_js<<endl;
  log_js.clear();

  return;
}

class ServerImpl final {
 public:
  ~ServerImpl() {
    server_->Shutdown();
    cq_->Shutdown();
  }

  void Run(string addr) {
    std::string key;
    std::string cert;
    std::string root;

    read_fs ( "server.crt", cert );
    read_fs ( "server.key", key );
    read_fs ( "ca.crt", root );

    grpc::SslServerCredentialsOptions::PemKeyCertPair keycert ={key,cert};
    grpc::SslServerCredentialsOptions sslOps;
    sslOps.pem_root_certs = root;
    sslOps.pem_key_cert_pairs.push_back ( keycert );

    std::string server_address(addr.c_str());

    ServerBuilder builder;
    builder.AddListeningPort(server_address, grpc::SslServerCredentials( sslOps ));
    builder.RegisterService(&service_);
    cq_ = builder.AddCompletionQueue();
    server_ = builder.BuildAndStart();
    //std::cout << "Server listening on " << server_address << std::endl;
    banner();

    HandleRpcs();
  }

 private:
  class CallData {
   public:
    CallData(coherence_offload::AsyncService* service, ServerCompletionQueue* cq)
        : service_(service), cq_(cq), responder_(&ctx_), status_(CREATE) {
      Proceed();
    }

    void Proceed() {
      if (status_ == CREATE) {
        status_ = PROCESS;
        service_->Requestcoherence_js(&ctx_, &request_, &responder_, cq_, cq_,this);
      } else if (status_ == PROCESS) {
        new CallData(service_, cq_);

        string answ,req;
        req=request_.req();
        coherence_start(req,answ);

        reply_.set_answ(answ);
        status_ = FINISH;
        responder_.Finish(reply_, Status::OK, this);

        req.clear();
        answ.clear();

      } else {
        GPR_ASSERT(status_ == FINISH);
        delete this;
      }
    }

   private:
    coherence_offload::AsyncService* service_;
    ServerCompletionQueue* cq_;
    ServerContext ctx_;

    coherence_req request_;
    coherence_answ reply_;

    ServerAsyncResponseWriter<coherence_answ> responder_;

    enum CallStatus { CREATE, PROCESS, FINISH };
    CallStatus status_;
  };

  void HandleRpcs() {
    new CallData(&service_, cq_.get());
    void* tag;  // uniquely identifies a request.
    bool ok;
    while (true) {
      GPR_ASSERT(cq_->Next(&tag, &ok));
      GPR_ASSERT(ok);
      static_cast<CallData*>(tag)->Proceed();
    }
  }

  std::unique_ptr<ServerCompletionQueue> cq_;
  coherence_offload::AsyncService service_;
  std::unique_ptr<Server> server_;
};

int main(int argc, char** argv) {
  if(argc!=3){
    printf(" IP PORT \n");
    return 1;
  }

  char str[INET_ADDRSTRLEN];
  unsigned short str2;
  struct sockaddr_in sa;
  inet_pton(AF_INET, argv[1], &(sa.sin_addr));
  inet_ntop(AF_INET, &(sa.sin_addr), str, INET_ADDRSTRLEN);

  str2=(unsigned short) atoi(argv[2]);
  string addr,port;
  if (str2<0 && str2>65535){
    cout<<"Bad addr IP PORT"<<endl;
    return 1;
  }

  port=to_string(str2);

  addr.append(str);
  addr.append(":");
  addr.append(port);

  ServerImpl server;
  server.Run(addr);

  return 0;
}
