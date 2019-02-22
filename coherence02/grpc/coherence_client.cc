#include <sstream>
#include <fstream>

#include <iostream>
#include <memory>
#include <string>

#include <grpcpp/grpcpp.h>

#include "coherence.grpc.pb.h"


using grpc::Channel;
using grpc::ClientContext;
using grpc::Status;
using coherence::coherence_req;
using coherence::coherence_answ;
using coherence::coherence_offload;

void read ( const std::string& filename, std::string& data ){
  std::ifstream file ( filename.c_str (), std::ios::in );
	if ( file.is_open () )
	{
		std::stringstream ss;
		ss << file.rdbuf ();
		file.close ();
		data = ss.str ();
	}

	return;
}


class CoherenceClient {
 public:
  CoherenceClient(std::shared_ptr<Channel> channel)
      : stub_(coherence_offload::NewStub(channel)) {}

  std::string coherence_js(const std::string& user) {
    coherence_req request;
    request.set_req(user);

    coherence_answ reply;

    ClientContext context;

    Status status = stub_->coherence_js(&context, request, &reply);

    if (status.ok()) {
      return reply.answ();
    } else {
      std::cout << status.error_code() << ": " << status.error_message()
                << std::endl;
      return "RPC failed";
    }
  }

 private:
  std::unique_ptr<coherence_offload::Stub> stub_;
};

int main(int argc, char** argv) {
  // Instantiate the client. It requires a channel, out of which the actual RPCs
  // are created. This channel models a connection to an endpoint (in this case,
  // localhost at port 50051). We indicate that the channel isn't authenticated
  // (use of InsecureChannelCredentials()).
  //CoherenceClient greeter(grpc::CreateChannel("localhost:6613", grpc::InsecureChannelCredentials()));

  std::string key;
  std::string cert;
  std::string root;

  //read ( "client.crt", cert );
  //read ( "client.key", key );
  read ( "ca.crt", root );

  grpc::SslCredentialsOptions opts ={root,key,cert};
  auto channel_creds = grpc::SslCredentials(grpc::SslCredentialsOptions(opts));
  auto channel = grpc::CreateChannel("localhost:6613", channel_creds);

  CoherenceClient greeter(channel);

  std::string req_js="{\"version\":1,\"algorithm\":\"SHA3_512\",\"type\":\"string\",\"plaintext\":\"Hello world!\"}";
  std::string reply = greeter.coherence_js(req_js);
  std::cout << "Greeter received: " << reply << std::endl;

  return 0;
}
