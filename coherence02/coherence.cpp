#include <fstream>
#include <algorithm>
#include <signal.h>

#include "pistache/endpoint.h"
#include "pistache/http.h"
#include "pistache/router.h"

#include "lib/parsing.h"

using namespace std;
using namespace Pistache;

ofstream log_file;

void banner(){
  printf("Welcome to Cryptoserver\n");
  printf(" _______  _____  _     _ _______  ______ _______ __   _ _______ _______\n");
  printf(" |       |     | |_____| |______ |_____/ |______ | \\  | |       |______\n");
  printf(" |_____  |_____| |     | |______ |    \\_ |______ |  \\_| |_____  |______\n");
  printf("\n");
  printf("\"Privacy is the power to selectively reveal oneself to the world.\" \n");
  printf("https://www.activism.net/cypherpunk/manifesto.html\n");
  printf("\n");
}

class StatsEndpoint {
public:
  StatsEndpoint(Address addr)
      : httpEndpoint(std::make_shared<Http::Endpoint>(addr)) {}

  void init(size_t thr = 2) {
    auto opts = Http::Endpoint::options();
    opts.threads(thr);
    //opts.maxPayload(131072);
    opts.maxRequestSize(1048576);
    httpEndpoint->init(opts);
    setupRoutes();
  }

  void start() {
    httpEndpoint->setHandler(router.handler());
    httpEndpoint->serve();
  }

  void stop() {
    httpEndpoint->shutdown();
  }

private:
  void setupRoutes() {
    using namespace Rest;
    Routes::Post(router, "/", Routes::bind(&StatsEndpoint::res, this));
  }

  void res(const Rest::Request &request, Http::ResponseWriter response) {
    clock_t t;
    t = clock();
    string answer, crypt_ops;
    string log_js="{}";
    stru_info_log log_info;
    crypt_ops=request.body();
    PARSING(crypt_ops, answer);

    response.send(Pistache::Http::Code::Ok, answer);
    t = clock()-t;
    log_info.exec_time=(float)t/CLOCKS_PER_SEC;
    log_info.answ=answer;
    log_info.timestamp=(int)time(NULL);
    log_info.req=request.body();
    parse_log(log_info, log_js);
    cout<<log_js<<endl;
  };

  std::shared_ptr<Http::Endpoint> httpEndpoint;
  Rest::Router router;
};

int main(int argc, char *argv[]) {
  sigset_t signals;
  if (sigemptyset(&signals)        != 0
    ||  sigaddset(&signals, SIGTERM) != 0
    ||  sigaddset(&signals, SIGINT)  != 0
    ||  sigaddset(&signals, SIGQUIT) != 0
    ||  sigaddset(&signals, SIGPIPE) != 0
    ||  sigaddset(&signals, SIGALRM) != 0
    ||  pthread_sigmask(SIG_BLOCK, &signals, nullptr) != 0){
      return false;
  }

  banner();
  Port port(6613);
  int thr = 2;

  if (argc >= 2) {
    port = std::stol(argv[1]);

    if (argc == 3)
      thr = std::stol(argv[2]);
  }

  Address addr(Ipv4::any(), port);
  // cout << "Cores = " << hardware_concurrency() << endl;
  // cout << "Using " << thr << " threads" << endl;
  StatsEndpoint stats(addr);

  stats.init(thr);
  stats.start();

  bool terminate = false;
  while (!terminate) {
    int number = 0;
    int status = sigwait(&signals, &number);
    if (status != 0) {
        break;
    }

    switch (number) {
        case SIGINT : terminate = true; break;
        case SIGTERM: terminate = true; break;
        case SIGQUIT: terminate = true; break;
        case SIGPIPE: break;
        case SIGALRM: break;
        default     : break;
    }
  }
  stats.stop();
}
