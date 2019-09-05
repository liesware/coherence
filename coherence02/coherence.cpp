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
    opts.maxPayload(65536);
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
    string answer, crypt_ops;
    crypt_ops=request.body();
    PARSING(crypt_ops, answer);

    response.send(Pistache::Http::Code::Ok, answer);
    cout << request.body() << endl;
    cout << answer << endl;
  };

  std::shared_ptr<Http::Endpoint> httpEndpoint;
  Rest::Router router;
};

int main(int argc, char *argv[]) {
  sigset_t signals;
  if (sigemptyset(&signals) != 0 || sigaddset(&signals, SIGTERM) != 0 ||
      sigaddset(&signals, SIGINT) != 0 || sigaddset(&signals, SIGHUP) != 0 ||
      pthread_sigmask(SIG_BLOCK, &signals, nullptr) != 0) {
    perror("install signal handler failed");
    return 1;
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
  int signal = 0;
  int status = sigwait(&signals, &signal);
  if (status == 0) {
    std::cout << "received signal " << signal << std::endl;
  } else {
    std::cerr << "sigwait returns " << status << std::endl;
  }
  stats.stop();

}
