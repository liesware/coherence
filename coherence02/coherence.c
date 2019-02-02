#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <time.h>
#include <netinet/in.h>

#include "uv.h"

#include "lib/parsing.h"

#include <fstream>

uv_loop_t *loop;
struct sockaddr_in addr;

ofstream log_file;

size_t coherence_size=4194304;

////////////////////////////////////////////////////////////////////////
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

////////////////////////////////////////////////////////////////////////
int ok_buff(const uv_buf_t *buf){
  int len_buff=strlen(buf->base);
  char cp_buff[len_buff];
  memcpy( cp_buff, buf->base, len_buff );
	if((strchr("{",cp_buff[0]) && strchr("}",cp_buff[len_buff-1]))!=0){
	  int i,k=0;
	  for(i=0;i<len_buff;i++){
	    if (!(isalnum(cp_buff[i]) || cp_buff[i]==' '|| strchr("!\"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~",cp_buff[i]))){
#ifdef DEBUG
		  printf("Bad buffer character %c \n", cp_buff[i]);
#endif
		  return 1;
	    }
    }
	  return 0;
	}
	else
	  return 1;
}


void alloc_buffer(uv_handle_t *handle, size_t coherence_size, uv_buf_t *buf) {
  buf->base = (char*)malloc(coherence_size);
  buf->len = coherence_size;
  memset (buf->base,'\0',coherence_size);
}

void on_close(uv_handle_t* handle) {
  free(handle);
}

void echo_write(uv_write_t *req, int status) {
  if(status) {
    fprintf(stderr, "Write error %s\n", uv_strerror(status));
  }
  free(req);
}

void echo_read(uv_stream_t *client, ssize_t nread, const uv_buf_t *buf) {
  if (nread < 0) {
      if (nread != UV_EOF) {
          fprintf(stderr, "Read error %s\n", uv_err_name(nread));
          try{
            uv_close((uv_handle_t*) client, on_close);
          }
          catch(int * e){
             cout << "An exception occurred. " << e << '\n';
          }
          return;
      }
  }
  else if (nread > 0) {
    stru_info_log log_info;

    uv_write_t *req = (uv_write_t *) malloc(sizeof(uv_write_t));

    sockaddr_in cli_addr;
    int name_len= sizeof(cli_addr);
    uv_tcp_t* uv_client = (uv_tcp_t*)client;
    uv_tcp_getpeername(uv_client, (struct sockaddr*) &cli_addr, &name_len);
    char ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &cli_addr.sin_addr, ip, INET_ADDRSTRLEN);

    log_info.timestamp=(int)time(NULL);
    log_info.ip=ip;
    log_info.req=buf->base;

#ifdef DEBUG
    printf("\nClient connect: %s\n", log_info.ip.c_str());
    printf("Timestamp: %d\n",log_info.timestamp);
    printf("Recived: %s\n",log_info.req.c_str());
#endif

    clock_t t;
    t = clock();

    string str_json;
    str_json.clear();
    str_json = buf->base;
    string answer;

    if(ok_buff(buf)!=0){
      answer.clear();
	    answer="{\"error\":\"Bad Buffer, plase see https://github.com/liesware/coherence  and report bugs\"}";
#ifdef DEBUG
	  printf("\nSended: %s\n",answer.c_str());
#endif
      log_info.answ=answer;

	    char *paramsp=strdup( answer.c_str());
	    uv_buf_t wrbuf= uv_buf_init(paramsp, answer.length());
	    uv_write(req, client, &wrbuf, 1, echo_write);
	    free(paramsp);

	    t = clock()-t;
      log_info.exec_time=(float)t/CLOCKS_PER_SEC;
      string log_js="{}";
      log_info.req="{\"error\":\"Bad json string format request\"}";
      parse_log(log_info, log_js);
      cout<<log_js<<endl;

	}
  else{

	  PARSING(str_json , answer);
#ifdef DEBUG
	  printf("\nSended: %s\n",answer.c_str());
#endif
      log_info.answ=answer;

	  char *paramsp=strdup( answer.c_str());
	  uv_buf_t wrbuf= uv_buf_init(paramsp, answer.length());
	  uv_write(req, client, &wrbuf, 1, echo_write);
	  free(paramsp);

	  t = clock()-t;
    log_info.exec_time=(float)t/CLOCKS_PER_SEC;
    string log_js="{}";
    parse_log(log_info, log_js);
    cout<<log_js<<endl;

  }
 }

  free(buf->base);
  uv_close((uv_handle_t*) client, on_close);

}

void on_new_connection(uv_stream_t *server, int status) {
  if(status < 0) {
    fprintf(stderr, "New connection error %s\n", uv_strerror(status));
      return;
  }

  uv_tcp_t *client = (uv_tcp_t*)malloc(sizeof(uv_tcp_t));
  uv_tcp_init(loop, client);
  if (uv_accept(server, (uv_stream_t*) client) == 0) {
      uv_read_start((uv_stream_t*)client, alloc_buffer, echo_read);
  }
  else {
    uv_close((uv_handle_t*) client, on_close);
  }
}

int main(int argc, char *argv[]) {
  if(argc!=3){
    printf(" IP PORT \n");
    return 1;
  }
  banner();


  loop = uv_default_loop();
  uv_tcp_t server;
  uv_tcp_init(loop, &server);
  uv_tcp_simultaneous_accepts(&server, 1);

  uv_ip4_addr(argv[1], atoi(argv[2]), &addr);
  uv_tcp_bind(&server, (const struct sockaddr*)&addr, 0);
  int r= uv_listen((uv_stream_t*)&server, 128, on_new_connection);
  if(r){
    fprintf(stderr, "Listen error %s\n", uv_strerror(r));
      return 1;
  }


#ifdef DEBUG
  printf("Process started\n");
#endif

  r= uv_run(loop, UV_RUN_DEFAULT);

  return r;
}
