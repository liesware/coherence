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

////////////////////////////////////////////////////////////////////////
void banner(){
  printf("Welcome to Cryptoserer\n");
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


void alloc_buffer(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf) {
  buf->base = (char*)malloc(suggested_size);
  buf->len = suggested_size;
  memset (buf->base,'\0',suggested_size);
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
          uv_close((uv_handle_t*) client, NULL);
      }
  } 
  else if (nread > 0) {	     
    stru_info_log log_info;
    
    uv_write_t *req = (uv_write_t *) malloc(sizeof(uv_write_t));                                  
            
    sockaddr_in cli_addr;
    int name_len;
    uv_tcp_t* uv_client = (uv_tcp_t*)client;
    uv_tcp_getpeername(uv_client, (struct sockaddr*) &cli_addr, &name_len);
    char ip[INET6_ADDRSTRLEN] = {0};        
    inet_ntop(AF_INET, &cli_addr.sin_addr, ip, INET6_ADDRSTRLEN);
    
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
    log_file.open ("file_test/coherence.log" ,ios::app);
    if (log_file.is_open()){
      //printf("Coherence server started and login\n");
    } 
    else
      printf("Unable to open log file\n");  
        
    string str_json;
    str_json.clear();
    str_json = buf->base;
    string answer;        
      
    if(ok_buff(buf)!=0){
      answer.clear();
	  answer="{\"error\":\"Bad Buffer\"}";
#ifdef DEBUG									
	  printf("\nSended: %s\n",answer.c_str());
#endif
      log_info.answ=answer;
      			  	    	    
	  char *paramsp=strdup( answer.c_str());          
	  uv_buf_t wrbuf= uv_buf_init(paramsp, answer.length());
	  uv_write(req, client, &wrbuf, 1, echo_write);
	  uv_close((uv_handle_t*) client, NULL);			
	  free(paramsp);
	  
	  t = clock()-t;
      log_info.exec_time=(float)t/CLOCKS_PER_SEC;  
      string log_js="{}";
      parse_log(log_info, log_js);
      log_file<<log_js<<endl;
      log_file.close(); 	  
	  			
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
	  //uv_close((uv_handle_t*) client, NULL);
	  free(paramsp);
	  
	  t = clock()-t;
      log_info.exec_time=(float)t/CLOCKS_PER_SEC;  
      string log_js="{}";
      parse_log(log_info, log_js);
      log_file<<log_js<<endl;
      log_file.close(); 
	  
    }                           
  }  

  if (buf->base) {
      free(buf->base);
  } 
 
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
    uv_close((uv_handle_t*) client, NULL);
  }
}

int main() {
  banner();
  	
  loop = uv_default_loop();
  uv_tcp_t server;
  uv_tcp_init(loop, &server);
  uv_tcp_simultaneous_accepts(&server, 1);
    
  uv_ip4_addr("0.0.0.0", 6613, &addr);
  uv_tcp_bind(&server, (const struct sockaddr*)&addr, 0);
  int r = uv_listen((uv_stream_t*)&server, 128, on_new_connection);
  if(r){
    fprintf(stderr, "Listen error %s\n", uv_strerror(r));
      return 1;
  }
               
       
#ifdef DEBUG			
  printf("Process started\n");
#endif    
    
  return uv_run(loop, UV_RUN_DEFAULT);
}
