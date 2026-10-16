// G6 BYO IPv6 probe.  Self-test modes use ordinary sockets; deployed mode gets
// its exact assigned configuration from NeuronHub and never changes networking.
#include <networking/includes.h>
#include <services/debug.h>
#include <services/bitsery.h>
#include <services/crypto.h>
#include <services/filesystem.h>
#include <networking/time.h>
#include <networking/ip.h>
#include <networking/socket.h>
#include <networking/stream.h>
#include <networking/pool.h>
#include <networking/ring.h>
#include <prodigy/neuron.hub.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>
#include <atomic>
#include <chrono>
#include <cctype>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <string>
#include <thread>
#include <vector>

namespace {
constexpr int maxTimeout = 60000, runtimeTimeout = 5000, trailingGrace = 25;
constexpr char ingress[] = "PRODIGY_G6_IPV6_INGRESS_CHALLENGE ", reply[] = "PRODIGY_G6_IPV6_INGRESS_RESPONSE ";
constexpr char egress[] = "PRODIGY_G6_WHITEHOLE_EGRESS_CHALLENGE ", egressReply[] = "PRODIGY_G6_WHITEHOLE_EGRESS_RESPONSE ";
bool port(const char* s, uint16_t& v) { char* e=nullptr; errno=0; unsigned long n=s?strtoul(s,&e,10):0; if(errno||!s||!*s||!e||*e||!n||n>65535)return false;v=n;return true; }
bool timeout(const char* s,int& v) { char* e=nullptr;errno=0;unsigned long n=s?strtoul(s,&e,10):0;if(errno||!s||!*s||!e||*e||!n||n>maxTimeout)return false;v=n;return true; }
bool ip6(const char*s,in6_addr&a) { return s&&inet_pton(AF_INET6,s,&a)==1&&!IN6_IS_ADDR_UNSPECIFIED(&a); }
bool byo(const in6_addr&a) { return a.s6_addr[0]==0x26&&a.s6_addr[1]==2&&a.s6_addr[2]==0xfa&&a.s6_addr[3]==0xc0&&a.s6_addr[4]==0; }
bool nonblock(int fd) { int f=fcntl(fd,F_GETFL);return f>=0&&fcntl(fd,F_SETFL,f|O_NONBLOCK)==0; }
bool wait(int fd,short events,int ms) { pollfd p={};p.fd=fd;p.events=events;for(;;){int r=poll(&p,1,ms);if(r>0)return (p.revents&events)!=0;if(!r||errno!=EINTR)return false;} }
bool owns(const in6_addr&a) { ifaddrs* p=nullptr;if(getifaddrs(&p))return false;bool yes=false;for(auto*q=p;q;q=q->ifa_next)if(q->ifa_addr&&q->ifa_addr->sa_family==AF_INET6&&memcmp(&reinterpret_cast<sockaddr_in6*>(q->ifa_addr)->sin6_addr,&a,sizeof(a))==0){yes=true;break;}freeifaddrs(p);return yes; }
bool connectTimed(int fd,const sockaddr_in6&to,int ms) { if(!nonblock(fd))return false;if(!connect(fd,reinterpret_cast<const sockaddr*>(&to),sizeof(to)))return true;if(errno!=EINPROGRESS||!wait(fd,POLLOUT,ms))return false;int err=0;socklen_t n=sizeof(err);return !getsockopt(fd,SOL_SOCKET,SO_ERROR,&err,&n)&&!err; }
bool writeAll(int fd,const std::string&s,int ms) { for(size_t at=0;at<s.size();){if(!wait(fd,POLLOUT,ms))return false;ssize_t n=send(fd,s.data()+at,s.size()-at,MSG_NOSIGNAL);if(n>0){at+=n;continue;}if(n<0&&(errno==EINTR||errno==EAGAIN||errno==EWOULDBLOCK))continue;return false;}return true; }
bool hexSize(const std::string&s,size_t size) { if(s.size()!=size)return false;for(char c:s)if(!((c>='0'&&c<='9')||(c>='a'&&c<='f')))return false;return true; }
bool hex(const std::string&s) { return hexSize(s,64); }
bool safeRow(const std::string&s) { if(s.empty()||s.size()>64)return false;for(char c:s)if(!std::isalnum(static_cast<unsigned char>(c))&&c!='.'&&c!='_'&&c!='-')return false;return true; }
bool readProof(const char*path,std::string&challenge,std::string&commit,std::string&row,std::string&binary) { int fd=open(path,O_RDONLY|O_CLOEXEC);if(fd<0)return false;char buffer[1025]={},extra=0;ssize_t n=read(fd,buffer,1024),tail=n>=0?read(fd,&extra,1):-1;close(fd);if(n<=0||tail!=0)return false;std::string value(buffer,size_t(n));constexpr char prefix[]="PRODIGY_G6_BYO_PROOF ";if(value.compare(0,sizeof(prefix)-1,prefix)||value.back()!='\n'||value.find('\n')!=value.size()-1)return false;value.pop_back();value.erase(0,sizeof(prefix)-1);size_t a=value.find(' '),b=a==std::string::npos?a:value.find(' ',a+1),c=b==std::string::npos?b:value.find(' ',b+1);if(a==std::string::npos||b==std::string::npos||c==std::string::npos||value.find(' ',c+1)!=std::string::npos)return false;challenge=value.substr(0,a);commit=value.substr(a+1,b-a-1);row=value.substr(b+1,c-b-1);binary=value.substr(c+1);return hex(challenge)&&hexSize(commit,40)&&safeRow(row)&&hex(binary); }
bool fileSHA256(const char*path,std::string&digest) { digest.clear();int fd=open(path,O_RDONLY|O_CLOEXEC);if(fd<0)return false;EVP_MD_CTX*ctx=EVP_MD_CTX_new();bool ok=ctx&&EVP_DigestInit_ex(ctx,EVP_sha256(),nullptr)==1;unsigned char buffer[65536],raw[EVP_MAX_MD_SIZE]={};unsigned int rawSize=0;while(ok){ssize_t n=read(fd,buffer,sizeof(buffer));if(!n)break;if(n<0){if(errno==EINTR)continue;ok=false;break;}ok=EVP_DigestUpdate(ctx,buffer,size_t(n))==1;}if(ok)ok=EVP_DigestFinal_ex(ctx,raw,&rawSize)==1&&rawSize==32;if(ctx)EVP_MD_CTX_free(ctx);close(fd);if(!ok)return false;constexpr char chars[]="0123456789abcdef";digest.reserve(64);for(unsigned int i=0;i<rawSize;i++){digest.push_back(chars[raw[i]>>4]);digest.push_back(chars[raw[i]&15]);}return true; }
bool proofMatchesExecutable(const char*proofPath,const char*executable,std::string&challenge,std::string&commit,std::string&row,std::string&binary) { std::string actual;return readProof(proofPath,challenge,commit,row,binary)&&fileSHA256(executable,actual)&&actual==binary; }
bool readChallenge(int fd,const char*prefix,std::string&token,int ms) { size_t size=strlen(prefix)+65;std::string line;while(line.size()<size){if(!wait(fd,POLLIN,ms))return false;char c;ssize_t n=recv(fd,&c,1,0);if(n==1){line+=c;if(c=='\n')break;}else if(!(n<0&&(errno==EINTR||errno==EAGAIN||errno==EWOULDBLOCK)))return false;}if(line.size()!=size||line.back()!='\n'||line.compare(0,strlen(prefix),prefix))return false;token.assign(line.data()+strlen(prefix),64);return hex(token); }
bool noTrailing(int fd) { return !wait(fd,POLLIN,trailingGrace); }
bool endpoint(int fd,const in6_addr&a,uint16_t port,bool peer) { sockaddr_in6 got={};socklen_t n=sizeof(got);int r=peer?getpeername(fd,reinterpret_cast<sockaddr*>(&got),&n):getsockname(fd,reinterpret_cast<sockaddr*>(&got),&n);return !r&&n==sizeof(got)&&got.sin6_family==AF_INET6&&got.sin6_port==htons(port)&&!memcmp(&got.sin6_addr,&a,sizeof(a)); }
bool traceHost(const char* value) { if(!value||!*value||strlen(value)>253)return false;for(const char*c=value;*c;c++)if(!((*c>='a'&&*c<='z')||(*c>='A'&&*c<='Z')||(*c>='0'&&*c<='9')||*c=='.'||*c=='-'))return false;return true; }
bool readToEof(int fd,std::string& value,int ms) { char buffer[1024];while(value.size()<=16384){if(!wait(fd,POLLIN,ms))return false;ssize_t n=recv(fd,buffer,sizeof(buffer),0);if(n>0){value.append(buffer,size_t(n));continue;}if(!n)return true;if(errno==EINTR||errno==EAGAIN||errno==EWOULDBLOCK)continue;return false;}return false; }
bool decimal(const std::string& text,size_t& value) { if(text.empty()||text.size()>5)return false;value=0;for(char c:text){if(c<'0'||c>'9')return false;value=value*10+size_t(c-'0');if(value>8192)return false;}return true; }
bool contentLength(const std::string& line) { constexpr char name[]="content-length: ";if(line.size()<sizeof(name)-1)return false;for(size_t i=0;i<sizeof(name)-1;i++)if(std::tolower(static_cast<unsigned char>(line[i]))!=name[i])return false;return true; }
bool traceResponse(const std::string& response,const std::string& assigned,std::string& observed) { size_t split=response.find("\r\n\r\n");if(split==std::string::npos||response.compare(0,7,"HTTP/1.")||response.compare(8,4," 200"))return false;size_t at=response.find("\r\n");if(at==std::string::npos)return false;size_t length=0;bool haveLength=false;for(size_t next=at+2;next<split;next=at+2){at=response.find("\r\n",next);if(at==std::string::npos||at>split)return false;std::string line=response.substr(next,at-next);if(line.empty())return false;if(contentLength(line)){if(haveLength||!decimal(line.substr(16),length))return false;haveLength=true;}}if(!haveLength||response.size()!=split+4+length)return false;std::string body=response.substr(split+4);if(body.empty()||body.back()!='\n')return false;bool ipLine=false;for(size_t begin=0;begin<body.size();){size_t end=body.find('\n',begin);if(end==std::string::npos||end==begin)return false;std::string line=body.substr(begin,end-begin);if(line.compare(0,3,"ip=")==0){if(ipLine||line.substr(3)!=assigned)return false;observed=line.substr(3);ipLine=true;}else if(line.find('=')==std::string::npos)return false;begin=end+1;}return ipLine; }
bool traceOnce(const in6_addr& source,uint16_t sourcePort,const char* observer,const char* host,std::string& assigned,std::string& observed) { in6_addr remote={};uint16_t remotePort=80;if(!ip6(observer,remote)||!traceHost(host))return false;char text[INET6_ADDRSTRLEN]={};if(!inet_ntop(AF_INET6,&source,text,sizeof(text)))return false;assigned=text;int fd=socket(AF_INET6,SOCK_STREAM|SOCK_CLOEXEC,0),one=1;sockaddr_in6 local={},to={};local.sin6_family=AF_INET6;local.sin6_addr=source;local.sin6_port=htons(sourcePort);to.sin6_family=AF_INET6;to.sin6_addr=remote;to.sin6_port=htons(remotePort);bool ok=fd>=0&&!setsockopt(fd,IPPROTO_IPV6,IPV6_V6ONLY,&one,sizeof(one))&&!bind(fd,reinterpret_cast<sockaddr*>(&local),sizeof(local))&&connectTimed(fd,to,runtimeTimeout)&&endpoint(fd,source,sourcePort,false);std::string response;if(ok)ok=writeAll(fd,std::string("GET /cdn-cgi/trace HTTP/1.1\r\nHost: ")+host+"\r\nConnection: close\r\n\r\n",runtimeTimeout)&&readToEof(fd,response,runtimeTimeout)&&traceResponse(response,assigned,observed);if(fd>=0)close(fd);return ok; }
int traceSelftest(int argc,char**argv) { std::string observed;return argc==4&&traceResponse(argv[3],argv[2],observed)?0:1; }
int proofSelftest(int argc,char**argv) { std::string challenge,commit,row,binary;return argc==4&&proofMatchesExecutable(argv[2],argv[3],challenge,commit,row,binary)?0:1; }

int wormhole(int argc,char**argv) { uint16_t p;int ms;if(argc!=4||!port(argv[2],p)||!timeout(argv[3],ms))return 2;int l=socket(AF_INET6,SOCK_STREAM|SOCK_CLOEXEC,0),one=1;sockaddr_in6 a={};a.sin6_family=AF_INET6;a.sin6_addr=in6addr_any;a.sin6_port=htons(p);if(l<0||!nonblock(l)||setsockopt(l,IPPROTO_IPV6,IPV6_V6ONLY,&one,sizeof(one))||bind(l,reinterpret_cast<sockaddr*>(&a),sizeof(a))||listen(l,1)||!wait(l,POLLIN,ms)){if(l>=0)close(l);return 1;}int fd=accept4(l,nullptr,nullptr,SOCK_NONBLOCK|SOCK_CLOEXEC);close(l);std::string t;bool ok=fd>=0&&readChallenge(fd,ingress,t,ms)&&noTrailing(fd)&&writeAll(fd,std::string(reply)+t+"\n",ms);if(fd>=0)close(fd);return ok?0:1; }
int whitehole(int argc,char**argv) { in6_addr source={},observer={};uint16_t sp,op;int ms;if(argc!=7||!ip6(argv[2],source)||!byo(source)||!port(argv[3],sp)||!ip6(argv[4],observer)||!port(argv[5],op)||!timeout(argv[6],ms))return 2;if(!owns(source))return 1;int fd=socket(AF_INET6,SOCK_STREAM|SOCK_CLOEXEC,0),one=1;sockaddr_in6 local={},to={};local.sin6_family=AF_INET6;local.sin6_addr=source;local.sin6_port=htons(sp);to.sin6_family=AF_INET6;to.sin6_addr=observer;to.sin6_port=htons(op);bool ok=fd>=0&&!setsockopt(fd,IPPROTO_IPV6,IPV6_V6ONLY,&one,sizeof(one))&&!bind(fd,reinterpret_cast<sockaddr*>(&local),sizeof(local))&&connectTimed(fd,to,ms)&&endpoint(fd,source,sp,false)&&endpoint(fd,observer,op,true);std::string t;ok=ok&&readChallenge(fd,egress,t,ms)&&noTrailing(fd)&&writeAll(fd,std::string(egressReply)+t+"\n",ms);if(fd>=0)close(fd);return ok?0:1; }

class ByoProbe final:public NeuronHubDispatch {
  std::unique_ptr<NeuronHub> hub;std::atomic<bool> stop{false};std::atomic<int> listener{-1};in6_addr source={};uint16_t sourcePort=0;std::string proofChallenge,proofCommit,proofRow,proofBinary;
  static bool whiteholeOK(const Whitehole&w) { const auto& address=*reinterpret_cast<const in6_addr*>(w.address.v6);return whiteholeDeclarationValid(w)&&w.hasAddress&&w.family==ExternalAddressFamily::ipv6&&w.address.is6&&byo(address)&&w.transport==ExternalAddressTransport::tcp&&w.sourcePort&&owns(address); }
  void closeListener(){int fd=listener.exchange(-1);if(fd>=0)close(fd);}
  bool install(const Vector<Wormhole>&ws) { closeListener();for(const auto&w:ws){const auto& address=*reinterpret_cast<const in6_addr*>(w.externalAddress.v6);if(!w.externalAddress.is6||!byo(address)||w.layer4!=IPPROTO_TCP||!w.externalPort||!w.containerPort)continue;int fd=socket(AF_INET6,SOCK_STREAM|SOCK_CLOEXEC|SOCK_NONBLOCK,0),one=1;sockaddr_in6 a={};a.sin6_family=AF_INET6;a.sin6_addr=in6addr_any;a.sin6_port=htons(w.containerPort);if(fd>=0&&!setsockopt(fd,SOL_SOCKET,SO_REUSEADDR,&one,sizeof(one))&&!setsockopt(fd,IPPROTO_IPV6,IPV6_V6ONLY,&one,sizeof(one))&&!bind(fd,reinterpret_cast<sockaddr*>(&a),sizeof(a))&&!listen(fd,16)){listener=fd;return true;}if(fd>=0)close(fd);}return false; }
  void serve(){while(!stop){int l=listener;if(l<0||!wait(l,POLLIN,250))continue;int fd=accept4(l,nullptr,nullptr,SOCK_NONBLOCK|SOCK_CLOEXEC);if(fd<0)continue;std::string t;bool ok=readChallenge(fd,ingress,t,runtimeTimeout)&&noTrailing(fd);if(ok)(void)writeAll(fd,std::string(reply)+t+"\n",runtimeTimeout);close(fd);}}
  void prove(){const char* observer=getenv("G6_BYO_TRACE_ADDRESS");const char* host=getenv("G6_BYO_TRACE_HOST");if(!observer)observer="2606:4700::6810:84e5";if(!host)host="cloudflare.com";for(int backoff=250;!stop;backoff=backoff<4000?backoff*2:4000){std::string assigned,observed;if(traceOnce(source,sourcePort,observer,host,assigned,observed)){printf("g6_byo_trace assigned=%s observed=%s challenge=%s candidateCommit=%s row=%s binarySHA256=%s\n",assigned.c_str(),observed.c_str(),proofChallenge.c_str(),proofCommit.c_str(),proofRow.c_str(),proofBinary.c_str());fflush(stdout);hub->signalRuntimeReady();return;}std::this_thread::sleep_for(std::chrono::milliseconds(backoff));}}
 public:
  void beginShutdown()override{stop=true;closeListener();} void endOfDynamicArgs()override{} void wormholesRefresh(const Vector<Wormhole>&ws)override{(void)install(ws);}
  void prepare(int argc,char**argv){Ring::createRing(64,128,512,128,-1,-1,0);hub=std::make_unique<NeuronHub>(this);hub->fillFromMainArgs(argc,argv);hub->afterRing();bool validSource=false;for(const auto&w:hub->parameters.whiteholes)if(whiteholeOK(w)){memcpy(&source,w.address.v6,sizeof(source));sourcePort=w.sourcePort;validSource=true;break;}if(!validSource||!install(hub->parameters.wormholes)||!proofMatchesExecutable("/g6-byo-proof","/proc/self/exe",proofChallenge,proofCommit,proofRow,proofBinary)){fprintf(stderr,"G6 BYO requires in-prefix IPv6 bindings and rollout-bound executable identity\n");exit(EXIT_FAILURE);}hub->signalReady();std::thread([this]{serve();}).detach();std::thread([this]{prove();}).detach();}
  void start(){Ring::start();}
};
}
int main(int argc,char**argv){if(argc>=2&&!strcmp(argv[1],"wormhole"))return wormhole(argc,argv);if(argc>=2&&!strcmp(argv[1],"whitehole"))return whitehole(argc,argv);if(argc>=2&&!strcmp(argv[1],"trace-selftest"))return traceSelftest(argc,argv);if(argc>=2&&!strcmp(argv[1],"proof-selftest"))return proofSelftest(argc,argv);ByoProbe probe;probe.prepare(argc,argv);probe.start();return 0;}
