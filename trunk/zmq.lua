local print = print
local string = string
local tonumber = tonumber
local setmetatable = setmetatable
local ffi = require('ffi')
local bit = require('bit')

ffi.cdef[[
void zmq_version (int *major, int *minor, int *patch);

int zmq_errno (void);
const char *zmq_strerror (int errnum);

void *zmq_ctx_new (void);
int zmq_ctx_term (void *context);
int zmq_ctx_shutdown (void *ctx_);
int zmq_ctx_set (void *context, int option, int optval);
int zmq_ctx_get (void *context, int option);

typedef struct {unsigned char _ [32];} zmq_msg_t;

typedef void (zmq_free_fn) (void *data, void *hint);

int zmq_msg_init (zmq_msg_t *msg);
int zmq_msg_init_size (zmq_msg_t *msg, size_t size);
int zmq_msg_init_data (zmq_msg_t *msg, void *data, size_t size, zmq_free_fn *ffn, void *hint);
int zmq_msg_send (zmq_msg_t *msg, void *s, int flags);
int zmq_msg_recv (zmq_msg_t *msg, void *s, int flags);
int zmq_msg_close (zmq_msg_t *msg);
int zmq_msg_move (zmq_msg_t *dest, zmq_msg_t *src);
int zmq_msg_copy (zmq_msg_t *dest, zmq_msg_t *src);
void *zmq_msg_data (zmq_msg_t *msg);
size_t zmq_msg_size (zmq_msg_t *msg);
int zmq_msg_more (zmq_msg_t *msg);
int zmq_msg_get (zmq_msg_t *msg, int option);
int zmq_msg_set (zmq_msg_t *msg, int option, int optval);

/*  Socket event data  */
typedef struct {
    uint16_t event;  // id of the event as bitfield
    int32_t  value ; // value is either error code, fd or reconnect interval
} zmq_event_t;

void *zmq_socket (void *, int type);
int zmq_close (void *s);
int zmq_setsockopt (void *s, int option, const void *optval, size_t optvallen);
int zmq_getsockopt (void *s, int option, void *optval, size_t *optvallen);
int zmq_bind (void *s, const char *addr);
int zmq_connect (void *s, const char *addr);
int zmq_unbind (void *s, const char *addr);
int zmq_disconnect (void *s, const char *addr);
int zmq_send (void *s, const void *buf, size_t len, int flags);
int zmq_send_const (void *s, const void *buf, size_t len, int flags);
int zmq_recv (void *s, void *buf, size_t len, int flags);
int zmq_socket_monitor (void *s, const char *addr, int events);

int zmq_sendmsg (void *s, zmq_msg_t *msg, int flags);
int zmq_recvmsg (void *s, zmq_msg_t *msg, int flags);

struct iovec;

int zmq_sendiov (void *s, struct iovec *iov, size_t count, int flags);
int zmq_recviov (void *s, struct iovec *iov, size_t *count, int flags);

typedef struct
{
    void *socket;
    int fd;
    short events;
    short revents;
} zmq_pollitem_t;

int zmq_poll (zmq_pollitem_t *items, int nitems, long timeout);
int zmq_proxy (void *frontend, void *backend, void *capture);
char *zmq_z85_encode (char *dest, uint8_t *data, size_t size);
uint8_t *zmq_z85_decode (uint8_t *dest, char *string);

int zmq_curve_keypair (char *z85_public_key, char *z85_secret_key);

typedef void (zmq_thread_fn) (void*);

void *zmq_stopwatch_start (void);
unsigned long zmq_stopwatch_stop (void *watch_);
void zmq_sleep (int seconds_);
void *zmq_threadstart (zmq_thread_fn* func, void* arg);
void zmq_threadclose (void* thread);
]]

local C = ffi.load('libzmq.dll')

module("zmq")

--Context options
IO_THREADS	= 1
MAX_SOCKETS	= 2

--Default for new contexts
IO_THREADS_DFLT = 1
MAX_SOCKETS_DFLT = 1023

--Socket types
PAIR		= 0
PUB			= 1
SUB			= 2
REQ			= 3
REP			= 4
DEALER		= 5
ROUTER		= 6
PULL		= 7
PUSH		= 8
XPUB		= 9
XSUB		= 10
STREAM		= 11

--Deprecated aliases
XREQ		= DEALER
XREP		= ROUTER

--Socket options.
AFFINITY	= 4
IDENTITY	= 5
SUBSCRIBE	= 6
UNSUBSCRIBE	= 7
RATE		= 8
RECOVERY_IVL	= 9
SNDBUF		= 11
RCVBUF		= 12
RCVMORE		= 13
FD			= 14
EVENTS		= 15
TYPE		= 16
LINGER		= 17
RECONNECT_IVL	= 18
BACKLOG		= 19
RECONNECT_IVL_MAX	= 21
MAXMSGSIZE	= 22
SNDHWM		= 23
RCVHWM		= 24
MULTICAST_HOPS	= 25
RCVTIMEO	= 27
SNDTIMEO	= 28
LAST_ENDPOINT	= 32
ROUTER_MANDATORY	= 33
TCP_KEEPALIVE	= 34
TCP_KEEPALIVE_CNT	= 35
TCP_KEEPALIVE_IDLE	= 36
TCP_KEEPALIVE_INTVL	= 37
TCP_ACCEPT_FILTER	= 38
IMMEDIATE	= 39
XPUB_VERBOSE	= 40
ROUTER_RAW	= 41
IPV6		= 42
MECHANISM	= 43
PLAIN_SERVER	= 44
PLAIN_USERNAME	= 45
PLAIN_PASSWORD	= 46
CURVE_SERVER	= 47
CURVE_PUBLICKEY	= 48
CURVE_SECRETKEY	= 49
CURVE_SERVERKEY	= 50
PROBE_ROUTER	= 51
REQ_CORRELATE	= 52
REQ_RELAXED		= 53
CONFLATE	= 54
ZAP_DOMAIN	= 55

--Message options
MORE		= 1

--Send/recv options
DONTWAIT	= 1
SNDMORE		= 2
NOBLOCK		= DONTWAIT

--Security mechanisms
NULL		= 0
PLAIN		= 1
CURVE		= 2

--Socket transport events (tcp and ipc only)
EVENT_CONNECTED			= 1
EVENT_CONNECT_DELAYED	= 2
EVENT_CONNECT_RETRIED	= 4
EVENT_LISTENING			= 8
EVENT_BIND_FAILED		= 16
EVENT_ACCEPTED			= 32
EVENT_ACCEPT_FAILED		= 64
EVENT_CLOSED			= 128
EVENT_CLOSE_FAILED		= 256
EVENT_DISCONNECTED		= 512
EVENT_MONITOR_STOPPED	= 1024
EVENT_ALL = bit.bor(EVENT_CONNECTED,EVENT_CONNECT_DELAYED,EVENT_CONNECT_RETRIED,EVENT_LISTENING,EVENT_BIND_FAILED,EVENT_ACCEPTED,EVENT_ACCEPT_FAILED,EVENT_CLOSED,EVENT_CLOSE_FAILED,EVENT_DISCONNECTED,EVENT_MONITOR_STOPPED)

--global zmq functions
function version()
	local major = ffi.new('int[1]')
	local minor = ffi.new('int[1]')
	local patch = ffi.new('int[1]')
	C.zmq_version(major, minor, patch)
	return string.format('%d.%d.%d', major[0], minor[0], patch[0])
end

function errno()
	return C.zmq_errno()
end

function strerror(err)
	return ffi.string(C.zmq_strerror(err));
end

function sleep(sec)
	C.zmq_sleep(sec)
end

function proxy(frontend, backend, capture)
	return C.zmq_proxy(frontend.ptr, backend.ptr, capture.ptr)
end

--zmq context
local ctx_meths = {}
local ctx_mt = { __index = ctx_meths }

function ctx_new()
	return setmetatable({
		ptr = C.zmq_ctx_new()
	}, ctx_mt)
end

function ctx_meths:term()
	return C.zmq_ctx_term(self.ptr)
end

function ctx_meths:shutdown()
	return C.zmq_ctx_shutdown(self.ptr)
end

function ctx_meths:set(opt, val)
	return C.zmq_ctx_set(self.ptr, opt, val)
end

function ctx_meths:get(opt)
	return C.zmq_ctx_get(self.ptr, opt)
end

function ctx_meths:socket(t)
	return sock_new(self, t)
end

--zmq message
local msg_meths = {}
local msg_mt = { __index = msg_meths }

function msg_new()
	return setmetatable({
		ptr = ffi.new('zmq_msg_t[1]')
	}, msg_mt)
end

function msg_meths:init()
	return C.zmq_msg_init(self.ptr)
end

function msg_meths:init_size(size)
	return C.zmq_msg_init_size(self.ptr, size)
end

function msg_meths:send(s, flags)
	return s.sendmsg(self, flags)
end

function msg_meths:recv(s, flags)
	return s.sendmsg(self, flags)
end

function msg_meths:close()
	return C.zmq_msg_close(self.ptr)
end

function msg_meths:move(dest)
	return C.zmq_msg_move(dest.ptr, self.ptr)
end

function msg_meths:copy(dest)
	return C.zmq_msg_copy(dest.ptr, self.ptr)
end

function msg_meths:data()
	return C.zmq_msg_data(self.ptr)
end

function msg_meths:size()
	return C.zmq_msg_size(self.ptr)
end

function msg_meths:more()
	return C.zmq_msg_more(self.ptr)
end

function msg_meths:get(opt)
	return C.zmq_msg_get(self.ptr, opt)
end

function msg_meths:set(opt, val)
	return C.zmq_msg_set(self.ptr, opt, val)
end

function msg_meths:tostring()
	return ffi.string(self:data(), self:size())
end

--zmq socket
local sock_meths = {}
local sock_mt = { __index = sock_meths }

function sock_new(ctx, t)
	return setmetatable({
		ptr = C.zmq_socket(ctx.ptr, t)
	}, sock_mt);
end

function sock_meths:close()
	return C.zmq_close(self.ptr)
end

function sock_meths:setsockopt(opt, val)
	return C.zmq_setsockopt(self.ptr, opt, val, #val)
end

function sock_meths:bind(addr)
	return C.zmq_bind(self.ptr, addr)
end

function sock_meths:connect(addr)
	return C.zmq_connect(self.ptr, addr)
end

function sock_meths:unbind(addr)
	return C.zmq_unbind(self.ptr, addr)
end

function sock_meths:disconnect(addr)
	return C.zmq_disconnect(self.ptr, addr)
end

function sock_meths:send(msg)
	return C.zmq_send(self.ptr, msg, #msg, 0)
end

function sock_meths:recv()
	local msg = msg_new()
	msg:init()
	self:recvmsg(msg, 0)
	return msg:tostring()
end

function sock_meths:sendmsg(msg, flags)
	return C.zmq_send(self.ptr, msg.ptr, msg:size(), flags)
end

function sock_meths:recvmsg(msg, flags)
	return C.zmq_recvmsg(self.ptr, msg.ptr, flags)
end
