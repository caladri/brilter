
#include <lauxlib.h>
#include <lua.h>
#include <lualib.h>

#include "netmap.h"
#include "pcap_filter.h"
#include "pipe.h"
#include "script.h"

#define	BRILTER_CONSUMER_TYPE	"brilter.consumer"
#define	BRILTER_PRODUCER_TYPE	"brilter.producer"
#define	BRILTER_PROCESSOR_TYPE	"brilter.processor"
#define	BRILTER_PIPE_TYPE	"brilter.type"

#define	SCRIPT_GET_UDATA(v, l, p, n)					\
	do {								\
		void **u;						\
									\
		u = luaL_checkudata(l, p, n);				\
		if (u == NULL)						\
			return (luaL_error(l, "could not get udata"));	\
									\
		v = *u;							\
	} while (0)

#define	SCRIPT_PUSH_UDATA(v, l, n)					\
	do {								\
		void **u;						\
									\
		u = lua_newuserdata(l, sizeof *u);			\
		if (u == NULL)						\
			return (luaL_error(l, "could not new udata"));	\
									\
		luaL_getmetatable(l, n);				\
		lua_setmetatable(l, -2);				\
									\
		*u = v;							\
	} while (0)

static int script_netmap_consumer(lua_State *);
static int script_netmap_producer(lua_State *);
static int script_pcap_filter_processor(lua_State *);
static int script_pipe_start(lua_State *);
static int script_pipe_wait(lua_State *);

static const luaL_Reg brilter_methods[] = {
	{ "netmap_consumer",		script_netmap_consumer },
	{ "netmap_producer",		script_netmap_producer },
	{ "pcap_filter_processor",	script_pcap_filter_processor },
	{ "pipe_start",			script_pipe_start },
	{ "pipe_wait",			script_pipe_wait },
	{ NULL,				NULL }
};

void
script_execute(const char *path)
{
	lua_State *L;

	L = luaL_newstate();
	luaL_openlibs(L);

	luaL_newlib(L, brilter_methods);
	lua_setglobal(L, "brilter");

	luaL_newmetatable(L, BRILTER_CONSUMER_TYPE);
	luaL_newmetatable(L, BRILTER_PRODUCER_TYPE);
	luaL_newmetatable(L, BRILTER_PROCESSOR_TYPE);
	luaL_newmetatable(L, BRILTER_PIPE_TYPE);

	luaL_dofile(L, path);
}

static int
script_netmap_consumer(lua_State *L)
{
	struct consumer *consumer;
	const char *ifname;

	ifname = luaL_checkstring(L, 1);
	if (ifname == NULL)
		return (luaL_error(L, "missing ifname"));

	consumer = netmap_consumer(ifname);
	if (consumer == NULL)
		return (luaL_error(L, "could not open consumer"));

	SCRIPT_PUSH_UDATA(consumer, L, BRILTER_CONSUMER_TYPE);
	return (1);
}

static int
script_netmap_producer(lua_State *L)
{
	struct producer *producer;
	const char *ifname;

	ifname = luaL_checkstring(L, 1);
	if (ifname == NULL)
		return (luaL_error(L, "missing ifname"));

	producer = netmap_producer(ifname);
	if (producer == NULL)
		return (luaL_error(L, "could not open producer"));

	SCRIPT_PUSH_UDATA(producer, L, BRILTER_PRODUCER_TYPE);
	return (1);
}

static int
script_pcap_filter_processor(lua_State *L)
{
	struct processor *processor;
	const char *filter;

	filter = luaL_checkstring(L, 1);
	if (filter == NULL)
		return (luaL_error(L, "missing filter"));

	processor = pcap_filter_processor(filter);
	if (processor == NULL)
		return (luaL_error(L, "could not create processor"));

	SCRIPT_PUSH_UDATA(processor, L, BRILTER_PROCESSOR_TYPE);
	return (1);
}

static int
script_pipe_start(lua_State *L)
{
	struct producer *producer;
	struct processor *processor;
	struct consumer *consumer;
	struct pipe *pipe;

	SCRIPT_GET_UDATA(producer, L, 1, BRILTER_PRODUCER_TYPE);
	SCRIPT_GET_UDATA(processor, L, 2, BRILTER_PROCESSOR_TYPE);
	SCRIPT_GET_UDATA(consumer, L, 3, BRILTER_CONSUMER_TYPE);

	pipe = pipe_start(producer, processor, consumer);

	SCRIPT_PUSH_UDATA(pipe, L, BRILTER_PIPE_TYPE);
	return (1);
}

static int
script_pipe_wait(lua_State *L)
{
	struct pipe *pipe;

	SCRIPT_GET_UDATA(pipe, L, 1, BRILTER_PIPE_TYPE);

	pipe_wait(pipe);
	return (0);
}
