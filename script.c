#include <assert.h>
#include <err.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdint.h>

#include <lauxlib.h>
#include <lua.h>
#include <lualib.h>

#include "cdefs.h"
#include "consumer.h"
#include "netmap.h"
#include "packet.h"
#include "pcap_filter.h"
#include "pipe.h"
#include "processor.h"
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

struct script_predicate_processor {
	struct processor spp_processor;
	lua_State *spp_thread;
	int spp_thread_registry_key;
	int spp_function_registry_key;
};

static int script_netmap_consumer(lua_State *);
static int script_netmap_producer(lua_State *);
static int script_pcap_filter_processor(lua_State *);
static int script_pipe_start(lua_State *);
static int script_pipe_wait(lua_State *);
static int script_predicate_processor(lua_State *);

static bool script_predicate_pass(void *, const struct packet *);
static void script_predicate_process(struct processor *, struct packet *, size_t, struct consumer *);

static const luaL_Reg brilter_methods[] = {
	{ "netmap_consumer",		script_netmap_consumer },
	{ "netmap_producer",		script_netmap_producer },
	{ "pcap_filter_processor",	script_pcap_filter_processor },
	{ "pipe_start",			script_pipe_start },
	{ "pipe_wait",			script_pipe_wait },
	{ "predicate_processor",	script_predicate_processor },
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
	lua_pop(L, 1);
	luaL_newmetatable(L, BRILTER_PRODUCER_TYPE);
	lua_pop(L, 1);
	luaL_newmetatable(L, BRILTER_PROCESSOR_TYPE);
	lua_pop(L, 1);
	luaL_newmetatable(L, BRILTER_PIPE_TYPE);
	lua_pop(L, 1);

	if (luaL_dofile(L, path))
		errx(1, "lua error: %s\n", lua_tostring(L, -1));
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

static int
script_predicate_processor(lua_State *L)
{
	struct script_predicate_processor *spp;

	luaL_checktype(L, 1, LUA_TFUNCTION);

	spp = malloc(sizeof *spp);
	if (spp == NULL)
		return (luaL_error(L, "could not create processor"));

	spp->spp_processor.p_process = script_predicate_process;

	/* Keep a reference to the function.  */
	spp->spp_function_registry_key = luaL_ref(L, LUA_REGISTRYINDEX);

	/* Create a new thread for this processor.  */
	spp->spp_thread = lua_newthread(L);
	spp->spp_thread_registry_key = luaL_ref(L, LUA_REGISTRYINDEX);

	/* Remove new thread from the stack.  */
	lua_pop(L, 1);

	SCRIPT_PUSH_UDATA(&spp->spp_processor, L, BRILTER_PROCESSOR_TYPE);
	return (1);
}

static bool
script_predicate_pass(void *arg, const struct packet *pkt)
{
	lua_State *L;
	bool pass;

	L = arg;

	/* Duplicate the predicate function at the top of the stack.  */
	lua_pushvalue(L, -1);

	/* Push the packet content as a string.  */
	lua_pushlstring(L, (const char *)pkt->p_data, pkt->p_datalen);

	/* Call the function with the packet data.  */
	lua_call(L, 1, 1);

	if (lua_type(L, -1) != LUA_TBOOLEAN) {
		(void)luaL_error(L, "return type of predicate function not boolean");
		return (false);
	}

	pass = lua_toboolean(L, -1);

	/* Pop the boolean from the stack.  */
	lua_pop(L, 1);

	return (pass);
}

static void
script_predicate_process(struct processor *processor, struct packet *pkts, size_t npkts, struct consumer *consumer)
{
	struct script_predicate_processor *spp;
	lua_State *L;

	spp = container_of(processor, struct script_predicate_processor, spp_processor);
	L = spp->spp_thread;

	/* Place the predicate function at the top of the stack.  */
	lua_rawgeti(L, LUA_REGISTRYINDEX, spp->spp_function_registry_key);

	process_predicate(script_predicate_pass, L, pkts, npkts, consumer);

	/* Pop the predicate function from the top of the stack.  */
	lua_pop(L, 1);
}
