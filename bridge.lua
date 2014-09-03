local open_interface = function(name)
	local iface = { }

	os.execute("ifconfig " .. name .. " promisc")

	iface.name = name
	iface.consumer = brilter.netmap_consumer(name)
	iface.producer = brilter.netmap_producer(name)

	return iface
end

local lan = open_interface("em2")
local wan = open_interface("em0")

local IP6_LINK_LOCAL_TRAFFIC_P = "(ip6 src net fe80::/112 and ip6 dst net fe80::/112)"
local IP6_MULTICAST_P = "(ip6 multicast)"
local ICMP6_P = "(icmp6)"
local IP6_TCP_P = "(ip6 proto \\tcp)"
local TCP_DST_PORT_P = function(port) return "(tcp dst port " .. port .. ")" end
local TCP_SYN_P = "(tcp[tcpflags] & (tcp-syn | tcp-ack) == tcp-syn)"

--
--	Allow link-local traffic, multicast and icmp6 in both directions.
--
local BASE_FILTER = "(" .. IP6_LINK_LOCAL_TRAFFIC_P .. "||" .. IP6_MULTICAST_P .. "||" .. ICMP6_P .. ")"

--
-- Allow inbound traffic TCP traffic that isn't a SYN unless the destination port is 22.
--
-- XXX This doesn't properly filter incoming SYNs because pcap-filter fails to handle TCP fields within IPv6.
--
local INBOUND_FILTER = "(" .. BASE_FILTER .. "||" .. "(" .. IP6_TCP_P .. "&&" .. "(" .. "(" .. "!" .. TCP_SYN_P .. ")" .. "||" .. "(" .. TCP_DST_PORT_P("22") .. ")" .. ")" .. ")" .. ")"

--
-- Allow outbound traffic that is TCP, or that meets the base criteria.
--
local OUTBOUND_FILTER = "(" .. BASE_FILTER .. "||" .. IP6_TCP_P .. ")"

local outbound = {
	producer = lan.producer,
	processor = brilter.pcap_filter_processor(OUTBOUND_FILTER),
	consumer = wan.consumer,
}

local inbound = {
	producer = wan.producer,
	processor = brilter.pcap_filter_processor(INBOUND_FILTER),
	consumer = lan.consumer,
}

local outbound_pipe = brilter.pipe_start(outbound.producer, outbound.processor, outbound.consumer)
local inbound_pipe = brilter.pipe_start(inbound.producer, inbound.processor, inbound.consumer)

brilter.pipe_wait(outbound_pipe)
brilter.pipe_wait(inbound_pipe)
