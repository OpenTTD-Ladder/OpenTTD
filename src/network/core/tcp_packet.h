/* $Id$ */

/*
 * This file is part of OpenTTD.
 * OpenTTD is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 2.
 * OpenTTD is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details. You should have received a copy of the GNU General Public License along with OpenTTD. If not, see <http://www.gnu.org/licenses/>.
 */

/**
 * @file tcp_packet.h Basic functions to receive and send TCP packets.
 */

#ifndef NETWORK_CORE_TCP_PACKET_H
#define NETWORK_CORE_TCP_PACKET_H

#include "os_abstraction.h"
#include "packet.h"

#ifdef ENABLE_NETWORK

/** The states of sending the packets. */
enum SendPacketsState {
	SPS_CLOSED,      ///< The connection got closed.
	SPS_NONE_SENT,   ///< The buffer is still full, so no (parts of) packets could be sent.
	SPS_PARTLY_SENT, ///< The packets are partly sent; there are more packets to be sent in the queue.
	SPS_ALL_SENT,    ///< All packets in the queue are sent.
};

/** Base socket handler for all TCP sockets */
class NetworkTCPPacketSocketHandler : public NetworkSocketHandler {
private:
	Packet *packet_queue;     ///< Packets that are awaiting delivery
	Packet *packet_recv;      ///< Partially received packet
public:
	SOCKET sock;              ///< The socket currently connected to
	bool writable;            ///< Can we write to this socket?

	/**
	 * Whether this socket is currently bound to a socket.
	 * @return true when the socket is bound, false otherwise
	 */
	bool IsConnected() const { return this->sock != INVALID_SOCKET; }

	virtual NetworkRecvStatus CloseConnection(bool error = true);
	virtual void SendPacket(Packet *packet);
	SendPacketsState SendPackets(bool closing_down = false);

	virtual Packet *ReceivePacket();

	bool CanSendReceive();

	/**
	 * Whether there is something pending in the send queue.
	 * @return true when something is pending in the send queue.
	 */
	bool HasSendQueue() { return this->packet_queue != NULL; }

	NetworkTCPPacketSocketHandler(SOCKET s = INVALID_SOCKET);
	~NetworkTCPPacketSocketHandler();
};

#endif /* ENABLE_NETWORK */

#endif /* NETWORK_CORE_TCP_PACKET_H */
