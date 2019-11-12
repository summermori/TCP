/*
 *  chiTCP - A simple, testable TCP stack
 *
 *  Implementation of the TCP protocol.
 *
 *  chiTCP follows a state machine approach to implementing TCP.
 *  This means that there is a handler function for each of
 *  the TCP states (CLOSED, LISTEN, SYN_RCVD, etc.). If an
 *  event (e.g., a packet arrives) while the connection is
 *  in a specific state (e.g., ESTABLISHED), then the handler
 *  function for that state is called, along with information
 *  about the event that just happened.
 *
 *  Each handler function has the following prototype:
 *
 *  int f(serverinfo_t *si, chisocketentry_t *entry, tcp_event_type_t event);
 *
 *  si is a pointer to the chiTCP server info. The functions in
 *       this file will not have to access the data in the server info,
 *       but this pointer is needed to call other functions.
 *
 *  entry is a pointer to the socket entry for the connection that
 *          is being handled. The socket entry contains the actual TCP
 *          data (variables, buffers, etc.), which can be extracted
 *          like this:
 *
 *            tcp_data_t *tcp_data = &entry->socket_state.active.tcp_data;
 *
 *          Other than that, no other fields in "entry" should be read
 *          or modified.
 *
 *  event is the event that has caused the TCP thread to wake up. The
 *          list of possible events corresponds roughly to the ones
 *          specified in http://tools.ietf.org/html/rfc793#section-3.9.
 *          They are:
 *
 *            APPLICATION_CONNECT: Application has called socket_connect()
 *            and a three-way handshake must be initiated.
 *
 *            APPLICATION_SEND: Application has called socket_send() and
 *            there is unsent data in the send buffer.
 *
 *            APPLICATION_RECEIVE: Application has called socket_recv() and
 *            any received-and-acked data in the recv buffer will be
 *            collected by the application (up to the maximum specified
 *            when calling socket_recv).
 *
 *            APPLICATION_CLOSE: Application has called socket_close() and
 *            a connection tear-down should be initiated.
 *
 *            PACKET_ARRIVAL: A packet has arrived through the network and
 *            needs to be processed (RFC 793 calls this "SEGMENT ARRIVES")
 *
 *            TIMEOUT: A timeout (e.g., a retransmission timeout) has
 *            happened.
 *
 */

/*
 *  Copyright (c) 2013-2014, The University of Chicago
 *  All rights reserved.
 *
 *  Redistribution and use in source and binary forms, with or withsend
 *  modification, are permitted provided that the following conditions are met:
 *
 *  - Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 *  - Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 *  - Neither the name of The University of Chicago nor the names of its
 *    contributors may be used to endorse or promote products derived from this
 *    software withsend specific prior written permission.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 *  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 *  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 *  ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 *  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 *  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 *  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 *  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 *  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 *  ARISING IN ANY WAY send OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 *  POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include "chitcp/log.h"
#include "chitcp/utils.h"
#include "chitcp/buffer.h"
#include "chitcp/chitcpd.h"
#include "serverinfo.h"
#include "connection.h"
#include "tcp.h"
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

int handle_packet(serverinfo_t *si, chisocketentry_t *entry);
int send_ack_pack(serverinfo_t *si, chisocketentry_t *entry, uint32_t ack_seq);
int send_fin_pack(serverinfo_t *si, chisocketentry_t *entry);


void tcp_data_init(serverinfo_t *si, chisocketentry_t *entry)
{
    tcp_data_t *tcp_data = &entry->socket_state.active.tcp_data;

    tcp_data->pending_packets = NULL;
    pthread_mutex_init(&tcp_data->lock_pending_packets, NULL);
    pthread_cond_init(&tcp_data->cv_pending_packets, NULL);

    /* Initialization of additional tcp_data_t fields,
     * and creation of retransmission thread, goes here */
}

void tcp_data_free(serverinfo_t *si, chisocketentry_t *entry)
{
    tcp_data_t *tcp_data = &entry->socket_state.active.tcp_data;

    circular_buffer_free(&tcp_data->send);
    circular_buffer_free(&tcp_data->recv);
    chitcp_packet_list_destroy(&tcp_data->pending_packets);
    pthread_mutex_destroy(&tcp_data->lock_pending_packets);
    pthread_cond_destroy(&tcp_data->cv_pending_packets);

    /* Cleanup of additional tcp_data_t fields goes here */
}


int chitcpd_tcp_state_handle_CLOSED(serverinfo_t *si, chisocketentry_t *entry, tcp_event_type_t event)
{
    if (event == APPLICATION_CONNECT)
    {
        tcp_data_init(si, entry);
        tcp_data_t *tcp_data = &entry->socket_state.active.tcp_data;
        circular_buffer_init(&tcp_data->recv, TCP_BUFFER_SIZE);
        tcphdr_t *header;
        //tcp_packet_t *packet = calloc(1,sizeof(tcp_packet_t));
        tcp_packet_t packet;
        chilog (INFO, "a");
        chitcpd_tcp_packet_create(entry, &packet, 0, 0);
        chilog (INFO, "b");    
        header = TCP_PACKET_HEADER(&packet);
        chilog (INFO, "c");   
        tcp_data->RCV_WND = tcp_data->recv.maxsize;
        chilog (INFO, "d");
        header->win = htons(tcp_data->RCV_WND);
        chilog (INFO, "e");
        header->syn = 1;
        chilog (INFO, "f");
        uint32_t iss = (uint32_t)(rand());
        header->seq = htonl(iss);
        tcp_data->ISS = iss;
        chitcpd_send_tcp_packet(si, entry, &packet);

        tcp_data->SND_UNA = tcp_data->ISS;
        tcp_data->SND_NXT = (1 + tcp_data->ISS);
        circular_buffer_init(&tcp_data->send, TCP_BUFFER_SIZE);
        circular_buffer_set_seq_initial(&tcp_data->send, 1 + iss);
        chitcpd_update_tcp_state(si, entry, SYN_SENT);
        //chilog (INFO, "ye");

    }
    else if (event == CLEANUP)
    {
        /* Any additional cleanup goes here */
    }
    else
        chilog(WARNING, "In CLOSED state, received unexpected event.");

    return CHITCP_OK;
}

int chitcpd_tcp_state_handle_LISTEN(serverinfo_t *si, chisocketentry_t *entry, tcp_event_type_t event)
{
    if (event == PACKET_ARRIVAL)
    {
        return handle_packet(si, entry);
    }
    else
        chilog(WARNING, "In LISTEN state, received unexpected event.");

    return CHITCP_OK;
}

int chitcpd_tcp_state_handle_SYN_RCVD(serverinfo_t *si, chisocketentry_t *entry, tcp_event_type_t event)
{
    if (event == PACKET_ARRIVAL)
    {
        return handle_packet(si, entry);
    }
    else if (event == TIMEOUT_RTX)
    {
    /* Your code goes here */
    }
    else
        chilog(WARNING, "In SYN_RCVD state, received unexpected event.");

    return CHITCP_OK;
}

int chitcpd_tcp_state_handle_SYN_SENT(serverinfo_t *si, chisocketentry_t *entry, tcp_event_type_t event)
{
    if (event == PACKET_ARRIVAL)
    {
        return handle_packet(si, entry);
    }
    else if (event == TIMEOUT_RTX)
    {
    /* Your code goes here */
    }
    else
        chilog(WARNING, "In SYN_SENT state, received unexpected event.");

    return CHITCP_OK;
}

int chitcpd_tcp_state_handle_ESTABLISHED(serverinfo_t *si, chisocketentry_t *entry, tcp_event_type_t event)
{
    if (event == APPLICATION_SEND)
    {
        int nbytes, maxbytes, pay_len;
        tcp_data_t *tcp_data = &entry->socket_state.active.tcp_data;
        tcp_packet_t fresh_packet;
        tcphdr_t *header;
        uint8_t tbs[TCP_MSS],total_pay[TCP_BUFFER_SIZE];
        pay_len = circular_buffer_peek(&tcp_data->send, total_pay, TCP_BUFFER_SIZE, 0);
        if(pay_len == EWOULDBLOCK)
        {pay_len = 0;}
        while(pay_len > 0)
        {
            memset(tbs, 0, TCP_MSS);
            if(tcp_data->SND_WND)
            {
                if(tcp_data->SND_WND < TCP_MSS)
                {
                    maxbytes = tcp_data->SND_WND;
                }
                else
                {
                    maxbytes = TCP_MSS;
                }
                
            }
            else
            {
                chilog (CRITICAL, "WNDW is 0");
                return CHITCP_OK;
            }
            nbytes = circular_buffer_read(&tcp_data->send, tbs, maxbytes, 1);
            if(!nbytes)
            {return -1;}
            chitcpd_tcp_packet_create(entry, &fresh_packet, tbs, nbytes);
            header = TCP_PACKET_HEADER(&fresh_packet);
            tcp_data->SND_WND -= nbytes;
            header->seq = htonl(tcp_data->SND_NXT + nbytes -1);
            header->win = htons(tcp_data->RCV_WND);
            tcp_data->SND_NXT += nbytes;
            pay_len -= nbytes;
        }
    }
    else if (event == PACKET_ARRIVAL)
    {
        return handle_packet(si, entry);
    }
    else if (event == APPLICATION_RECEIVE)
    {
        tcp_data_t *tcp_data = &entry->socket_state.active.tcp_data;
        tcp_data->RCV_WND = circular_buffer_available(&tcp_data->recv);
    }
    else if (event == APPLICATION_CLOSE)
    {
        send_fin_pack(si, entry);
    }
    else if (event == TIMEOUT_RTX)
    {
      /* Your code goes here */
    }
    else
        chilog(WARNING, "In ESTABLISHED state, received unexpected event (%i).", event);

    return CHITCP_OK;
}

int chitcpd_tcp_state_handle_FIN_WAIT_1(serverinfo_t *si, chisocketentry_t *entry, tcp_event_type_t event)
{
    if (event == PACKET_ARRIVAL)
    {
        return handle_packet(si, entry);
    }
    else if (event == APPLICATION_RECEIVE)
    {
        tcp_data_t *tcp_data = &entry->socket_state.active.tcp_data;
        tcp_data->RCV_WND = circular_buffer_available(&tcp_data->recv);
    }
    else if (event == TIMEOUT_RTX)
    {
      /* Your code goes here */
    }
    else
       chilog(WARNING, "In FIN_WAIT_1 state, received unexpected event (%i).", event);

    return CHITCP_OK;
}


int chitcpd_tcp_state_handle_FIN_WAIT_2(serverinfo_t *si, chisocketentry_t *entry, tcp_event_type_t event)
{
    if (event == PACKET_ARRIVAL)
    {
        return handle_packet(si, entry);
    }
    else if (event == APPLICATION_RECEIVE)
    {
        tcp_data_t *tcp_data = &entry->socket_state.active.tcp_data;
        tcp_data->RCV_WND = circular_buffer_available(&tcp_data->recv);
    }
    else if (event == TIMEOUT_RTX)
    {
      /* Your code goes here */
    }
    else
        chilog(WARNING, "In FIN_WAIT_2 state, received unexpected event (%i).", event);

    return CHITCP_OK;
}


int chitcpd_tcp_state_handle_CLOSE_WAIT(serverinfo_t *si, chisocketentry_t *entry, tcp_event_type_t event)
{
    if (event == APPLICATION_CLOSE)
    {
        send_fin_pack(si, entry);
        chitcpd_update_tcp_state(si, entry, LAST_ACK);
    }
    else if (event == PACKET_ARRIVAL)
    {
        return handle_packet(si, entry);
    }
    else if (event == TIMEOUT_RTX)
    {
      /* Your code goes here */
    }
    else
       chilog(WARNING, "In CLOSE_WAIT state, received unexpected event (%i).", event);


    return CHITCP_OK;
}


int chitcpd_tcp_state_handle_CLOSING(serverinfo_t *si, chisocketentry_t *entry, tcp_event_type_t event)
{
    if (event == PACKET_ARRIVAL)
    {
        return handle_packet(si, entry);
    }
    else if (event == TIMEOUT_RTX)
    {
      /* Your code goes here */
    }
    else
       chilog(WARNING, "In CLOSING state, received unexpected event (%i).", event);

    return CHITCP_OK;
}


int chitcpd_tcp_state_handle_TIME_WAIT(serverinfo_t *si, chisocketentry_t *entry, tcp_event_type_t event)
{
    chilog(WARNING, "Running handler for TIME_WAIT. This should not happen.");

    return CHITCP_OK;
}


int chitcpd_tcp_state_handle_LAST_ACK(serverinfo_t *si, chisocketentry_t *entry, tcp_event_type_t event)
{
    if (event == PACKET_ARRIVAL)
    {
        return handle_packet(si, entry);
    }
    else if (event == TIMEOUT_RTX)
    {
      /* Your code goes here */
    }
    else
       chilog(WARNING, "In LAST_ACK state, received unexpected event (%i).", event);

    return CHITCP_OK;
}

/*                                                           */
/*     Any additional functions you need should go here      */
/*                                                           */

int handle_packet(serverinfo_t *si, chisocketentry_t *entry)
{
    tcp_data_t *tcp_data = &entry->socket_state.active.tcp_data;
    tcp_packet_t *fresh_packet = list_fetch(&tcp_data->pending_packets);
    chilog(INFO, "Fresh Packet");
    chilog(INFO, "pack addr: 0x%x", fresh_packet);
    if(!fresh_packet)
    {
        chilog(ERROR, "no pending packet");
        return -1;
    }
    tcphdr_t *header = TCP_PACKET_HEADER(fresh_packet);
    if(header->res1)
    {
        chilog(ERROR, "res1!");
        return -1;
    }
    if((entry->tcp_state == LISTEN) && header->ack)
    {
        chilog(ERROR, "ACK while in LISTEN");
        return -1;
    }
    if(header->syn)
    {
        uint32_t irs = ntohl(header->seq);
        chilog(INFO, "syn seq: %d", irs);
        if(header->ack)
        {
            uint32_t ack_seq;
            ack_seq = ntohl(header->ack_seq);
            chilog(INFO, "ack seq: %d", ack_seq);
            if(!((tcp_data->SND_NXT >= ack_seq) && (tcp_data->SND_UNA <= ack_seq)))
            {
                chilog(ERROR, "Invalid ack_seq");
                return -1;
            }
            else
            {
                send_ack_pack(si, entry, irs + 1);
                tcp_data->SND_UNA = ack_seq;
                tcp_data->SND_WND = ntohs(header->win);
                tcp_data->RCV_NXT = irs + 1;
                tcp_data->IRS = irs;
                circular_buffer_set_seq_initial(&tcp_data->recv, irs + 1);
                chitcpd_update_tcp_state(si, entry, ESTABLISHED);
            }
        }    
        else
        {
            tcphdr_t *header2;
            tcp_packet_t ack_pack;
        
            circular_buffer_init(&tcp_data->recv, TCP_BUFFER_SIZE);
            circular_buffer_set_seq_initial(&tcp_data->recv, irs + 1);
            chitcpd_tcp_packet_create(entry, &ack_pack, 0, 0);

            tcp_data->SND_WND = ntohs(header->win);
            tcp_data->RCV_NXT = irs + 1;
            tcp_data->IRS = irs;

            header2 = TCP_PACKET_HEADER(&ack_pack);
            header2->ack = 1;
            header2->syn = 1;
            uint32_t iss = (uint32_t)(rand());
            header2->seq = htonl(iss);
            header2->ack_seq = htonl(tcp_data->RCV_NXT);

            tcp_data->ISS = iss;
            tcp_data->SND_UNA = iss;
            tcp_data->SND_NXT = iss + 1;
            tcp_data->RCV_WND = tcp_data->recv.maxsize;
            header2->win = htons(tcp_data->RCV_WND);

            circular_buffer_init(&tcp_data->send, TCP_BUFFER_SIZE);
            circular_buffer_set_seq_initial(&tcp_data->send, iss + 1);
            chitcpd_send_tcp_packet(si, entry, &ack_pack);
            chitcpd_update_tcp_state(si, entry, SYN_RCVD);
        }
    }
        else if(header->ack)
        {
            chilog (INFO, "ack pack seq: %d", ntohl(header->ack_seq));
            if(!(ntohl(header->ack_seq) <= tcp_data->SND_NXT))
            {
                chilog (ERROR, "invalid ack");
                return -1;
            }
            tcp_data->SND_UNA = ntohl(header->ack_seq);
            tcp_data->SND_WND = ntohs(header->win);
            if(tcp_data->SND_WND && (entry->tcp_state == ESTABLISHED))
            {chitcpd_tcp_state_handle_ESTABLISHED(si, entry, APPLICATION_SEND);}
            if(entry->tcp_state == LAST_ACK)
            {chitcpd_update_tcp_state(si, entry, CLOSED);}
            else if(entry->tcp_state == SYN_RCVD)
            {chitcpd_update_tcp_state(si, entry, ESTABLISHED);}
            else if(entry->tcp_state == CLOSING)
            {
                chitcpd_update_tcp_state(si, entry, CLOSED);
                chitcpd_update_tcp_state(si, entry, TIME_WAIT);
            }
            else if(entry->tcp_state == FIN_WAIT_1)
            {chitcpd_update_tcp_state(si, entry, FIN_WAIT_2);}
        }
        else if(header->fin)
        {
            uint32_t fin_seq;
            fin_seq = ntohl(header->seq);
            chilog (INFO, "fin pack seq: %d", fin_seq);
            if(!(fin_seq >= tcp_data->RCV_NXT))
            {
                chilog(ERROR, "Invalid fin_seq");
                return -1;
            }
            else
            {
                if(entry->tcp_state == ESTABLISHED)
                {chitcpd_update_tcp_state(si,entry,CLOSE_WAIT);}
                if(entry->tcp_state == FIN_WAIT_1)
                {chitcpd_update_tcp_state(si,entry,CLOSING);}
                if(entry->tcp_state == FIN_WAIT_2)
                {
                    chitcpd_update_tcp_state(si,entry,TIME_WAIT);
                    chitcpd_update_tcp_state(si, entry, CLOSED);
                }
                else
                {
                    chilog(ERROR, "unexpected fin packet");
                    return -1;
                }
                send_ack_pack(si, entry, fin_seq + 1);
            }
        }
        else
        {
            int pay_len = TCP_PAYLOAD_LEN(fresh_packet);
            chilog(INFO, "payload length: %d", pay_len);
            tcp_data->SND_WND = ntohs(header->win);
            if(pay_len > tcp_data->RCV_WND)
            {
                chilog(WARNING, "no space in buffer");
                send_ack_pack(si, entry, tcp_data->RCV_NXT);
            }
            else
            {
                if(!(ntohl(header->seq) <= tcp_data->RCV_NXT))
                {
                    chilog(ERROR, "unexpected sequence %d", ntohl(header->seq));
                    return 1;
                }
                else
                {
                    uint8_t* pay_ptr = TCP_PAYLOAD_START(fresh_packet);
                    chilog(INFO, "writing buffer...");
                    circular_buffer_write(&tcp_data->recv, pay_ptr, pay_len, 1);
                    chilog(INFO, "write success");
                    tcp_data->RCV_WND -= pay_len;
                    tcp_data->RCV_NXT += pay_len;
                    send_ack_pack(si, entry, tcp_data->RCV_NXT);
                }
                
            }
        }
        return CHITCP_OK;
}

int send_fin_pack(serverinfo_t *si, chisocketentry_t * entry)
{
    chilog(INFO, "sending fin pack");
    tcphdr_t *header;
    tcp_packet_t fin_pack;
    tcp_data_t *tcp_data = &entry->socket_state.active.tcp_data;
    chitcpd_tcp_packet_create(entry, &fin_pack, 0, 0);
    tcp_data->SND_NXT++;
    header = TCP_PACKET_HEADER(&fin_pack);
    header->seq = htonl(tcp_data->SND_NXT);
    header->fin = 1;
    header->win = htons(entry->socket_state.active.tcp_data.RCV_WND);
    chitcpd_send_tcp_packet(si, entry, &fin_pack);
    return CHITCP_OK;
}

int send_ack_pack(serverinfo_t *si, chisocketentry_t *entry, uint32_t ack_seq)
{
    tcphdr_t *header;
    tcp_packet_t ack_pack;
    chitcpd_tcp_packet_create(entry, &ack_pack, 0, 0);
    header->ack = 1;
    header->ack_seq = htonl(ack_seq);
    header->win = htons(entry->socket_state.active.tcp_data.RCV_WND);
    chitcpd_send_tcp_packet(si, entry, &ack_pack);
    chilog(INFO, "sending ack pack. seq: %d, wndw: %d", ack_seq, ntohs(header->win));
    return CHITCP_OK;
}