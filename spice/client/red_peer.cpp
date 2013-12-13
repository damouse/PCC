/* -*- Mode: C; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
   Copyright (C) 2009 Red Hat, Inc.

   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with this library; if not, see <http://www.gnu.org/licenses/>.
*/
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#ifdef WIN32
#include <winsock2.h>
#endif
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <spice/protocol.h>
#include "common/ssl_verify.h"

#include "common.h"
#include "red_peer.h"
#include "utils.h"
#include "debug.h"
#include "platform_utils.h"

static void SPICE_GNUC_NORETURN ssl_error()
{
    unsigned long last_error = ERR_peek_last_error();

    ERR_print_errors_fp(stderr);
    THROW_ERR(SPICEC_ERROR_CODE_SSL_ERROR, "SSL Error: %s", ERR_error_string(last_error, NULL));
}

RedPeer::RedPeer()
    : _peer (INVALID_SOCKET)
    , _shut (false)
    , _ctx (NULL)
    , _ssl (NULL)
{
    //CHANGED ADD
    for(int i = 0; i< 100; i++)
        {
            readBufArray[i].sockfd = -1;
        }

    //
}

RedPeer::~RedPeer()
{
    cleanup();
}

void RedPeer::cleanup()
{
    if (_ssl) {
        SSL_free(_ssl);
        _ssl = NULL;
    }

    if (_ctx) {
        SSL_CTX_free(_ctx);
        _ctx = NULL;
    }

    if (_peer != INVALID_SOCKET) {
        closesocket(_peer);
        _peer = INVALID_SOCKET;
    }
}

void RedPeer::connect_to_peer(const char* host, int portnr)
{
    struct addrinfo ai, *result = NULL, *e;
    char uaddr[INET6_ADDRSTRLEN+1];
    char uport[33], port[33];
    int err = 0, rc, no_delay = 1;
    ASSERT(_ctx == NULL && _ssl == NULL && _peer == INVALID_SOCKET);
    try {
        memset(&ai,0, sizeof(ai));
        ai.ai_flags = AI_CANONNAME;
#ifdef AI_ADDRCONFIG
        ai.ai_flags |= AI_ADDRCONFIG;
#endif
        ai.ai_family = PF_UNSPEC;
        // CHANGED
        ai.ai_socktype = SOCK_DGRAM;
        //        ai.ai_socktype = SOCK_STREAM;
        snprintf(port, sizeof(port), "%d", portnr);
        rc = getaddrinfo(host, port, &ai, &result);
        if (rc != 0) {
            THROW_ERR(SPICEC_ERROR_CODE_GETHOSTBYNAME_FAILED, "cannot resolve host address %s", host);
        }
        Lock lock(_lock);
        _peer = INVALID_SOCKET;
        for (e = result; e != NULL; e = e->ai_next) {
            //change -add
            printf("socktype: %i, sockdgram: %i protocol: %i, udp: %i\n", e->ai_socktype, SOCK_DGRAM,  e->ai_protocol, IPPROTO_UDP);
            //
            if ((_peer = socket(e->ai_family, e->ai_socktype, e->ai_protocol)) == INVALID_SOCKET) {
                int err = sock_error();
                THROW_ERR(SPICEC_ERROR_CODE_SOCKET_FAILED, "failed to create socket: %s (%d)",
                          sock_err_message(err), err);
            }
            //CHANGED -adding
            /* if (bind(_peer, (struct sockaddr *) e->ai_addr, sizeof(*e->ai_addr)) < 0) { */
            /*     perror("bind failed"); */
            /*     THROW_ERR(SPICEC_ERROR_CODE_SOCKET_FAILED, "failed to bind socket: %s (%d)", */
            /*               sock_err_message(err), err); */
            /* } */
            //

            //CHANGED
            /* if (setsockopt(_peer, IPPROTO_TCP, TCP_NODELAY, (const char*)&no_delay, sizeof(no_delay)) == */
            /*     SOCKET_ERROR) { */
            /*     LOG_WARN("set TCP_NODELAY failed"); */
            /* } */

            getnameinfo((struct sockaddr*)e->ai_addr, e->ai_addrlen,
                        uaddr,INET6_ADDRSTRLEN, uport,32,
                        NI_NUMERICHOST | NI_NUMERICSERV);
            DBG(0, "Trying %s %s", uaddr, uport);
            //CHANGED
            /* if (::connect(_peer, e->ai_addr, e->ai_addrlen) == SOCKET_ERROR) { */
            /*     err = sock_error(); */
            /*     LOG_INFO("Connect failed: %s (%d)", */
            /*              sock_err_message(err), err); */
            /*     closesocket(_peer); */
            /*     _peer = INVALID_SOCKET; */
            /*     continue; */
            /* } */

            //CHANGED - ADD
            printf("HERE\n");
            uint8_t buf[10];
            memset(buf, 0, sizeof(buf));
            /* for(int i = 0; i < sizeof(buf); i++) */
            /*     { */
            /*         buf[i] = 0; */
            /*     } */
            //            send(buf, sizeof(buf));//1  //get the event to trigger to accept connection.
            //            send(buf,sizeof(buf)); //1
            sendto(_peer, buf, sizeof(buf), NULL, e->ai_addr, e->ai_addrlen); //1
            sockaddr_in addr_in;
            int len = sizeof(addr_in);
            recvfrom(_peer, buf, sizeof(buf), NULL,(sockaddr*) &addr_in, (socklen_t*) &len); //4
            printf("Received IP: %s Port: %i\n", inet_ntoa(addr_in.sin_addr), addr_in.sin_port);
            /* if ((_peer = socket(addr_in.sin_family, SOCK_DGRAM, IPPROTO_UDP)) == INVALID_SOCKET) { */
            /*     int err = sock_error(); */
            /*     THROW_ERR(SPICEC_ERROR_CODE_SOCKET_FAILED, "failed to create socket: %s (%d)", */
            /*               sock_err_message(err), err); */

            /* } */

            if (::connect(_peer, (sockaddr* )&addr_in,(socklen_t) len) == SOCKET_ERROR) { //5
                err = sock_error();
                LOG_INFO("Connect failed: %s (%d)",
                         sock_err_message(err), err);
                closesocket(_peer);
                _peer = INVALID_SOCKET;
                continue;
            }
            printf("Sending to new socket\n");
            send(buf, sizeof(buf)); //6
            printf("aftersend\n");
            /* for(int i = 1; i<2; i++) */
            /*     { */
            /*         send(buf,sizeof(buf)); */
            /*         sleep(1); */
            /*     } */

            
            //

            int index = 0;
            for(; readBufArray[index].sockfd != -1; index++){}
            readBufArray[index].read_offset = 0;
            readBufArray[index].write_offset = 0;
            readBufArray[index].sockfd = _peer;
            readBufArray[index].readBuffer = (char*) malloc(READBUFFERSIZE);
            DBG(0, "Connected to %s %s", uaddr, uport);
            break;
        }
        lock.unlock();
        freeaddrinfo(result);
        if (_peer == INVALID_SOCKET) {
            THROW_ERR(SPICEC_ERROR_CODE_CONNECT_FAILED, "failed to connect: %s (%d)",
                      sock_err_message(err), err);
        }
        _serial = 0;
    } catch (...) {
        Lock lock(_lock);
        cleanup();
        throw;
    }
}

void RedPeer::connect_unsecure(const char* host, int portnr)
{
    connect_to_peer(host, portnr);
    ASSERT(_ctx == NULL && _ssl == NULL && _peer != INVALID_SOCKET);
    LOG_INFO("Connected to %s %d", host, portnr);
}

void RedPeer::connect_secure(const ConnectionOptions& options, const char* host)
{
    int return_code;
    SPICE_SSL_VERIFY_OP auth_flags;
    SpiceOpenSSLVerify* verify = NULL;
    int portnr = options.secure_port;

    connect_to_peer(host, portnr);
    ASSERT(_ctx == NULL && _ssl == NULL && _peer != INVALID_SOCKET);
    LOG_INFO("Connected to %s %d", host, portnr);

    try {
#if OPENSSL_VERSION_NUMBER >= 0x10000000L
        const SSL_METHOD *ssl_method = TLSv1_method();
#else
        SSL_METHOD *ssl_method = TLSv1_method();
#endif
        _ctx = SSL_CTX_new(ssl_method);
        if (_ctx == NULL) {
            ssl_error();
        }

        auth_flags = options.host_auth.type_flags;
        if ((auth_flags & SPICE_SSL_VERIFY_OP_HOSTNAME) ||
            (auth_flags & SPICE_SSL_VERIFY_OP_SUBJECT)) {
            std::string CA_file = options.host_auth.CA_file;
            ASSERT(!CA_file.empty());

            return_code = SSL_CTX_load_verify_locations(_ctx, CA_file.c_str(), NULL);
            if (return_code != 1) {
                if (auth_flags & SPICE_SSL_VERIFY_OP_PUBKEY) {
                    LOG_WARN("SSL_CTX_load_verify_locations failed, CA_file=%s. "
                             "only pubkey authentication is active", CA_file.c_str());
                    auth_flags = SPICE_SSL_VERIFY_OP_PUBKEY;
                }
                else {
                    LOG_ERROR("SSL_CTX_load_verify_locations failed CA_file=%s", CA_file.c_str());
                    ssl_error();
                }
            }
        }

        return_code = SSL_CTX_set_cipher_list(_ctx, options.ciphers.c_str());
        if (return_code != 1) {
            LOG_ERROR("SSL_CTX_set_cipher_list failed, ciphers=%s", options.ciphers.c_str());
            ssl_error();
        }

        _ssl = SSL_new(_ctx);
        if (!_ssl) {
            THROW("create ssl failed");
        }

        verify = spice_openssl_verify_new(
            _ssl, auth_flags,
            host,
            (char*)&options.host_auth.host_pubkey[0],
            options.host_auth.host_pubkey.size(),
            options.host_auth.host_subject.c_str());

        BIO* sbio = BIO_new_socket(_peer, BIO_NOCLOSE);
        if (!sbio) {
            THROW("alloc new socket bio failed");
        }

        SSL_set_bio(_ssl, sbio, sbio);

        return_code = SSL_connect(_ssl);
        if (return_code <= 0) {
            int ssl_error_code = SSL_get_error(_ssl, return_code);
            LOG_ERROR("failed to connect w/SSL, ssl_error %s",
                     ERR_error_string(ssl_error_code, NULL));
            ssl_error();
        }
    } catch (...) {
        Lock lock(_lock);
        spice_openssl_verify_free(verify);
        cleanup();
        throw;
    }

    spice_openssl_verify_free(verify);
}

void RedPeer::shutdown()
{
    if (_peer != INVALID_SOCKET) {
        if (_ssl) {
            SSL_shutdown(_ssl);
        }
        ::shutdown(_peer, SHUT_RDWR);
    }
    _shut = true;
}

void RedPeer::disconnect()
{
    Lock lock(_lock);
    shutdown();
}

void RedPeer::close()
{
    Lock lock(_lock);
    if (_peer != INVALID_SOCKET) {
        if (_ctx) {
            SSL_free(_ssl);
            _ssl = NULL;
            SSL_CTX_free(_ctx);
            _ctx = NULL;
        }

        closesocket(_peer);
        _peer = INVALID_SOCKET;
    }
}

void RedPeer::swap(RedPeer* other)
{
    Lock lock(_lock);
    SOCKET temp_peer = _peer;
    SSL_CTX *temp_ctx = _ctx;
    SSL *temp_ssl = _ssl;

    _peer = other->_peer;
    other->_peer = temp_peer;

    if (_ctx) {
        _ctx = other->_ctx;
        _ssl = other->_ssl;

        other->_ctx = temp_ctx;
        other->_ssl = temp_ssl;
    }

    if (_shut) {
        shutdown();
    }
}

int RedPeer::ourReceive(int sock, char *buf, int size, int doNothing)
{
    //CHANGED -add
    int index = 0;
    for(; readBufArray[index].sockfd != sock; index++){}
    struct sockBuffer* readSockBuffer = &readBufArray[index]; 
    int readSize = 10000;
    int howMuchRead = 0;
    char* ourBuffer = (char*) malloc(readSize);
    if((readSize = read(sock, ourBuffer, readSize)) != -1)
        {
            int tmpWriteOffset = (readSockBuffer->write_offset + readSize) % READBUFFERSIZE;
            if(readSockBuffer->read_offset < tmpWriteOffset)
                {
                    memcpy(readSockBuffer->readBuffer + readSockBuffer->write_offset, ourBuffer, readSize);
                }
            else
                {
                    int cpySoFar = READBUFFERSIZE - readSockBuffer->write_offset;
                    memcpy(readSockBuffer->readBuffer + readSockBuffer->write_offset, ourBuffer, cpySoFar);
                    memcpy(readSockBuffer->readBuffer, ourBuffer + cpySoFar, readSize - cpySoFar);
                }
            readSockBuffer->write_offset = (readSockBuffer->write_offset + readSize) % READBUFFERSIZE;
        }
    if(readSockBuffer->read_offset != readSockBuffer->write_offset)
        {
            if(readSockBuffer->read_offset < readSockBuffer->write_offset) //normal case
                {
                    if(readSockBuffer->write_offset - readSockBuffer->read_offset < size) //want to read more than is there
                        {
                            howMuchRead = readSockBuffer->write_offset - readSockBuffer->read_offset;
                            memcpy(buf, readSockBuffer->readBuffer +readSockBuffer->read_offset, howMuchRead);
                        }
                    else //we can read full size
                        {
                            memcpy(buf, readSockBuffer->readBuffer + readSockBuffer->read_offset, size);
                            howMuchRead = size;
                        }
                    readSockBuffer->read_offset += howMuchRead;
                            
                }
            else //write buffer has wrapped around
                {           
                    if(readSockBuffer->read_offset + size > READBUFFERSIZE) //then wraparound
                        {
                            int  readSoFar = READBUFFERSIZE - readSockBuffer->read_offset;
                            memcpy(buf, readSockBuffer->readBuffer + readSockBuffer->read_offset, READBUFFERSIZE - readSockBuffer->read_offset);
                            if(readSockBuffer->write_offset < size - (READBUFFERSIZE - readSockBuffer->read_offset))//we want to read more than is there
                                { 
                                    memcpy(buf + readSoFar, readSockBuffer->readBuffer, readSockBuffer->write_offset);
                                    howMuchRead = readSoFar + readSockBuffer->write_offset;
                                }
                            else //there is plenty there to read what they want
                                {
                                    memcpy(buf + readSoFar, readSockBuffer->readBuffer, size - readSoFar);
                                    howMuchRead = size;
                                }
                            readSockBuffer->read_offset = howMuchRead - (READBUFFERSIZE - readSockBuffer->read_offset);
                        }
                }
            free(ourBuffer);
            return howMuchRead;
        }
    else
        {
            free(ourBuffer);
            return -1;
        }

}

uint32_t RedPeer::receive(uint8_t *buf, uint32_t size)
{
    uint8_t *pos = buf;
    while (size) {
        int now;
        if (_ctx == NULL) {
            //changed recv to ourreevie
            if ((now = ourReceive(_peer, (char *)pos, size, 0)) <= 0) {
                int err = sock_error();
                if (now == SOCKET_ERROR && err == WOULDBLOCK_ERR) {
                    break;
                }

                if (now == 0 || err == SHUTDOWN_ERR) {
                    throw RedPeer::DisconnectedException();
                }

                if (err == INTERRUPTED_ERR) {
                    continue;
                }
                THROW_ERR(SPICEC_ERROR_CODE_RECV_FAILED, "%s (%d)", sock_err_message(err), err);
            }
            size -= now;
            pos += now;
        } else {
            if ((now = SSL_read(_ssl, pos, size)) <= 0) {
                int ssl_error = SSL_get_error(_ssl, now);

                if (ssl_error == SSL_ERROR_WANT_READ) {
                    break;
                }

                if (ssl_error == SSL_ERROR_SYSCALL) {
                    int err = sock_error();
                    if (now == -1) {
                        if (err == WOULDBLOCK_ERR) {
                            break;
                        }
                        if (err == INTERRUPTED_ERR) {
                            continue;
                        }
                    }
                    if (now == 0 || (now == -1 && err == SHUTDOWN_ERR)) {
                        throw RedPeer::DisconnectedException();
                    }
                    THROW_ERR(SPICEC_ERROR_CODE_SEND_FAILED, "%s (%d)", sock_err_message(err), err);
                } else if (ssl_error == SSL_ERROR_ZERO_RETURN) {
                    throw RedPeer::DisconnectedException();
                }
                THROW_ERR(SPICEC_ERROR_CODE_RECV_FAILED, "ssl error %d", ssl_error);
            }
            size -= now;
            pos += now;
        }
    }
    return pos - buf;
}

RedPeer::CompoundInMessage* RedPeer::receive()
{
    SpiceDataHeader header;
    AutoRef<CompoundInMessage> message;

    receive((uint8_t*)&header, sizeof(SpiceDataHeader));
    message.reset(new CompoundInMessage(header.serial, header.type, header.size, header.sub_list));
    receive((*message)->data(), (*message)->compound_size());
    return message.release();
}

uint32_t RedPeer::send(uint8_t *buf, uint32_t size)
{
    uint8_t *pos = buf;
    while (size) {
        int now;

        if (_ctx == NULL) {
            if ((now = ::send(_peer, (char *)pos, size, 0)) == SOCKET_ERROR) {
                int err = sock_error();
                if (err == WOULDBLOCK_ERR) {
                    break;
                }
                if (err == SHUTDOWN_ERR) {
                    throw RedPeer::DisconnectedException();
                }
                if (err == INTERRUPTED_ERR) {
                    continue;
                }
                THROW_ERR(SPICEC_ERROR_CODE_SEND_FAILED, "%s (%d)", sock_err_message(err), err);
            }
            size -= now;
            pos += now;
        } else {
            if ((now = SSL_write(_ssl, pos, size)) <= 0) {
                int ssl_error = SSL_get_error(_ssl, now);

                if (ssl_error == SSL_ERROR_WANT_WRITE) {
                    break;
                }
                if (ssl_error == SSL_ERROR_SYSCALL) {
                    int err = sock_error();
                    if (now == -1) {
                        if (err == WOULDBLOCK_ERR) {
                            break;
                        }
                        if (err == INTERRUPTED_ERR) {
                            continue;
                        }
                    }
                    if (now == 0 || (now == -1 && err == SHUTDOWN_ERR)) {
                        throw RedPeer::DisconnectedException();
                    }
                    THROW_ERR(SPICEC_ERROR_CODE_SEND_FAILED, "%s (%d)", sock_err_message(err), err);
                } else if (ssl_error == SSL_ERROR_ZERO_RETURN) {
                    throw RedPeer::DisconnectedException();
                }
                THROW_ERR(SPICEC_ERROR_CODE_SEND_FAILED, "ssl error %d", ssl_error);
            }
            size -= now;
            pos += now;
        }
    }
    return pos - buf;
}

uint32_t RedPeer::do_send(RedPeer::OutMessage& message, uint32_t skip_bytes)
{
    uint8_t *data;
    int free_data;
    size_t len;
    uint32_t res;

    data = spice_marshaller_linearize(message.marshaller(), skip_bytes,
                                      &len, &free_data);

    res = send(data, len);

    if (free_data) {
        free(data);
    }
    return res;
}

uint32_t RedPeer::send(RedPeer::OutMessage& message)
{

    message.header().serial = ++_serial;
    message.header().size = message.message_size() - sizeof(SpiceDataHeader);

    return do_send(message, 0);
}

RedPeer::OutMessage::OutMessage(uint32_t type)
    : _marshaller (spice_marshaller_new())
{
    SpiceDataHeader *header;
    header = (SpiceDataHeader *)
        spice_marshaller_reserve_space(_marshaller, sizeof(SpiceDataHeader));
    spice_marshaller_set_base(_marshaller, sizeof(SpiceDataHeader));

    header->type = type;
    header->sub_list = 0;
}

void RedPeer::OutMessage::reset(uint32_t type)
{
    spice_marshaller_reset(_marshaller);

    SpiceDataHeader *header;
    header = (SpiceDataHeader *)
        spice_marshaller_reserve_space(_marshaller, sizeof(SpiceDataHeader));
    spice_marshaller_set_base(_marshaller, sizeof(SpiceDataHeader));

    header->type = type;
    header->sub_list = 0;
}

RedPeer::OutMessage::~OutMessage()
{
    spice_marshaller_destroy(_marshaller);
}
