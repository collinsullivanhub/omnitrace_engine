#define PY_SSIZE_T_CLEAN
#include <Python.h>

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <process.h>
typedef SOCKET socket_t;
#define CLOSE_SOCKET(s) closesocket(s)
#define IS_INVALID_SOCKET(s) ((s) == INVALID_SOCKET)
#define GET_PID() ((uint16_t)(GetCurrentProcessId() & 0xFFFF))
#else
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>
#include <netdb.h>
#include <fcntl.h>
typedef int socket_t;
#define CLOSE_SOCKET(s) close(s)
#define IS_INVALID_SOCKET(s) ((s) < 0)
#define INVALID_SOCKET (-1)
#define SOCKET_ERROR (-1)
#define GET_PID() ((uint16_t)(getpid() & 0xFFFF))
#endif

/* Protocols for probing */
typedef enum {
    PROT_ICMP,
    PROT_UDP,
    PROT_TCP,
    PROT_ICMP_TOS,
    PROT_ICMP_NODF,
    PROT_UDP_DNS,
    PROT_UDP_QUIC,
    PROT_UDP_NTP
} probe_protocol_t;

/* Packet structures */
#ifdef _MSC_VER
#pragma pack(push, 1)
#endif

struct icmp_hdr {
    uint8_t type;
    uint8_t code;
    uint16_t checksum;
    uint16_t id;
    uint16_t seq;
}
#ifndef _MSC_VER
__attribute__((packed))
#endif
;

struct icmp_packet {
    struct icmp_hdr hdr;
    char payload[32];
}
#ifndef _MSC_VER
__attribute__((packed))
#endif
;

#ifdef _MSC_VER
#pragma pack(pop)
#endif

/* Hop results struct used in the C thread (GIL-free) */
typedef struct {
    int hop;
    char ip[64];
    double min_ms;
    double max_ms;
    double sum_ms;
    int sent;
    int received;
    char proto[16];
    char device[32];
} hop_result_t;

/* Global counter to make trace IDs unique across concurrent runs */
static volatile uint16_t global_trace_id_counter = 0;

/* Standard 16-bit 1's complement Internet checksum */
static uint16_t calculate_checksum(unsigned short *addr, int count) {
    uint32_t sum = 0;
    while (count > 1) {
        sum += *addr++;
        count -= 2;
    }
    if (count > 0) {
        sum += *(unsigned char *)addr;
    }
    while (sum >> 16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    return (uint16_t)(~sum);
}

/* High-precision monotonic time helper in milliseconds */
static double get_time_ms(void) {
#ifdef _WIN32
    LARGE_INTEGER count, freq;
    QueryPerformanceCounter(&count);
    QueryPerformanceFrequency(&freq);
    return (double)count.QuadPart * 1000.0 / (double)freq.QuadPart;
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec * 1000.0 + (double)ts.tv_nsec / 1000000.0;
#endif
}

/* Fingerprint OS / device family based on the received TTL of the responder */
static void fingerprint_device(uint8_t ttl, char *output) {
    if (ttl > 128 && ttl <= 255) {
        int hops = 255 - ttl;
        sprintf(output, "Cisco/Core (dist=%d)", hops);
    } else if (ttl > 64 && ttl <= 128) {
        int hops = 128 - ttl;
        sprintf(output, "Windows/Host (dist=%d)", hops);
    } else if (ttl > 0 && ttl <= 64) {
        int hops = 64 - ttl;
        sprintf(output, "Linux/Juniper (dist=%d)", hops);
    } else {
        strcpy(output, "Unknown");
    }
}

/* Create a non-blocking TCP socket and trigger a TCP SYN packet */
static socket_t create_tcp_syn_probe(struct sockaddr_in *dest_addr, int ttl, uint16_t *local_port) {
    socket_t s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (IS_INVALID_SOCKET(s)) return s;

    /* Set non-blocking mode */
#ifdef _WIN32
    u_long mode = 1;
    ioctlsocket(s, FIONBIO, &mode);
#else
    int flags = fcntl(s, F_GETFL, 0);
    fcntl(s, F_SETFL, flags | O_NONBLOCK);
#endif

    /* Set TTL */
    int ttl_val = ttl;
#ifdef _WIN32
    setsockopt(s, IPPROTO_IP, IP_TTL, (const char *)&ttl_val, sizeof(ttl_val));
#else
    setsockopt(s, IPPROTO_IP, IP_TTL, &ttl_val, sizeof(ttl_val));
#endif

    /* Trigger TCP SYN connection */
    connect(s, (struct sockaddr *)dest_addr, sizeof(struct sockaddr_in));

    /* Get OS-assigned local transient port */
    struct sockaddr_in local_sin;
#ifdef _WIN32
    int local_len = sizeof(local_sin);
#else
    socklen_t local_len = sizeof(local_sin);
#endif
    if (getsockname(s, (struct sockaddr *)&local_sin, &local_len) == 0) {
        *local_port = ntohs(local_sin.sin_port);
    } else {
        *local_port = 0;
    }

    return s;
}

/* Create a UDP socket and send a probe packet */
static socket_t create_udp_probe(struct sockaddr_in *dest_addr, int ttl, uint16_t *local_port, const char *payload, int payload_len) {
    socket_t s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (IS_INVALID_SOCKET(s)) return s;

    /* Bind to wildcard address to allocate a local transient port */
    struct sockaddr_in local_sin;
    memset(&local_sin, 0, sizeof(local_sin));
    local_sin.sin_family = AF_INET;
    local_sin.sin_addr.s_addr = INADDR_ANY;
    local_sin.sin_port = 0;

    if (bind(s, (struct sockaddr *)&local_sin, sizeof(local_sin)) == SOCKET_ERROR) {
        CLOSE_SOCKET(s);
        return INVALID_SOCKET;
    }

    /* Get local port */
#ifdef _WIN32
    int local_len = sizeof(local_sin);
#else
    socklen_t local_len = sizeof(local_sin);
#endif
    if (getsockname(s, (struct sockaddr *)&local_sin, &local_len) == 0) {
        *local_port = ntohs(local_sin.sin_port);
    } else {
        *local_port = 0;
    }

    /* Set TTL */
    int ttl_val = ttl;
#ifdef _WIN32
    setsockopt(s, IPPROTO_IP, IP_TTL, (const char *)&ttl_val, sizeof(ttl_val));
#else
    setsockopt(s, IPPROTO_IP, IP_TTL, &ttl_val, sizeof(ttl_val));
#endif

    sendto(s, payload, payload_len, 0, (struct sockaddr *)dest_addr, sizeof(struct sockaddr_in));

    return s;
}

/* Executes a probe cycle for a specific protocol */
static void run_probe_cycle(
    socket_t icmp_sock,
    struct sockaddr_in *dest_addr,
    int ttl,
    probe_protocol_t protocol,
    uint16_t port,
    uint16_t my_id,
    int timeout_ms,
    int probes_per_hop,
    hop_result_t *res,
    int *target_reached
) {
    /* Reset stats for this fallback cycle */
    res->sent = 0;
    res->received = 0;
    res->min_ms = 0.0;
    res->max_ms = 0.0;
    res->sum_ms = 0.0;
    strcpy(res->ip, "*");
    strcpy(res->proto, "*");
    strcpy(res->device, "*");

    for (int probe = 0; probe < probes_per_hop; probe++) {
        if (*target_reached) {
            break;
        }

        uint16_t seq_num = (uint16_t)((ttl * probes_per_hop) + probe);
        socket_t probe_sock = INVALID_SOCKET;
        uint16_t local_probe_port = 0;
        double send_time = get_time_ms();

        if (protocol == PROT_ICMP || protocol == PROT_ICMP_TOS || protocol == PROT_ICMP_NODF) {
            int ttl_val = ttl;
#ifdef _WIN32
            setsockopt(icmp_sock, IPPROTO_IP, IP_TTL, (const char *)&ttl_val, sizeof(ttl_val));
#else
            setsockopt(icmp_sock, IPPROTO_IP, IP_TTL, &ttl_val, sizeof(ttl_val));
#endif

            if (protocol == PROT_ICMP_TOS) {
                int tos_val = 0xB8; /* Expedited Forwarding */
#ifdef _WIN32
                setsockopt(icmp_sock, IPPROTO_IP, IP_TOS, (const char *)&tos_val, sizeof(tos_val));
#else
                setsockopt(icmp_sock, IPPROTO_IP, IP_TOS, &tos_val, sizeof(tos_val));
#endif
            }

            if (protocol == PROT_ICMP_NODF) {
                int df_val = 0; /* Allow fragmentation (turn off DF flag) */
#ifdef _WIN32
                setsockopt(icmp_sock, IPPROTO_IP, IP_DONTFRAGMENT, (const char *)&df_val, sizeof(df_val));
#else
#ifdef IP_MTU_DISCOVER
                int discover = IP_PMTUDISC_DONT;
                setsockopt(icmp_sock, IPPROTO_IP, IP_MTU_DISCOVER, &discover, sizeof(discover));
#endif
#endif
            }

            struct icmp_packet packet;
            memset(&packet, 0, sizeof(packet));
            packet.hdr.type = 8; /* Echo Request */
            packet.hdr.code = 0;
            packet.hdr.id = htons(my_id);
            packet.hdr.seq = htons(seq_num);
            strcpy(packet.payload, "omnitrace_engine_payload_data!!!");
            packet.hdr.checksum = 0;
            
            /* If TOS, we send 0-byte payload for filtering bypass */
            int packet_size = sizeof(packet);
            if (protocol == PROT_ICMP_TOS) {
                packet_size = sizeof(struct icmp_hdr);
            }
            packet.hdr.checksum = calculate_checksum((unsigned short *)&packet, packet_size);

            res->sent++;
            int send_ret = sendto(icmp_sock, (const char *)&packet, packet_size, 0, (struct sockaddr *)dest_addr, sizeof(struct sockaddr_in));

            /* Restore defaults */
            if (protocol == PROT_ICMP_TOS) {
                int zero_tos = 0;
#ifdef _WIN32
                setsockopt(icmp_sock, IPPROTO_IP, IP_TOS, (const char *)&zero_tos, sizeof(zero_tos));
#else
                setsockopt(icmp_sock, IPPROTO_IP, IP_TOS, &zero_tos, sizeof(zero_tos));
#endif
            }
            if (protocol == PROT_ICMP_NODF) {
                int one_df = 1;
#ifdef _WIN32
                setsockopt(icmp_sock, IPPROTO_IP, IP_DONTFRAGMENT, (const char *)&one_df, sizeof(one_df));
#else
#ifdef IP_MTU_DISCOVER
                int default_discover = IP_PMTUDISC_WANT;
                setsockopt(icmp_sock, IPPROTO_IP, IP_MTU_DISCOVER, &default_discover, sizeof(default_discover));
#endif
#endif
            }

            if (send_ret == -1) {
                continue;
            }
        } else if (protocol == PROT_UDP || protocol == PROT_UDP_DNS || protocol == PROT_UDP_QUIC || protocol == PROT_UDP_NTP) {
            struct sockaddr_in probe_dest = *dest_addr;
            const char *payload = "omnitrace_udp_probe";
            int payload_len = 20;

            unsigned char dns_payload[] = { 
                0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 
                0x00, 0x00, 0x00, 0x00, 0x06, 'g', 'o', 'o', 'g', 'l', 'e', 
                0x03, 'c', 'o', 'm', 0x00, 0x00, 0x01, 0x00, 0x01 
            };
            unsigned char ntp_payload[48];
            memset(ntp_payload, 0, 48);
            ntp_payload[0] = 0x1B; /* LI=0, VN=3, Mode=3 (Client) */

            if (protocol == PROT_UDP) {
                probe_dest.sin_port = htons((uint16_t)(port + probe));
                payload = "omnitrace_udp_probe";
                payload_len = 20;
            } else if (protocol == PROT_UDP_DNS) {
                probe_dest.sin_port = htons(port);
                payload = (const char *)dns_payload;
                payload_len = sizeof(dns_payload);
            } else if (protocol == PROT_UDP_QUIC) {
                probe_dest.sin_port = htons(port);
                payload = "QUIC_INITIAL";
                payload_len = 12;
            } else if (protocol == PROT_UDP_NTP) {
                probe_dest.sin_port = htons(port);
                payload = (const char *)ntp_payload;
                payload_len = sizeof(ntp_payload);
            }
            
            probe_sock = create_udp_probe(&probe_dest, ttl, &local_probe_port, payload, payload_len);
            if (IS_INVALID_SOCKET(probe_sock)) {
                continue;
            }
            res->sent++;
        } else if (protocol == PROT_TCP) {
            struct sockaddr_in probe_dest = *dest_addr;
            probe_dest.sin_port = htons(port);

            probe_sock = create_tcp_syn_probe(&probe_dest, ttl, &local_probe_port);
            if (IS_INVALID_SOCKET(probe_sock)) {
                continue;
            }
            res->sent++;
        }

        /* Wait for response */
        while (1) {
            double elapsed = get_time_ms() - send_time;
            double remaining = (double)timeout_ms - elapsed;
            if (remaining <= 0.0) {
                break; /* Timeout reached */
            }

            fd_set read_fds, write_fds;
            FD_ZERO(&read_fds);
            FD_ZERO(&write_fds);

            FD_SET(icmp_sock, &read_fds);
            socket_t max_fd = icmp_sock;

            if (protocol == PROT_TCP && !IS_INVALID_SOCKET(probe_sock)) {
                FD_SET(probe_sock, &read_fds);
                FD_SET(probe_sock, &write_fds);
                if (probe_sock > max_fd) {
                    max_fd = probe_sock;
                }
            }

            struct timeval tv;
            tv.tv_sec = (long)(remaining / 1000.0);
            tv.tv_usec = (long)((remaining - (tv.tv_sec * 1000.0)) * 1000.0);
            if (tv.tv_sec < 0) tv.tv_sec = 0;
            if (tv.tv_usec < 0) tv.tv_usec = 0;

            int activity = select((int)max_fd + 1, &read_fds, &write_fds, NULL, &tv);
            if (activity <= 0) {
                break; /* Timeout or socket error */
            }

            /* Check if TCP probe completed connection / responded directly (reached target) */
            if (protocol == PROT_TCP && !IS_INVALID_SOCKET(probe_sock) && 
                (FD_ISSET(probe_sock, &read_fds) || FD_ISSET(probe_sock, &write_fds))) {
                
                double rtt = get_time_ms() - send_time;
                if (res->received == 0) {
                    res->min_ms = rtt;
                    res->max_ms = rtt;
                } else {
                    if (rtt < res->min_ms) res->min_ms = rtt;
                    if (rtt > res->max_ms) res->max_ms = rtt;
                }
                res->sum_ms += rtt;
                res->received++;

                unsigned char *ip_bytes = (unsigned char *)&dest_addr->sin_addr.s_addr;
                sprintf(res->ip, "%d.%d.%d.%d", ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3]);
                strcpy(res->proto, "TCP");
                strcpy(res->device, "Host (TCP)");

                *target_reached = 1;
                break;
            }

            /* Check if ICMP response was received */
            if (FD_ISSET(icmp_sock, &read_fds)) {
                char recv_buf[1024];
                struct sockaddr_in from_addr;
#ifdef _WIN32
                int from_len = sizeof(from_addr);
                int recv_len = recvfrom(icmp_sock, recv_buf, sizeof(recv_buf), 0, (struct sockaddr *)&from_addr, &from_len);
#else
                socklen_t from_len = sizeof(from_addr);
                int recv_len = recvfrom(icmp_sock, recv_buf, sizeof(recv_buf), 0, (struct sockaddr *)&from_addr, &from_len);
#endif
                if (recv_len < 20) {
                    continue;
                }

                uint8_t ip_header_len = (recv_buf[0] & 0x0F) * 4;
                uint8_t ip_proto = recv_buf[9];

                if (ip_proto != 1 || recv_len < ip_header_len + 8) {
                    continue;
                }

                struct icmp_hdr *recv_icmp = (struct icmp_hdr *)(recv_buf + ip_header_len);
                int is_match = 0;

                if (recv_icmp->type == 0 && protocol == PROT_ICMP) {
                    uint16_t r_id = ntohs(recv_icmp->id);
                    uint16_t r_seq = ntohs(recv_icmp->seq);
                    if (r_id == my_id && r_seq == seq_num) {
                        is_match = 1;
                    }
                } else if (recv_icmp->type == 11 || recv_icmp->type == 3) {
                    int inner_ip_offset = ip_header_len + 8;
                    if (recv_len >= inner_ip_offset + 20) {
                        char *inner_ip_ptr = recv_buf + inner_ip_offset;
                        uint8_t inner_ip_header_len = (inner_ip_ptr[0] & 0x0F) * 4;
                        uint8_t inner_ip_proto = inner_ip_ptr[9];

                        if (recv_len >= inner_ip_offset + inner_ip_header_len + 8) {
                            char *inner_payload_ptr = inner_ip_ptr + inner_ip_header_len;
                            
                            if ((protocol == PROT_ICMP || protocol == PROT_ICMP_TOS || protocol == PROT_ICMP_NODF) && inner_ip_proto == 1) {
                                struct icmp_hdr *inner_icmp = (struct icmp_hdr *)inner_payload_ptr;
                                uint16_t r_id = ntohs(inner_icmp->id);
                                uint16_t r_seq = ntohs(inner_icmp->seq);
                                if (r_id == my_id && r_seq == seq_num) {
                                    is_match = 1;
                                }
                            } else if ((protocol == PROT_UDP || protocol == PROT_UDP_DNS || protocol == PROT_UDP_QUIC || protocol == PROT_UDP_NTP) && inner_ip_proto == 17) {
                                uint16_t inner_src_port = ((unsigned char)inner_payload_ptr[0] << 8) | (unsigned char)inner_payload_ptr[1];
                                if (inner_src_port == local_probe_port) {
                                    is_match = 1;
                                }
                            } else if (protocol == PROT_TCP && inner_ip_proto == 6) {
                                uint16_t inner_src_port = ((unsigned char)inner_payload_ptr[0] << 8) | (unsigned char)inner_payload_ptr[1];
                                if (inner_src_port == local_probe_port) {
                                    is_match = 1;
                                }
                            }
                        }
                    }
                }

                if (is_match) {
                    double rtt = get_time_ms() - send_time;
                    if (res->received == 0) {
                        res->min_ms = rtt;
                        res->max_ms = rtt;
                    } else {
                        if (rtt < res->min_ms) res->min_ms = rtt;
                        if (rtt > res->max_ms) res->max_ms = rtt;
                    }
                    res->sum_ms += rtt;
                    res->received++;

                    unsigned char *ip_bytes = (unsigned char *)&from_addr.sin_addr.s_addr;
                    sprintf(res->ip, "%d.%d.%d.%d", ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3]);

                    if (protocol == PROT_ICMP) strcpy(res->proto, "ICMP");
                    else if (protocol == PROT_ICMP_TOS) strcpy(res->proto, "ICMP-TOS");
                    else if (protocol == PROT_ICMP_NODF) strcpy(res->proto, "ICMP-NDF");
                    else if (protocol == PROT_UDP) strcpy(res->proto, "UDP");
                    else if (protocol == PROT_UDP_DNS) strcpy(res->proto, "UDP-DNS");
                    else if (protocol == PROT_UDP_QUIC) strcpy(res->proto, "UDP-QUIC");
                    else if (protocol == PROT_UDP_NTP) strcpy(res->proto, "UDP-NTP");
                    else if (protocol == PROT_TCP) strcpy(res->proto, "TCP");

                    uint8_t recv_ttl = (uint8_t)recv_buf[8];
                    fingerprint_device(recv_ttl, res->device);

                    if (from_addr.sin_addr.s_addr == dest_addr->sin_addr.s_addr) {
                        *target_reached = 1;
                    }
                    break;
                }
            }
        }

        if (!IS_INVALID_SOCKET(probe_sock)) {
            CLOSE_SOCKET(probe_sock);
        }
    }
}

/* Core trace function exposed to Python */
static PyObject* py_trace(PyObject* self, PyObject* args) {
    const char* target_ip;
    int max_hops;
    int timeout_ms;
    int probes_per_hop;

    if (!PyArg_ParseTuple(args, "siii", &target_ip, &max_hops, &timeout_ms, &probes_per_hop)) {
        return NULL;
    }

    /* Input validation */
    if (max_hops <= 0 || max_hops > 255) {
        PyErr_SetString(PyExc_ValueError, "max_hops must be between 1 and 255");
        return NULL;
    }
    if (timeout_ms <= 0) {
        PyErr_SetString(PyExc_ValueError, "timeout_ms must be positive");
        return NULL;
    }
    if (probes_per_hop <= 0 || probes_per_hop > 100) {
        PyErr_SetString(PyExc_ValueError, "probes_per_hop must be between 1 and 100");
        return NULL;
    }

    /* Initialize Winsock on Windows */
#ifdef _WIN32
    WSADATA wsaData;
    int wsa_err = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (wsa_err != 0) {
        PyErr_Format(PyExc_RuntimeError, "WSAStartup failed with error %d", wsa_err);
        return NULL;
    }
#endif

    /* Resolve target IP address */
    struct addrinfo hints, *info = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET; /* IPv4 only */
    hints.ai_socktype = SOCK_RAW;

    int resolve_err = getaddrinfo(target_ip, NULL, &hints, &info);
    if (resolve_err != 0) {
#ifdef _WIN32
        WSACleanup();
#endif
        PyErr_Format(PyExc_ValueError, "Failed to resolve target IP '%s': %s", target_ip, gai_strerror(resolve_err));
        return NULL;
    }
    struct sockaddr_in dest_addr = *(struct sockaddr_in *)info->ai_addr;
    freeaddrinfo(info);

    /* Create raw ICMP socket */
    socket_t sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (IS_INVALID_SOCKET(sock)) {
#ifdef _WIN32
        int err = WSAGetLastError();
        WSACleanup();
        if (err == WSAEACCES) {
            PyErr_SetString(PyExc_PermissionError, "Raw sockets require administrative privileges. Please run as Administrator.");
        } else {
            PyErr_Format(PyExc_RuntimeError, "Socket creation failed with Winsock error %d", err);
        }
#else
        int err = errno;
        if (err == EACCES || err == EPERM) {
            PyErr_SetString(PyExc_PermissionError, "Raw sockets require root privileges. Please run with sudo.");
        } else {
            PyErr_Format(PyExc_RuntimeError, "Socket creation failed with error %d (%s)", err, strerror(err));
        }
#endif
        return NULL;
    }

    /* Allocate C array for hop results */
    hop_result_t *results = (hop_result_t *)calloc(max_hops, sizeof(hop_result_t));
    if (!results) {
        CLOSE_SOCKET(sock);
#ifdef _WIN32
        WSACleanup();
#endif
        return PyErr_NoMemory();
    }

    /* Generate a unique trace session ID */
    uint16_t my_id = (uint16_t)((GET_PID() ^ global_trace_id_counter++) & 0xFFFF);

    int max_hops_completed = 0;
    int target_reached = 0;

    /* Release the GIL before entering the intensive packet loops */
    Py_BEGIN_ALLOW_THREADS

    for (int ttl = 1; ttl <= max_hops; ttl++) {
        if (target_reached) {
            break;
        }

        hop_result_t *res = &results[ttl - 1];
        res->hop = ttl;
        strcpy(res->ip, "*");
        strcpy(res->proto, "*");
        strcpy(res->device, "*");
        res->min_ms = 0.0;
        res->max_ms = 0.0;
        res->sum_ms = 0.0;
        res->sent = 0;
        res->received = 0;

        max_hops_completed = ttl;

        /* 1. Try ICMP Echo Request first */
        run_probe_cycle(sock, &dest_addr, ttl, PROT_ICMP, 0, my_id, timeout_ms, probes_per_hop, res, &target_reached);

        /* If ICMP failed, enter escalation logging mode */
        if (res->received == 0 && !target_reached) {
            printf("\033[90m  [Hop %d] ICMP timed out. Escalating to UDP...\033[0m\n", ttl);
            fflush(stdout);
            
            run_probe_cycle(sock, &dest_addr, ttl, PROT_UDP, 33434, my_id, timeout_ms, probes_per_hop, res, &target_reached);
            if (res->received > 0) {
                printf("\033[38;5;150m  [Hop %d] Responded using UDP!\033[0m\n", ttl);
                fflush(stdout);
            } else {
                printf("\033[90m  [Hop %d] UDP timed out. Escalating to ICMP-TOS...\033[0m\n", ttl);
                fflush(stdout);
                
                run_probe_cycle(sock, &dest_addr, ttl, PROT_ICMP_TOS, 0, my_id, timeout_ms, probes_per_hop, res, &target_reached);
                if (res->received > 0) {
                    printf("\033[38;5;150m  [Hop %d] Responded using ICMP-TOS!\033[0m\n", ttl);
                    fflush(stdout);
                } else {
                    printf("\033[90m  [Hop %d] ICMP-TOS timed out. Escalating to ICMP-NDF...\033[0m\n", ttl);
                    fflush(stdout);
                    
                    run_probe_cycle(sock, &dest_addr, ttl, PROT_ICMP_NODF, 0, my_id, timeout_ms, probes_per_hop, res, &target_reached);
                    if (res->received > 0) {
                        printf("\033[38;5;150m  [Hop %d] Responded using ICMP-NDF!\033[0m\n", ttl);
                        fflush(stdout);
                    } else {
                        printf("\033[90m  [Hop %d] ICMP-NDF timed out. Escalating to UDP-DNS...\033[0m\n", ttl);
                        fflush(stdout);
                        
                        run_probe_cycle(sock, &dest_addr, ttl, PROT_UDP_DNS, 53, my_id, timeout_ms, probes_per_hop, res, &target_reached);
                        if (res->received > 0) {
                            printf("\033[38;5;150m  [Hop %d] Responded using UDP-DNS!\033[0m\n", ttl);
                            fflush(stdout);
                        } else {
                            printf("\033[90m  [Hop %d] UDP-DNS timed out. Escalating to UDP-QUIC...\033[0m\n", ttl);
                            fflush(stdout);
                            
                            run_probe_cycle(sock, &dest_addr, ttl, PROT_UDP_QUIC, 443, my_id, timeout_ms, probes_per_hop, res, &target_reached);
                            if (res->received > 0) {
                                printf("\033[38;5;150m  [Hop %d] Responded using UDP-QUIC!\033[0m\n", ttl);
                                fflush(stdout);
                            } else {
                                printf("\033[90m  [Hop %d] UDP-QUIC timed out. Escalating to UDP-NTP...\033[0m\n", ttl);
                                fflush(stdout);
                                
                                run_probe_cycle(sock, &dest_addr, ttl, PROT_UDP_NTP, 123, my_id, timeout_ms, probes_per_hop, res, &target_reached);
                                if (res->received > 0) {
                                    printf("\033[38;5;150m  [Hop %d] Responded using UDP-NTP!\033[0m\n", ttl);
                                    fflush(stdout);
                                } else {
                                    printf("\033[38;5;203m  [Hop %d] All protocols timed out. Hop marked as silent (*).\033[0m\n", ttl);
                                    fflush(stdout);
                                }
                            }
                        }
                    }
                }
            }
        }

#ifndef _WIN32
        /* 8. If still no response, escalate to TCP SYN Port 80 (POSIX only - Windows TCP stack overrides SYN TTL) */
        if (res->received == 0 && !target_reached) {
            run_probe_cycle(sock, &dest_addr, ttl, PROT_TCP, 80, my_id, timeout_ms, probes_per_hop, res, &target_reached);
        }

        /* 9. If still no response, escalate to TCP SYN Port 443 (POSIX only - Windows TCP stack overrides SYN TTL) */
        if (res->received == 0 && !target_reached) {
            run_probe_cycle(sock, &dest_addr, ttl, PROT_TCP, 443, my_id, timeout_ms, probes_per_hop, res, &target_reached);
        }
#endif
    }

    /* Re-acquire the GIL before interacting with Python C-API */
    Py_END_ALLOW_THREADS

    /* Build Python return list of dictionaries */
    PyObject* list_obj = PyList_New(max_hops_completed);
    if (!list_obj) {
        free(results);
        CLOSE_SOCKET(sock);
#ifdef _WIN32
        WSACleanup();
#endif
        return PyErr_NoMemory();
    }

    for (int i = 0; i < max_hops_completed; i++) {
        hop_result_t *res = &results[i];
        double avg_ms = (res->received > 0) ? (res->sum_ms / res->received) : 0.0;
        double loss_pct = ((double)(res->sent - res->received) / (double)res->sent) * 100.0;

        PyObject* dict = PyDict_New();
        if (!dict) {
            Py_DECREF(list_obj);
            free(results);
            CLOSE_SOCKET(sock);
#ifdef _WIN32
            WSACleanup();
#endif
            return NULL;
        }

        PyObject* hop_val = PyLong_FromLong(res->hop);
        PyObject* ip_val = PyUnicode_FromString(res->ip);
        PyObject* proto_val = PyUnicode_FromString(res->proto);
        PyObject* device_val = PyUnicode_FromString(res->device);
        PyObject* min_val = PyFloat_FromDouble(res->min_ms);
        PyObject* max_val = PyFloat_FromDouble(res->max_ms);
        PyObject* avg_val = PyFloat_FromDouble(avg_ms);
        PyObject* loss_val = PyFloat_FromDouble(loss_pct);

        PyDict_SetItemString(dict, "hop", hop_val);
        PyDict_SetItemString(dict, "ip", ip_val);
        PyDict_SetItemString(dict, "proto", proto_val);
        PyDict_SetItemString(dict, "device", device_val);
        PyDict_SetItemString(dict, "min_ms", min_val);
        PyDict_SetItemString(dict, "max_ms", max_val);
        PyDict_SetItemString(dict, "avg_ms", avg_val);
        PyDict_SetItemString(dict, "loss_pct", loss_val);

        Py_DECREF(hop_val);
        Py_DECREF(ip_val);
        Py_DECREF(proto_val);
        Py_DECREF(device_val);
        Py_DECREF(min_val);
        Py_DECREF(max_val);
        Py_DECREF(avg_val);
        Py_DECREF(loss_val);

        PyList_SetItem(list_obj, i, dict);
    }

    /* Clean up resources */
    free(results);
    CLOSE_SOCKET(sock);
#ifdef _WIN32
    WSACleanup();
#endif

    return list_obj;
}

/* Python C-API bindings */
static PyMethodDef OmnitraceMethods[] = {
    {"trace", py_trace, METH_VARARGS, "Run raw socket traceroute to target IP."},
    {NULL, NULL, 0, NULL}
};

static struct PyModuleDef omnitrace_engine_module = {
    PyModuleDef_HEAD_INIT,
    "omnitrace_engine",
    "High-speed raw socket packet traceroute engine",
    -1,
    OmnitraceMethods
};

PyMODINIT_FUNC PyInit_omnitrace_engine(void) {
    return PyModule_Create(&omnitrace_engine_module);
}
