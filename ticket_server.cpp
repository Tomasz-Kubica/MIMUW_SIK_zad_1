#ifdef NDEBUG
#define DEBUG_MESSAGES false
#else
#define DEBUG_MESSAGES true
#endif

#include <iostream>
#include <fstream>
#include <unordered_map>
#include <bitset>
#include <ctime>
#include <vector>
#include <cstdlib>
#include <cstdio>
#include <cstdarg>
#include <cerrno>
#include <cstring>


// network includes
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <cstdint>
#include <fcntl.h>
#include <endian.h>


#define BUFFER_SIZE 80000

#define DATAGRAM_LIMIT 65527

#define COOKIE_LENGTH 48
#define COOKIE_LOWEST 33
#define COOKIE_HIGHEST 126

#define TICKET_LENGTH 7

#define MIN_RESERVATION_ID 1000000

// Evaluate `x`: if false, print an error message and exit with an error.
#define ENSURE(x)                                                         \
    do {                                                                  \
        bool result = (x);                                                \
        if (!result) {                                                    \
            fprintf(stderr, "Error: %s was false in %s at %s:%d\n",       \
                #x, __func__, __FILE__, __LINE__);                        \
            exit(EXIT_FAILURE);                                           \
        }                                                                 \
    } while (0)

// Check if errno is non-zero, and if so, print an error message and exit with an error.
#define PRINT_ERRNO()                                                  \
    do {                                                               \
        if (errno != 0) {                                              \
            fprintf(stderr, "Error: errno %d in %s at %s:%d\n%s\n",    \
              errno, __func__, __FILE__, __LINE__, strerror(errno));   \
            exit(EXIT_FAILURE);                                        \
        }                                                              \
    } while (0)

// Set `errno` to 0 and evaluate `x`. If `errno` changed, describe it and exit.
#define CHECK_ERRNO(x)                                                             \
    do {                                                                           \
        errno = 0;                                                                 \
        (void) (x);                                                                \
        PRINT_ERRNO();                                                             \
    } while (0)

// Print an error message and exit with an error.
void fatal(const char *fmt, ...) {
    va_list fmt_args;

    fprintf(stderr, "Error: ");
    va_start(fmt_args, fmt);
    vfprintf(stderr, fmt, fmt_args);
    va_end(fmt_args);
    fprintf(stderr, "\n");
    exit(EXIT_FAILURE);
}

using message_id_t = uint8_t;
using event_id_t = uint32_t;
using description_length_t = uint8_t;
using ticket_count_t = uint16_t;
using expiration_time_t = uint64_t;
using reservation_id_t = uint32_t;

struct cookie_t {
    char c[COOKIE_LENGTH];

    bool operator==(const cookie_t &other) {
        for (size_t i = 0; i < COOKIE_LENGTH; i++) {
            if (this->c[i] != other.c[i])
                return false;
        }
        return true;
    }
} __attribute__((packed));

struct ticket_t {
    char c[TICKET_LENGTH];
} __attribute__((packed));


struct reservation_info_t {
    ticket_count_t t_count;
    cookie_t cookie;
    expiration_time_t expiration_time;
} __attribute__((packed));

struct get_reservation_t {
    event_id_t e_id;
    ticket_count_t t_count;
} __attribute__((packed));

struct reservation_t {
    reservation_id_t reservation_id;
    event_id_t e_id;
    reservation_info_t info;
} __attribute__((packed));

struct get_tickets_t {
    reservation_id_t reservation_id;
    cookie_t cookie;
} __attribute__((packed));

const message_id_t GET_EVENTS = 1;
const message_id_t GET_RESERVATION = 3;
const message_id_t GET_TICKETS = 5;

const message_id_t EVENTS = 2;
const message_id_t RESERVATION = 4;
const message_id_t TICKETS = 6;
const message_id_t BAD_REQUEST = 255;

const size_t MAX_TICKETS = 1000; // TODO

const ticket_t TICKET_ZERO = {{'0', '0', '0', '0', '0', '0', '0'}};

char shared_buffer[BUFFER_SIZE];

uint8_t host_to_network(uint8_t x) {
    return x;
}

uint16_t host_to_network(uint16_t x) {
    return htons(x);
}

uint32_t host_to_network(uint32_t x) {
    return htonl(x);
}

uint64_t host_to_network(uint64_t x) {
    return htobe64(x);
}

uint16_t network_to_host(uint16_t x) {
    return ntohs(x);
}

uint32_t network_to_host(uint32_t x) {
    return ntohl(x);
}

uint16_t read_port(char *string) {
    errno = 0;
    char *end;
    unsigned long port = strtoul(string, &end, 10);
    PRINT_ERRNO();
    if ((size_t)(end - string) != strlen(string)) {
        fatal("given port couldn't be interpreted as number");
    }
    if (port > UINT16_MAX) {
        fatal("%ul is not a valid port number", port);
    }

    return (uint16_t) port;
}

int bind_socket(uint16_t port) {
    int socket_fd = socket(AF_INET, SOCK_DGRAM, 0); // creating IPv4 UDP socket
    ENSURE(socket_fd > 0);
    // after socket() call; we should close(sock) on any execution path;

    struct sockaddr_in server_address;
    server_address.sin_family = AF_INET; // IPv4
    server_address.sin_addr.s_addr = htonl(
            INADDR_ANY); // listening on all interfaces
    server_address.sin_port = htons(port);

    // bind the socket to a concrete address
    CHECK_ERRNO(bind(socket_fd, (struct sockaddr *) &server_address,
                     (socklen_t) sizeof(server_address)));

    return socket_fd;
}

ticket_t next_ticket(ticket_t ticket) {
    for (char &i: ticket.c) {
        if (i != 'Z') {
            if (i == '9')
                i = 'A';
            else
                i++;
            return ticket;
        }
    }
    if (DEBUG_MESSAGES) {
        std::cerr << "WARNING: ticket number overflow\n";
    }
    return TICKET_ZERO;
}

size_t
read_message(int socket_fd, struct sockaddr_in *client_address, char *buffer,
             size_t max_length) {
    socklen_t address_length = (socklen_t) sizeof(*client_address);
    int flags = 0; // we do not request anything special
    errno = 0;
    ssize_t len = recvfrom(socket_fd, buffer, max_length, flags,
                           (struct sockaddr *) client_address, &address_length);
    if (len < 0) {
        PRINT_ERRNO();
    }
    return (size_t) len;
}

void send_message(int socket_fd, const struct sockaddr_in *client_address,
                  const char *message, size_t length) {
    socklen_t address_length = (socklen_t) sizeof(*client_address);
    int flags = 0;
    ssize_t sent_length = sendto(socket_fd, message, length, flags,
                                 (struct sockaddr *) client_address,
                                 address_length);
    ENSURE(sent_length == (ssize_t) length);
}

void write_message(int file_fd, const char *message, size_t length) {
    ssize_t sent_length = write(file_fd, message, length);
    ENSURE(sent_length == (ssize_t) length);
}

using reservations_map = std::unordered_map<event_id_t, std::unordered_map<reservation_id_t, reservation_info_t>>;

std::unordered_map<event_id_t, std::pair<std::string, ticket_count_t>> events;
reservations_map reservations;
std::unordered_map<reservation_id_t, event_id_t> reservations_to_events;
std::unordered_map<reservation_id_t, std::pair<std::vector<ticket_t>, cookie_t>> reservation_tickets;
reservation_id_t nex_reservation_id = MIN_RESERVATION_ID;
ticket_t next_ticket_number = TICKET_ZERO;

void clear_reservations() {
    const uint64_t time = std::time(nullptr);
    for (auto &it_events: reservations) {
        std::vector<reservation_id_t> to_erase;
        for (auto &it_reservations: it_events.second) {
            if (it_reservations.second.expiration_time <= time) {
                to_erase.push_back(it_reservations.first);
                events[it_events.first].second += it_reservations.second.t_count;
            }
        }
        for (reservation_id_t id: to_erase) {
            it_events.second.erase(id);
            reservations_to_events.erase(id);
        }
    }
}

cookie_t generate_cookie() {
    cookie_t cookie;
    for (char &c: cookie.c) {
        c = rand() % (COOKIE_HIGHEST - COOKIE_LOWEST + 1) + COOKIE_LOWEST;
    }
    return cookie;
}

int main(int argc, char *argv[]) {
    std::string file_name;
    uint16_t port = 2022;
    uint32_t timeout = 5;
    for (int i = 1; i < argc; i += 2) {
        if (i + 1 >= argc)
            fatal("incorrect parameters");
        if (strcmp(argv[i], "-f") == 0) {
            file_name = std::string(argv[i + 1]);
        } else if (strcmp(argv[i], "-p") == 0) {
            port = read_port(argv[i + 1]);
        } else if (strcmp(argv[i], "-t") == 0) {
            char *timeout_end;
            timeout = strtoul(argv[i + 1], &timeout_end, 10);
            if (timeout < 1 || timeout > 86400 ||
                argv[i + 1] + strlen(argv[i + 1]) != timeout_end)
                fatal("incorrect timeout %s, %d", argv[i + 1], timeout);
        } else {
            fatal("unknown parameter \"%s\"", argv[i]);
        }
    }

    if (file_name.empty()) {
        fatal("incorrect or missing file name");
    }

    std::string event_description;
    uint16_t tickets_amount;
    std::ifstream file_stream;
    file_stream.open(file_name);
    event_id_t next_id = 0;
    while (std::getline(file_stream, event_description)) {
        file_stream >> tickets_amount;
        events.insert({next_id, {event_description, tickets_amount}});
        reservations.insert({next_id, {}});
        next_id++;
        if (DEBUG_MESSAGES) {
            std::cerr << "wczytano:\n";
            std::cerr << "  description: " << event_description << "\n";
            std::cerr << "  tickets amount: " << tickets_amount << "\n";
        }
        std::getline(file_stream, event_description);
    }

    if (DEBUG_MESSAGES) {
        std::cerr << "timeout: " << timeout << '\n';
        std::cerr << "file name: " << file_name << '\n';
        std::cerr << "Listening on port " << port << '\n';
        std::cerr << "\n----------------------------\n\n";
    }

    memset(shared_buffer, 0, sizeof(shared_buffer));

    int socket_fd = bind_socket(port);

    struct sockaddr_in client_address;
    size_t read_length;
    do {
        read_length = read_message(socket_fd, &client_address, shared_buffer,
                                   sizeof(shared_buffer));
//        char *client_ip = inet_ntoa(client_address.sin_addr);
//        uint16_t client_port = ntohs(client_address.sin_port);

        message_id_t *message_id = (message_id_t *) shared_buffer;

        if (DEBUG_MESSAGES) {
            std::cerr << "received message_id: " << (int) (*message_id) << '\n';
        }

        size_t used_space = 0;
        used_space += sizeof(message_id_t);
        if (*message_id == GET_EVENTS) {
            if (read_length != sizeof(message_id_t)) {
                continue; // brak odpowiedzi na niepoprawny komunikat
            }
            clear_reservations();
            *message_id = EVENTS;
            for (auto &event: events) {
                event_id_t event_id = event.first;
                std::string description = event.second.first;
                ticket_count_t count = event.second.second;
                description_length_t desc_len = description.size();
                size_t event_data_size =
                        sizeof(event_id_t) + sizeof(ticket_count_t) +
                        sizeof(description_length_t) + desc_len;
                if (used_space + event_data_size > DATAGRAM_LIMIT) {
                    break;
                }
                *((event_id_t *) (shared_buffer +
                                  used_space)) = host_to_network(event_id);
                used_space += sizeof(event_id_t);

                *((ticket_count_t *) (shared_buffer +
                                      used_space)) = host_to_network(count);
                used_space += sizeof(ticket_count_t);

                *((description_length_t *) (shared_buffer +
                                            used_space)) = host_to_network(
                        desc_len);
                used_space += sizeof(description_length_t);

                memcpy(shared_buffer + used_space, description.c_str(),
                       desc_len);
                used_space += desc_len;

            }
        } else if (*message_id == GET_RESERVATION) {
            size_t expected_length =
                    sizeof(message_id_t) + sizeof(get_reservation_t);
            if (read_length != expected_length) {
                if (DEBUG_MESSAGES) {
                    std::cerr << "incorrect message length, expected: "
                              << expected_length << ", received: "
                              << read_length << '\n';
                }
                continue; // brak odpowiedzi na niepoprawny komunikat
            }

            get_reservation_t request = *((get_reservation_t *) (shared_buffer +
                                                                 sizeof(message_id_t)));
            request.t_count = network_to_host(request.t_count);
            request.e_id = network_to_host(request.e_id);
            if (DEBUG_MESSAGES) {
                std::cerr << (int) request.e_id << ' ' << (int) request.t_count
                          << '\n';
            }

            clear_reservations();

            if (request.t_count == 0 ||
                events.find(request.e_id) == events.end() ||
                events[request.e_id].second < request.t_count ||
                MAX_TICKETS < request.t_count) {
                // zła liczba biletów
                *message_id = BAD_REQUEST;
                *(event_id_t *) (shared_buffer + used_space) = host_to_network(
                        request.e_id);
                used_space += sizeof(event_id_t);
            } else {
                *message_id = RESERVATION;
                events[request.e_id].second -= request.t_count;
                reservation_id_t reservation_id = nex_reservation_id;
                nex_reservation_id++;
                reservation_t reservation;
                reservation.e_id = host_to_network(request.e_id);
                reservation.reservation_id = host_to_network(reservation_id);
                reservation_info_t info;
                info.t_count = request.t_count;
                info.expiration_time = std::time(nullptr) + timeout;
                info.cookie = generate_cookie();
                reservations[request.e_id].insert({reservation_id, info});
                reservations_to_events.insert(
                        {reservation_id, (event_id_t) request.e_id});
                info.expiration_time = host_to_network(info.expiration_time);
                info.t_count = host_to_network(info.t_count);
                reservation.info = info;

                *(reservation_t *) (shared_buffer + used_space) = reservation;
                used_space += sizeof(reservation_t);
            }


        } else if (*message_id == GET_TICKETS) {
            size_t expected_length =
                    sizeof(message_id_t) + sizeof(get_tickets_t);
            if (read_length != expected_length) {
                if (DEBUG_MESSAGES) {
                    std::cerr << "incorrect message length, expected: "
                              << expected_length << ", received: "
                              << read_length << '\n';
                }
                continue; // brak odpowiedzi na niepoprawny komunikat
            }
            get_tickets_t get_tickets = *(get_tickets_t *) (shared_buffer +
                                                            sizeof(message_id_t));
            get_tickets.reservation_id = network_to_host(
                    get_tickets.reservation_id);
            clear_reservations();
            bool send_tickets = false;
            if (reservation_tickets.find(get_tickets.reservation_id) !=
                reservation_tickets.end() &&
                reservation_tickets[get_tickets.reservation_id].second ==
                get_tickets.cookie) {
                *message_id = TICKETS;
                *(reservation_id_t *) (shared_buffer +
                                       used_space) = host_to_network(
                        get_tickets.reservation_id);
                used_space += sizeof(reservation_id_t);
                *(ticket_count_t *) (shared_buffer +
                                     used_space) = host_to_network(
                        (ticket_count_t) reservation_tickets[get_tickets.reservation_id].first.size());
                if (DEBUG_MESSAGES) {
                    std::cerr << "tickets_count: "
                              << reservation_tickets[get_tickets.reservation_id].first.size()
                              << '\n';
                }
                used_space += sizeof(ticket_count_t);
                send_tickets = true;
            } else if (
                    reservations_to_events.find(get_tickets.reservation_id) !=
                    reservations_to_events.end() &&
                    reservations[reservations_to_events[get_tickets.reservation_id]][get_tickets.reservation_id].cookie ==
                    get_tickets.cookie) {
                *message_id = TICKETS;
                *(reservation_id_t *) (shared_buffer +
                                       used_space) = host_to_network(
                        get_tickets.reservation_id);
                used_space += sizeof(reservation_id_t);
                ticket_count_t ticket_count = reservations[reservations_to_events[get_tickets.reservation_id]][get_tickets.reservation_id].t_count;
                reservations[reservations_to_events[get_tickets.reservation_id]][get_tickets.reservation_id].t_count = 0; // rezerwacja zrealizowana usuwamy z niej bilety
                *(ticket_count_t *) (shared_buffer +
                                     used_space) = host_to_network(
                        ticket_count);
                used_space += sizeof(ticket_count_t);
                std::vector<ticket_t> tickets;
                for (ticket_count_t i = 0; i < ticket_count; i++) {
                    tickets.push_back(next_ticket_number);
                    next_ticket_number = next_ticket(next_ticket_number);
                }
                reservation_tickets.insert(
                        {(reservation_id_t) get_tickets.reservation_id,
                         {std::move(tickets), get_tickets.cookie}});
                send_tickets = true;
            } else {
                *message_id = BAD_REQUEST;
                *(reservation_id_t *) (shared_buffer +
                                       sizeof(message_id_t)) = host_to_network(
                        get_tickets.reservation_id);
                used_space += sizeof(reservation_id_t);
            }
            if (send_tickets) {
                for (ticket_t &ticket: reservation_tickets[get_tickets.reservation_id].first) {
                    *(ticket_t *) (shared_buffer + used_space) = ticket;
                    used_space += sizeof(ticket_t);
                }
            }

        } else {
            if (DEBUG_MESSAGES)
                std::cerr << "invalid message id\n";
            continue;
        }
        send_message(socket_fd, &client_address, shared_buffer, used_space);

    } while (read_length > 0);

    CHECK_ERRNO(close(socket_fd));

    return 0;
}
