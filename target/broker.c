#define _GNU_SOURCE

#include "protocol.h"

#include <arpa/inet.h>
#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#if !defined(LAB_MODE) || LAB_MODE != 1
#error "broker is a lab target; compile with -DLAB_MODE=1"
#endif

#if UINTPTR_MAX != UINT64_MAX
#error "broker requires a 64-bit target"
#endif

#define DEFAULT_PORT 31337u
#define LISTEN_BACKLOG 16
#define JOB_SIZE 256u
#define JOB_HANDLER_OFFSET 16u
#define JOB_PROGRAM_OFFSET 24u
#define JOB_ARGV_OFFSET 32u
#define JOB_STORAGE_OFFSET 64u
#define JOB_INLINE_OFFSET 80u
#define JOB_INLINE_SIZE 176u
#define NOTE_BODY_SIZE 240u

#if defined(__GNUC__)
#define BROKER_EXPORT __attribute__((noinline, used, retain, visibility("default")))
#define NOINLINE __attribute__((noinline))
#else
#define BROKER_EXPORT
#define NOINLINE
#endif

struct job;
typedef void (*job_handler)(struct job *, int);

struct job {
    struct job *next;
    uint64_t id;
    job_handler handler;
    char *program;
    char *argv[4];
    char *storage;
    uint32_t storage_len;
    uint32_t options;
    unsigned char inline_storage[JOB_INLINE_SIZE];
};

_Static_assert(sizeof(job_handler) == 8, "function pointer size");
_Static_assert(sizeof(struct job) == JOB_SIZE, "job size");
_Static_assert(offsetof(struct job, handler) == JOB_HANDLER_OFFSET, "handler offset");
_Static_assert(offsetof(struct job, program) == JOB_PROGRAM_OFFSET, "program offset");
_Static_assert(offsetof(struct job, argv) == JOB_ARGV_OFFSET, "argv offset");
_Static_assert(offsetof(struct job, storage) == JOB_STORAGE_OFFSET, "storage offset");
_Static_assert(offsetof(struct job, inline_storage) == JOB_INLINE_OFFSET, "inline offset");

struct note {
    uint64_t id;
    uint32_t length;
    uint32_t flags;
    unsigned char body[NOTE_BODY_SIZE];
};

_Static_assert(sizeof(struct note) == JOB_SIZE, "allocator class parity");
_Static_assert(offsetof(struct note, body) == JOB_HANDLER_OFFSET, "note body offset");

struct session {
    enum broker_phase phase;
    uint64_t next_job_id;
    uint64_t next_note_id;
    struct job *owner;
    struct job *pending;
    void *note;
};

struct request {
    uint8_t opcode;
    uint32_t request_id;
};

static volatile sig_atomic_t stopping;

BROKER_EXPORT void job_log(struct job *job, int fd)
{
    uint32_t len = job->storage_len;

    (void)fd;
    if (len > JOB_INLINE_SIZE)
        len = JOB_INLINE_SIZE;
    dprintf(STDERR_FILENO, "broker[%ld]: dispatched job %" PRIu64 " (%.*s)\n",
            (long)getpid(), job->id, (int)len, job->storage);
}

BROKER_EXPORT void job_exec(struct job *job, int fd)
{
    char *const envp[] = {
        (char *)"PATH=/usr/bin:/bin",
        (char *)"LANG=C",
        (char *)"LC_ALL=C",
        NULL,
    };

    if (dup2(fd, STDIN_FILENO) < 0 ||
        dup2(fd, STDOUT_FILENO) < 0 ||
        dup2(fd, STDERR_FILENO) < 0)
        _exit(126);

    execve(job->program, job->argv, envp);
    dprintf(STDERR_FILENO, "execve: %s\n", strerror(errno));
    _exit(127);
}

static ssize_t read_full(int fd, void *buffer, size_t length)
{
    unsigned char *p = buffer;
    size_t done = 0;

    while (done < length) {
        ssize_t n = recv(fd, p + done, length - done, 0);
        if (n == 0)
            return done == 0 ? 0 : -1;
        if (n < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        done += (size_t)n;
    }
    return (ssize_t)done;
}

static int write_full(int fd, const void *buffer, size_t length)
{
    const unsigned char *p = buffer;
    size_t done = 0;

    while (done < length) {
        ssize_t n = send(fd, p + done, length - done, MSG_NOSIGNAL);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (n == 0)
            return -1;
        done += (size_t)n;
    }
    return 0;
}

static uint64_t load_be64(const unsigned char *p)
{
    uint64_t value = 0;
    size_t i;

    for (i = 0; i < 8; ++i)
        value = (value << 8) | p[i];
    return value;
}

static void store_be64(unsigned char *p, uint64_t value)
{
    int i;

    for (i = 7; i >= 0; --i) {
        p[i] = (unsigned char)value;
        value >>= 8;
    }
}

static int reply(int fd, const struct request *request, enum broker_status status,
                 const void *data, uint32_t data_len)
{
    struct broker_frame_header header = {
        .magic = htonl(BROKER_MAGIC),
        .version = BROKER_VERSION,
        .opcode = request->opcode,
        .flags = htons(BROKER_FLAG_RESPONSE),
        .request_id = htonl(request->request_id),
        .payload_len = htonl(sizeof(uint32_t) + data_len),
    };
    uint32_t wire_status = htonl((uint32_t)status);

    if (write_full(fd, &header, sizeof(header)) < 0 ||
        write_full(fd, &wire_status, sizeof(wire_status)) < 0)
        return -1;
    if (data_len != 0 && write_full(fd, data, data_len) < 0)
        return -1;
    return 0;
}

static int reply_phase(int fd, const struct request *request,
                       enum broker_status status, enum broker_phase phase)
{
    unsigned char value = (unsigned char)phase;
    return reply(fd, request, status, &value, sizeof(value));
}

static NOINLINE void retire_job(struct job *job)
{
    free(job);
}

static bool session_started(const struct session *session)
{
    return session->phase != BROKER_PHASE_NEW;
}

static int handle_hello(struct session *session, int fd, const struct request *request,
                        const unsigned char *payload, uint32_t length)
{
    unsigned char hello[9];

    (void)payload;
    if (session->phase != BROKER_PHASE_NEW)
        return reply_phase(fd, request, BROKER_STATUS_BAD_STATE, session->phase);
    if (length != 0)
        return reply(fd, request, BROKER_STATUS_BAD_PAYLOAD, NULL, 0);

    session->phase = BROKER_PHASE_READY;
    hello[0] = (unsigned char)session->phase;
    store_be64(hello + 1, (uint64_t)getpid());
    return reply(fd, request, BROKER_STATUS_OK, hello, sizeof(hello));
}

static int handle_auth_begin(struct session *session, int fd,
                             const struct request *request,
                             const unsigned char *payload, uint32_t length)
{
    (void)payload;
    if (session->phase != BROKER_PHASE_READY)
        return reply_phase(fd, request, BROKER_STATUS_BAD_STATE, session->phase);
    if (length != 0)
        return reply(fd, request, BROKER_STATUS_BAD_PAYLOAD, NULL, 0);

    session->phase = BROKER_PHASE_AUTH_PENDING;
    return reply_phase(fd, request, BROKER_STATUS_OK, session->phase);
}

static int handle_auth_abort(struct session *session, int fd,
                             const struct request *request,
                             const unsigned char *payload, uint32_t length)
{
    (void)payload;
    if (session->phase != BROKER_PHASE_AUTH_PENDING)
        return reply_phase(fd, request, BROKER_STATUS_BAD_STATE, session->phase);
    if (length != 0)
        return reply(fd, request, BROKER_STATUS_BAD_PAYLOAD, NULL, 0);

    session->phase = BROKER_PHASE_READY;
    return reply_phase(fd, request, BROKER_STATUS_OK, session->phase);
}

static int handle_auth_finish(struct session *session, int fd,
                              const struct request *request,
                              const unsigned char *payload, uint32_t length)
{
    const char *expected = getenv("BROKER_AUTH_TOKEN");
    size_t expected_len;
    unsigned char difference = 0;
    uint32_t i;

    if (session->phase != BROKER_PHASE_AUTH_PENDING)
        return reply_phase(fd, request, BROKER_STATUS_BAD_STATE, session->phase);
    expected_len = expected == NULL ? 0 : strlen(expected);
    if (expected_len != length) {
        session->phase = BROKER_PHASE_READY;
        return reply_phase(fd, request, BROKER_STATUS_DENIED, session->phase);
    }
    for (i = 0; i < length; ++i)
        difference |= payload[i] ^ (unsigned char)expected[i];
    if (difference != 0) {
        session->phase = BROKER_PHASE_READY;
        return reply_phase(fd, request, BROKER_STATUS_DENIED, session->phase);
    }

    session->phase = BROKER_PHASE_AUTHENTICATED;
    return reply_phase(fd, request, BROKER_STATUS_OK, session->phase);
}

static int handle_queue(struct session *session, int fd, const struct request *request,
                        const unsigned char *payload, uint32_t length)
{
    static char shell[] = "/bin/sh";
    static char shell_name[] = "sh";
    static char shell_command[] = "-c";
    static const unsigned char default_label[] = "queued";
    unsigned char wire_id[8];
    struct job *job;
    unsigned char kind;
    const unsigned char *body;
    uint32_t body_len;

    if (!session_started(session))
        return reply(fd, request, BROKER_STATUS_BAD_STATE, NULL, 0);
    if (length == 0)
        return reply(fd, request, BROKER_STATUS_BAD_PAYLOAD, NULL, 0);
    kind = payload[0];
    body = payload + 1;
    body_len = length - 1;
    if (body_len >= JOB_INLINE_SIZE || kind > 1)
        return reply(fd, request, BROKER_STATUS_BAD_PAYLOAD, NULL, 0);
    if (kind == 1 && session->phase != BROKER_PHASE_AUTHENTICATED)
        return reply(fd, request, BROKER_STATUS_DENIED, NULL, 0);
    if (session->pending != NULL)
        return reply(fd, request, BROKER_STATUS_BUSY, NULL, 0);

    job = calloc(1, sizeof(*job));
    if (job == NULL)
        return reply(fd, request, BROKER_STATUS_NOMEM, NULL, 0);

    job->id = ++session->next_job_id;
    job->storage = (char *)job->inline_storage;
    if (body_len != 0) {
        memcpy(job->inline_storage, body, body_len);
        job->storage_len = body_len;
    } else {
        memcpy(job->inline_storage, default_label, sizeof(default_label));
        job->storage_len = sizeof(default_label) - 1;
    }
    if (kind == 1) {
        job->handler = job_exec;
        job->program = shell;
        job->argv[0] = shell_name;
        job->argv[1] = shell_command;
        job->argv[2] = job->storage;
    } else {
        job->handler = job_log;
        job->program = job->storage;
        job->argv[0] = job->storage;
    }

    session->owner = job;
    session->pending = job;
    store_be64(wire_id, job->id);
    return reply(fd, request, BROKER_STATUS_OK, wire_id, sizeof(wire_id));
}

static int handle_cancel(struct session *session, int fd, const struct request *request,
                         const unsigned char *payload, uint32_t length)
{
    struct job *job;

    if (!session_started(session))
        return reply(fd, request, BROKER_STATUS_BAD_STATE, NULL, 0);
    if (length != 8)
        return reply(fd, request, BROKER_STATUS_BAD_PAYLOAD, NULL, 0);
    if (session->owner == NULL || session->owner->id != load_be64(payload))
        return reply(fd, request, BROKER_STATUS_NOT_FOUND, NULL, 0);

    job = session->owner;
    session->owner = NULL;
#ifdef FIXED
    if (session->pending == job)
        session->pending = NULL;
#endif
    retire_job(job);

#ifndef FIXED
    /* The owner slot is cleared, but the pending queue still retains job. */
#endif
    return reply(fd, request, BROKER_STATUS_OK, NULL, 0);
}

static int handle_inspect(struct session *session, int fd, const struct request *request,
                          const unsigned char *payload, uint32_t length)
{
    (void)payload;
    if (length != 0)
        return reply(fd, request, BROKER_STATUS_BAD_PAYLOAD, NULL, 0);

#ifdef FIXED
    if (session->phase != BROKER_PHASE_AUTHENTICATED)
        return reply(fd, request, BROKER_STATUS_DENIED, NULL, 0);
#else
    /* AUTH_PENDING (3) incorrectly satisfies this ordinal authorization test. */
    if (session->phase < BROKER_PHASE_AUTHENTICATED)
        return reply(fd, request, BROKER_STATUS_DENIED, NULL, 0);
#endif
    if (session->pending == NULL)
        return reply(fd, request, BROKER_STATUS_NOT_FOUND, NULL, 0);

    return reply(fd, request, BROKER_STATUS_OK, session->pending, JOB_SIZE);
}

static int handle_note(struct session *session, int fd, const struct request *request,
                       const unsigned char *payload, uint32_t length)
{
    struct note *note;

    if (!session_started(session))
        return reply(fd, request, BROKER_STATUS_BAD_STATE, NULL, 0);
    if (length > NOTE_BODY_SIZE)
        return reply(fd, request, BROKER_STATUS_BAD_PAYLOAD, NULL, 0);
    if (session->note != NULL)
        return reply(fd, request, BROKER_STATUS_BUSY, NULL, 0);

    note = malloc(sizeof(*note));
    if (note == NULL)
        return reply(fd, request, BROKER_STATUS_NOMEM, NULL, 0);
    note->id = ++session->next_note_id;
    note->length = length;
    note->flags = 0;
    memset(note->body, 0, sizeof(note->body));
    memcpy(note->body, payload, length);
    session->note = note;
    return reply(fd, request, BROKER_STATUS_OK, NULL, 0);
}

static int handle_dispatch(struct session *session, int fd,
                           const struct request *request,
                           const unsigned char *payload, uint32_t length)
{
    struct job *job;
    bool live;

    (void)payload;
    if (!session_started(session))
        return reply(fd, request, BROKER_STATUS_BAD_STATE, NULL, 0);
    if (length != 0)
        return reply(fd, request, BROKER_STATUS_BAD_PAYLOAD, NULL, 0);
    if (session->pending == NULL)
        return reply(fd, request, BROKER_STATUS_NOT_FOUND, NULL, 0);

    job = session->pending;
    live = session->owner == job;
    session->pending = NULL;
    if (live)
        session->owner = NULL;

    if (reply(fd, request, BROKER_STATUS_OK, NULL, 0) < 0) {
        if (live)
            retire_job(job);
        return -1;
    }

    job->handler(job, fd);
    if (live)
        retire_job(job);
    return 0;
}

static int handle_request(struct session *session, int fd,
                          const struct request *request,
                          const unsigned char *payload, uint32_t length)
{
    switch (request->opcode) {
    case BROKER_OP_HELLO:
        return handle_hello(session, fd, request, payload, length);
    case BROKER_OP_AUTH_BEGIN:
        return handle_auth_begin(session, fd, request, payload, length);
    case BROKER_OP_AUTH_ABORT:
        return handle_auth_abort(session, fd, request, payload, length);
    case BROKER_OP_AUTH_FINISH:
        return handle_auth_finish(session, fd, request, payload, length);
    case BROKER_OP_QUEUE:
        return handle_queue(session, fd, request, payload, length);
    case BROKER_OP_CANCEL:
        return handle_cancel(session, fd, request, payload, length);
    case BROKER_OP_INSPECT:
        return handle_inspect(session, fd, request, payload, length);
    case BROKER_OP_NOTE:
        return handle_note(session, fd, request, payload, length);
    case BROKER_OP_DISPATCH:
        return handle_dispatch(session, fd, request, payload, length);
    default:
        return reply(fd, request, BROKER_STATUS_BAD_OPCODE, NULL, 0);
    }
}

static void destroy_session(struct session *session)
{
    struct job *owner = session->owner;

    if (owner != NULL)
        retire_job(owner);
    if (session->note != NULL && session->note != owner)
        free(session->note);
}

static void serve_client(int fd)
{
    struct session session = { .phase = BROKER_PHASE_NEW };
    unsigned char payload[BROKER_MAX_PAYLOAD];

    for (;;) {
        struct broker_frame_header wire;
        struct request request;
        uint32_t length;
        uint16_t flags;
        ssize_t n;

        n = read_full(fd, &wire, sizeof(wire));
        if (n <= 0)
            break;

        request.opcode = wire.opcode;
        request.request_id = ntohl(wire.request_id);
        length = ntohl(wire.payload_len);
        flags = ntohs(wire.flags);

        if (ntohl(wire.magic) != BROKER_MAGIC) {
            reply(fd, &request, BROKER_STATUS_BAD_MAGIC, NULL, 0);
            break;
        }
        if (wire.version != BROKER_VERSION) {
            reply(fd, &request, BROKER_STATUS_BAD_VERSION, NULL, 0);
            break;
        }
        if (length > BROKER_MAX_PAYLOAD) {
            reply(fd, &request, BROKER_STATUS_TOO_LARGE, NULL, 0);
            break;
        }
        if (length != 0 && read_full(fd, payload, length) != (ssize_t)length)
            break;
        if (flags != 0) {
            if (reply(fd, &request, BROKER_STATUS_BAD_FLAGS, NULL, 0) < 0)
                break;
            continue;
        }
        if (request.opcode == BROKER_OP_QUIT) {
            if (length == 0)
                reply(fd, &request, BROKER_STATUS_OK, NULL, 0);
            else
                reply(fd, &request, BROKER_STATUS_BAD_PAYLOAD, NULL, 0);
            break;
        }
        if (handle_request(&session, fd, &request, payload, length) < 0)
            break;
    }

    destroy_session(&session);
}

static void on_stop(int signal_number)
{
    (void)signal_number;
    stopping = 1;
}

static void on_child(int signal_number)
{
    int saved_errno = errno;

    (void)signal_number;
    while (waitpid(-1, NULL, WNOHANG) > 0)
        ;
    errno = saved_errno;
}

static int install_signals(void)
{
    struct sigaction action = { 0 };

    sigemptyset(&action.sa_mask);
    action.sa_handler = on_stop;
    if (sigaction(SIGINT, &action, NULL) < 0 ||
        sigaction(SIGTERM, &action, NULL) < 0)
        return -1;

    action.sa_handler = on_child;
    action.sa_flags = SA_RESTART | SA_NOCLDSTOP;
    if (sigaction(SIGCHLD, &action, NULL) < 0)
        return -1;

    action.sa_handler = SIG_IGN;
    action.sa_flags = 0;
    return sigaction(SIGPIPE, &action, NULL);
}

static void reset_child_signals(void)
{
    struct sigaction action = { 0 };

    sigemptyset(&action.sa_mask);
    action.sa_handler = SIG_DFL;
    sigaction(SIGINT, &action, NULL);
    sigaction(SIGTERM, &action, NULL);
    sigaction(SIGCHLD, &action, NULL);
}

static int parse_port(const char *text, uint16_t *port)
{
    char *end;
    unsigned long value;

    if (text == NULL || *text == '\0' || *text == '-')
        return -1;
    errno = 0;
    value = strtoul(text, &end, 10);
    if (errno != 0 || *end != '\0' || value > UINT16_MAX)
        return -1;
    *port = (uint16_t)value;
    return 0;
}

static int open_listener(uint16_t requested_port, uint16_t *bound_port)
{
    struct sockaddr_in address = {
        .sin_family = AF_INET,
        .sin_port = htons(requested_port),
        .sin_addr.s_addr = htonl(INADDR_LOOPBACK),
    };
    socklen_t address_len = sizeof(address);
    int one = 1;
    int fd;

    fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0)
        return -1;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) < 0 ||
        bind(fd, (struct sockaddr *)&address, sizeof(address)) < 0 ||
        listen(fd, LISTEN_BACKLOG) < 0 ||
        getsockname(fd, (struct sockaddr *)&address, &address_len) < 0) {
        close(fd);
        return -1;
    }
    *bound_port = ntohs(address.sin_port);
    return fd;
}

static void usage(const char *program)
{
    fprintf(stderr, "usage: %s [--port 0..65535]\n", program);
}

int main(int argc, char **argv)
{
    uint16_t requested_port = DEFAULT_PORT;
    uint16_t bound_port;
    int listener;
    int i;

    if (getenv("LAB_MODE") == NULL || strcmp(getenv("LAB_MODE"), "1") != 0) {
        fprintf(stderr, "broker: set LAB_MODE=1 to run this lab target\n");
        return EXIT_FAILURE;
    }
    if (getenv("BROKER_AUTH_TOKEN") == NULL ||
        strlen(getenv("BROKER_AUTH_TOKEN")) < 16) {
        fprintf(stderr, "broker: set BROKER_AUTH_TOKEN to at least 16 bytes\n");
        return EXIT_FAILURE;
    }

    for (i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--port") == 0 && i + 1 < argc) {
            if (parse_port(argv[++i], &requested_port) < 0) {
                usage(argv[0]);
                return EXIT_FAILURE;
            }
        } else {
            usage(argv[0]);
            return EXIT_FAILURE;
        }
    }

    if (install_signals() < 0) {
        perror("sigaction");
        return EXIT_FAILURE;
    }
    listener = open_listener(requested_port, &bound_port);
    if (listener < 0) {
        perror("listen");
        return EXIT_FAILURE;
    }

    printf("LISTEN 127.0.0.1:%u\n", (unsigned)bound_port);
    fflush(stdout);

    while (!stopping) {
        struct sockaddr_in peer;
        socklen_t peer_len = sizeof(peer);
        int client = accept4(listener, (struct sockaddr *)&peer, &peer_len, SOCK_CLOEXEC);
        pid_t parent_pid;
        pid_t child;

        if (client < 0) {
            if (errno == EINTR)
                continue;
            perror("accept");
            break;
        }
        if ((ntohl(peer.sin_addr.s_addr) >> 24) != 127) {
            close(client);
            continue;
        }

        parent_pid = getpid();
        child = fork();
        if (child == 0) {
            reset_child_signals();
            if (prctl(PR_SET_PDEATHSIG, SIGTERM) < 0 || getppid() != parent_pid)
                _exit(EXIT_FAILURE);
            close(listener);
            serve_client(client);
            close(client);
            _exit(EXIT_SUCCESS);
        }
        close(client);
        if (child < 0)
            perror("fork");
    }

    close(listener);
    return EXIT_SUCCESS;
}
