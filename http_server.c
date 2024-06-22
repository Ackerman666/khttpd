#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt


#include <linux/fs.h>
#include <linux/fs_struct.h>
#include <linux/kthread.h>
#include <linux/sched/signal.h>
#include <linux/tcp.h>
#include <linux/workqueue.h>

#include "http_parser.h"
#include "http_server.h"
#include "mime_type.h"

#define CRLF "\r\n"

#define HTTP_RESPONSE_200_DUMMY                               \
    ""                                                        \
    "HTTP/1.1 200 OK" CRLF "Server: " KBUILD_MODNAME CRLF     \
    "Content-Type: text/plain" CRLF "Content-Length: 12" CRLF \
    "Connection: Close" CRLF CRLF "Hello World!" CRLF

#define HTTP_RESPONSE_200_KEEPALIVE                       \
    ""                                                    \
    "HTTP/1.1 200 OK" CRLF "Server: " KBUILD_MODNAME CRLF \
    "Content-Type: %s" CRLF "Content-Length: %d" CRLF     \
    "Connection: Close" CRLF CRLF

#define HTTP_RESPONSE_200_CHUNKED_KEEPALIVE                   \
    ""                                                        \
    "HTTP/1.1 200 OK" CRLF "Server: " KBUILD_MODNAME CRLF     \
    "Content-Type: %s" CRLF "Transfer-Encoding: chunked" CRLF \
    "Connection: Keep-Alive" CRLF CRLF



#define HTTP_RESPONSE_501                                              \
    ""                                                                 \
    "HTTP/1.1 501 Not Implemented" CRLF "Server: " KBUILD_MODNAME CRLF \
    "Content-Type: text/plain" CRLF "Content-Length: 21" CRLF          \
    "Connection: Close" CRLF CRLF "501 Not Implemented" CRLF
#define HTTP_RESPONSE_501_KEEPALIVE                                    \
    ""                                                                 \
    "HTTP/1.1 501 Not Implemented" CRLF "Server: " KBUILD_MODNAME CRLF \
    "Content-Type: text/plain" CRLF "Content-Length: 21" CRLF          \
    "Connection: KeepAlive" CRLF CRLF "501 Not Implemented" CRLF

#define HTTP_RESPONSE_404                                        \
    ""                                                           \
    "HTTP/1.1 404 Not Found" CRLF "Server: " KBUILD_MODNAME CRLF \
    "Content-Type: text/plain" CRLF "Content-Length: 13" CRLF    \
    "Connection: Close" CRLF CRLF "404 Not Found" CRLF

#define RECV_BUFFER_SIZE 4096
#define SEND_BUFFER_SIZE 4096



struct dir_tracer {
    struct dir_context dir_context;
    struct socket *socket;
};



struct request_handler {
    struct work_struct w;
    void *socket;
};

struct http_request {
    struct socket *socket;
    enum http_method method;
    char request_url[128];
    int complete;
};


static int http_server_recv(struct socket *sock, char *buf, size_t size)
{
    struct kvec iov = {.iov_base = (void *) buf, .iov_len = size};
    struct msghdr msg = {.msg_name = 0,
                         .msg_namelen = 0,
                         .msg_control = NULL,
                         .msg_controllen = 0,
                         .msg_flags = 0};
    return kernel_recvmsg(sock, &msg, &iov, 1, size, msg.msg_flags);
}

static int http_server_send(struct socket *sock, const char *buf, size_t size)
{
    struct msghdr msg = {.msg_name = NULL,
                         .msg_namelen = 0,
                         .msg_control = NULL,
                         .msg_controllen = 0,
                         .msg_flags = 0};
    int done = 0;
    while (done < size) {
        struct kvec iov = {
            .iov_base = (void *) ((char *) buf + done),
            .iov_len = size - done,
        };
        int length = kernel_sendmsg(sock, &msg, &iov, 1, iov.iov_len);
        if (length < 0) {
            pr_err("write error: %d\n", length);
            break;
        }
        done += length;
    }
    return done;
}

static bool trace_directory(struct dir_context *dir_context,
                            const char *name,
                            int name_size,
                            loff_t offset,
                            u64 ino,
                            unsigned int d_type)
{
    //"." represents the current directory, ".." represents the parent
    // directory, and neither of them will be displayed.
    if (strcmp(name, ".") && strcmp(name, "..")) {
        struct dir_tracer *tracer =
            container_of(dir_context, struct dir_tracer, dir_context);


        char buf[SEND_BUFFER_SIZE] = {0};
        char chunk_header[10] = {0};
        unsigned long chunk_size;

        snprintf(buf, SEND_BUFFER_SIZE,
                 "<tr><td><a href=\"%s\">%s</a></td></tr>\r\n", name, name);

        // Calculate chunk size
        chunk_size = strlen(buf);
        // Prepare chunk header
        snprintf(chunk_header, sizeof(chunk_header), "%lu\r\n", chunk_size);
        // Send chunk header
        http_server_send(tracer->socket, chunk_header, strlen(chunk_header));
        // Send chunk data
        http_server_send(tracer->socket, buf, chunk_size);
        // Send CRLF
        http_server_send(tracer->socket, CRLF, strlen(CRLF));
    }

    return true;
}



static void directory_listing(struct http_request *request, struct file *fp)
{
    struct dir_tracer d_tracer = {
        .dir_context =
            {
                .actor = trace_directory,
            },
        .socket = request->socket,
    };

    char buf[SEND_BUFFER_SIZE] = {0};

    // send header
    snprintf(buf, SEND_BUFFER_SIZE, HTTP_RESPONSE_200_CHUNKED_KEEPALIVE,
             "text/html");
    http_server_send(request->socket, buf, strlen(buf));

    // send html header
    snprintf(buf, SEND_BUFFER_SIZE, "7B\r\n%s%s%s%s", "<html><head><style>\r\n",
             "body{font-family: monospace; font-size: 15px;}\r\n",
             "td {padding: 1.5px 6px;}\r\n",
             "</style></head><body><table>\r\n");
    http_server_send(request->socket, buf, strlen(buf));

    iterate_dir(fp, &d_tracer.dir_context);
    snprintf(buf, SEND_BUFFER_SIZE, "16\r\n</table></body></html>\r\n");
    http_server_send(request->socket, buf, strlen(buf));

    // Sending the final chunk to indicate the end of the chunked transfer
    // encoding
    snprintf(buf, SEND_BUFFER_SIZE, "0\r\n\r\n\r\n");
    http_server_send(request->socket, buf, strlen(buf));
    filp_close(fp, NULL);

    return;
}


static int file_content_response(struct http_request *request, struct file *fp)
{
    char *read_data = kmalloc(fp->f_inode->i_size, GFP_KERNEL);
    int ret = kernel_read(fp, read_data, fp->f_inode->i_size, 0);
    char buf[SEND_BUFFER_SIZE] = {0};

    snprintf(buf, SEND_BUFFER_SIZE, HTTP_RESPONSE_200_KEEPALIVE,
             get_mime_str(request->request_url), ret);
    pr_info("Response Header content %s ! : ", buf);
    http_server_send(request->socket, buf, strlen(buf));
    http_server_send(request->socket, read_data, ret);

    kfree(read_data);
    return 0;
}



static int http_server_response(struct http_request *request, int keep_alive)
{
    pr_info("requested_url = %s\n", request->request_url);
    if (request->method != HTTP_GET) {
        char *response =
            keep_alive ? HTTP_RESPONSE_501_KEEPALIVE : HTTP_RESPONSE_501;
        http_server_send(request->socket, response, strlen(response));
    } else {
        char filepath[256];
        char *path = "/home/xiang/Desktop/linux2024/khttpd";
        snprintf(filepath, sizeof(filepath), "%s%s", path,
                 request->request_url);
        pr_info("request path ! %s\n", filepath);

        struct file *fp = filp_open(filepath, O_RDONLY, 0);
        if (IS_ERR(fp)) {
            pr_info("Open file failed");
            pr_err("request resouce not found ! \n");
            http_server_send(request->socket, HTTP_RESPONSE_404,
                             strlen(HTTP_RESPONSE_404));
        }

        // response directory list
        else if (S_ISDIR(fp->f_inode->i_mode)) {
            directory_listing(request, fp);
        }

        // response file content
        else if (S_ISREG(fp->f_inode->i_mode)) {
            file_content_response(request, fp);
        } else {
            pr_err("request resouce not found ! \n");
            http_server_send(request->socket, HTTP_RESPONSE_404,
                             strlen(HTTP_RESPONSE_404));
        }
        filp_close(fp, NULL);
    }
    return 0;
}

static int http_parser_callback_message_begin(http_parser *parser)
{
    struct http_request *request = parser->data;
    struct socket *socket = request->socket;
    memset(request, 0x00, sizeof(struct http_request));
    request->socket = socket;
    return 0;
}

static int http_parser_callback_request_url(http_parser *parser,
                                            const char *p,
                                            size_t len)
{
    struct http_request *request = parser->data;
    strncat(request->request_url, p, len);
    return 0;
}

static int http_parser_callback_header_field(http_parser *parser,
                                             const char *p,
                                             size_t len)
{
    return 0;
}

static int http_parser_callback_header_value(http_parser *parser,
                                             const char *p,
                                             size_t len)
{
    return 0;
}

static int http_parser_callback_headers_complete(http_parser *parser)
{
    struct http_request *request = parser->data;
    request->method = parser->method;
    return 0;
}

static int http_parser_callback_body(http_parser *parser,
                                     const char *p,
                                     size_t len)
{
    return 0;
}

static int http_parser_callback_message_complete(http_parser *parser)
{
    struct http_request *request = parser->data;
    http_server_response(request, http_should_keep_alive(parser));
    request->complete = 1;
    return 0;
}



/* kthread version
static int http_server_worker(void *arg)
{
    char *buf;
    struct http_parser parser;
    struct http_parser_settings setting = {
        .on_message_begin = http_parser_callback_message_begin,
        .on_url = http_parser_callback_request_url,
        .on_header_field = http_parser_callback_header_field,
        .on_header_value = http_parser_callback_header_value,
        .on_headers_complete = http_parser_callback_headers_complete,
        .on_body = http_parser_callback_body,
        .on_message_complete = http_parser_callback_message_complete};
    struct http_request request;
    struct socket *socket = (struct socket *) arg;

    allow_signal(SIGKILL);
    allow_signal(SIGTERM);

    buf = kzalloc(RECV_BUFFER_SIZE, GFP_KERNEL);
    if (!buf) {
        pr_err("can't allocate memory!\n");
        return -1;
    }

    request.socket = socket;
    http_parser_init(&parser, HTTP_REQUEST);
    parser.data = &request;
    while (!kthread_should_stop()) {
        int ret = http_server_recv(socket, buf, RECV_BUFFER_SIZE - 1);
        if (ret <= 0) {
            if (ret)
                pr_err("recv error: %d\n", ret);
            break;
        }
        http_parser_execute(&parser, &setting, buf, ret);
        if (request.complete && !http_should_keep_alive(&parser))
            break;
        memset(buf, 0, RECV_BUFFER_SIZE);
    }
    kernel_sock_shutdown(socket, SHUT_RDWR);
    sock_release(socket);
    kfree(buf);
    return 0;
}
*/

/*
CMWQ version
*/
static void http_server_worker(struct work_struct *w)
{
    struct request_handler *handler =
        container_of(w, struct request_handler, w);

    char *buf;
    struct http_parser parser;
    struct http_parser_settings setting = {
        .on_message_begin = http_parser_callback_message_begin,
        .on_url = http_parser_callback_request_url,
        .on_header_field = http_parser_callback_header_field,
        .on_header_value = http_parser_callback_header_value,
        .on_headers_complete = http_parser_callback_headers_complete,
        .on_body = http_parser_callback_body,
        .on_message_complete = http_parser_callback_message_complete};
    struct http_request request;
    struct socket *socket = (struct socket *) handler->socket;

    allow_signal(SIGKILL);
    allow_signal(SIGTERM);

    buf = kzalloc(RECV_BUFFER_SIZE, GFP_KERNEL);
    if (!buf) {
        pr_err("can't allocate memory!\n");
        // return -1;
    }

    request.socket = socket;
    http_parser_init(&parser, HTTP_REQUEST);
    parser.data = &request;
    // can add a thread or worker to count down, if out of time execute shutdown
    while (1) {
        // reset timer
        int ret = http_server_recv(socket, buf, RECV_BUFFER_SIZE - 1);
        if (ret <= 0) {
            if (ret)
                pr_err("recv error: %d\n", ret);
            break;
        }
        http_parser_execute(&parser, &setting, buf, ret);
        if (request.complete && !http_should_keep_alive(&parser))
            break;
        memset(buf, 0, RECV_BUFFER_SIZE);
    }
    kernel_sock_shutdown(socket, SHUT_RDWR);
    sock_release(socket);
    kfree(buf);
    kfree(handler);
    // return 0;
}

// if success run, return 1, otherwise return 0
int handle_client_request(void *arg, struct workqueue_struct *workqueue)
{
    struct request_handler *handler =
        kmalloc(sizeof(struct request_handler), GFP_KERNEL);
    handler->socket = arg;
    INIT_WORK(&handler->w, http_server_worker);
    if (queue_work(workqueue, &handler->w) == 0) {
        pr_err("work was already on a queue.");
        return 0;
    }
    return 1;

    /*
    struct task_struct *worker =
        kthread_run(http_server_worker, arg, KBUILD_MODNAME);
    if (IS_ERR(worker)){
        pr_err("can't create more worker process\n");
        return 0;
    }
    return 1;
    */
}

int http_server_daemon(void *arg)
{
    /*
    pr_err("test %s", HTTP_RESPONSE_200_CHUNKED_KEEPALIVE);
    return 0;
    */

    struct workqueue_struct *workqueue =
        alloc_workqueue("khttp", 0, WQ_MAX_ACTIVE);


    struct socket *socket;
    // struct task_struct *worker;
    struct http_server_param *param = (struct http_server_param *) arg;

    allow_signal(SIGKILL);
    allow_signal(SIGTERM);

    while (!kthread_should_stop()) {
        int err = kernel_accept(param->listen_socket, &socket, 0);
        if (err < 0) {
            if (signal_pending(current))
                break;
            pr_err("kernel_accept() error: %d\n", err);
            continue;
        }

        if (!handle_client_request(socket, workqueue)) {
            pr_err(
                "can't create more worker process to handle client request\n");
            continue;
        }

        // worker = kthread_run(http_server_worker, socket, KBUILD_MODNAME);
        /*
        if (IS_ERR(worker)) {
            pr_err("can't create more worker process\n");
            continue;
        }
        */
    }
    destroy_workqueue(workqueue);
    return 0;
}