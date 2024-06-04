#ifndef OFIB_H
#define OFIB_H
#include <stdio.h>

#include "lib/lists.h"
#include "lib/socket.h"
#include "lib/event.h"
#include "ospf.h"
#include <time.h>

#include "ofib_ffi.h"

struct opref {
    node node;

    sock *csk;		/**< Connection sk */
    sock *ssk;		/**< Stream sk */
    bool done;
    struct ospf_proto *p;
    event *cb;

    RemoteInfo info;	/**< Timing data passed back to FFI */
    struct Ofib *ofib;
};

void ofib_cb(struct ospf_neighbor *n);

#endif
