#include "ofib.h"
#include "lib/event.h"
#include "lib/timer.h"
#include "lib/lists.h"
#include "lib/socket.h"
#include "ospf.h"
#include "ospf_defs.h"

void ofib_err_hook(sock UNUSED *sk, int UNUSED err) {
    //struct opref *o = (struct opref*) sk->data;
    log(L_TRACE "ofib: Connection error with peer <%I>", sk->faddr);
}

int ofib_convergence_notification(sock *sk, uint size) {
    if (size == 1 && sk->rbuf[0] == 1) {
	log(L_TRACE "ofib: Got convergence notification from peer <%I>", sk->faddr);

	struct opref *o = (struct opref*) sk->data;
	if (!o) {
	    // This should never happen
	    log(L_ERR "ofib: No ordered prefix data attached to this stream sk!");
	    return 1;
	}

	struct timespec tp;
	clock_gettime(CLOCK_MONOTONIC, &tp);
	o->info.conf_recep.tv_sec = tp.tv_sec;
	o->info.conf_recep.tv_nsec = tp.tv_nsec;

	// Close our connection and mark convergence
	if (o->ssk) sk_close_transport(o->ssk);
	o->ssk = NULL;
	//if (o->csk) sk_close_transport(o->csk);
	//o->csk = NULL;
	o->done = true;

	// Trigger next peer convergence, if any
	struct opref *next = NODE_NEXT(o), *n, *nxt;
	if (next && o != TAIL(o->p->ofib)) {
	    log(L_TRACE "ofib: Schedule convergence of next peer <%I>", next->ssk->faddr);
	    ev_schedule(next->cb);
	} else {
	    // We are the last node, ordered convergence is finished!
	    // We must recompute our own routes now.
	    log(L_TRACE "ofib: End of ordered convergence. Emptying peer list.");
	    // struct Ofib *ofib = next->ofib;
    WALK_LIST_DELSAFE(n, nxt, o->p->ofib) {
        ofib_register_timers(n->ofib, n->info);
		    rem_node(NODE(n));
	    }

	    ofib_dump_timers(o->ofib);
	    ofib_free(o->ofib);

	    // Advance our current LSA to flood it through the entire area
	    struct ospf_area *area = HEAD(o->p->area_list);
	    struct top_hash_entry *lsa = area->rt;
	    o->p->ofib_neigh = NULL;
	    ospf_advance_lsa(o->p, lsa, &lsa->lsa, lsa->lsa_type, lsa->domain, NULL);

	    // Schedule and apply FIB update
	    ospf_schedule_rtcalc(o->p) ;
	    o->p->disp_timer->hook(o->p->disp_timer);
	}
	
    } else
	log(L_WARN "ofib: Unexpected message received on stream from peer <%I>", sk->faddr);
    return 1;
}

static inline void ofib_send_lsa(sock *sk) {
    struct opref *o = (struct opref*) sk->data;
    struct ospf_proto *p = o->p;
    // TODO : Get the correct area from somewhere
    struct ospf_area *oa = HEAD(p->area_list);
    struct top_hash_entry *h = oa->rt;
    struct timespec tp;

    size_t lsa_header_len = sizeof(struct ospf_lsa_header);
    memcpy(sk->tbuf, &h->lsa, lsa_header_len);
    memcpy(&sk->tbuf[lsa_header_len], h->lsa_body, h->lsa.length - lsa_header_len);

    log(L_TRACE "ofib: Sending new LSA to remote <%I>\nSeq: %08x, Age: %4u, Sum: %04x",
	    sk->faddr, h->lsa.sn, h->lsa.age, h->lsa.checksum);

    clock_gettime(CLOCK_MONOTONIC, &tp);
    o->info.lsa_sent.tv_sec = tp.tv_sec;
    o->info.lsa_sent.tv_nsec = tp.tv_nsec;

    sk_send(sk, h->lsa.length);
}

void ofib_stream_connected(sock *sk);

void ofib_wake_hook(void *arg) {
    log(L_TRACE "ofib: Wake hook called.");
    ofib_stream_connected((sock *) arg);
}

#define NODE_PREV(n) ((void*)(NODE (n))->prev)

/**
 * Main stream callback, it may be called multiple times.
 *
 * The first call indicates that we have a stream connected with our peer.
 * If we are the first socket of the list or if the previous peer already converged, we send
 * our new LSA to our peer.
 * If the previous peer has not converged yet, we register an event that will be called by the
 * previous socket on convergence notification. That event is a new call to this callback.
 *
 * The second call indicates that the previous peer converged so that we are the next in the 
 * ordered list of peers.
 *
 * @param[in]	sk	The transport stream socket
 *
 */
void ofib_stream_connected(sock *sk) {
    struct opref *o = (struct opref*) sk->data;
    struct ospf_proto *p = o->p;

    if (!o->ssk) {
	struct timespec tp;
	clock_gettime(CLOCK_MONOTONIC, &tp);
	o->info.stream_created.tv_sec = tp.tv_sec;
	o->info.stream_created.tv_nsec = tp.tv_nsec;
	log(L_TRACE "ofib: Stream connected to peer <%I>", sk->faddr);
	o->ssk = sk;
    }

    struct opref *prev = NODE_PREV(o);
    u8 i_am_the_first = HEAD(p->ofib) == o || !prev;

    // TODO : enforce that new LSA has been originated by comparing seqnums
    if ((i_am_the_first && p->ofib_lsa_orignated & 0x1) || prev->done) {
        // If we are the first remote peer or the previous one has converged, we send our new LSA
	sk->rx_hook = ofib_convergence_notification;
	ofib_send_lsa(sk);
    } else {
	if (!o->cb) {
	    // We must wait that the previous node converge.
	    log(L_TRACE "ofib: Register wake callback.");
	    o->cb = ev_new_init(sk->pool, ofib_wake_hook, (void*) sk);
	    /* We are the first node, indicate to origination process that we are ready to start */
	    if (i_am_the_first) p->ofib_lsa_orignated |= 0x2;
	} else {
	    // We already attempted once to trigger convergence but failed again
	    // This should not happen
	    log(L_ERR "ofib: Failed at least twice to trigger convergence on remote peer.");
	    ev_schedule(o->cb);
	}
    }
}

void ofib_tx_hook(sock *sk) {

    struct opref *opref = (struct opref*) sk->data;

    struct timespec tp;
    clock_gettime(CLOCK_MONOTONIC, &tp);
    opref->info.co_created.tv_sec = tp.tv_sec;
    opref->info.co_created.tv_nsec = tp.tv_nsec;

    log(L_TRACE "ofib: Connected to peer at addr <%I>", sk->daddr);
    if (sk_open_stream(sk, ofib_stream_connected) < 0)
	    log(L_ERR "ofib: Failed to open a stream.");
}

/**
 * Main Ordered Convergence callback
 *
 * When called, this function performs the following steps:
 *
 * 1. Generate the ordered prefix lists
* 	1.a. Feed the graph computation routine with LSAs describing the topology
 * 	1.b. Compute the ordered prefix list
 *
 * 2. Establish a QUIC session and open a transport stream toward each prefix.
 *
 * The remaining of the convergence control is performed by the callbacks defined above.
 *
 * @param[in]	n	The failed neighbor
 *
 */
void ofib_cb(struct ospf_neighbor *n) {
    
    struct top_hash_entry *runner;
    struct ospf_config *c;
    struct ospf_proto *p;
    Buffer buf, rids_buf;
    struct Ofib *ofib;


    p = n->ifa->oa->po;
    c = (struct ospf_config*) p->p.cf;

    ofib = ofib_init(p->router_id);

    log(L_TRACE "ofib: Collecting LSAs");
    WALK_SLIST(runner, p->lsal) {
	ofib_add_lsa(ofib, (const struct ospf_lsa_header*) &runner->lsa,
		(const void*) runner->lsa_body);
    }

    // TODO: replace by an iterator
    buf = ofib_converge(ofib, n->rid, p->router_id, c->ofib_type);
    rids_buf = ofib_get_rids(ofib);
    uint8_t *buf2 = (uint8_t *) buf.buffer;
    uint32_t *rids = (uint32_t*) rids_buf.buffer;

    log(L_TRACE "ofib: Got <%u> node(s) to contact", buf.len);
    
    char qlog_dir[100], sni[100];
    ip6_addr peer;
    sock *sk;

    // for each prefix:
    // 1. open a QUIC connection with the peer
    // 2. send our new router-lsa(s)
    // 3. wait for convergence notification of the peer
    // 4. close the QUIC connection
    //
    // Thoses steps are blocking to ensure the ordered convergence.
    for (uint64_t i = 0; i < buf.len; i++) {
        peer = get_ip6(&buf2[i*16]);

        struct opref *opref = (struct opref*) xmalloc(sizeof(struct opref));
        memset(opref, 0, sizeof(struct opref));

        sk = sk_new(p->p.pool);
        opref->csk = sk;
        opref->p = p;
        opref->ofib = ofib;
        sk->data = (void*) opref;

        sk->type = SK_QUIC_ACTIVE;

        // QUIC (pun intented) hack to forge SNI
        sprintf(qlog_dir, "/tmp/node%u", p->router_id);
        sprintf(sni, "r%u", rids[i] - 1);

        sk_set_tls_config(sk, c->tls_insecure, c->tls_cert_path, c->tls_key_path, c->alpn,
        			"/tmp/secret", 1, c->tls_root_ca, sni, qlog_dir);
        sk->rbsize = sk->tbsize = 2048;
        sk->iface = n->ifa->iface;
        sk->dport = p->trans_serv_sk->sport;
        sk->tx_hook = ofib_tx_hook;
        //sk->rx_hook = sk_ofib_rx_hook;
        sk->err_hook = ofib_err_hook;
        sk->daddr = peer;

        log(L_TRACE "ofib: connecting to %I", peer);

        opref->info.node_info.src = p->router_id;
        opref->info.node_info.dst = rids[i]-1;

        struct timespec tp;
        clock_gettime(CLOCK_MONOTONIC, &tp);
        opref->info.co_init.tv_sec = tp.tv_sec;
        opref->info.co_init.tv_nsec = tp.tv_nsec;

        if (sk_open(sk) < 0) {
            log(L_ERR "ofib: Failed to open connection to remote peer.");
        } else
            add_tail(&p->ofib, NODE opref);
        }
}
