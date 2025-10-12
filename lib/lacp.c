/* Copyright (c) 2011, 2012, 2013, 2014, 2015 Nicira, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <config.h>
#include "lacp.h"

#include <stdlib.h>

#include "connectivity.h"
#include "openvswitch/dynamic-string.h"
#include "hash.h"
#include "openvswitch/hmap.h"
#include "dp-packet.h"
#include "ovs-atomic.h"
#include "packets.h"
#include "openvswitch/poll-loop.h"
#include "seq.h"
#include "openvswitch/shash.h"
#include "timer.h"
#include "timeval.h"
#include "unixctl.h"
#include "openvswitch/vlog.h"
#include "util.h"

VLOG_DEFINE_THIS_MODULE(lacp);

/* Masks for lacp_info state member. */
// lacp状态标志位
#define LACP_STATE_ACT  0x01 /* Activity. Active or passive? 活动状态 主动 或 被动 */
#define LACP_STATE_TIME 0x02 /* Timeout. Short or long timeout? 超时配置 短超时 或 长超时 */
#define LACP_STATE_AGG  0x04 /* Aggregation. Is the link is bondable? 端口是否加入聚合组 链路是否可聚合 */
#define LACP_STATE_SYNC 0x08 /* Synchronization. Is the link in up to date? 端口组信息和聚合组是否同步 链路是否处于最新状态 */
#define LACP_STATE_COL  0x10 /* Collecting. Is the link receiving frames? 端口是否接受数据帧 */
#define LACP_STATE_DIST 0x20 /* Distributing. Is the link sending frames? 端口是否发送数据帧 */
#define LACP_STATE_DEF  0x40 /* Defaulted. Using default partner info? 是否使用默认的对端信息 */
#define LACP_STATE_EXP  0x80 /* Expired. Using expired partner info? 是否使用过期的对端信息 */

#define LACP_FAST_TIME_TX 1000  /* Fast transmission rate. 快速发送间隔 1秒 */ 
#define LACP_SLOW_TIME_TX 30000 /* Slow transmission rate. 慢速发送间隔 30秒 */
#define LACP_RX_MULTIPLIER 3    /* Multiply by TX rate to get RX rate. 接收超时倍数 */

#define LACP_INFO_LEN 15 // lacp_info结构体的长度
OVS_PACKED(
struct lacp_info {
    ovs_be16 sys_priority;            /* System priority. 系统优先级 */
    struct eth_addr sys_id;           /* System ID. 系统ID */
    ovs_be16 key;                     /* Operational key. 操作KEY */
    ovs_be16 port_priority;           /* Port priority. 端口优先级 */
    ovs_be16 port_id;                 /* Port ID. 端口ID */
    uint8_t state;                    /* State mask.  See LACP_STATE macros. 状态标志位 */
});
BUILD_ASSERT_DECL(LACP_INFO_LEN == sizeof(struct lacp_info));

/*BUILD_ASSERT_DECL为一个断言宏，用于检查结构体的长度是否符合标准*/

#define LACP_PDU_LEN 110    // lacp_pdu结构体的长度
struct lacp_pdu {
    uint8_t subtype;          /* Always 1. */
    uint8_t version;          /* Always 1. */

    uint8_t actor_type;       /* Always 1. */
    uint8_t actor_len;        /* Always 20. */
    struct lacp_info actor;   /* LACP actor information. 存储lacp本端信息 */
    uint8_t z1[3];            /* Reserved.  Always 0. */

    uint8_t partner_type;     /* Always 2. */
    uint8_t partner_len;      /* Always 20. */
    struct lacp_info partner; /* LACP partner information. 存储lacp对端信息 */
    uint8_t z2[3];            /* Reserved.  Always 0. */

    uint8_t collector_type;   /* Always 3. */
    uint8_t collector_len;    /* Always 16. */
    ovs_be16 collector_delay; /* Maximum collector delay. Set to UINT16_MAX. */
    uint8_t z3[64];           /* Combination of several fields.  Always 0. */
};
BUILD_ASSERT_DECL(LACP_PDU_LEN == sizeof(struct lacp_pdu));

/* Implementation. */

/* Link Aggregation Marker Protocol 的作用
 * Marker Protocol 是链路聚合（Link Aggregation，如IEEE 802.3ad标准）中的一个子协议，主要用于确保在动态调整聚合组（LAG）成员端口时，数据包不会丢失或乱序。其核心功能包括：
 * 
 * 1. 状态同步：
 * 当聚合组中的某个端口需要被移除（如链路故障、手动禁用）或添加时，Marker Protocol 会在成员端口之间发送标记帧（Marker PDU），通知对端设备“暂停数据转发”，直到所有未完成的数据包被确认处理完毕。
 * 2. 数据完整性：
 * 通过标记帧交换，确保在端口状态变更期间，已发送的数据包被对端完整接收，避免因端口切换导致的数据丢失或重复。
 * 3. 协调LACP操作：
 * 与 LACP（Link Aggregation Control Protocol） 配合使用，实现聚合组的动态维护。
*/

// pdu子类型
enum pdu_subtype {
    SUBTYPE_UNUSED = 0, // 未使用
    SUBTYPE_LACP,       /* Link Aggregation Control Protocol. */
    SUBTYPE_MARKER,     /* Link Aggregation Marker Protocol. */
};

// 成员lacp状态（由partner进行更新）
enum member_status {
    LACP_CURRENT,   /* Current State.  Partner up to date. 最新状态 */
    LACP_EXPIRED,   /* Expired State.  Partner out of date. 过期状态 */
    LACP_DEFAULTED, /* Defaulted State.  No partner. 默认状态 */
};

/* A LACP primary interface. */
// lacp主对象
struct lacp {
    struct ovs_list node;         /* Node in all_lacps list. 指针结构体，内含一个*prev和*next */
    char *name;                   /* Name of this lacp object. lacp对象的名字 */
    struct eth_addr sys_id;       /* System ID. 系统ID，通常为聚合口的mac地址 */
    uint16_t sys_priority;        /* System Priority. 系统优先级，ovs默认为65532 */
    bool active;                  /* Active or Passive. 主动模式/被动模式 */

    struct hmap members;        /* Members this LACP object controls. 当前这lacp所含成员的哈希表 */
    struct member *key_member;  /* Member whose ID will be aggregation key. 当前聚合键是哪个成员 */

    bool fast;               /* True if using fast probe interval. 是否为快速发包模式 */
    bool negotiated;         /* True if LACP negotiations were successful. 聚合协商是否成功 */
    bool update;             /* True if lacp_update() needs to be called. 是否需要出发lacp_update() 函数进行状态更新 */
    bool fallback_ab;        /* True if fallback to active-backup on LACP failure. lacp失败时是否回退为主备模式 */

    struct ovs_refcount ref_cnt; /* 引用计数 用于跟踪当前使用该LACP对象的引用数量。*/ 
    /* 引用计数的作用：确保对象在无引用时安全释放，避免内存泄漏或悬垂指针。*/
};

/* A LACP member interface. */
// lacp成员对象
struct member {
    void *aux;                    /* Handle used to identify this member. */
                                  // 用户自定义句柄，用于标识或关联外部资源（如网络接口设备）。便于在回调或操作中快速访问相关数据
    struct hmap_node node;        /* Node in primary's members map. */
                                  // 哈希表节点，用于将成员接口加入所属LACP对象的哈希映射中，实现快速查找和管理。

    struct lacp *lacp;            /* LACP object containing this member. 当前成员属于哪个lacp对象 */
    uint16_t port_id;             /* Port ID. 端口ID */
    uint16_t port_priority;       /* Port Priority. 端口优先级 */
    uint16_t key;                 /* Aggregation Key. 0 if default. 聚合键，默认为0 */
    char *name;                   /* Name of this member. 当前成员的名字 */

    enum member_status status;    /* Member status. 成员状态 */
    bool attached;                /* Attached. Traffic may flow. 是否加入到聚合组中 */
                                  /* 若为true，表示该接口可参与数据转发（通过聚合逻辑端口）*/
    bool carrier_up;              /* Carrier state of link. 物理载波状态是否正常(是否插线) */
    struct lacp_info partner;     /* Partner information. 对端信息 */
    struct lacp_info ntt_actor;   /* Used to decide if we Need To Transmit. */
                                  // 标记本地LACP信息是否变化。若变化（如状态更新），触发发送LACPDU
    struct timer tx;              /* Next message transmission timer. lacpdu发送定时器 */
    struct timer rx;              /* Expected message receive timer. 接收超时定时器 */

    // 统计计数
    uint32_t count_rx_pdus;         /* dot3adAggPortStatsLACPDUsRx 收到的有效pdu报文数量*/
    uint32_t count_rx_pdus_bad;     /* dot3adAggPortStatsIllegalRx 收到的异常pdu报文数量*/
    uint32_t count_rx_pdus_marker;  /* dot3adAggPortStatsMarkerPDUsRx 收到的pdu Marker协议报文数量*/
    uint32_t count_tx_pdus;         /* dot3adAggPortStatsLACPDUsTx 发送的pdu报文数量*/
    uint32_t count_link_expired;    /* Num of times link expired 超时的次数*/
    uint32_t count_link_defaulted;  /* Num of times link defaulted 默认的次数*/
    uint32_t count_carrier_changed; /* Num of times link status changed 载波状态变化的次数*/
};

static struct ovs_mutex mutex;
static struct ovs_list all_lacps__ = OVS_LIST_INITIALIZER(&all_lacps__);
static struct ovs_list *const all_lacps OVS_GUARDED_BY(mutex) = &all_lacps__;

static void lacp_update_attached(struct lacp *) OVS_REQUIRES(mutex);

static void member_destroy(struct member *) OVS_REQUIRES(mutex);
static void member_set_defaulted(struct member *) OVS_REQUIRES(mutex);
static void member_set_expired(struct member *) OVS_REQUIRES(mutex);
static void member_get_actor(struct member *, struct lacp_info *actor)
    OVS_REQUIRES(mutex);
static void member_get_priority(struct member *, struct lacp_info *priority)
    OVS_REQUIRES(mutex);
static bool member_may_tx(const struct member *)
    OVS_REQUIRES(mutex);
static struct member *member_lookup(const struct lacp *, const void *member)
    OVS_REQUIRES(mutex);
static bool info_tx_equal(struct lacp_info *, struct lacp_info *)
    OVS_REQUIRES(mutex);
static bool member_may_enable__(struct member *) OVS_REQUIRES(mutex);

static unixctl_cb_func lacp_unixctl_show;
static unixctl_cb_func lacp_unixctl_show_stats;

/* Populates 'pdu' with a LACP PDU comprised of 'actor' and 'partner'. */
// 将actor和partner信息进行组装，然后填入pdu报文中
static void
compose_lacp_pdu(const struct lacp_info *actor,
                 const struct lacp_info *partner, struct lacp_pdu *pdu)
{
    memset(pdu, 0, sizeof *pdu);

    pdu->subtype = 1;
    pdu->version = 1;

    pdu->actor_type = 1;
    pdu->actor_len = 20;
    pdu->actor = *actor;

    pdu->partner_type = 2;
    pdu->partner_len = 20;
    pdu->partner = *partner;

    pdu->collector_type = 3;
    pdu->collector_len = 16;
    pdu->collector_delay = htons(0);
}

/* Parses 'p' which represents a packet containing a LACP PDU. This function
 * returns NULL if 'p' is malformed, or does not represent a LACP PDU format
 * supported by OVS.  Otherwise, it returns a pointer to the lacp_pdu contained
 * within 'p'. It also returns the subtype of PDU.*/

/* 解析表示包含LACP PDU的数据包'p'。
 * 若'p'格式错误或不代表OVS支持的LACP PDU格式，则此函数返回NULL；否则，返回指向'p'中lacp_pdu的指针，并同时返回PDU的子类型。*/

static const struct lacp_pdu *
parse_lacp_packet(const struct dp_packet *p, enum pdu_subtype *subtype)
{
    const struct lacp_pdu *pdu;

    pdu = dp_packet_at(p, (uint8_t *)dp_packet_l3(p) - (uint8_t *)dp_packet_data(p),
                    LACP_PDU_LEN);

    // 根据报文中的type和len参数确定当前pdu报文的subtype
    if (pdu && pdu->subtype == 1
        && pdu->actor_type == 1 && pdu->actor_len == 20
        && pdu->partner_type == 2 && pdu->partner_len == 20) {
        *subtype = SUBTYPE_LACP;
        return pdu;
    } else if (pdu && pdu->subtype == SUBTYPE_MARKER) {
        *subtype = SUBTYPE_MARKER;
        return NULL;
    } else{
        *subtype = SUBTYPE_UNUSED;
        return NULL;
    }
}

/* LACP Protocol Implementation. */
// lacp协议实现

/* Initializes the lacp module. */
// lacp模块初始化
// 将lacp/show和lacp/show-stats进行注册
void
lacp_init(void)
{
    unixctl_command_register("lacp/show", "[port]", 0, 1,
                             lacp_unixctl_show, NULL);
    unixctl_command_register("lacp/show-stats", "[port]", 0, 1,
                             lacp_unixctl_show_stats, NULL);
}

// lacp 加锁与释放锁
static void
lacp_lock(void) OVS_ACQUIRES(mutex)
{
    static struct ovsthread_once once = OVSTHREAD_ONCE_INITIALIZER;

    if (ovsthread_once_start(&once)) {
        ovs_mutex_init_recursive(&mutex); // 初始化递归锁
        ovsthread_once_done(&once);
    }
    ovs_mutex_lock(&mutex); //拿锁
}

static void
lacp_unlock(void) OVS_RELEASES(mutex)
{
    ovs_mutex_unlock(&mutex); //释放锁
}

/* Creates a LACP object. */

/* 创建lacp对象（lacp_create）
 * 1. 申请内存
 * 2. 初始化lacp成员哈希表
 * 3. 初始化引用计数变量
 * 4. lacp_lock 拿锁
 * 5. ovs_list_push_back 将当前lacp对象加入全局的all_lacps中
 * 6. lacp_unlock 释放锁
*/
struct lacp *
lacp_create(void) OVS_EXCLUDED(mutex)
{
    struct lacp *lacp;

    lacp = xzalloc(sizeof *lacp);       // 申请内存
    hmap_init(&lacp->members);          // 初始化lacp成员哈希表
    ovs_refcount_init(&lacp->ref_cnt);  // 初始化引用计数变量

    lacp_lock();                                    // 拿锁
    ovs_list_push_back(all_lacps, &lacp->node);     // 将当前lacp对象加入全局的all_lacps中
    lacp_unlock();                                  // 释放锁
    return lacp;
}

// lacp引用与解引用（lacp_ref/lacp_unref）
struct lacp *
lacp_ref(const struct lacp *lacp_)
{
    struct lacp *lacp = CONST_CAST(struct lacp *, lacp_);
    if (lacp) {
        ovs_refcount_ref(&lacp->ref_cnt);
    }
    return lacp;
}

/* Destroys 'lacp' and its members. Does nothing if 'lacp' is NULL. */
// 销毁lacp及其成员对象，如果lacp对象为NULL则跳过。
void
lacp_unref(struct lacp *lacp) OVS_EXCLUDED(mutex)
{
    if (lacp && ovs_refcount_unref_relaxed(&lacp->ref_cnt) == 1) {
        struct member *member;

        lacp_lock();
        HMAP_FOR_EACH_SAFE (member, node, &lacp->members) {
            member_destroy(member);
        }

        hmap_destroy(&lacp->members);
        ovs_list_remove(&lacp->node);
        free(lacp->name);
        free(lacp);
        lacp_unlock();
    }
}

/* Configures 'lacp' with settings from 's'. */
// 从lacp_settings的's'变量配置lacp对象'lacp'
void
lacp_configure(struct lacp *lacp, const struct lacp_settings *s)
    OVS_EXCLUDED(mutex)
{
    ovs_assert(!eth_addr_is_zero(s->id));

    lacp_lock();
    if (!lacp->name || strcmp(s->name, lacp->name)) {
        free(lacp->name);
        lacp->name = xstrdup(s->name);
    }

    if (!eth_addr_equals(lacp->sys_id, s->id)
        || lacp->sys_priority != s->priority) {
        lacp->sys_id = s->id;
        lacp->sys_priority = s->priority;
        lacp->update = true;
    }

    lacp->active = s->active;
    lacp->fast = s->fast;

    if (lacp->fallback_ab != s->fallback_ab_cfg) {
        lacp->fallback_ab = s->fallback_ab_cfg;
        lacp->update = true;
    }

    lacp_unlock();
}

// lacp模式判断/获取
/* Returns true if 'lacp' is configured in active mode, false if 'lacp' is
 * configured for passive mode. */
// 如果lacp配置为主动模式则返回true，如果配置为被动模式则返回false
bool
lacp_is_active(const struct lacp *lacp) OVS_EXCLUDED(mutex)
{
    bool ret;
    lacp_lock();
    ret = lacp->active;
    lacp_unlock();
    return ret;
}

/* Processes 'packet' which was received on 'member_'.  This function should be
 * called on all packets received on 'member_' with Ethernet Type
 * ETH_TYPE_LACP.
 */

// 处理在'member_'上收到的'packet'。此函数应在所有以太网类型为ETH_TYPE_LACP的'member_'上收到的数据包上调用。

bool
lacp_process_packet(struct lacp *lacp, const void *member_,
                    const struct dp_packet *packet)
    OVS_EXCLUDED(mutex)
{
    static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
    const struct lacp_pdu *pdu;
    long long int tx_rate;
    struct member *member;
    bool lacp_may_enable = false;       // 默认设置为false
    enum pdu_subtype subtype;

    lacp_lock();
    member = member_lookup(lacp, member_);  // 确认member_是否存在于当前lacp对象中
    if (!member) {
        goto out;
    }
    member->count_rx_pdus++;

    pdu = parse_lacp_packet(packet, &subtype);
    switch (subtype) {
        case SUBTYPE_LACP:
            break;
        case SUBTYPE_MARKER:
            member->count_rx_pdus_marker++;
            VLOG_DBG("%s: received a LACP marker PDU.", lacp->name);
            goto out;
        case SUBTYPE_UNUSED:
        default:
            member->count_rx_pdus_bad++;
            VLOG_WARN_RL(&rl, "%s: received an unparsable LACP PDU.",
                         lacp->name);
            goto out;
    }

    /* On some NICs L1 state reporting is slow. In case LACP packets are
     * received while carrier (L1) state is still down, drop the LACP PDU and
     * trigger re-checking of L1 state. */
    // 在某些网络接口卡（NIC）上，物理层（L1）状态的上报可能存在延迟。
    // 当链路聚合控制协议（LACP）数据包在物理层载波（L1）状态尚未恢复时被接收，系统会丢弃该LACP协议数据单元（PDU），并触发对物理层状态的重新检测。

    if (!member->carrier_up) {
        VLOG_INFO_RL(&rl, "%s: carrier state is DOWN,"
                     " dropping received LACP PDU.", member->name);
        seq_change(connectivity_seq_get());     // 触发连接性序列号变更，驱动上层状态机更新
        goto out;
    }

    member->status = LACP_CURRENT;
    tx_rate = lacp->fast ? LACP_FAST_TIME_TX : LACP_SLOW_TIME_TX;
    timer_set_duration(&member->rx, LACP_RX_MULTIPLIER * tx_rate);

    member->ntt_actor = pdu->partner;

    /* Update our information about our partner if it's out of date. This may
     * cause priorities to change so re-calculate attached status of all
     * members. */
    // 若当前记录的合作伙伴信息已过时，则更新相关信息。
    // 此操作可能导致优先级发生变更，因此需重新计算所有成员端口的附着状态。

    if (memcmp(&member->partner, &pdu->actor, sizeof pdu->actor)) { // 比对内存中的partner数据结构是否发生变化
        lacp->update = true;
        member->partner = pdu->actor;
    }

    /* Evaluate may_enable here to avoid dropping of packets till main thread
     * sets may_enable to true. */
    // 此处评估 may_enable 状态，以避免主线程设置may_enable为true时引起数据包丢失
    lacp_may_enable = member_may_enable__(member);

out:
    lacp_unlock();

    return lacp_may_enable;
}

/* Returns the lacp_status of the given 'lacp' object (which may be NULL). */
// 返回给定'lacp'对象的lacp_status（该对象可能为NULL）。
enum lacp_status
lacp_status(const struct lacp *lacp) OVS_EXCLUDED(mutex)
{
    if (lacp) {
        enum lacp_status ret;

        lacp_lock();
        ret = lacp->negotiated ? LACP_NEGOTIATED : LACP_CONFIGURED;
        lacp_unlock();
        return ret;
    } else {
        /* Don't take 'mutex'.  It might not even be initialized, since we
         * don't know that any lacp object has been created. */
        // 不获取'mutex'锁。因为我们无法确定是否已经创建了任何lacp对象，所以'mutex'可能尚未初始化。
        return LACP_DISABLED;
    }
}

// lacp状态描述
const char *lacp_status_description(enum lacp_status lacp_status)
{
    switch (lacp_status) {
    case LACP_NEGOTIATED:
        return "negotiated";
    case LACP_CONFIGURED:
        return "configured";
    case LACP_DISABLED:
        return "off";
    default:
        return "<unknown>";
    }
}

/* Registers 'member_' as subordinate to 'lacp'.  This should be called at
 * least once per member in a LACP managed bond.  Should also be called
 * whenever a member's settings change. */
// 将'member_'注册为'lacp'的从属项。
// 在LACP管理的绑定中，每个成员至少应调用一次此操作。当成员的设置发生变更时，也应调用该操作。
void
lacp_member_register(struct lacp *lacp, void *member_,
                     const struct lacp_member_settings *s)
    OVS_EXCLUDED(mutex)
{
    struct member *member;

    lacp_lock();
    member = member_lookup(lacp, member_);          // 判断member_成员是否在当前lacp中

    // member_不在当前lacp中，初始化member信息并加入当前lacp
    if (!member) {
        member = xzalloc(sizeof *member);
        member->lacp = lacp;
        member->aux = member_;
        hmap_insert(&lacp->members, &member->node, hash_pointer(member_, 0));
        member_set_defaulted(member);   // 新加入的member状态设置为LACP_DEFAULTED

        // 如果此时lacp中还没有key_member，则将当前member设置为key_member
        // 即第一个加入lacp的member会被作为key_member
        if (!lacp->key_member) {
            lacp->key_member = member;
        }
    }

    // 若member的name不存在（刚刚加入）或member的name信息发生变化，更新member->name
    // member成员使用aux进行标记，可进行修改（例如修改网卡的名字）
    if (!member->name || strcmp(s->name, member->name)) {
        free(member->name);
        member->name = xstrdup(s->name);
    }

    // 若member与lacp相关的信息发生变化（端口ID、端口优先级、聚合key（操作key？））
    if (member->port_id != s->id
        || member->port_priority != s->priority
        || member->key != s->key) {
        member->port_id = s->id;
        member->port_priority = s->priority;
        member->key = s->key;

        // lacp更新标志置为true
        lacp->update = true;

        // 若lacp为主动模式或已协商状态，将当前member的LACP状态修改为过期状态LACP_EXPIRED
        // 等待LACP重新协商
        if (lacp->active || lacp->negotiated) {
            member_set_expired(member);
        }
    }
    lacp_unlock();
}

/* Unregisters 'member_' with 'lacp'.  */
// 将'member_'从'lacp'中注销。
void
lacp_member_unregister(struct lacp *lacp, const void *member_)
    OVS_EXCLUDED(mutex)
{
    struct member *member;

    lacp_lock();
    member = member_lookup(lacp, member_);  // 确认member_(member->aux)是否存在于当前lacp

    // member_存在于lacp中
    if (member) {
        member_destroy(member); // 销毁member对象
        lacp->update = true;    // lacp更新标志置为true
    }
    lacp_unlock();
}

/* This function should be called whenever the carrier status of 'member_' has
 * changed.  If 'lacp' is null, this function has no effect.*/
// 每当'member_'的载波状态发生变化时，应调用此函数。如果'lacp'为null，则此函数无效。
void
lacp_member_carrier_changed(const struct lacp *lacp, const void *member_,
                            bool carrier_up)
    OVS_EXCLUDED(mutex)
{
    struct member *member;
    if (!lacp) {
        return;
    }

    lacp_lock();
    member = member_lookup(lacp, member_);
    // member_不存在于当前lacp
    if (!member) {
        goto out;
    }

    // member当前的LACP状态为最新 或 member所属的lacp为主动模式
    if (member->status == LACP_CURRENT || member->lacp->active) {
        member_set_expired(member);         // member的LACP状态设置为过期
    }

    // member的carrier_up状态发生变化，更新member成员的变量并将carrier_changed计数增加1
    if (member->carrier_up != carrier_up) {
        member->carrier_up = carrier_up;
        member->count_carrier_changed++;
    }

out:
    lacp_unlock();
}

/**
 * member成员是否可用（member_may_enable__）
 * 需满足以下条件
 * 1. member->attached为true（当前member处于聚合组中）
 * 2. member的对端lacp标志位中存在LACP_STATE_SYNC 或 （ member的lacp存在 且 lacp的回退主备开启中 且 成员状态为LACP_DEFAULTED ）
 */
static bool
member_may_enable__(struct member *member) OVS_REQUIRES(mutex)
{
    /* The member may be enabled if it's attached to an aggregator and its
     * partner is synchronized.*/
    // 如果成员已连接到聚合器且partner处于同步状态，则可能启用该成员。
    return member->attached && (member->partner.state & LACP_STATE_SYNC
            || (member->lacp && member->lacp->fallback_ab
                && member->status == LACP_DEFAULTED));
}

/* This function should be called before enabling 'member_' to send or receive
 * traffic.  If it returns false, 'member_' should not enabled.  As a
 * convenience, returns true if 'lacp' is NULL. */
// 在启用'member_'以发送或接收流量之前应调用此函数。如果返回false，则不应启用'member_'。
// 作为一种便利，如果'lacp'为NULL，则返回true。
bool
lacp_member_may_enable(const struct lacp *lacp, const void *member_)
    OVS_EXCLUDED(mutex)
{
    if (lacp) {
        struct member *member;
        bool ret = false;

        lacp_lock();
        member = member_lookup(lacp, member_);
        if (member) {
            /* It is only called when carrier is up. So, enable member's
             * carrier state if it is currently down. */
            // 仅在载波启动时调用。因此，若当前为关闭状态，则启用成员的载波状态。
            if (!member->carrier_up) {
                member->carrier_up = true;
            }
            ret = member_may_enable__(member);
        }
        lacp_unlock();
        return ret;
    } else {
        return true;
    }
}

/* Returns true if partner information on 'member_' is up to date.  'member_'
 * not being current, generally indicates a connectivity problem, or a
 * misconfigured (or broken) partner. */
/* 如果'member_'上的partner信息是最新的，则返回true。  
 * 'member_'未保持最新通常表示存在连接问题，或合作伙伴配置错误（或故障）。*/

// member->status由partner进行更新
bool
lacp_member_is_current(const struct lacp *lacp, const void *member_)
    OVS_EXCLUDED(mutex)
{
    struct member *member;
    bool ret;

    lacp_lock();
    member = member_lookup(lacp, member_);
    // member->status不为LACP_DEFAULTED即可，LACP_CURRENT和LACP_EXPIRED都可
    // 这里也就说明只要member存在且收到过lacp报文，ret就是true
    ret = member ? member->status != LACP_DEFAULTED : false;
    lacp_unlock();
    return ret;
}

/* This function should be called periodically to update 'lacp'. */
// 定期调用此函数以更新'lacp'。
// 1. 遍历lacp的所有成员，检查rx定时器是否过期，若过期则更新成员的状态
// 2. 若lacp的update标志为true，则调用lacp_update_attached()函数更新成员的attached状态
// 3. 遍历lacp的所有成员，检查tx定时器是否过期，若过期则发送lacp_pdu报文

void
lacp_run(struct lacp *lacp, lacp_send_pdu *send_pdu) OVS_EXCLUDED(mutex)
{
    struct member *member;

    lacp_lock();
    // member收包检查
    HMAP_FOR_EACH (member, node, &lacp->members) {
        if (timer_expired(&member->rx)) {
            enum member_status old_status = member->status;

            if (member->status == LACP_CURRENT) {
                member_set_expired(member);
                member->count_link_expired++;
            } else if (member->status == LACP_EXPIRED) {
                member_set_defaulted(member);
                member->count_link_defaulted++;
            }
            if (member->status != old_status) {
                seq_change(connectivity_seq_get());
            }
        }
    }

    // lacp状态更新
    if (lacp->update) {
        lacp_update_attached(lacp);
        seq_change(connectivity_seq_get());
    }

    // member发包检查
    HMAP_FOR_EACH (member, node, &lacp->members) {
        struct lacp_info actor;

        if (!member_may_tx(member)) {
            continue;
        }

        member_get_actor(member, &actor);

        if (timer_expired(&member->tx)
            || !info_tx_equal(&actor, &member->ntt_actor)) {
            long long int duration;
            struct lacp_pdu pdu;

            member->ntt_actor = actor;
            compose_lacp_pdu(&actor, &member->partner, &pdu);
            send_pdu(member->aux, &pdu, sizeof pdu);
            member->count_tx_pdus++;

            duration = (member->partner.state & LACP_STATE_TIME
                        ? LACP_FAST_TIME_TX
                        : LACP_SLOW_TIME_TX);

            timer_set_duration(&member->tx, duration);
            seq_change(connectivity_seq_get());
        }
    }
    lacp_unlock();
}

/* Causes poll_block() to wake up when lacp_run() needs to be called again. */
// 使poll_block()在需要再次调用lacp_run()时唤醒。
void
lacp_wait(struct lacp *lacp) OVS_EXCLUDED(mutex)
{
    struct member *member;

    lacp_lock();
    HMAP_FOR_EACH (member, node, &lacp->members) {
        if (member_may_tx(member)) {
            timer_wait(&member->tx);
        }

        if (member->status != LACP_DEFAULTED) {
            timer_wait(&member->rx);
        }
    }
    lacp_unlock();
}

/* Static Helpers. */
// 静态辅助函数

/* Updates the attached status of all members controlled by 'lacp' and sets its
 * negotiated parameter to true if any members are attachable. */
// 更新由'lacp'控制的所有成员的attach状态，若存在可attach的成员，则将其协商参数设为true。
static void
lacp_update_attached(struct lacp *lacp) OVS_REQUIRES(mutex)
{
    struct member *lead, *lead_current, *member;
    struct lacp_info lead_pri;
    bool lead_enable;
    static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 10);

    lacp->update = false;

    lead = NULL;
    lead_current = NULL;
    lead_enable = false;

    /* Check if there is a working interface.
     * Store as lead_current, if there is one. */
    /* 检查是否存在有效接口。
     * 若存在，将其存储为 lead_current。 */
    
    // 遍历所有的member成员，选取pri最高的可attach的member作为lead_current.
    HMAP_FOR_EACH (member, node, &lacp->members) {
        if (member->status == LACP_CURRENT && member->attached) {
            struct lacp_info pri;
            member_get_priority(member, &pri);
            if (!lead_current || memcmp(&pri, &lead_pri, sizeof pri) < 0) {
                lead_current = member;
                lead = lead_current;
                lead_pri = pri;
                lead_enable = true;
            }
        }
    }

    /* Find interface with highest priority. */
    // 查找优先级最高的接口。
    HMAP_FOR_EACH (member, node, &lacp->members) {
        struct lacp_info pri;

        member->attached = false;

        /* XXX: In the future allow users to configure the expected system ID.
         * For now just special case loopback. */
        /* XXX：未来应允许用户配置预期的系统ID。
         * 目前仅特殊处理环回情况。 */
        if (eth_addr_equals(member->partner.sys_id, member->lacp->sys_id)) {
            VLOG_WARN_RL(&rl, "member %s: Loopback detected. Interface is "
                         "connected to its own bond", member->name);
            continue;
        }

        if (member->status == LACP_DEFAULTED) {
            if (lacp->fallback_ab) {
                // member处于默认状态，并且lacp开启失败回退主备，将当前member的attached置为true
                member->attached = true;
            }
            continue;
        }

        member_get_priority(member, &pri);          // 获取member的系统优先级
        bool enable = member_may_enable__(member);  // 获取member的可用状态

        /* Check if partner MAC address is the same as on the working
         * interface. Activate member only if the MAC is the same, or
         * there is no working interface. */
        /* 检查partner MAC地址是否与工作接口（lead_current）上的相同。仅当MAC地址相同或无工作接口（lead_current）时，才激活成员。 */
        if (!lead_current || (lead_current
            && eth_addr_equals(member->partner.sys_id,
                               lead_current->partner.sys_id))) {
            member->attached = true;
        }

        // 再对lead再进行一轮更新，将lead修改为pri最高的member
        // !!! 注意此时lead和lead_current可能是不同的
        if (member->attached &&
                (!lead
                 || enable > lead_enable
                 || (enable == lead_enable
                     && memcmp(&pri, &lead_pri, sizeof pri) < 0))) {
            lead = member;
            lead_enable = enable;
            lead_pri = pri;
        }
    }

    // lead不为空，则认为lacp协商成功
    lacp->negotiated = lead != NULL;

    if (lead) {
        // 存在lead的情况下，检查所有member
        // 若member->partner的操作key或系统ID和lead不一致时，将member->attached置为false（踢出聚合）
        HMAP_FOR_EACH (member, node, &lacp->members) {
            if ((lacp->fallback_ab && member->status == LACP_DEFAULTED)
                || lead->partner.key != member->partner.key
                || !eth_addr_equals(lead->partner.sys_id,
                                    member->partner.sys_id)) {
                member->attached = false;
            }
        }
    }
}

static void
member_destroy(struct member *member) OVS_REQUIRES(mutex)
{
    // member 存在
    if (member) {
        // 获取member对应lacp
        struct lacp *lacp = member->lacp;

        lacp->update = true;    // 标记lacp需要进行更新
        hmap_remove(&lacp->members, &member->node); // 将member从lacp->members哈希表中移除

        // 若当前member为key_member
        if (lacp->key_member == member) {
            // 获取哈希表中的第一个member节点
            struct hmap_node *member_node = hmap_first(&lacp->members);

            // 若member_node节点存在则将其更新为当前lacp的key_member
            // 否则当前lacp的key_member赋值为NULL
            if (member_node) {
                lacp->key_member = CONTAINER_OF(member_node, struct member,
                                                node);
            } else {
                lacp->key_member = NULL;
            }
        }

        // 释放内存
        free(member->name);
        free(member);
    }
}

static void
member_set_defaulted(struct member *member) OVS_REQUIRES(mutex)
{
    // 将member->partner清空
    memset(&member->partner, 0, sizeof member->partner);

    member->lacp->update = true;        // member所属lacp标记为需要更新
    member->status = LACP_DEFAULTED;    // member状态标记为LACP_DEFAULTED
}

static void
member_set_expired(struct member *member) OVS_REQUIRES(mutex)
{
    member->status = LACP_EXPIRED;              // member状态标记为LACP_EXPIRED

    // member->partner标记位中添加LACP_STATE_TIME（fast模式），移除LACP_STATE_SYNC
    member->partner.state |= LACP_STATE_TIME;
    member->partner.state &= ~LACP_STATE_SYNC;

    // 设置接收定时器超时时间，强制使用快超时LACP_FAST_TIME_TX
    timer_set_duration(&member->rx, LACP_RX_MULTIPLIER * LACP_FAST_TIME_TX);
}

static void
member_get_actor(struct member *member, struct lacp_info *actor)
    OVS_REQUIRES(mutex)
{
    struct lacp *lacp = member->lacp;
    uint16_t key;
    uint8_t state = 0;

    // lacp状态标记位确定
    // 主动模式
    if (lacp->active) {
        state |= LACP_STATE_ACT;
    }

    // 快超时FAST
    if (lacp->fast) {
        state |= LACP_STATE_TIME;
    }

    // member是否在聚合组中
    if (member->attached) {
        state |= LACP_STATE_SYNC;
    }

    // member状态（默认/超时）
    if (member->status == LACP_DEFAULTED) {
        state |= LACP_STATE_DEF;
    }

    if (member->status == LACP_EXPIRED) {
        state |= LACP_STATE_EXP;
    }

    // 是否存在聚合组，memeber至少有2个
    if (hmap_count(&lacp->members) > 1) {
        state |= LACP_STATE_AGG;
    }

    // member是否在聚合组中或lacp协商失败
    if (member->attached || !lacp->negotiated) {
        state |= LACP_STATE_COL | LACP_STATE_DIST;
    }

    // 操作key使用key_member的key或端口ID
    key = lacp->key_member->key;
    if (!key) {
        key = lacp->key_member->port_id;
    }

    actor->state = state;       // LACP状态标记位
    actor->key = htons(key);    // 操作key
    actor->port_priority = htons(member->port_priority);    // 端口优先级
    actor->port_id = htons(member->port_id);                // 端口ID （网卡mac）
    actor->sys_priority = htons(lacp->sys_priority);        // 系统优先级
    actor->sys_id = lacp->sys_id;                           // 系统ID（bond口mac）
}

/* Given 'member', populates 'priority' with data representing its LACP link
 * priority.  If two priority objects populated by this function are compared
 * using memcmp, the higher priority link will be less than the lower priority
 * link. */
/* 给定'member'，用表示其LACP链路优先级的数据填充'priority'。  
 * 若使用memcmp比较由此函数填充的两个优先级对象，
 * 较高优先级的链路将小于较低优先级的链路。（pri值越小，优先级越高） */
static void
member_get_priority(struct member *member, struct lacp_info *priority)
    OVS_REQUIRES(mutex)
{
    uint16_t partner_priority, actor_priority;

    /* Choose the lacp_info of the higher priority system by comparing their
     * system priorities and mac addresses. */
    /* 通过比较系统优先级和MAC地址，选择更高优先级系统的lacp_info。 */
    actor_priority = member->lacp->sys_priority;                // 本端lacp系统优先级
    partner_priority = ntohs(member->partner.sys_priority);     // 对端partner系统优先级
    if (actor_priority < partner_priority) {
        // 本端系统优先级更高，从member信息中提取优先级信息
        member_get_actor(member, priority);
    } else if (partner_priority < actor_priority) {
        // 对端系统优先级更高，直接使用member->partner的信息作为优先级信息
        *priority = member->partner;
    } else if (eth_addr_compare_3way(member->lacp->sys_id,
                                     member->partner.sys_id) < 0) {
        // 系统优先级相同，本端端口优先级更高，从member信息中提取优先级信息
        member_get_actor(member, priority);
    } else {
        // 对端端口优先级更高或相同，直接使用member->partner的信息作为优先级信息
        *priority = member->partner;
    }

    /* Key and state are not used in priority comparisons. */
    /* 操作key和lacp状态不用于优先级比较。 */
    priority->key = 0;
    priority->state = 0;
}

static bool
member_may_tx(const struct member *member) OVS_REQUIRES(mutex)
{
    /* Check for L1 state as well as LACP state. */
    // 检查L1状态及LACP状态。
    // 要求：载波状态为UP且（lacp为主动模式或member状态不为默认）
    return (member->carrier_up) && ((member->lacp->active) ||
            (member->status != LACP_DEFAULTED));
}

static struct member *
member_lookup(const struct lacp *lacp, const void *member_) OVS_REQUIRES(mutex)
{
    struct member *member;

    // 遍历哈希表lacp->members
    HMAP_FOR_EACH_IN_BUCKET (member, node, hash_pointer(member_, 0),
                             &lacp->members) {
        if (member->aux == member_) {   // aux为member的标记变量
            return member;
        }
    }

    return NULL;
}

/* Two lacp_info structures are tx_equal if and only if they do not differ in
 * ways which would require a lacp_pdu transmission. */
/* 两个lacp_info结构体存在且仅在不会导致需要发送lacp_pdu的差异情况下被视为tx_equal（存在差异时才应触发发送pdu）*/
static bool
info_tx_equal(struct lacp_info *a, struct lacp_info *b)
{

    /* LACP specification dictates that we transmit whenever the actor and
     * remote_actor differ in the following fields: Port, Port Priority,
     * System, System Priority, Aggregation Key, Activity State, Timeout State,
     * Sync State, and Aggregation State. The state flags are most likely to
     * change so are checked first. */
    /* LACP规范规定，当本端与远端在以下字段存在差异时需发送报文：
     * 端口、端口优先级、系统、系统优先级、操作key、
     * 主动模式（active）、超时状态（timeout）、同步状态（sync）及聚合组状态（agg）。
     * 其中状态标志位最易变动，故优先检查。*/  
    return !((a->state ^ b->state) & (LACP_STATE_ACT
                                      | LACP_STATE_TIME
                                      | LACP_STATE_SYNC
                                      | LACP_STATE_AGG))
        && a->port_id == b->port_id
        && a->port_priority == b->port_priority
        && a->key == b->key
        && a->sys_priority == b->sys_priority
        && eth_addr_equals(a->sys_id, b->sys_id);
}

static struct lacp *
lacp_find(const char *name) OVS_REQUIRES(mutex)
{
    struct lacp *lacp;

    // 遍历all_lacps查找lacp的名字
    LIST_FOR_EACH (lacp, node, all_lacps) {
        if (!strcmp(lacp->name, name)) {
            return lacp;
        }
    }

    return NULL;
}

static void
ds_put_lacp_state(struct ds *ds, uint8_t state)
{
    if (state & LACP_STATE_ACT) {
        ds_put_cstr(ds, " activity");
    }

    if (state & LACP_STATE_TIME) {
        ds_put_cstr(ds, " timeout");
    }

    if (state & LACP_STATE_AGG) {
        ds_put_cstr(ds, " aggregation");
    }

    if (state & LACP_STATE_SYNC) {
        ds_put_cstr(ds, " synchronized");
    }

    // 收包
    if (state & LACP_STATE_COL) {
        ds_put_cstr(ds, " collecting");
    }

    // 发包
    if (state & LACP_STATE_DIST) {
        ds_put_cstr(ds, " distributing");
    }

    if (state & LACP_STATE_DEF) {
        ds_put_cstr(ds, " defaulted");
    }

    if (state & LACP_STATE_EXP) {
        ds_put_cstr(ds, " expired");
    }
}

static void
lacp_print_details(struct ds *ds, struct lacp *lacp) OVS_REQUIRES(mutex)
{
    struct shash member_shash = SHASH_INITIALIZER(&member_shash);
    const struct shash_node **sorted_members = NULL;

    struct member *member;
    int i;

    ds_put_format(ds, "---- %s ----\n", lacp->name);
    ds_put_format(ds, "  status: %s", lacp->active ? "active" : "passive");
    if (lacp->negotiated) {
        ds_put_cstr(ds, " negotiated");
    }
    ds_put_cstr(ds, "\n");

    ds_put_format(ds, "  sys_id: " ETH_ADDR_FMT "\n", ETH_ADDR_ARGS(lacp->sys_id));
    ds_put_format(ds, "  sys_priority: %u\n", lacp->sys_priority);
    ds_put_cstr(ds, "  aggregation key: ");
    if (lacp->key_member) {
        ds_put_format(ds, "%u", lacp->key_member->key
                                ? lacp->key_member->key
                                : lacp->key_member->port_id);
    } else {
        ds_put_cstr(ds, "none");
    }
    ds_put_cstr(ds, "\n");

    ds_put_cstr(ds, "  lacp_time: ");
    if (lacp->fast) {
        ds_put_cstr(ds, "fast\n");
    } else {
        ds_put_cstr(ds, "slow\n");
    }

    HMAP_FOR_EACH (member, node, &lacp->members) {
        shash_add(&member_shash, member->name, member);
    }
    sorted_members = shash_sort(&member_shash);

    for (i = 0; i < shash_count(&member_shash); i++) {
        char *status;
        struct lacp_info actor;

        member = sorted_members[i]->data;
        member_get_actor(member, &actor);
        switch (member->status) {
        case LACP_CURRENT:
            status = "current";
            break;
        case LACP_EXPIRED:
            status = "expired";
            break;
        case LACP_DEFAULTED:
            status = "defaulted";
            break;
        default:
            OVS_NOT_REACHED();
        }

        ds_put_format(ds, "\nmember: %s: %s %s\n", member->name, status,
                      member->attached ? "attached" : "detached");
        ds_put_format(ds, "  port_id: %u\n", member->port_id);
        ds_put_format(ds, "  port_priority: %u\n", member->port_priority);
        ds_put_format(ds, "  may_enable: %s\n", (member_may_enable__(member)
                                                 ? "true" : "false"));

        ds_put_format(ds, "\n  actor sys_id: " ETH_ADDR_FMT "\n",
                      ETH_ADDR_ARGS(actor.sys_id));
        ds_put_format(ds, "  actor sys_priority: %u\n",
                      ntohs(actor.sys_priority));
        ds_put_format(ds, "  actor port_id: %u\n",
                      ntohs(actor.port_id));
        ds_put_format(ds, "  actor port_priority: %u\n",
                      ntohs(actor.port_priority));
        ds_put_format(ds, "  actor key: %u\n",
                      ntohs(actor.key));
        ds_put_cstr(ds, "  actor state:");
        ds_put_lacp_state(ds, actor.state);
        ds_put_cstr(ds, "\n\n");

        ds_put_format(ds, "  partner sys_id: " ETH_ADDR_FMT "\n",
                      ETH_ADDR_ARGS(member->partner.sys_id));
        ds_put_format(ds, "  partner sys_priority: %u\n",
                      ntohs(member->partner.sys_priority));
        ds_put_format(ds, "  partner port_id: %u\n",
                      ntohs(member->partner.port_id));
        ds_put_format(ds, "  partner port_priority: %u\n",
                      ntohs(member->partner.port_priority));
        ds_put_format(ds, "  partner key: %u\n",
                      ntohs(member->partner.key));
        ds_put_cstr(ds, "  partner state:");
        ds_put_lacp_state(ds, member->partner.state);
        ds_put_cstr(ds, "\n");
    }

    shash_destroy(&member_shash);
    free(sorted_members);
}

static void
lacp_print_stats(struct ds *ds, struct lacp *lacp) OVS_REQUIRES(mutex)
{
    struct shash member_shash = SHASH_INITIALIZER(&member_shash);
    const struct shash_node **sorted_members = NULL;

    struct member *member;
    int i;

    ds_put_format(ds, "---- %s statistics ----\n", lacp->name);

    HMAP_FOR_EACH (member, node, &lacp->members) {
        shash_add(&member_shash, member->name, member);
    }
    sorted_members = shash_sort(&member_shash);

    for (i = 0; i < shash_count(&member_shash); i++) {
        member = sorted_members[i]->data;
        ds_put_format(ds, "\nmember: %s:\n", member->name);
        ds_put_format(ds, "  TX PDUs: %u\n", member->count_tx_pdus);
        ds_put_format(ds, "  RX PDUs: %u\n", member->count_rx_pdus);
        ds_put_format(ds, "  RX Bad PDUs: %u\n", member->count_rx_pdus_bad);
        ds_put_format(ds, "  RX Marker Request PDUs: %u\n",
                      member->count_rx_pdus_marker);
        ds_put_format(ds, "  Link Expired: %u\n",
                      member->count_link_expired);
        ds_put_format(ds, "  Link Defaulted: %u\n",
                      member->count_link_defaulted);
        ds_put_format(ds, "  Carrier Status Changed: %u\n",
                      member->count_carrier_changed);
    }

    shash_destroy(&member_shash);
    free(sorted_members);
}

static void
lacp_unixctl_show(struct unixctl_conn *conn, int argc, const char *argv[],
                  void *aux OVS_UNUSED) OVS_EXCLUDED(mutex)
{
    struct ds ds = DS_EMPTY_INITIALIZER;
    struct lacp *lacp;

    lacp_lock();
    if (argc > 1) {
        lacp = lacp_find(argv[1]);
        if (!lacp) {
            unixctl_command_reply_error(conn, "no such lacp object");
            goto out;
        }
        lacp_print_details(&ds, lacp);
    } else {
        LIST_FOR_EACH (lacp, node, all_lacps) {
            lacp_print_details(&ds, lacp);
        }
    }

    unixctl_command_reply(conn, ds_cstr(&ds));
    ds_destroy(&ds);

out:
    lacp_unlock();
}

static void
lacp_unixctl_show_stats(struct unixctl_conn *conn,
                  int argc,
                  const char *argv[],
                  void *aux OVS_UNUSED) OVS_EXCLUDED(mutex)
{
    struct ds ds = DS_EMPTY_INITIALIZER;
    struct lacp *lacp;

    lacp_lock();
    if (argc > 1) {
        lacp = lacp_find(argv[1]);
        if (!lacp) {
            unixctl_command_reply_error(conn, "no such lacp object");
            goto out;
        }
        lacp_print_stats(&ds, lacp);
    } else {
        LIST_FOR_EACH (lacp, node, all_lacps) {
            lacp_print_stats(&ds, lacp);
        }
    }

    unixctl_command_reply(conn, ds_cstr(&ds));
    ds_destroy(&ds);

out:
    lacp_unlock();
}

// 下面这个函数有点奇怪，还在使用比较原始的方式进行加锁，lacp正常应该统一使用lacp_lock才对。

// 该函数好像是给sflow获取计数信息使用的？有点迷惑。
// sflow_agent_get_counters->ofproto_port_get_lacp_stats->port_get_lacp_stats->lacp_get_member_stats


/* Extract a snapshot of the current state and counters for a member port.
   Return false if the member is not active. */
/* 提取成员端口的当前状态及计数器快照。
   若该成员未激活，则返回false。 */
bool
lacp_get_member_stats(const struct lacp *lacp, const void *member_,
                   struct lacp_member_stats *stats)
    OVS_EXCLUDED(mutex)
{
    struct member *member;
    struct lacp_info actor;
    bool ret;

    ovs_mutex_lock(&mutex);

    member = member_lookup(lacp, member_);
    if (member) {
        ret = true;
        member_get_actor(member, &actor);
        stats->dot3adAggPortActorSystemID = actor.sys_id;
        stats->dot3adAggPortPartnerOperSystemID = member->partner.sys_id;
        stats->dot3adAggPortAttachedAggID = (lacp->key_member->key ?
                                             lacp->key_member->key :
                                             lacp->key_member->port_id);

        /* Construct my admin-state.  Assume aggregation is configured on. */
        /* 构建我的管理状态。假设聚合功能已启用。*/
        stats->dot3adAggPortActorAdminState = LACP_STATE_AGG;
        if (lacp->active) {
            stats->dot3adAggPortActorAdminState |= LACP_STATE_ACT;
        }
        if (lacp->fast) {
            stats->dot3adAggPortActorAdminState |= LACP_STATE_TIME;
        }
        /* XXX Not sure how to know the partner admin state. It
         * might have to be captured and remembered during the
         * negotiation phase.
         */
        /* XXX 不确定如何获知对端管理状态。可能需要在协商阶段捕获并记录该信息。*/
        stats->dot3adAggPortPartnerAdminState = 0;

        stats->dot3adAggPortActorOperState = actor.state;
        stats->dot3adAggPortPartnerOperState = member->partner.state;

        /* Read out the latest counters */
        /* 读取最新的计数器值 */
        stats->dot3adAggPortStatsLACPDUsRx = member->count_rx_pdus;
        stats->dot3adAggPortStatsIllegalRx = member->count_rx_pdus_bad;
        stats->dot3adAggPortStatsLACPDUsTx = member->count_tx_pdus;
    } else {
        ret = false;
    }
    ovs_mutex_unlock(&mutex);
    return ret;

}
