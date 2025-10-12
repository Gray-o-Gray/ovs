/*
 * Copyright (c) 2011 Nicira, Inc.
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

#ifndef LACP_H
#define LACP_H 1

#include <stdbool.h>
#include <stdint.h>
#include "packets.h"

/* LACP Protocol Implementation. */

// lacp协商状态
enum lacp_status {
    LACP_NEGOTIATED,                  /* Successful LACP negotiations. 协商成功 */
    LACP_CONFIGURED,                  /* LACP is enabled but not negotiated. 协商失败 */
    LACP_DISABLED                     /* LACP is not enabled. 未启用 */
};

// lacp协议配置
struct lacp_settings {
    char *name;                       /* Name (for debugging). lacp名字，为debugging设计 */
    struct eth_addr id;               /* System ID. Must be nonzero. 系统ID（必须非零） */
    uint16_t priority;                /* System priority. 系统优先级 */
    bool active;                      /* Active or passive mode? 是否为主动模式 */
    bool fast;                        /* Fast or slow probe interval. 是否为快速探测模式 */
    bool fallback_ab_cfg;             /* Fallback to BM_SLB on LACP failure. 是否在LACP失败时自动降级为静态主备模式 */
};

void lacp_init(void);   // lacp初始化
struct lacp *lacp_create(void);     // 创建lacp
void lacp_unref(struct lacp *);     // 销毁lacp及其member
struct lacp *lacp_ref(const struct lacp *); // 获取lacp对象的引用计数

void lacp_configure(struct lacp *, const struct lacp_settings *);   // 通过lacp_settings类型的对象 对 lacp对象进行配置
bool lacp_is_active(const struct lacp *);   // 返回lacp对象是否配置主动探测模式

bool lacp_process_packet(struct lacp *, const void *member,
                         const struct dp_packet *packet);   // 成员lacp报文处理函数
enum lacp_status lacp_status(const struct lacp *);  // 获取lacp状态
const char *lacp_status_description(enum lacp_status);  // lacp状态描述

// lacp成员配置
struct lacp_member_settings {
    char *name;                       /* Name (for debugging). */
    uint16_t id;                      /* Port ID. 端口ID */
    uint16_t priority;                /* Port priority. 端口优先级 */
    uint16_t key;                     /* Aggregation key. 聚合key */
};

void lacp_member_register(struct lacp *, void *member_,
                          const struct lacp_member_settings *); // lacp成员注册
void lacp_member_unregister(struct lacp *, const void *member); // lacp成员注销
void lacp_member_carrier_changed(const struct lacp *, const void *member,
                                 bool carrier_up);  // lacp member 的 carrier状态变更时 更新member状态
bool lacp_member_may_enable(const struct lacp *, const void *member);   // 检查 lacp member 是否可使用
bool lacp_member_is_current(const struct lacp *, const void *member_);  // 检查 lacp member 信息是否为最新

/* Callback function for lacp_run() for sending a LACP PDU. */
typedef void lacp_send_pdu(void *member, const void *pdu, size_t pdu_size); // lacp_run()的回调函数，用于发送LACP PDU

void lacp_run(struct lacp *, lacp_send_pdu *);  // 定期更新lacp状态和信息
void lacp_wait(struct lacp *);                  // lacp状态机等待

// lacp成员统计信息
struct lacp_member_stats {
    /* id */
    struct eth_addr dot3adAggPortActorSystemID;             // 本端系统ID
    struct eth_addr dot3adAggPortPartnerOperSystemID;       // ? 对端系统ID
    uint32_t dot3adAggPortAttachedAggID;                    // ? 聚合key
    /* state */
    uint8_t dot3adAggPortActorAdminState;                   // ? 本端主状态
    uint8_t dot3adAggPortActorOperState;                    // ? 本端操作状态
    uint8_t dot3adAggPortPartnerAdminState;                 // ? 对端主状态
    uint8_t dot3adAggPortPartnerOperState;                  // ? 对端操作状态
    /* counters */
    uint32_t dot3adAggPortStatsLACPDUsRx;                   // PDU 接收数
    /* uint32_t dot3adAggPortStatsMarkerPDUsRx; */
    /* uint32_t dot3adAggPortStatsMarkerResponsePDUsRx; */
    /* uint32_t dot3adAggPortStatsUnknownRx; */
    uint32_t dot3adAggPortStatsIllegalRx;                   // 异常PDU接收数 -> RX Bad PDUs
    uint32_t dot3adAggPortStatsLACPDUsTx;                   // PDU 发送数
    /* uint32_t dot3adAggPortStatsMarkerPDUsTx; */
    /* uint32_t dot3adAggPortStatsMarkerResponsePDUsTx; */
};

bool lacp_get_member_stats(const struct lacp *, const void *member_,
                           struct lacp_member_stats *);     // 获取lacp member 的当前状态

#endif /* lacp.h */
