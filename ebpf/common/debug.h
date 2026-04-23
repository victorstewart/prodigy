#include <switchboard/common/structs.h>

#pragma once

struct bpf_string {
   
   char string[32];
   __u32 len;
};

enum packet_frame_type {

   is_eth_frame,
   is_ip_frame,
   is_ip6_frame,
   is_icmp6_frame,
   is_tcp_frame,
   is_udp_frame,
   is_other_frame
};

struct packet_frame {

   enum packet_frame_type type;

   union {

      struct {
         __u8 src[6];
         __u8 dest[6];
         __u16 proto;
      } eth;

      struct {
         __u8 src[16];
         __u8 dest[16];
         __u8 proto;
      } ip6;

      struct {
         __u8 src[4];
         __u8 dest[4];
         __u8 proto;
      } ip;

      struct {
         __u32 seq;
         __u32 ack_seq;
         __u16 sport;
         __u16 dport;
         __u16 window;
         __u16 payload_len;
         bool isSyn;
         bool isAck;
         bool isFin;
         bool isRst;
      } tcp;

      struct {
         __u16 sport;
         __u16 dport;
         __u16 payload_len;
      } udp;

      struct {
         __u8 type;
         __u8 code;
      } icmp6;
   };
};


struct packet {

   __u32 index;
   __u32 nFrames;
   __u32 redirectIfIdx;
   int instruction;
   struct bpf_string checkpoint;
   struct bpf_string buffer;
   struct packet_frame frames[4];

// balancer
   bool balancer;
   bool localDelivery;
   struct container_id containerID;
   __u8 gateway_mac[6];
};