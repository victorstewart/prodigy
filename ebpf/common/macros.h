#pragma once

// we dont want to do htons for each packet, so this is ETH_P_IPV6 and ETH_P_IP in be format
// clang-format off
#define BE_ETH_P_IP 8
#define BE_ETH_P_IPV6 56710
// clang-format on
