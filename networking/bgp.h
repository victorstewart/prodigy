#pragma once

enum class BGPState : uint8_t {

	idle = 0,
	opensent,
	openconfirm,
	established,
	failed
};

// https://datatracker.ietf.org/doc/html/rfc4271
#ifdef __linux__
#include <netinet/tcp.h> // TCP_MD5SIG
#include <services/debug.h>
#endif
#include <netinet/in.h>

template <typename T> requires(std::is_integral_v<std::remove_reference_t<T>>)
static inline constexpr T reverseByteOrder(T value)
{
	T reversed = 0;

	for (size_t i = 0; i < sizeof(T); i += 1)
	{
		reversed <<= 8;
		reversed |= (value & 0xFF);
		value >>= 8;
	}

	return reversed;
}

class BGPPeer : public StreamBase, public TCPSocket {
private:

	uint8_t nBytesForCIDR(uint8_t cidr)
	{
		uint8_t nBytes = cidr / 8;
		if ((cidr % 8) > 0) nBytes += 1;

		return nBytes;
	}

	void printMessage(const String& message) // auto assume the message is valid
	{
		uint8_t *cursor = message.data();
		const uint8_t *tail = message.pTail();

		// basics_log_hex("message:", cursor, tail - cursor);

		auto extractLambda = [&] <typename T, bool reverse = true, typename Lambda> (Lambda&& lambda) -> void {

			T value;
			memcpy(&value, cursor, sizeof(T));
			if constexpr (reverse && sizeof(T) > 1) value = reverseByteOrder(value);
			cursor += sizeof(T);
			lambda(value);
		};

		auto extract = [&] <typename T, bool reverse = true> (void) -> T {

			T value;
			memcpy(&value, cursor, sizeof(T));
			if constexpr (reverse && sizeof(T) > 1) value = reverseByteOrder(value);
			cursor += sizeof(T);
			return value;
		};

		auto extractPrint = [&] <typename T> (const char *format) -> void {

			extractLambda.template operator()<T>([&] (T value) -> void {

				basics_log(format, value);
			});
		};

		auto extractPrintAFI = [&] (const char *shift) -> uint16_t {

			uint16_t value = 0;

			extractLambda.template operator()<uint16_t>([&] (uint16_t AFI) -> void {

				switch (AFI)
				{
					case 1:
					{
						basics_log("%sAFI: IPv4\n", shift);
						break;
					}
					case 2:
					{
						basics_log("%sAFI: IPv6\n", shift);
						break;
					}
					default:
					{
						basics_log("%sAFI: other = %hu\n", shift, AFI);
						break;
					}
				}

				value = AFI;
			});

			return value;
		};

		auto extractPrintSAFI = [&] (const char *shift) -> void {

			extractLambda.template operator()<uint8_t>([&] (uint8_t SAFI) -> void {

				switch (SAFI)
				{
					case 1:
					{
						basics_log("%sSAFI: unicast\n", shift);
						break;
					}
					case 2:
					{
						basics_log("%sSAFI: multicast\n", shift);
						break;
					}
					default:
					{
						basics_log("%sSAFI: other = %hhu\n", shift, SAFI);
						break;
					}
				}
			});
		};

		cursor += 16; // marker

		uint16_t message_len = extract.template operator()<uint16_t>();
		uint8_t message_type = extract.template operator()<uint8_t>();

		switch (message_type)
		{
			case 1: // Open
			{
				basics_log("Open Message\n");

				extractPrint.template operator()<uint8_t>("\tVersion: %hhu\n");
				extractPrint.template operator()<uint16_t>("\tASN: %hu\n");
				extractPrint.template operator()<uint16_t>("\tHold Time: %hu\n");

				extractLambda.template operator()<struct in_addr, false>([&] (struct in_addr bgpid) -> void {

					basics_log("\tBGP ID: %s\n", inet_ntoa(bgpid));
				});

				uint8_t options_len = extract.template operator()<uint8_t>();

				if (options_len > 0)
				{
					uint8_t optional_code = extract.template operator()<uint8_t>();
					uint8_t optional_len = extract.template operator()<uint8_t>();

					if (optional_code == 2) // capbilities
					{
						do
						{
							uint8_t capability_code = extract.template operator()<uint8_t>();
							uint8_t capability_len = extract.template operator()<uint8_t>();
							
							// ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:00:39:01:04:ff:fa:00:b4:56:6d:0d:13:1c:02:1a:02:00:46:00:41:04:00:00:ff:fa:01:04:00:02:00:01:40:02:41:2c:45:04:00:02:01:01

							// https://www.rfc-editor.org/rfc/rfc2918.html
							// "This capability is advertised using the Capability code 2 and Capability length 0"
							switch (capability_code)
							{
								case 1:
								{
									basics_log("\tMP-BGP\n");

									extractPrintAFI("\t\t");

									cursor += 1; // reserved

									extractPrintSAFI("\t\t");
									break;
								}
								case 2:
								{
									basics_log("\tRoute Refresh\n");
									break;
								}
								case 3:
								{
									basics_log("\tOutbound Route Filtering\n");
									break;
								}
								case 5:
								{
									basics_log("\tExtended Next Hop Encoding\n");
									break;
								}
								case 6:
								{
									basics_log("\tBGP Extended Message\n");
									break;
								}
								case 7:
								{
									basics_log("\tBGPsec\n");
									break;
								}
								case 8:
								{
									basics_log("\tMultiple Labels\n");
									break;
								}
								case 9:
								{
									basics_log("\tBGP Role\n");
									break;
								}
								case 64:
								{
									basics_log("\tGraceful Restart\n");
									break;
								}
								case 65:
								{
									basics_log("\t4-octet AS number\n");
									break;
								}
								case 67:
								{
									basics_log("\tDynamic Capability\n");
									break;
								}
								case 68:
								{
									basics_log("\tMultisession BGP\n");
									break;
								}
								case 69:
								{
									basics_log("\tADD-PATH\n");
									break;
								}
								case 70:
								{
									basics_log("\tEnhanced Route Refresh\n");
									break;
								}
								case 71:
								{
									basics_log("\tLong-Lived Graceful Restart\n");
									break;
								}
								case 72:
								{
									basics_log("\tRouting Policy Distribution\n");
									break;
								}
								case 73:
								{
									basics_log("\tFQDN\n");
									break;
								}
								case 74:
								{
									basics_log("\tBFD\n");
									break;
								}
								case 75:
								{
									basics_log("\tSoftware Version \n");
									break;
								}
								case 76:
								{
									basics_log("\tPATHS-LIMIT\n");
									break;
								}
								default:
								{
									basics_log("\tother capability = %hhu\n", capability_code);
									break;
								}
							}

							switch (capability_code)
							{
								case 1:
								{
									break;
								}
								default:
								{
									cursor += capability_len;
									break;
								}
							}
							
						} while (cursor < tail);
					}
					else cursor += optional_len;
				}

				break;
			}
			case 2: // Update
			{
				basics_log("Update Message:\n");
				uint16_t withdrawn_len = extract.template operator()<uint16_t>();

				if (withdrawn_len > 0)
				{
					const uint8_t *withdrawn_tail = cursor + withdrawn_len;

					basics_log("\tWithdrawn IPv4 Routes:\n");

					do
					{
						uint8_t cidr = extract.template operator()<uint8_t>();

						struct in_addr prefix = {};

						if (cidr > 0)
						{
							uint8_t byte_len = cidr / 8;
							if (cidr % 8 > 0) byte_len += 1;

							memcpy(&prefix, cursor, byte_len);
							cursor += byte_len;
						}

						basics_log("\t\t%s/%s\n", inet_ntoa(prefix), cidr);

					} while (cursor < withdrawn_tail);
				}

				uint16_t pathattributes_len = extract.template operator()<uint16_t>();

				if (pathattributes_len > 0)
				{
					const uint8_t *pathattributes_tail = cursor + pathattributes_len;

					basics_log("\tPath Attributes:\n");

					auto printFlags = [] (uint8_t flags) -> void {

						basics_log("\t\t\tFlags: ");

							if (flags & 0x80) basics_log("Optional ");
							if (flags & 0x40) basics_log("Transitive ");
							if (flags & 0x20) basics_log("Partial ");
							if (flags & 0x10) basics_log("Extended Length ");
							
						basics_log("\n");
					};

					do
					{
						uint8_t flags = extract.template operator()<uint8_t>();
						uint8_t type_code = extract.template operator()<uint8_t>();
						uint8_t attrib_len = extract.template operator()<uint8_t>();

						switch (type_code)
						{
							case 1:
							{
								basics_log("\t\tORIGIN:\n");
								printFlags(flags);

								extractLambda.template operator()<uint8_t>([&] (uint8_t origin) -> void {

									switch (origin)
									{
										case 0:
										{
											basics_log("\t\t\tIGP");
											break;
										}
										case 1:
										{
											basics_log("\t\t\tEGP");
											break;
										}
										case 2:
										{
											basics_log("\t\t\tIncomplete");
											break;
										}
									}

									basics_log("\n");
								});

								basics_log("\n");

								break;
							}
							case 2:
							{
								basics_log("\t\tAS_PATH:\n");
								printFlags(flags);

								extractLambda.template operator()<uint8_t>([&] (uint8_t sequence) -> void {

									switch (sequence)
									{
										case 1:
										{
											basics_log("\t\t\tAS_SET");
											break;
										}
										case 2:
										{
											basics_log("\t\t\tAS_SEQUENCE");
											break;
										}
									}

									basics_log("\n");
								});

								uint8_t nASNs = extract.template operator()<uint8_t>();

								do
								{
									extractPrint.template operator()<uint16_t>("\t\t\t%hu\n");

								} while (--nASNs > 0);
					
								basics_log("\n");

								break;
							}
							case 3:
							{
								basics_log("\t\tNEXT_HOP:\n"); // ipv4 only
								printFlags(flags);

								extractLambda.template operator()<struct in_addr, false>([&] (struct in_addr next_hop) -> void {

									basics_log("\t\t\t%s\n", inet_ntoa(next_hop));
								});

								basics_log("\n");

								break;
							}
							case 4:
							{
								basics_log("\t\tMULTI_EXIT_DISC:\n");
								cursor += attrib_len;
								break;
							}
							case 5:
							{
								basics_log("\t\tLOCAL_PREF:\n");
								cursor += attrib_len;
								break;
							}
							case 6:
							{
								basics_log("\t\tATOMIC_AGGREGATE:\n");
								cursor += attrib_len;
								break;
							}
							case 7:
							{
								basics_log("\t\tAGGREGATOR:\n"); // ipv4 only
								cursor += attrib_len;
								break;
							}
							case 8:
							{
								basics_log("\t\tCOMMUNITY:\n");

								cursor += attrib_len;
								break;
							}
							case 14: // Optional + Transitive, ipv6 only. requires ORIGIN and AS_PATH. and no NEXT_HOP
							{
								basics_log("\t\tMP_REACH_NLRI:\n");
								printFlags(flags);

								uint8_t *attrib_tail = cursor + attrib_len;

								uint16_t AFI = extractPrintAFI("\t\t\t");
								extractPrintSAFI("\t\t\t");

								uint8_t next_hop_len = extract.template operator()<uint8_t>();

								if (AFI == 2) // ipv6
								{
									char str[INET6_ADDRSTRLEN];
									inet_ntop(AF_INET6, cursor, str, INET6_ADDRSTRLEN);

									basics_log("\t\t\tNext Hop: %s\n", str);
								}
									
								cursor += next_hop_len;

								cursor += 1; // reserved

								do
								{
									uint8_t cidr = extract.template operator()<uint8_t>();
									uint8_t nlri_len = nBytesForCIDR(cidr);

									if (AFI == 2) // ipv6
									{
										uint8_t address[16];
										memset(address, 0, 16);
										memcpy(address, cursor, nlri_len);

										char str[INET6_ADDRSTRLEN];
										inet_ntop(AF_INET6, address, str, INET6_ADDRSTRLEN);
										basics_log("\t\t\tNLRI: %s/%hhu\n", str, cidr);
									}

									cursor += nlri_len;

								} while (cursor < attrib_tail);

								break;
							}
							case 15: // Optional + Non-Transitive, ipv6 only. requires no other path attributes
							{
								basics_log("\t\tMP_UNREACH_NLRI:\n");
								printFlags(flags);

								uint8_t *attrib_tail = cursor + attrib_len;

								uint16_t AFI = extractPrintAFI("\t\t\t");
								extractPrintSAFI("\t\t\t");

								while (cursor < attrib_tail)
								{
									uint8_t cidr = extract.template operator()<uint8_t>();
									uint8_t nlri_len = nBytesForCIDR(cidr);

									if (AFI == 2) // ipv6
									{
										uint8_t address[16];
										memset(address, 0, 16);
										memcpy(address, cursor, nlri_len);

										char str[INET6_ADDRSTRLEN];
										inet_ntop(AF_INET6, address, str, INET6_ADDRSTRLEN);
										basics_log("\t\t\tNLRI: %s/%hhu\n", str, cidr);
									}

									cursor += nlri_len;
								}

								break;
							}
							default:
							{
								basics_log("\t\tother path attribute = %hhu\n", type_code);
								cursor += attrib_len;
								break;
							}
						}

					} while (cursor < pathattributes_tail);
				}

				uint32_t total_nlri_len = message_len - 23 - pathattributes_len - withdrawn_len;

				if (total_nlri_len > 0) // ipv4 only
				{
					basics_log("\nNLRI:\n");

					do
					{
						uint8_t cidr = extract.template operator()<uint8_t>();
						uint8_t nlri_len = nBytesForCIDR(cidr);
					
						uint8_t address[4];
						memset(address, 0, 4);
						memcpy(address, cursor, nlri_len);

						char str[INET_ADDRSTRLEN];
						inet_ntop(AF_INET, address, str, INET_ADDRSTRLEN);
						basics_log("\t\t%s/%hhu\n", str, cidr);

						cursor += nlri_len;

					} while (cursor < tail);
				}

				break;
			}
			case 3: // Notification
			{
				basics_log("Notification Message\n");

				uint8_t error_code = extract.template operator()<uint8_t>();
				uint8_t error_subcode = extract.template operator()<uint8_t>();

				switch (error_code)
				{
					case 1:
					{
						basics_log("\tMessage Header Error\n");

						switch (error_subcode)
						{
							case 1:
							{
								basics_log("\tConnection Not Synchronized\n");
								break;
							}
							case 2:
							{
								basics_log("\tBad Message Length\n");
								break;
							}
							case 3:
							{
								basics_log("\tBad Message Type\n");
								break;
							}
							default:
							{
								basics_log("\tother error subcode = %hhu\n", error_subcode);
								break;
							}
						}

						break;
					}
					case 2:
					{
						basics_log("\tOpen Message Error\n");

						switch (error_subcode)
						{
							case 1:
							{
								basics_log("\tUnsupported Version Number\n");
								break;
							}
							case 2:
							{
								basics_log("\tBad Peer AS\n");
								break;
							}
							case 3:
							{
								basics_log("\tBad BGP Identifier\n");
								break;
							}
							case 4:
							{
								basics_log("\tUnsupported Optional Parameter\n");
								break;
							}
							case 6:
							{
								basics_log("\tUnacceptable Hold Time\n");
								break;
							}
							case 7:
							{
								basics_log("\tUnsupported Capability\n");
								break;
							}
							default:
							{
								basics_log("\tother error subcode = %hhu\n", error_subcode);
								break;
							}
						}

						break;
					}
					case 3:
					{
						basics_log("\tUpdate Message Error\n");

						switch (error_subcode)
						{
							case 1:
							{
								basics_log("\tMalformed Attribute List\n");
								break;
							}
							case 2:
							{
								basics_log("\tUnrecognized Well-known Attribute\n");
								break;
							}
							case 3:
							{
								basics_log("\tMissing Well-known Attribute\n");
								break;
							}
							case 4:
							{
								basics_log("\tAttribute Flags Error\n");
								break;
							}
							case 5:
							{
								basics_log("\tAttribute Length Error\n");
								break;
							}
							case 6:
							{
								basics_log("\tInvalid ORIGIN Attribute\n");
								break;
							}
							case 8:
							{
								basics_log("\tInvalid NEXT_HOP Attribute\n");
								break;
							}
							case 9:
							{
								basics_log("\tOptional Attribute Error\n");
								break;
							}
							case 10:
							{
								basics_log("\tInvalid Network Field\n");
								break;
							}
							case 11:
							{
								basics_log("\tMalformed AS_PATH\n");
								break;
							}
							default:
							{
								basics_log("\tother error subcode = %hhu\n", error_subcode);
								break;
							}
						}

						break;
					}
					case 4:
					{
						basics_log("\tHold Timer Expired\n");
						break;
					}
					case 5:
					{
						basics_log("\tFinite State Machine Error\n");
						break;
					}
					case 6:
					{
						basics_log("\tCease\n");
						break;
					}
					default:
					{
						basics_log("\tother error = %hhu\n", error_code);
						break;
					}
				}

				break;
			}
			case 4: // Keepalive
			{
				basics_log("Keepalive Message\n");

				// A KEEPALIVE message consists of only the message header and has a length of 19 octets.
				break;
			}
			default: break;
		}
	}

	static constexpr uint8_t marker[16] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

	uint16_t fillOpenMesage(Buffer& wBuffer, uint32_t bgpid, bool is6)
	{
		// if (is6)
		// {
		// 	// for ipv6 we need to lie to it and mimic it's open message for it to accept us... whatever
		// 	static constexpr uint8_t data[] = {
		//     	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		//     	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		//     	0x00, 0x39, 0x01, 0x04, 0x8c, 0x1e, 0x00, 0xb4,
		//     	0x0a, 0x0c, 0xe8, 0x81, 0x1c, 0x02, 0x1a, 0x02,
		//     	0x00, 0x46, 0x00, 0x41, 0x04, 0x00, 0x00, 0x8c,
		//     	0x1e, 0x01, 0x04, 0x00, 0x02, 0x00, 0x01, 0x40,
		//     	0x02, 0x41, 0x2c, 0x45, 0x04, 0x00, 0x02, 0x01,
		//     	0x01
		// 	};
		//  ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:00:39:01:04:8c:1e:00:b4:0a:0c:e8:81:1c:02:1a:02:00:46:00:41:04:00:00:8c:1e:01:04:00:02:00:01:40:02:41:2c:45:04:00:02:01:01"
		//  ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:00:25:01:04:8c:1e:00:b4:0a:0c:e8:81:06:02:06:01:04:00:02:00:01
		//
		// 	wBuffer.append(data, sizeof(data));
		// 	return sizeof(data);
		// }

		//  If one of the Optional Parameters in the OPEN message is recognized, but is malformed, then the Error Subcode MUST be set to 0

		uint32_t header_offset = wBuffer.size();

		wBuffer.append(marker, sizeof(marker));
		
		wBuffer.advance(2); // message_len

		// 01:04:00:02:00:01

		wBuffer.append(uint8_t(0x01)); // Open
		wBuffer.append(uint8_t(0x04)); // BGP version 4
		wBuffer.append(reverseByteOrder(uint16_t(35870))); // our ASN
		wBuffer.append(reverseByteOrder(uint16_t(180))); // hold time
		wBuffer.append(bgpid);

		uint32_t optional_params_len_idx = wBuffer.size();
		wBuffer.advance(1);

		wBuffer.append(uint8_t(0x02)); // Capabilities Optional Parameter

		uint32_t capability_list_len_idx = wBuffer.size();
		wBuffer.advance(1);

		// // route refresh
		// wBuffer.append(uint8_t(0x02));
		// wBuffer.append(uint8_t(0x00));

		// // enhanced route refresh
		// wBuffer.append(uint8_t(0x46));
		// wBuffer.append(uint8_t(0x00));

		// // 4 octet asns
		// wBuffer.append(uint8_t(0x41));
		// wBuffer.append(uint8_t(0x04));
		// wBuffer.append(uint8_t(0x00));
		// wBuffer.append(uint8_t(0x00));
		// wBuffer.append(uint8_t(0x8c));
		// wBuffer.append(uint8_t(0x1e));

	// MP-BGP
		wBuffer.append(uint8_t(0x01)); // MP-BGP
		wBuffer.append(uint8_t(0x04)); // option length

		if (is6) wBuffer.append(reverseByteOrder(uint16_t(0x02))); // AFI = ipv6
		else     wBuffer.append(reverseByteOrder(uint16_t(0x01))); // AFI = ipv4

		wBuffer.append(uint8_t(0x00)); // reserved
		wBuffer.append(uint8_t(0x01)); // SAFI = unicast

	// Graceful Restart
		wBuffer.append(uint8_t(0x40)); // Graceful Restart
		wBuffer.append(uint8_t(0x02)); // option length

		// setting the top bit to 1 signifies we restarted so don't wait for end of rib message
		// before sending us routes
		wBuffer.append(uint16_t(0b0000'0001'0010'1100)); // bottom 12 bits are timeout but they're ignored

		// leftmost bit most significant

	// additional paths
		// wBuffer.append(uint8_t(0x45));
		// wBuffer.append(uint8_t(0x04));
		// wBuffer.append(uint8_t(0x00));
		// wBuffer.append(uint8_t(0x01));
		// wBuffer.append(uint8_t(0x01));
		// wBuffer.append(uint8_t(0x01));

		wBuffer[capability_list_len_idx] = uint8_t(wBuffer.size() - capability_list_len_idx - 1); // -1 because don't include itself in the length
		wBuffer[optional_params_len_idx] = uint8_t(wBuffer.size() - optional_params_len_idx - 1); // -1 because don't include itself in the length

		uint16_t hlen = wBuffer.size() - header_offset;
		uint16_t nlen = reverseByteOrder(hlen);
		memcpy(wBuffer.data() + header_offset + sizeof(marker), &nlen, 2);

		return hlen;
	}

	void fillAnnouncePrefixMessage(String& message, const IPPrefix& prefix, const IPAddress& gateway, bool globally, uint32_t community = 0)
	{
		String cidr_string;
   	cidr_string.assignItoa(prefix.cidr);

   	char prefix_string[INET6_ADDRSTRLEN];
   	char gateway_string[INET6_ADDRSTRLEN];

   	int af = prefix.network.is6 ? AF_INET6 : AF_INET;
   
   	inet_ntop(af, prefix.network.v6, prefix_string, INET6_ADDRSTRLEN);
		inet_ntop(af, gateway.v6, gateway_string, INET6_ADDRSTRLEN);
		
		// basics_log("fillAnnouncePrefixMessage: prefix %s/%s via gateway %s\n", prefix_string, cidr_string.c_str(), gateway_string);

		message.append(marker, sizeof(marker));
		message.advance(2); // message length

		message.append(uint8_t(0x02)); // Update

		message.append(uint16_t(0x00)); // withdrawn length 0

		uint32_t total_attributes_len_idx = message.size();
		message.append(uint16_t(0x00));

		// ORIGIN
		message.append(uint8_t(0b0100'0000)); // transitive
		message.append(uint8_t(0x01)); // origin
		message.append(uint8_t(0x01));
		message.append(uint8_t(0x0)); // IGP, all routes we announce were learned internally
		
		// AS_PATH
		message.append(uint8_t(0b0100'0000)); // transitive
		message.append(uint8_t(0x02)); // as_path
		message.append(uint8_t(0x04));
		message.append(uint8_t(0x02)); // AS_SEQUENCE
		message.append(uint8_t(0x01)); // 1 ASN to follow
		message.append(reverseByteOrder(uint16_t(35870))); // our ASN

		if (prefix.network.is6)
		{
			// MP_REACH_NLRI
			message.append(uint8_t(0b1000'0000)); // optional + transitive
			message.append(uint8_t(0x0e)); // MP_REACH_NLRI
			uint32_t attrib_len_idx = message.size();
			message.append(uint8_t(0x00));

			message.append(reverseByteOrder(uint16_t(0x02))); // AFI == ipv6
			message.append(uint8_t(0x01)); // SAFI == unicast

			message.append(uint8_t(0x10)); // 16, length of gateway address
			message.append(gateway.v6, 0x10);

			message.append(uint8_t(0x00)); // reserved

			message.append(uint8_t(prefix.cidr));
			message.append(prefix.network.v6, nBytesForCIDR(prefix.cidr));

			message[attrib_len_idx] = uint8_t(message.size() - attrib_len_idx - 1);
		}
		else
		{
			// NEXT_HOP
			message.append(uint8_t(0b0100'0000)); // transitive
			message.append(uint8_t(0x03)); // next_hop
			message.append(uint8_t(0x04)); // len
			message.append(gateway.v6, 4); // next hop address ipv4
		}

		if (community > 0)
		{
			// COMMUNITY
			message.append(uint8_t(0b1100'0000)); // optional + transitive
			message.append(uint8_t(0x08)); // COMMUNITY
			message.append(uint8_t(0x04)); // only one community so len always 4
			message.append(uint32_t(community));
		}

		uint16_t len = reverseByteOrder(uint16_t(message.size() - total_attributes_len_idx - 2)); // -2 -> don't count this length in the total length
		memcpy(message.data() + total_attributes_len_idx, &len, 2);

		if (prefix.network.is6 == false)
		{
			message.append(uint8_t(prefix.cidr));
			message.append(prefix.network.v6, nBytesForCIDR(prefix.cidr));
		}

		uint16_t hlen = message.size();
		uint16_t nlen = reverseByteOrder(hlen);
		memcpy(message.data() + sizeof(marker), &nlen, 2);
	}

	uint16_t fillWithdrawPrefixMessage(Buffer& wBuffer, const IPPrefix& prefix)
	{	
		uint32_t header_offset = wBuffer.size();

		wBuffer.append(marker, sizeof(marker));
		wBuffer.advance(2); // message len

		wBuffer.append(uint8_t(0x02)); // Update

		if (prefix.network.is6)
		{
			wBuffer.append(uint16_t(0x00)); // withdrawn length 0
		}
		else
		{
			wBuffer.append(uint8_t(prefix.cidr));
			wBuffer.append(prefix.network.v6, nBytesForCIDR(prefix.cidr));
		}	

		uint32_t total_attributes_len_idx = wBuffer.size();
		wBuffer.advance(2);

		if (prefix.network.is6)
		{
			// MP_UNREACH_NLRI
			wBuffer.append(uint8_t(0b1100'0000)); // optional + transitive
			wBuffer.append(uint8_t(0x0f)); // MP_UNREACH_NLRI

			uint32_t attrib_len_idx = wBuffer.size();
			wBuffer.append(uint8_t(0x00));

			wBuffer.append(reverseByteOrder(uint16_t(0x02))); // AFI == ipv6
			wBuffer.append(uint8_t(0x01)); // SAFI == unicast

			wBuffer.append(uint8_t(prefix.cidr));
			wBuffer.append(prefix.network.v6, nBytesForCIDR(prefix.cidr));

			wBuffer[attrib_len_idx] = uint8_t(wBuffer.size() - attrib_len_idx - 1);
		}

		uint16_t len = reverseByteOrder(uint16_t(wBuffer.size() - total_attributes_len_idx - 2)); // -2 -> don't count this length in the total length
		memcpy(wBuffer.data() + total_attributes_len_idx, &len, 2);
		
		uint16_t hlen = wBuffer.size();
		uint16_t nlen = reverseByteOrder(hlen);
		memcpy(wBuffer.data() + header_offset + sizeof(marker), &nlen, 2);

		return hlen;
	}

	uint16_t fillEndOfRibMessage(Buffer& wBuffer)
	{
		wBuffer.append(marker, sizeof(marker));
		wBuffer.append(reverseByteOrder(uint16_t(0x17))); // message_len = 23
		wBuffer.append(uint8_t(0x02)); // Update
		wBuffer.append(uint16_t(0x00)); // withdrawn length 0
		wBuffer.append(uint16_t(0x00)); // attributes length 0

		return 23;
	}

	void fillKeepaliveMessage(Buffer& wBuffer)
	{
		constexpr uint8_t keepalive[19] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x13, 0x04};
		wBuffer.append(keepalive, 19);
	}

	void pushRoutes(void)
	{
		for (const auto& [prefix, message] : routes)
		{
			printMessage(message);
			wBuffer.need(message.size());
			wBuffer.append(message);
		}

		wBuffer.need(23);
		fillEndOfRibMessage(wBuffer);

		Ring::queueSend(this);
	}

	bytell_hash_map<IPPrefix, String> routes;

	int64_t lastTime = 0;
	int64_t firstTime = 0;

public:

	uint32_t bgpid;
	BGPState state = BGPState::idle;
	bool is6;
    uint8_t hopLimit{0}; // 0 = use system default

    // TCP-MD5 authentication (RFC 2385) support
    String md5Key; // stored in-memory only; do not log
    bool   hasMD5 = false;

#ifdef __linux__
    void applyMD5ToSocket()
    {
        if (!hasMD5 || fd < 0) return;

        struct tcp_md5sig opt = {};
        // Copy destination address for matching
        memcpy(&opt.tcpm_addr, daddr<struct sockaddr_storage>(), sizeof(struct sockaddr_storage));
        // Prefixlen: 32 for IPv4, 128 for IPv6
        if (is6) opt.tcpm_prefixlen = 128; else opt.tcpm_prefixlen = 32;
        // Key
        opt.tcpm_keylen = (uint32_t)std::min<size_t>(md5Key.size(), TCP_MD5SIG_MAXKEYLEN);
        memcpy(opt.tcpm_key, md5Key.data(), opt.tcpm_keylen);
        // Apply to this socket
        setsockopt(fd, SOL_TCP, TCP_MD5SIG, &opt, sizeof(opt));
        // Zeroize local copy of key buffer used for setsockopt stack struct
        memset(opt.tcpm_key, 0, sizeof(opt.tcpm_key));
    }
#else
    void applyMD5ToSocket() {}
#endif

    void setMD5Password(const String& key)
    {
        md5Key = key; hasMD5 = (md5Key.size() > 0);
        applyMD5ToSocket(); // if socket and daddr are ready, apply immediately
    }

    void setHopLimit(uint8_t ttl)
    {
        hopLimit = ttl;
        // configureSocket() will apply when (re)creating sockets
    }

	void sendOpen(void)
	{
		wBuffer.need(128);

		uint32_t len = fillOpenMesage(wBuffer, bgpid, is6);

		String message;
		message.setInvariant(wBuffer.pTail() - len, len);
		printMessage(message);

		Ring::queueSend(this);
		state = BGPState::opensent;
	}

	void sendKeepalive(void)
	{
		int64_t timeNow = Time::now<TimeResolution::sec>();

		if (firstTime == 0)
		{
			firstTime = timeNow;
			lastTime = timeNow;
		}

		lastTime = timeNow;

		wBuffer.need(19);
		fillKeepaliveMessage(wBuffer);
		Ring::queueSend(this);
	}

		void announcePrefix(const IPPrefix& prefix, const IPAddress& gateway, bool globally, uint32_t community = 0)
		{
			String& message = routes[prefix];
			message.reserve(128);
			fillAnnouncePrefixMessage(message, prefix, gateway, globally, community);

		if (state == BGPState::established)
		{
			printMessage(message);

			wBuffer.need(message.size());
			wBuffer.append(message);
			Ring::queueSend(this);
		}
	}

	void announceAnycastPrefix(const IPPrefix& prefix, const IPAddress& gateway)
	{
		announcePrefix(prefix, gateway, true, 0);
	}

	void announceLocalPrefix(const IPPrefix& prefix, const IPAddress& gateway)
	{
		announcePrefix(prefix, gateway, false, 0);
	}

	void withdrawPrefix(const IPPrefix& prefix)
	{
		routes.erase(prefix);

		if (state == BGPState::established)
		{
			wBuffer.need(128);

			uint32_t len = fillWithdrawPrefixMessage(wBuffer, prefix);
			
			String message;
			message.setInvariant(wBuffer.pTail() - len, len);

			printMessage(message);
			Ring::queueSend(this);
		}
	}

	void handleMessage(void)
	{
		if (rBuffer.outstandingBytes() >= 18)
		{
			// messages are not aligned, so we can't make any assumptions

			uint8_t *cursor = rBuffer.pHead();

			uint16_t message_len = (uint16_t)(cursor[16] << 8 | cursor[17]);

			if (rBuffer.outstandingBytes() >= message_len)
			{
				String message;
				message.setInvariant(cursor, message_len);
				printMessage(message);

				cursor += 18;
				uint8_t message_type = *cursor;

				switch (message_type)
				{
					case 1: // Open
					{
						sendKeepalive();
						state = BGPState::openconfirm;

						break;
					}
					case 2: // Update
					{
						// we do not currently import or act on UPDATE messages on this session
						break;
					}
					case 3: // Notification
					{
						// we might receive these if an error, they'll already be printed though
						state = BGPState::failed;
						Ring::queueClose(this);
						break;
					}
					case 4: // Keepalive
					{
						if (state == BGPState::openconfirm)
						{
							state = BGPState::established;
							pushRoutes();
						}
						else
						{
							// something is screwed up with our timer but if we send keepalives when we get one we should be good and never expire
							sendKeepalive(); 
						}

						break;
					}
					default:
					{
						// ipc_printf("handleMessage: unknown/bad message_type = %hhu\n", message_type);
						break;
					}
				}

				rBuffer.consume(message_len, false);
			}
		}
	}

	void goIdle(void)
	{
		state = BGPState::idle;
	}

	BGPPeer()
	{
		rBuffer.reserve(4_KB);
		wBuffer.reserve(4_KB);
	}

    // Ensure MD5 is re-applied on socket recreation
    void configureSocket(void) override
    {
        TCPSocket::configureSocket();
        applyMD5ToSocket();
        if (hopLimit > 0)
        {
            int v = hopLimit;
            if (is6)
            {
                setsockopt(fd, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &v, sizeof(v));
            }
            else
            {
                setsockopt(fd, IPPROTO_IP, IP_TTL, &v, sizeof(v));
            }
        }
    }
};

class BGPHub : public RingInterface {
private:

	bytell_hash_set<BGPPeer *> peers;
	bool shuttingDown = false;

public:

	uint32_t ourBGPID;

	void addPeer(uint16_t peerASN, const IPAddress& peerAddress, const IPAddress& srcAddress)
	{
		static constexpr uint16_t BGP_PORT = 179;

		BGPPeer *peer = new BGPPeer();
		peer->bgpid = ourBGPID;

		if (peerAddress.is6)
		{
			peer->is6 = true;
			peer->setIPVersion(AF_INET6);
			peer->setDaddr(peerAddress, BGP_PORT);
		}
		else
		{
			peer->is6 = false;
			peer->setIPVersion(AF_INET);
			peer->setDaddr(peerAddress, BGP_PORT);
		}

		peer->setSaddr(srcAddress);
		peer->setDatacenterCongestion();

		peers.insert(peer);

		RingDispatcher::installMultiplexee(peer, this);
		Ring::installFDIntoFixedFileSlot(peer);
		Ring::queueConnect(peer);
	}

	void addPeer(uint16_t peerASN, const IPAddress& peerAddress, const IPAddress& srcAddress, const String& md5Password)
	{
		static constexpr uint16_t BGP_PORT = 179;

		BGPPeer *peer = new BGPPeer();
		peer->bgpid = ourBGPID;

		if (peerAddress.is6)
		{
			peer->is6 = true;
			peer->setIPVersion(AF_INET6);
			peer->setDaddr(peerAddress, BGP_PORT);
		}
		else
		{
			peer->is6 = false;
			peer->setIPVersion(AF_INET);
			peer->setDaddr(peerAddress, BGP_PORT);
		}

		peer->setSaddr(srcAddress);
		peer->setDatacenterCongestion();
		peer->setMD5Password(md5Password);

		peers.insert(peer);

		RingDispatcher::installMultiplexee(peer, this);
		Ring::installFDIntoFixedFileSlot(peer);
		Ring::queueConnect(peer);
	}

	void addPeer(uint16_t peerASN, const IPAddress& peerAddress, const IPAddress& srcAddress, const String& md5Password, uint8_t hopLimit)
	{
		static constexpr uint16_t BGP_PORT = 179;

		BGPPeer *peer = new BGPPeer();
		peer->bgpid = ourBGPID;

		if (peerAddress.is6)
		{
			peer->is6 = true;
			peer->setIPVersion(AF_INET6);
			peer->setDaddr(peerAddress, BGP_PORT);
		}
		else
		{
			peer->is6 = false;
			peer->setIPVersion(AF_INET);
			peer->setDaddr(peerAddress, BGP_PORT);
		}

		peer->setSaddr(srcAddress);
		peer->setDatacenterCongestion();
		peer->setMD5Password(md5Password);
		peer->setHopLimit(hopLimit);

		peers.insert(peer);

		RingDispatcher::installMultiplexee(peer, this);
		Ring::installFDIntoFixedFileSlot(peer);
		Ring::queueConnect(peer);
	}

	void withdrawPeer(const IPAddress& peerAddress)
	{
		for (auto it = peers.begin(); it != peers.end(); it++)
		{
			BGPPeer *peer = *it;

			if (peer->is6 == peerAddress.is6)
			{	
				if (peer->daddrEqual(peerAddress))
				{
					peers.erase(it);
					Ring::queueClose(peer);
					break;
				}
			}
		}
	}

	void withdrawPrefix(const IPPrefix& prefix)
	{
		for (BGPPeer *peer : peers)
		{
			if (prefix.network.is6 == peer->is6)
			{
				peer->withdrawPrefix(prefix);
			}
		}
	}

	void announceAnycastPrefix(const IPPrefix& prefix, const IPAddress& gateway)
	{
		for (BGPPeer *peer : peers)
		{
			if (prefix.network.is6 == peer->is6)
			{
				peer->announceAnycastPrefix(prefix, gateway);
			}
		}
	}

	void announceLocalPrefix(const IPPrefix& prefix, const IPAddress& gateway)
	{
		for (BGPPeer *peer : peers)
		{
			if (prefix.network.is6 == peer->is6)
			{
				peer->announceLocalPrefix(prefix, gateway);
			}
		}
	}

	// Provider-driven community: announce a prefix with a specific 32-bit community
	void announceWithCommunity(const IPPrefix& prefix, const IPAddress& gateway, uint32_t community)
	{
		for (BGPPeer *peer : peers)
		{
			if (prefix.network.is6 == peer->is6)
			{
				peer->announcePrefix(prefix, gateway, false, community);
			}
		}
	}

	void connectHandler(void *socket, int result)
	{
		BGPPeer *peer = static_cast<BGPPeer *>(socket);

		if (result == 0)
		{
			peer->sendOpen();
			Ring::queueRecv(peer);
		}
		else Ring::queueConnect(peer);
	}

	void recvHandler(void *socket, int result)
	{
		BGPPeer *peer = static_cast<BGPPeer *>(socket);
		peer->pendingRecv = false;

		if (peers.contains(peer)) // otherwise being withdrawn
		{
			if (result > 0)
			{
				peer->rBuffer.advance(result);
				peer->handleMessage();
				Ring::queueRecv(peer);
			}
			else if (result == 0)
			{
				peer->state = BGPState::failed;
				Ring::queueClose(peer);
			}
			else if (result != -9)
			{
				peer->goIdle();
				Ring::queueClose(peer);
			}
		}
	}

		void sendHandler(void *socket, int result) 
		{
			BGPPeer *peer = static_cast<BGPPeer *>(socket);

			peer->pendingSend = false;
			peer->pendingSendBytes = 0;

		if (peers.contains(peer)) // otherwise being withdrawn
		{
			if (result > 0)
			{
				peer->wBuffer.consume(result, true);
				peer->wBuffer.noteSendCompleted();

				if (peer->wBuffer.outstandingBytes() > 0)
				{
					Ring::queueSend(peer);
				}
			}
			else if (result != -9)
			{
				peer->wBuffer.noteSendCompleted();
				peer->goIdle();
				Ring::queueClose(peer);
			}
			else
			{
				peer->wBuffer.noteSendCompleted();
			}
		}
		else
		{
			peer->wBuffer.noteSendCompleted();
		}
	}

	virtual void hasShutdownBGP(void) = 0;

    // Update MD5 key on all peers (used for key rotation)
    void updateAllPeersMD5(const String& key)
    {
        for (BGPPeer *peer : peers)
        {
            peer->setMD5Password(key);
        }
    }

	void closeHandler(void *socket)
	{
		BGPPeer *peer = static_cast<BGPPeer *>(socket);

		if (peers.contains(peer)) // otherwise being withdrawn
		{
			if (peer->state != BGPState::failed) 
			{
				peer->recreateSocket();
				Ring::installFDIntoFixedFileSlot(peer);
				Ring::queueConnect(peer);
			}
			else if (shuttingDown)
			{
				peers.erase(peer);
				if (peers.size() == 0) hasShutdownBGP();
			}
		}
		else
		{
			RingDispatcher::eraseMultiplexee(peer);
			delete peer;
		}
	}

	void shutdown(void)
	{
		shuttingDown = true;

		for (BGPPeer *peer : peers)
		{
			if (peer->fslot > -1) 
			{
				Ring::queueClose(peer);
				peer->state = BGPState::failed;
			}
		}
	}
};
