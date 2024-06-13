create materialized view test3.convert_types_at_start TO test3.types AS
select
   queryx.frame_interface_id as Query_frame_interface_id,
   queryx.frame_interface_id_tree.frame_interface_name as "Query_frame_interface_id_tree.frame_interface_name",
   queryx.frame_encap_type as Query_frame_encap_type,
   queryx.frame_time as Query_frame_time,
   queryx.frame_offset_shift as Query_frame_offset_shift,
   queryx.frame_time_epoch as Query_frame_time_epoch,
   if(isNotNull(queryx.frame_time_epoch), FROM_UNIXTIME(toUInt32(substring(queryx.frame_time_epoch, 1, 
   position(queryx.frame_time_epoch, '.') - 1))), null) as Query_frame_time_epoch_2,
   if(isNotNull(queryx.frame_time_epoch), toUInt32(substring(queryx.frame_time_epoch, 
   position(queryx.frame_time_epoch, '.') + 1)), null) as Query_frame_time_epoch_nanos,
   if(isNotNull(queryx.frame_time_epoch), toDayOfYear(Query_frame_time_epoch_2), null) as Query_day_of_year, 
   if(isNotNull(queryx.frame_time_epoch), toDayOfWeek(Query_frame_time_epoch_2), null) as Query_day_of_week, 
   if(isNotNull(queryx.frame_time_epoch), toHour(Query_frame_time_epoch_2), null) as Query_hour,
   queryx.frame_time_delta as Query_frame_time_delta,
   queryx.frame_time_delta_displayed as Query_frame_time_delta_displayed,
   queryx.frame_time_relative as Query_frame_time_relative,
   queryx.frame_number as Query_frame_number,
   queryx.frame_len as Query_frame_len,
   queryx.frame_cap_len as Query_frame_cap_len,
   queryx.frame_marked as Query_frame_marked,
   queryx.frame_ignored as Query_frame_ignored,
   queryx.frame_protocols as Query_frame_protocols,

   reinterpretAsUInt16(reverse(unhex(queryx.dns_id))) as Query_dns_id,
   reinterpretAsUInt16(reverse(unhex(queryx.dns_flags))) as Query_dns_flags,
   queryx.dns_count_queries as Query_dns_count_queries,
   queryx.dns_count_answers as Query_dns_count_answers,
   queryx.dns_count_auth_rr as Query_dns_count_auth_rr,
   queryx.dns_count_add_rr as Query_dns_count_add_rr,
   queryx.dns_response_to as Query_dns_response_to,
   queryx.dns_time as Query_dns_time,
   queryx.dns_flags_response as Query_dns_flags_response,
   queryx.dns_flags_opcode as Query_dns_flags_opcode,
   queryx.dns_flags_authoritative as Query_dns_flags_authoritative,
   queryx.dns_flags_truncated as Query_dns_flags_truncated,
   queryx.dns_flags_recdesired as Query_dns_flags_recdesired,
   queryx.dns_flags_recavail as Query_dns_flags_recavail,
   queryx.dns_flags_z as Query_dns_flags_z,
   queryx.dns_flags_authenticated as Query_dns_flags_authenticated,
   queryx.dns_flags_checkdisable as Query_dns_flags_checkdisable,
   queryx.dns_flags_rcode as Query_dns_flags_rcode,
   queryx.dns_unsolicited as Query_dns_unsolicited,
   -- dns_id_tree
   queryx.dns_retransmit_request_in as Query_dns_retransmit_request_in,
   queryx.dns_retransmission as Query_dns_retransmission,
   queryx.dns_retransmit_response_in as Query_dns_retransmit_response_in,

   queryx.udp_srcport as Query_udp_srcport,
   queryx.udp_dstport as Query_udp_dstport,
   queryx.udp_port as Query_udp_port,
   queryx.udp_length as Query_udp_length,
   reinterpretAsUInt16(reverse(unhex(queryx.udp_checksum))) as Query_udp_checksum,
   queryx.udp_checksum_status as Query_udp_checksum_status,
   queryx.udp_stream as Query_udp_stream,
   -- udp_srcport_tree
   -- udp_dstport_tree

   queryx.ip_version as Query_ip_version,
   queryx.ip_hdr_len as Query_ip_hdr_len,
   reinterpretAsUInt8(reverse(unhex(queryx.ip_dsfield))) as Query_ip_dsfield,
   queryx.ip_len as Query_ip_len,
   reinterpretAsUInt16(reverse(unhex(queryx.ip_id))) as Query_ip_id,
   reinterpretAsUInt16(reverse(unhex(queryx.ip_flags))) as Query_ip_flags,
   queryx.ip_ttl as Query_ip_ttl,
   queryx.ip_proto as Query_ip_proto,
   reinterpretAsUInt16(reverse(unhex(queryx.ip_checksum))) as Query_ip_checksum,
   queryx.ip_checksum_status as Query_ip_checksum_status,
   queryx.ip_src as Query_ip_src,
   queryx.ip_addr as Query_ip_addr,
   queryx.ip_src_host as Query_ip_src_host,
   if(SUBSTRING(IPv4NumToString(Query_ip_src), 1, 6) == '255.25', 0,
   if(SUBSTRING(IPv4NumToString(Query_ip_src), 1, 6) == '254.25', 1, 2)) as Query_ip_src_class,
   queryx.ip_host as Query_ip_host,
   queryx.ip_dst as Query_ip_dst,
   queryx.ip_dst_host as Query_ip_dst_host,
   queryx.ip_dsfield_dscp as Query_ip_dsfield_dscp,
   queryx.ip_dsfield_ecn as Query_ip_dsfield_ecn,
   queryx.ip_flags_rb as Query_ip_flags_rb,
   queryx.ip_flags_df as Query_ip_flags_df,
   queryx.ip_flags_mf as Query_ip_flags_mf,
   queryx.ip_frag_offset as Query_ip_frag_offset,

   queryx."Additional_records.dns_resp_name" as "Query_Additional_records.dns_resp_name",
   queryx."Additional_records.dns_resp_type" as "Query_Additional_records.dns_resp_type",
   arrayMap(i -> reinterpretAsUInt16(reverse(unhex(i))), queryx."Additional_records.dns_resp_class") as "Query_Additional_records.dns_resp_class",
   queryx."Additional_records.dns_resp_ttl" as "Query_Additional_records.dns_resp_ttl",
   queryx."Additional_records.dns_resp_len" as "Query_Additional_records.dns_resp_len",
   arrayMap(i -> toIPv4(i), queryx."Additional_records.dns_a") as "Query_Additional_records.dns_a",
   arrayMap(i -> toIPv6(i), queryx."Additional_records.dns_aaaa") as "Query_Additional_records.dns_aaaa",
   queryx."Additional_records.dns_resp_edns0_version" as "Query_Additional_records.dns_resp_edns0_version",
   queryx."Additional_records.dns_resp_ext_rcode" as "Query_Additional_records.dns_resp_ext_rcode",
   arrayMap(i -> reinterpretAsUInt16(reverse(unhex(i))), queryx."Additional_records.dns_resp_z") as "Query_Additional_records.dns_resp_z",
   -- dns_resp_z_tree
   queryx."Additional_records.dns_rr_udp_payload_size" as "Query_Additional_records.dns_rr_udp_payload_size",
   -- dns_opt
   queryx."Additional_records.dns_rrsig_algorithm" as "Query_Additional_records.dns_rrsig_algorithm",
   queryx."Additional_records.dns_rrsig_key_tag" as "Query_Additional_records.dns_rrsig_key_tag",
   queryx."Additional_records.dns_rrsig_labels" as "Query_Additional_records.dns_rrsig_labels",
   queryx."Additional_records.dns_rrsig_original_ttl" as "Query_Additional_records.dns_rrsig_original_ttl",
   queryx."Additional_records.dns_rrsig_signature" as "Query_Additional_records.dns_rrsig_signature",
   queryx."Additional_records.dns_rrsig_signature_expiration" as "Query_Additional_records.dns_rrsig_signature_expiration",
   queryx."Additional_records.dns_rrsig_signature_inception" as "Query_Additional_records.dns_rrsig_signature_inception",
   queryx."Additional_records.dns_rrsig_signers_name" as "Query_Additional_records.dns_rrsig_signers_name",
   queryx."Additional_records.dns_rrsig_type_covered" as "Query_Additional_records.dns_rrsig_type_covered",
   queryx."Additional_records.dns_srv_name" as "Query_Additional_records.dns_srv_name",
   queryx."Additional_records.dns_nsec3_algo" as "Query_Additional_records.dns_nsec3_algo",
   queryx."Additional_records.dns_srv_port" as "Query_Additional_records.dns_srv_port",
   queryx."Additional_records.dns_srv_priority" as "Query_Additional_records.dns_srv_priority",
   queryx."Additional_records.dns_srv_proto" as "Query_Additional_records.dns_srv_proto",
   queryx."Additional_records.dns_srv_service" as "Query_Additional_records.dns_srv_service",
   queryx."Additional_records.dns_srv_target" as "Query_Additional_records.dns_srv_target",
   queryx."Additional_records.dns_srv_weight" as "Query_Additional_records.dns_srv_weight",
   queryx."Additional_records.dns_nsec3_flags" as "Query_Additional_records.dns_nsec3_flags",
   -- dns_nsec3_flags_tree
   queryx."Additional_records.dns_nsec3_hash_length" as "Query_Additional_records.dns_nsec3_hash_length",
   queryx."Additional_records.dns_nsec3_hash_value" as "Query_Additional_records.dns_nsec3_hash_value",
   queryx."Additional_records.dns_nsec3_iterations" as "Query_Additional_records.dns_nsec3_iterations",
   queryx."Additional_records.dns_nsec3_salt_length" as "Query_Additional_records.dns_nsec3_salt_length",
   queryx."Additional_records.dns_nsec3_salt_value"  as "Query_Additional_records.dns_nsec3_salt_value",
   queryx."Additional_records.dns_rp_mailbox" as "Query_Additional_records.dns_rp_mailbox",
   queryx."Additional_records.dns_rp_txt_rr" as "Query_Additional_records.dns_rp_txt_rr",
   queryx."Additional_records.dns_tlsa_certificate_association_data" as "Query_Additional_records.dns_tlsa_certificate_association_data",
   queryx."Additional_records.dns_tlsa_certificate_usage" as "Query_Additional_records.dns_tlsa_certificate_usage",
   queryx."Additional_records.dns_tlsa_matching_type" as "Query_Additional_records.dns_tlsa_matching_type",
   queryx."Additional_records.dns_dname" as "Query_Additional_records.dns_dname",
   queryx."Additional_records.dns_tlsa_selector" as "Query_Additional_records.dns_tlsa_selector",

   queryx."Queries.dns_qry_name" as "Query_Queries.dns_qry_name",
   queryx."Queries.dns_qry_name_len" as "Query_Queries.dns_qry_name_len",
   queryx."Queries.dns_count_labels" as "Query_Queries.dns_count_labels",
   queryx."Queries.dns_qry_type" as "Query_Queries.dns_qry_type",
   arrayMap(i -> reinterpretAsUInt16(reverse(unhex(i))), queryx."Queries.dns_qry_class") as "Query_Queries.dns_qry_class",

   -- Response
   response.frame_interface_id as Response_frame_interface_id,
   response.frame_interface_id_tree.frame_interface_name as "Response_frame_interface_id_tree.frame_interface_name",
   response.frame_encap_type as Response_frame_encap_type,
   response.frame_time as Response_frame_time,
   response.frame_offset_shift as Response_frame_offset_shift,
   response.frame_time_epoch as Response_frame_time_epoch,
   if(isNotNull(response.frame_time_epoch), FROM_UNIXTIME(toUInt32(substring(response.frame_time_epoch, 1, 
   position(response.frame_time_epoch, '.') - 1))), null) as Response_frame_time_epoch_2,
   if(isNotNull(response.frame_time_epoch), toUInt32(substring(response.frame_time_epoch, 
   position(response.frame_time_epoch, '.') + 1)), null) as Response_frame_time_epoch_nanos,
   if (isNotNull(response.frame_time_epoch), toDayOfYear(Response_frame_time_epoch_2), null) as Response_day_of_year, 
   if (isNotNull(response.frame_time_epoch), toDayOfWeek(Response_frame_time_epoch_2), null) as Response_day_of_week, 
   if (isNotNull(response.frame_time_epoch), toHour(Response_frame_time_epoch_2), null) as Response_hour,
   response.frame_time_delta as Response_frame_time_delta,
   response.frame_time_delta_displayed as Response_frame_time_delta_displayed,
   response.frame_time_relative as Response_frame_time_relative,
   response.frame_number as Response_frame_number,
   response.frame_len as Response_frame_len,
   response.frame_cap_len as Response_frame_cap_len,
   response.frame_marked as Response_frame_marked,
   response.frame_ignored as Response_frame_ignored,
   response.frame_protocols as Response_frame_protocols,

   reinterpretAsUInt16(reverse(unhex(response.dns_id))) as Response_dns_id,
   reinterpretAsUInt16(reverse(unhex(response.dns_flags))) as Response_dns_flags,
   response.dns_count_queries as Response_dns_count_queries,
   response.dns_count_answers as Response_dns_count_answers,
   response.dns_count_auth_rr as Response_dns_count_auth_rr,
   response.dns_count_add_rr as Response_dns_count_add_rr,
   response.dns_response_to as Response_dns_response_to,
   response.dns_time as Response_dns_time,
   response.dns_flags_response as Response_dns_flags_response,
   response.dns_flags_opcode as Response_dns_flags_opcode,
   response.dns_flags_authoritative as Response_dns_flags_authoritative,
   response.dns_flags_truncated as Response_dns_flags_truncated,
   response.dns_flags_recdesired as Response_dns_flags_recdesired,
   response.dns_flags_recavail as Response_dns_flags_recavail,
   response.dns_flags_z as Response_dns_flags_z,
   response.dns_flags_authenticated as Response_dns_flags_authenticated,
   response.dns_flags_checkdisable as Response_dns_flags_checkdisable,
   response.dns_flags_rcode as Response_dns_flags_rcode,
   response.dns_unsolicited as Response_dns_unsolicited,
   -- dns_id_tree
   response.dns_retransmit_request_in as Response_dns_retransmit_request_in,
   response.dns_retransmission as Response_dns_retransmission,
   response.dns_retransmit_response_in as Response_dns_retransmit_response_in,

   response.udp_srcport as Response_udp_srcport,
   response.udp_dstport as Response_udp_dstport,
   response.udp_port as Response_udp_port,
   response.udp_length as Response_udp_length,
   reinterpretAsUInt16(reverse(unhex(response.udp_checksum))) as Response_udp_checksum,
   response.udp_checksum_status as Response_udp_checksum_status,
   response.udp_stream as Response_udp_stream,
   -- udp_srcport_tree
   -- udp_dstport_tree

   response.ip_version as Response_ip_version,
   response.ip_hdr_len as Response_ip_hdr_len,
   reinterpretAsUInt8(reverse(unhex(response.ip_dsfield))) as Response_ip_dsfield,
   response.ip_len as Response_ip_len,
   reinterpretAsUInt16(reverse(unhex(response.ip_id))) as Response_ip_id,
   reinterpretAsUInt16(reverse(unhex(response.ip_flags))) as Response_ip_flags,
   response.ip_ttl as Response_ip_ttl,
   response.ip_proto as Response_ip_proto,
   reinterpretAsUInt16(reverse(unhex(response.ip_checksum))) as Response_ip_checksum,
   response.ip_checksum_status as Response_ip_checksum_status,
   response.ip_src as Response_ip_src,
   response.ip_addr as Response_ip_addr,
   response.ip_src_host as Response_ip_src_host,
   response.ip_host as Response_ip_host,
   response.ip_dst as Response_ip_dst,
   response.ip_dst_host as Response_ip_dst_host,
   response.ip_dsfield_dscp as Response_ip_dsfield_dscp,
   response.ip_dsfield_ecn as Response_ip_dsfield_ecn,
   response.ip_flags_rb as Response_ip_flags_rb,
   response.ip_flags_df as Response_ip_flags_df,
   response.ip_flags_mf as Response_ip_flags_mf,
   response.ip_frag_offset as Response_ip_frag_offset,	

   response."Additional_records.dns_resp_name" as "Response_Additional_records.dns_resp_name",
   response."Additional_records.dns_resp_type" as "Response_Additional_records.dns_resp_type",
   arrayMap(i -> reinterpretAsUInt16(reverse(unhex(i))), response."Additional_records.dns_resp_class") as "Response_Additional_records.dns_resp_class",
   response."Additional_records.dns_resp_ttl" as "Response_Additional_records.dns_resp_ttl",
   response."Additional_records.dns_resp_len" as "Response_Additional_records.dns_resp_len",
   arrayMap( i-> toIPv4(i), response."Additional_records.dns_a") as "Response_Additional_records.dns_a",
   arrayMap( i-> toIPv6(i), response."Additional_records.dns_aaaa") as "Response_Additional_records.dns_aaaa",
   response."Additional_records.dns_resp_edns0_version" as "Response_Additional_records.dns_resp_edns0_version",
   response."Additional_records.dns_resp_ext_rcode" as "Response_Additional_records.dns_resp_ext_rcode",
   arrayMap(i -> reinterpretAsUInt16(reverse(unhex(i))), response."Additional_records.dns_resp_z") as "Response_Additional_records.dns_resp_z",
   -- dns_resp_z_tree
   response."Additional_records.dns_rr_udp_payload_size" as "Response_Additional_records.dns_rr_udp_payload_size",
   -- dns_opt
   response."Additional_records.dns_rrsig_algorithm" as "Response_Additional_records.dns_rrsig_algorithm",
   response."Additional_records.dns_rrsig_key_tag" as "Response_Additional_records.dns_rrsig_key_tag",
   response."Additional_records.dns_rrsig_labels" as "Response_Additional_records.dns_rrsig_labels",
   response."Additional_records.dns_rrsig_original_ttl" as "Response_Additional_records.dns_rrsig_original_ttl",
   response."Additional_records.dns_rrsig_signature" as "Response_Additional_records.dns_rrsig_signature",
   response."Additional_records.dns_rrsig_signature_expiration" as "Response_Additional_records.dns_rrsig_signature_expiration",
   response."Additional_records.dns_rrsig_signature_inception" as "Response_Additional_records.dns_rrsig_signature_inception",
   response."Additional_records.dns_rrsig_signers_name" as "Response_Additional_records.dns_rrsig_signers_name",
   response."Additional_records.dns_rrsig_type_covered" as "Response_Additional_records.dns_rrsig_type_covered",
   response."Additional_records.dns_srv_name" as "Response_Additional_records.dns_srv_name",
   response."Additional_records.dns_nsec3_algo" as "Response_Additional_records.dns_nsec3_algo",
   response."Additional_records.dns_srv_port" as "Response_Additional_records.dns_srv_port",
   response."Additional_records.dns_srv_priority" as "Response_Additional_records.dns_srv_priority",
   response."Additional_records.dns_srv_proto" as "Response_Additional_records.dns_srv_proto",
   response."Additional_records.dns_srv_service" as "Response_Additional_records.dns_srv_service",
   response."Additional_records.dns_srv_target" as "Response_Additional_records.dns_srv_target",
   response."Additional_records.dns_srv_weight" as "Response_Additional_records.dns_srv_weight",	
   response."Additional_records.dns_nsec3_flags" as "Response_Additional_records.dns_nsec3_flags",
   -- dns_nsec3_flags_tree
   response."Additional_records.dns_nsec3_hash_length" as "Response_Additional_records.dns_nsec3_hash_length",
   response."Additional_records.dns_nsec3_hash_value" as "Response_Additional_records.dns_nsec3_hash_value",
   response."Additional_records.dns_nsec3_iterations" as "Response_Additional_records.dns_nsec3_iterations",
   response."Additional_records.dns_nsec3_salt_length" as "Response_Additional_records.dns_nsec3_salt_length",
   response."Additional_records.dns_nsec3_salt_value"  as "Response_Additional_records.dns_nsec3_salt_value",
   response."Additional_records.dns_rp_mailbox" as "Response_Additional_records.dns_rp_mailbox",
   response."Additional_records.dns_rp_txt_rr" as "Response_Additional_records.dns_rp_txt_rr",
   response."Additional_records.dns_tlsa_certificate_association_data" as "Response_Additional_records.dns_tlsa_certificate_association_data",
   response."Additional_records.dns_tlsa_certificate_usage" as "Response_Additional_records.dns_tlsa_certificate_usage",
   response."Additional_records.dns_tlsa_matching_type" as "Response_Additional_records.dns_tlsa_matching_type",
   response."Additional_records.dns_dname" as "Response_Additional_records.dns_dname",
   response."Additional_records.dns_tlsa_selector" as "Response_Additional_records.dns_tlsa_selector",
	
   response."Authoritative_nameservers.dns_resp_name" as "Response_Authoritative_nameservers.dns_resp_name",
   response."Authoritative_nameservers.dns_resp_type" as "Response_Authoritative_nameservers.dns_resp_type",
   arrayMap(i -> reinterpretAsUInt16(reverse(unhex(i))), response."Authoritative_nameservers.dns_resp_class") as "Response_Authoritative_nameservers.dns_resp_class",
   response."Authoritative_nameservers.dns_resp_ttl" as "Response_Authoritative_nameservers.dns_resp_ttl",
   response."Authoritative_nameservers.dns_resp_len" as "Response_Authoritative_nameservers.dns_resp_len",
   response."Authoritative_nameservers.dns_ns" as "Response_Authoritative_nameservers.dns_ns",
   response."Authoritative_nameservers.dns_soa_expire_limit" as "Response_Authoritative_nameservers.dns_soa_expire_limit",
   response."Authoritative_nameservers.dns_soa_mininum_ttl" as "Response_Authoritative_nameservers.dns_soa_mininum_ttl",
   response."Authoritative_nameservers.dns_soa_mname" as "Response_Authoritative_nameservers.dns_soa_mname",
   response."Authoritative_nameservers.dns_soa_refresh_interval" as "Response_Authoritative_nameservers.dns_soa_refresh_interval",
   response."Authoritative_nameservers.dns_soa_retry_interval" as "Response_Authoritative_nameservers.dns_soa_retry_interval",
   response."Authoritative_nameservers.dns_soa_rname" as "Response_Authoritative_nameservers.dns_soa_rname",
   response."Authoritative_nameservers.dns_soa_serial_number" as "Response_Authoritative_nameservers.dns_soa_serial_number",
   response."Authoritative_nameservers.dns_nsec_next_domain_name" as "Response_Authoritative_nameservers.dns_nsec_next_domain_name",
   response."Authoritative_nameservers.dns_rrsig_algorithm" as "Response_Authoritative_nameservers.dns_rrsig_algorithm",
   response."Authoritative_nameservers.dns_rrsig_key_tag" as "Response_Authoritative_nameservers.dns_rrsig_key_tag",
   response."Authoritative_nameservers.dns_rrsig_labels" as "Response_Authoritative_nameservers.dns_rrsig_labels",
   response."Authoritative_nameservers.dns_rrsig_original_ttl" as "Response_Authoritative_nameservers.dns_rrsig_original_ttl",
   response."Authoritative_nameservers.dns_rrsig_signature" as "Response_Authoritative_nameservers.dns_rrsig_signature",
   response."Authoritative_nameservers.dns_rrsig_signature_expiration" as "Response_Authoritative_nameservers.dns_rrsig_signature_expiration",
   response."Authoritative_nameservers.dns_rrsig_signature_inception" as "Response_Authoritative_nameservers.dns_rrsig_signature_inception",
   response."Authoritative_nameservers.dns_rrsig_signers_name" as "Response_Authoritative_nameservers.dns_rrsig_signers_name",
   response."Authoritative_nameservers.dns_rrsig_type_covered" as "Response_Authoritative_nameservers.dns_rrsig_type_covered",
   response."Authoritative_nameservers.dns_ds_algorithm" as "Response_Authoritative_nameservers.dns_ds_algorithm",
   response."Authoritative_nameservers.dns_ds_digest" as "Response_Authoritative_nameservers.dns_ds_digest",
   response."Authoritative_nameservers.dns_ds_digest_type" as "Response_Authoritative_nameservers.dns_ds_digest_type",
   response."Authoritative_nameservers.dns_ds_key_id" as "Response_Authoritative_nameservers.dns_ds_key_id",
   -- dns_nsec3.flags_tree
   response."Authoritative_nameservers.dns_nsec3_algo" as "Response_Authoritative_nameservers.dns_nsec3_algo",
   response."Authoritative_nameservers.dns_nsec3_flags" as "Response_Authoritative_nameservers.dns_nsec3_flags",
   response."Authoritative_nameservers.dns_nsec3_iterations" as "Response_Authoritative_nameservers.dns_nsec3_iterations",
   response."Authoritative_nameservers.dns_nsec3_salt_length" as "Response_Authoritative_nameservers.dns_nsec3_salt_length",
   response."Authoritative_nameservers.dns_nsec3_salt_value" as "Response_Authoritative_nameservers.dns_nsec3_salt_value",
   response."Authoritative_nameservers.dns_nsec3_hash_length" as "Response_Authoritative_nameservers.dns_nsec3_hash_length",
   response."Authoritative_nameservers.dns_nsec3_hash_value" as "Response_Authoritative_nameservers.dns_nsec3_hash_value",
   response."Authoritative_nameservers.dns_srv_name" as "Response_Authoritative_nameservers.dns_srv_name",

   response."Queries.dns_qry_name" as "Response_Queries.dns_qry_name",
   response."Queries.dns_qry_name_len" as "Response_Queries.dns_qry_name_len",
   response."Queries.dns_count_labels" as "Response_Queries.dns_count_labels",
   response."Queries.dns_qry_type" as "Response_Queries.dns_qry_type",
   arrayMap(i -> reinterpretAsUInt16(reverse(unhex(i))), response."Queries.dns_qry_class") as "Response_Queries.dns_qry_class",

   response."Answers.dns_resp_name" as "Response_Answers.dns_resp_name",
   response."Answers.dns_resp_type" as "Response_Answers.dns_resp_type",
   arrayMap(i -> reinterpretAsUInt16(reverse(unhex(i))), response."Answers.dns_resp_class") as "Response_Answers.dns_resp_class",
   response."Answers.dns_resp_ttl" as "Response_Answers.dns_resp_ttl",
   response."Answers.dns_resp_len" as "Response_Answers.dns_resp_len",
   arrayMap(i -> toIPv4(i), response."Answers.dns_a") as "Response_Answers.dns_a",
   arrayMap(i -> toIPv6(i), response."Answers.dns_aaaa") as "Response_Answers.dns_aaaa",
   response."Answers.dns_cname" as "Response_Answers.dns_cname",
   response."Answers.dns_ptr_domain_name" as "Response_Answers.dns_ptr_domain_name",
   response."Answers.dns_rrsig_algorithm" as "Response_Answers.dns_rrsig_algorithm",
   response."Answers.dns_rrsig_key_tag" as "Response_Answers.dns_rrsig_key_tag",
   response."Answers.dns_rrsig_labels" as "Response_Answers.dns_rrsig_labels",
   response."Answers.dns_rrsig_original_ttl" as "Response_Answers.dns_rrsig_original_ttl",
   response."Answers.dns_rrsig_signature" as "Response_Answers.dns_rrsig_signature",
   response."Answers.dns_rrsig_signature_expiration" as "Response_Answers.dns_rrsig_signature_expiration",
   response."Answers.dns_rrsig_signature_inception" as "Response_Answers.dns_rrsig_signature_inception",
   response."Answers.dns_rrsig_signers_name" as "Response_Answers.dns_rrsig_signers_name",
   response."Answers.dns_rrsig_type_covered" as "Response_Answers.dns_rrsig_type_covered",
   response."Answers.dns_ds_algorithm" as "Response_Answers.dns_ds_algorithm",
   response."Answers.dns_ds_digest" as "Response_Answers.dns_ds_digest",
   response."Answers.dns_ds_digest_type" as "Response_Answers.dns_ds_digest_type",
   response."Answers.dns_ds_key_id" as "Response_Answers.dns_ds_key_id",
   response."Answers.dns_txt" as "Response_Answers.dns_txt",
   response."Answers.dns_txt_length" as "Response_Answers.dns_txt_length",
   response."Answers.dns_mx_mail_exchange" as "Response_Answers.dns_mx_mail_exchange",
   response."Answers.dns_mx_preference" as "Response_Answers.dns_mx_preference",
   response."Answers.dns_dnskey_algorithm" as "Response_Answers.dns_dnskey_algorithm",
   response."Answers.dns_dnskey_flags" as "Response_Answers.dns_dnskey_flags",
      -- dns_dnskey_flags_tree
   response."Answers.dns_dnskey_key_id" as "Response_Answers.dns_dnskey_key_id",
   response."Answers.dns_dnskey_protocol" as "Response_Answers.dns_dnskey_protocol",
   response."Answers.dns_dnskey_public_key" as "Response_Answers.dns_dnskey_public_key",
   response."Answers.dns_soa_expire_limit" as "Response_Answers.dns_soa_expire_limit",
   response."Answers.dns_soa_mininum_ttl" as "Response_Answers.dns_soa_mininum_ttl",
   response."Answers.dns_soa_mname" as "Response_Answers.dns_soa_mname",
   response."Answers.dns_soa_refresh_interval" as "Response_Answers.dns_soa_refresh_interval",
   response."Answers.dns_soa_retry_interval" as "Response_Answers.dns_soa_retry_interval",
   response."Answers.dns_soa_rname" as "Response_Answers.dns_soa_rname",
   response."Answers.dns_soa_serial_number" as "Response_Answers.dns_soa_serial_number",
   response."Answers.dns_ns" as "Response_Answers.dns_ns",
   -- _ws_expert
   response."Answers.dns_srv_name" as "Response_Answers.dns_srv_name",
   response."Answers.dns_srv_port" as "Response_Answers.dns_srv_port",
   response."Answers.dns_naptr_flags" as "Response_Answers.dns_naptr_flags",
   response."Answers.dns_srv_priority" as "Response_Answers.dns_srv_priority",
   response."Answers.dns_srv_proto" as "Response_Answers.dns_srv_proto",
   response."Answers.dns_srv_service" as "Response_Answers.dns_srv_service",
   response."Answers.dns_srv_target" as "Response_Answers.dns_srv_target",
   response."Answers.dns_srv_weight" as "Response_Answers.dns_srv_weight",
   response."Answers.dns_data" as "Response_Answers.dns_data",
   response."Answers.dns_naptr_flags_length" as "Response_Answers.dns_naptr_flags_length",
   response."Answers.dns_naptr_order" as "Response_Answers.dns_naptr_order",
   response."Answers.dns_naptr_preference" as "Response_Answers.dns_naptr_preference",
   response."Answers.dns_naptr_regex" as "Response_Answers.dns_naptr_regex",
   response."Answers.dns_naptr_regex_length" as "Response_Answers.dns_naptr_regex_length",
   response."Answers.dns_naptr_replacement" as "Response_Answers.dns_naptr_replacement",
   response."Answers.dns_naptr_service" as "Response_Answers.dns_naptr_service",
   response."Answers.dns_naptr_service_length" as "Response_Answers.dns_naptr_service_length",
   response."Answers.dns_naptr_replacement_length" as "Response_Answers.dns_naptr_replacement_length",
   response."Answers.dns_spf" as "Response_Answers.dns_spf",
   response."Answers.dns_spf_length" as "Response_Answers.dns_spf_length",
   response."Answers.dns_dname" as "Response_Answers.dns_dname",
   response."Answers.dns_resp_edns0_version" as "Response_Answers.dns_resp_edns0_version",
   response."Answers.dns_resp_ext_rcode" as "Response_Answers.dns_resp_ext_rcode",
   arrayMap(i -> reinterpretAsUInt16(reverse(unhex(i))), response."Answers.dns_resp_z") as "Response_Answers.dns_resp_z",
   -- dns_resp_z_tree
   response."Answers.dns_rr_udp_payload_size" as "Response_Answers.dns_rr_udp_payload_size"
   
from test3.no_types as queryx left outer join test3.no_types as response on queryx.frame_number=response.dns_response_to
where queryx.dns_response_to is null and toUInt16OrNull(response.udp_srcport) = 53;