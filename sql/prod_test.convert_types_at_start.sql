-- prod_test.convert_types_at_start source

CREATE MATERIALIZED VIEW prod_test.convert_types_at_start TO prod_test.types
(

    `Query_frame_interface_id` Nullable(String),

    `Query_frame_interface_id_tree.frame_interface_name` Array(Nullable(String)),

    `Query_frame_encap_type` Nullable(String),

    `Query_frame_time` Nullable(String),

    `Query_frame_offset_shift` Nullable(String),

    `Query_frame_time_epoch` String,

    `Query_frame_time_epoch_2` Nullable(DateTime),

    `Query_frame_time_epoch_nanos` Nullable(UInt32),

    `Query_day_of_year` Nullable(UInt16),

    `Query_day_of_week` Nullable(UInt8),

    `Query_hour` Nullable(UInt8),

    `Query_frame_time_delta` Nullable(String),

    `Query_frame_time_delta_displayed` Nullable(String),

    `Query_frame_time_relative` Nullable(String),

    `Query_frame_number` Nullable(String),

    `Query_frame_len` Nullable(String),

    `Query_frame_cap_len` Nullable(String),

    `Query_frame_marked` Nullable(String),

    `Query_frame_ignored` Nullable(String),

    `Query_frame_protocols` Nullable(String),

    `Query_dns_id` Nullable(UInt16),

    `Query_dns_flags` Nullable(UInt16),

    `Query_dns_count_queries` Nullable(String),

    `Query_dns_count_answers` Nullable(String),

    `Query_dns_count_auth_rr` Nullable(String),

    `Query_dns_count_add_rr` Nullable(String),

    `Query_dns_response_to` Nullable(String),

    `Query_dns_time` Nullable(String),

    `Query_dns_flags_response` Nullable(String),

    `Query_dns_flags_opcode` Nullable(String),

    `Query_dns_flags_authoritative` Nullable(String),

    `Query_dns_flags_truncated` Nullable(String),

    `Query_dns_flags_recdesired` Nullable(String),

    `Query_dns_flags_recavail` Nullable(String),

    `Query_dns_flags_z` Nullable(String),

    `Query_dns_flags_authenticated` Nullable(String),

    `Query_dns_flags_checkdisable` Nullable(String),

    `Query_dns_flags_rcode` Nullable(String),

    `Query_dns_unsolicited` Nullable(String),

    `Query_dns_retransmit_request_in` Nullable(String),

    `Query_dns_retransmission` Nullable(String),

    `Query_dns_retransmit_response_in` Nullable(String),

    `Query_udp_srcport` Nullable(String),

    `Query_udp_dstport` Nullable(String),

    `Query_udp_port` Nullable(String),

    `Query_udp_length` Nullable(String),

    `Query_udp_checksum` Nullable(UInt16),

    `Query_udp_checksum_status` Nullable(String),

    `Query_udp_stream` Nullable(String),

    `Query_ip_version` Nullable(String),

    `Query_ip_hdr_len` Nullable(String),

    `Query_ip_dsfield` Nullable(UInt8),

    `Query_ip_len` Nullable(String),

    `Query_ip_id` Nullable(UInt16),

    `Query_ip_flags` Nullable(UInt8),

    `Query_ip_ttl` Nullable(String),

    `Query_ip_proto` Nullable(String),

    `Query_ip_checksum` Nullable(UInt16),

    `Query_ip_checksum_status` Nullable(String),

    `Query_ip_src` Nullable(IPv4),

    `Query_ip_addr` Nullable(IPv4),

    `Query_ip_src_host` Nullable(IPv4),

    `Query_ip_src_class` UInt8,

    `Query_ip_host` Nullable(IPv4),

    `Query_ip_dst` Nullable(IPv4),

    `Query_ip_dst_host` Nullable(IPv4),

    `Query_ip_dsfield_dscp` Nullable(String),

    `Query_ip_dsfield_ecn` Nullable(String),

    `Query_ip_flags_rb` Nullable(String),

    `Query_ip_flags_df` Nullable(String),

    `Query_ip_flags_mf` Nullable(String),

    `Query_ip_frag_offset` Nullable(String),

    `Query_Additional_records.dns_resp_name` Array(Nullable(String)),

    `Query_Additional_records.dns_resp_type` Array(Nullable(String)),

    `Query_Additional_records.dns_resp_class` Array(Nullable(UInt16)),

    `Query_Additional_records.dns_resp_ttl` Array(Nullable(String)),

    `Query_Additional_records.dns_resp_len` Array(Nullable(String)),

    `Query_Additional_records.dns_a` Array(Nullable(IPv4)),

    `Query_Additional_records.dns_aaaa` Array(Nullable(IPv6)),

    `Query_Additional_records.dns_resp_edns0_version` Array(Nullable(String)),

    `Query_Additional_records.dns_resp_ext_rcode` Array(Nullable(String)),

    `Query_Additional_records.dns_resp_z` Array(Nullable(String)),

    `Query_Additional_records.dns_rr_udp_payload_size` Array(Nullable(String)),

    `Query_Additional_records.dns_rrsig_algorithm` Array(Nullable(String)),

    `Query_Additional_records.dns_rrsig_key_tag` Array(Nullable(String)),

    `Query_Additional_records.dns_rrsig_labels` Array(Nullable(String)),

    `Query_Additional_records.dns_rrsig_original_ttl` Array(Nullable(String)),

    `Query_Additional_records.dns_rrsig_signature` Array(Nullable(String)),

    `Query_Additional_records.dns_rrsig_signature_expiration` Array(Nullable(String)),

    `Query_Additional_records.dns_rrsig_signature_inception` Array(Nullable(String)),

    `Query_Additional_records.dns_rrsig_signers_name` Array(Nullable(String)),

    `Query_Additional_records.dns_rrsig_type_covered` Array(Nullable(String)),

    `Query_Additional_records.dns_srv_name` Array(Nullable(String)),

    `Query_Additional_records.dns_nsec3_algo` Array(Nullable(String)),

    `Query_Additional_records.dns_srv_port` Array(Nullable(String)),

    `Query_Additional_records.dns_srv_priority` Array(Nullable(String)),

    `Query_Additional_records.dns_srv_proto` Array(Nullable(String)),

    `Query_Additional_records.dns_srv_service` Array(Nullable(String)),

    `Query_Additional_records.dns_srv_target` Array(Nullable(String)),

    `Query_Additional_records.dns_srv_weight` Array(Nullable(String)),

    `Query_Additional_records.dns_nsec3_flags` Array(Nullable(String)),

    `Query_Additional_records.dns_nsec3_hash_length` Array(Nullable(String)),

    `Query_Additional_records.dns_nsec3_hash_value` Array(Nullable(String)),

    `Query_Additional_records.dns_nsec3_iterations` Array(Nullable(String)),

    `Query_Additional_records.dns_nsec3_salt_length` Array(Nullable(String)),

    `Query_Additional_records.dns_nsec3_salt_value` Array(Nullable(String)),

    `Query_Additional_records.dns_rp_mailbox` Array(Nullable(String)),

    `Query_Additional_records.dns_rp_txt_rr` Array(Nullable(String)),

    `Query_Additional_records.dns_tlsa_certificate_association_data` Array(Nullable(String)),

    `Query_Additional_records.dns_tlsa_certificate_usage` Array(Nullable(String)),

    `Query_Additional_records.dns_tlsa_matching_type` Array(Nullable(String)),

    `Query_Additional_records.dns_dname` Array(Nullable(String)),

    `Query_Additional_records.dns_tlsa_selector` Array(Nullable(String)),

    `Query_Queries.dns_qry_name` Array(Nullable(String)),

    `Query_Queries.dns_qry_name_len` Array(Nullable(String)),

    `Query_Queries.dns_count_labels` Array(Nullable(String)),

    `Query_Queries.dns_qry_type` Array(Nullable(String)),

    `Query_Queries.dns_qry_class` Array(Nullable(UInt16)),

    `Response_frame_interface_id` Nullable(String),

    `Response_frame_interface_id_tree.frame_interface_name` Array(Nullable(String)),

    `Response_frame_encap_type` Nullable(String),

    `Response_frame_time` Nullable(String),

    `Response_frame_offset_shift` Nullable(String),

    `Response_frame_time_epoch` Float64,

    `Response_frame_time_epoch_2` Nullable(DateTime),

    `Response_frame_time_epoch_nanos` Nullable(UInt32),

    `Response_day_of_year` Nullable(UInt16),

    `Response_day_of_week` Nullable(UInt8),

    `Response_hour` Nullable(UInt8),

    `Response_frame_time_delta` Nullable(String),

    `Response_frame_time_delta_displayed` Nullable(String),

    `Response_frame_time_relative` Nullable(String),

    `Response_frame_number` Nullable(String),

    `Response_frame_len` Nullable(String),

    `Response_frame_cap_len` Nullable(String),

    `Response_frame_marked` Nullable(String),

    `Response_frame_ignored` Nullable(String),

    `Response_frame_protocols` Nullable(String),

    `Response_dns_id` Nullable(UInt16),

    `Response_dns_flags` Nullable(UInt16),

    `Response_dns_count_queries` Nullable(String),

    `Response_dns_count_answers` Nullable(String),

    `Response_dns_count_auth_rr` Nullable(String),

    `Response_dns_count_add_rr` Nullable(String),

    `Response_dns_response_to` Nullable(String),

    `Response_dns_time` Nullable(String),

    `Response_dns_flags_response` Nullable(String),

    `Response_dns_flags_opcode` Nullable(String),

    `Response_dns_flags_authoritative` Nullable(String),

    `Response_dns_flags_truncated` Nullable(String),

    `Response_dns_flags_recdesired` Nullable(String),

    `Response_dns_flags_recavail` Nullable(String),

    `Response_dns_flags_z` Nullable(String),

    `Response_dns_flags_authenticated` Nullable(String),

    `Response_dns_flags_checkdisable` Nullable(String),

    `Response_dns_flags_rcode` Nullable(String),

    `Response_dns_unsolicited` Nullable(String),

    `Response_dns_retransmit_request_in` Nullable(String),

    `Response_dns_retransmission` Nullable(String),

    `Response_dns_retransmit_response_in` Nullable(String),

    `Response_udp_srcport` Nullable(String),

    `Response_udp_dstport` Nullable(String),

    `Response_udp_port` Nullable(String),

    `Response_udp_length` Nullable(String),

    `Response_udp_checksum` Nullable(UInt16),

    `Response_udp_checksum_status` Nullable(String),

    `Response_udp_stream` Nullable(String),

    `Response_ip_version` Nullable(String),

    `Response_ip_hdr_len` Nullable(String),

    `Response_ip_dsfield` Nullable(UInt8),

    `Response_ip_len` Nullable(String),

    `Response_ip_id` Nullable(UInt16),

    `Response_ip_flags` Nullable(UInt8),

    `Response_ip_ttl` Nullable(String),

    `Response_ip_proto` Nullable(String),

    `Response_ip_checksum` Nullable(UInt16),

    `Response_ip_checksum_status` Nullable(String),

    `Response_ip_src` Nullable(IPv4),

    `Response_ip_addr` Nullable(IPv4),

    `Response_ip_src_host` Nullable(IPv4),

    `Response_ip_host` Nullable(IPv4),

    `Response_ip_dst` Nullable(IPv4),

    `Response_ip_dst_host` Nullable(IPv4),

    `Response_ip_dsfield_dscp` Nullable(String),

    `Response_ip_dsfield_ecn` Nullable(String),

    `Response_ip_flags_rb` Nullable(String),

    `Response_ip_flags_df` Nullable(String),

    `Response_ip_flags_mf` Nullable(String),

    `Response_ip_frag_offset` Nullable(String),

    `Response_Additional_records.dns_resp_name` Array(Nullable(String)),

    `Response_Additional_records.dns_resp_type` Array(Nullable(String)),

    `Response_Additional_records.dns_resp_class` Array(Nullable(UInt16)),

    `Response_Additional_records.dns_resp_ttl` Array(Nullable(String)),

    `Response_Additional_records.dns_resp_len` Array(Nullable(String)),

    `Response_Additional_records.dns_a` Array(Nullable(IPv4)),

    `Response_Additional_records.dns_aaaa` Array(Nullable(IPv6)),

    `Response_Additional_records.dns_resp_edns0_version` Array(Nullable(String)),

    `Response_Additional_records.dns_resp_ext_rcode` Array(Nullable(String)),

    `Response_Additional_records.dns_resp_z` Array(Nullable(String)),

    `Response_Additional_records.dns_rr_udp_payload_size` Array(Nullable(String)),

    `Response_Additional_records.dns_rrsig_algorithm` Array(Nullable(String)),

    `Response_Additional_records.dns_rrsig_key_tag` Array(Nullable(String)),

    `Response_Additional_records.dns_rrsig_labels` Array(Nullable(String)),

    `Response_Additional_records.dns_rrsig_original_ttl` Array(Nullable(String)),

    `Response_Additional_records.dns_rrsig_signature` Array(Nullable(String)),

    `Response_Additional_records.dns_rrsig_signature_expiration` Array(Nullable(String)),

    `Response_Additional_records.dns_rrsig_signature_inception` Array(Nullable(String)),

    `Response_Additional_records.dns_rrsig_signers_name` Array(Nullable(String)),

    `Response_Additional_records.dns_rrsig_type_covered` Array(Nullable(String)),

    `Response_Additional_records.dns_srv_name` Array(Nullable(String)),

    `Response_Additional_records.dns_nsec3_algo` Array(Nullable(String)),

    `Response_Additional_records.dns_srv_port` Array(Nullable(String)),

    `Response_Additional_records.dns_srv_priority` Array(Nullable(String)),

    `Response_Additional_records.dns_srv_proto` Array(Nullable(String)),

    `Response_Additional_records.dns_srv_service` Array(Nullable(String)),

    `Response_Additional_records.dns_srv_target` Array(Nullable(String)),

    `Response_Additional_records.dns_srv_weight` Array(Nullable(String)),

    `Response_Additional_records.dns_nsec3_flags` Array(Nullable(String)),

    `Response_Additional_records.dns_nsec3_hash_length` Array(Nullable(String)),

    `Response_Additional_records.dns_nsec3_hash_value` Array(Nullable(String)),

    `Response_Additional_records.dns_nsec3_iterations` Array(Nullable(String)),

    `Response_Additional_records.dns_nsec3_salt_length` Array(Nullable(String)),

    `Response_Additional_records.dns_nsec3_salt_value` Array(Nullable(String)),

    `Response_Additional_records.dns_rp_mailbox` Array(Nullable(String)),

    `Response_Additional_records.dns_rp_txt_rr` Array(Nullable(String)),

    `Response_Additional_records.dns_tlsa_certificate_association_data` Array(Nullable(String)),

    `Response_Additional_records.dns_tlsa_certificate_usage` Array(Nullable(String)),

    `Response_Additional_records.dns_tlsa_matching_type` Array(Nullable(String)),

    `Response_Additional_records.dns_dname` Array(Nullable(String)),

    `Response_Additional_records.dns_tlsa_selector` Array(Nullable(String)),

    `Response_Authoritative_nameservers.dns_resp_name` Array(Nullable(String)),

    `Response_Authoritative_nameservers.dns_resp_type` Array(Nullable(String)),

    `Response_Authoritative_nameservers.dns_resp_class` Array(Nullable(UInt16)),

    `Response_Authoritative_nameservers.dns_resp_ttl` Array(Nullable(String)),

    `Response_Authoritative_nameservers.dns_resp_len` Array(Nullable(String)),

    `Response_Authoritative_nameservers.dns_ns` Array(Nullable(String)),

    `Response_Authoritative_nameservers.dns_soa_expire_limit` Array(Nullable(String)),

    `Response_Authoritative_nameservers.dns_soa_mininum_ttl` Array(Nullable(String)),

    `Response_Authoritative_nameservers.dns_soa_mname` Array(Nullable(String)),

    `Response_Authoritative_nameservers.dns_soa_refresh_interval` Array(Nullable(String)),

    `Response_Authoritative_nameservers.dns_soa_retry_interval` Array(Nullable(String)),

    `Response_Authoritative_nameservers.dns_soa_rname` Array(Nullable(String)),

    `Response_Authoritative_nameservers.dns_soa_serial_number` Array(Nullable(String)),

    `Response_Authoritative_nameservers.dns_nsec_next_domain_name` Array(Nullable(String)),

    `Response_Authoritative_nameservers.dns_rrsig_algorithm` Array(Nullable(String)),

    `Response_Authoritative_nameservers.dns_rrsig_key_tag` Array(Nullable(String)),

    `Response_Authoritative_nameservers.dns_rrsig_labels` Array(Nullable(String)),

    `Response_Authoritative_nameservers.dns_rrsig_original_ttl` Array(Nullable(String)),

    `Response_Authoritative_nameservers.dns_rrsig_signature` Array(Nullable(String)),

    `Response_Authoritative_nameservers.dns_rrsig_signature_expiration` Array(Nullable(String)),

    `Response_Authoritative_nameservers.dns_rrsig_signature_inception` Array(Nullable(String)),

    `Response_Authoritative_nameservers.dns_rrsig_signers_name` Array(Nullable(String)),

    `Response_Authoritative_nameservers.dns_rrsig_type_covered` Array(Nullable(String)),

    `Response_Authoritative_nameservers.dns_ds_algorithm` Array(Nullable(String)),

    `Response_Authoritative_nameservers.dns_ds_digest` Array(Nullable(String)),

    `Response_Authoritative_nameservers.dns_ds_digest_type` Array(Nullable(String)),

    `Response_Authoritative_nameservers.dns_ds_key_id` Array(Nullable(String)),

    `Response_Authoritative_nameservers.dns_nsec3_algo` Array(Nullable(String)),

    `Response_Authoritative_nameservers.dns_nsec3_flags` Array(Nullable(String)),

    `Response_Authoritative_nameservers.dns_nsec3_iterations` Array(Nullable(String)),

    `Response_Authoritative_nameservers.dns_nsec3_salt_length` Array(Nullable(String)),

    `Response_Authoritative_nameservers.dns_nsec3_salt_value` Array(Nullable(String)),

    `Response_Authoritative_nameservers.dns_nsec3_hash_length` Array(Nullable(String)),

    `Response_Authoritative_nameservers.dns_nsec3_hash_value` Array(Nullable(String)),

    `Response_Authoritative_nameservers.dns_srv_name` Array(Nullable(String)),

    `Response_Queries.dns_qry_name` Array(Nullable(String)),

    `Response_Queries.dns_qry_name_len` Array(Nullable(String)),

    `Response_Queries.dns_count_labels` Array(Nullable(String)),

    `Response_Queries.dns_qry_type` Array(Nullable(String)),

    `Response_Queries.dns_qry_class` Array(Nullable(UInt16)),

    `Response_Answers.dns_resp_name` Array(Nullable(String)),

    `Response_Answers.dns_resp_type` Array(Nullable(String)),

    `Response_Answers.dns_resp_class` Array(Nullable(UInt16)),

    `Response_Answers.dns_resp_ttl` Array(Nullable(String)),

    `Response_Answers.dns_resp_len` Array(Nullable(String)),

    `Response_Answers.dns_a` Array(Nullable(IPv4)),

    `Response_Answers.dns_aaaa` Array(Nullable(IPv6)),

    `Response_Answers.dns_cname` Array(Nullable(String)),

    `Response_Answers.dns_ptr_domain_name` Array(Nullable(String)),

    `Response_Answers.dns_rrsig_algorithm` Array(Nullable(String)),

    `Response_Answers.dns_rrsig_key_tag` Array(Nullable(String)),

    `Response_Answers.dns_rrsig_labels` Array(Nullable(String)),

    `Response_Answers.dns_rrsig_original_ttl` Array(Nullable(String)),

    `Response_Answers.dns_rrsig_signature` Array(Nullable(String)),

    `Response_Answers.dns_rrsig_signature_expiration` Array(Nullable(String)),

    `Response_Answers.dns_rrsig_signature_inception` Array(Nullable(String)),

    `Response_Answers.dns_rrsig_signers_name` Array(Nullable(String)),

    `Response_Answers.dns_rrsig_type_covered` Array(Nullable(String)),

    `Response_Answers.dns_ds_algorithm` Array(Nullable(String)),

    `Response_Answers.dns_ds_digest` Array(Nullable(String)),

    `Response_Answers.dns_ds_digest_type` Array(Nullable(String)),

    `Response_Answers.dns_ds_key_id` Array(Nullable(String)),

    `Response_Answers.dns_txt` Array(Nullable(String)),

    `Response_Answers.dns_txt_length` Array(Nullable(String)),

    `Response_Answers.dns_mx_mail_exchange` Array(Nullable(String)),

    `Response_Answers.dns_mx_preference` Array(Nullable(String)),

    `Response_Answers.dns_dnskey_algorithm` Array(Nullable(String)),

    `Response_Answers.dns_dnskey_flags` Array(Nullable(String)),

    `Response_Answers.dns_dnskey_key_id` Array(Nullable(String)),

    `Response_Answers.dns_dnskey_protocol` Array(Nullable(String)),

    `Response_Answers.dns_dnskey_public_key` Array(Nullable(String)),

    `Response_Answers.dns_soa_expire_limit` Array(Nullable(String)),

    `Response_Answers.dns_soa_mininum_ttl` Array(Nullable(String)),

    `Response_Answers.dns_soa_mname` Array(Nullable(String)),

    `Response_Answers.dns_soa_refresh_interval` Array(Nullable(String)),

    `Response_Answers.dns_soa_retry_interval` Array(Nullable(String)),

    `Response_Answers.dns_soa_rname` Array(Nullable(String)),

    `Response_Answers.dns_soa_serial_number` Array(Nullable(String)),

    `Response_Answers.dns_ns` Array(Nullable(String)),

    `Response_Answers.dns_srv_name` Array(Nullable(String)),

    `Response_Answers.dns_srv_port` Array(Nullable(String)),

    `Response_Answers.dns_naptr_flags` Array(Nullable(String)),

    `Response_Answers.dns_srv_priority` Array(Nullable(String)),

    `Response_Answers.dns_srv_proto` Array(Nullable(String)),

    `Response_Answers.dns_srv_service` Array(Nullable(String)),

    `Response_Answers.dns_srv_target` Array(Nullable(String)),

    `Response_Answers.dns_srv_weight` Array(Nullable(String)),

    `Response_Answers.dns_data` Array(Nullable(String)),

    `Response_Answers.dns_naptr_flags_length` Array(Nullable(String)),

    `Response_Answers.dns_naptr_order` Array(Nullable(String)),

    `Response_Answers.dns_naptr_preference` Array(Nullable(String)),

    `Response_Answers.dns_naptr_regex` Array(Nullable(String)),

    `Response_Answers.dns_naptr_regex_length` Array(Nullable(String)),

    `Response_Answers.dns_naptr_replacement` Array(Nullable(String)),

    `Response_Answers.dns_naptr_service` Array(Nullable(String)),

    `Response_Answers.dns_naptr_service_length` Array(Nullable(String)),

    `Response_Answers.dns_naptr_replacement_length` Array(Nullable(String)),

    `Response_Answers.dns_spf` Array(Nullable(String)),

    `Response_Answers.dns_spf_length` Array(Nullable(String)),

    `Response_Answers.dns_dname` Array(Nullable(String)),

    `Response_Answers.dns_resp_edns0_version` Array(Nullable(String)),

    `Response_Answers.dns_resp_ext_rcode` Array(Nullable(String)),

    `Response_Answers.dns_resp_z` Array(Nullable(String)),

    `Response_Answers.dns_rr_udp_payload_size` Array(Nullable(String))
) AS
SELECT
    queryx.frame_interface_id AS Query_frame_interface_id,

    queryx.frame_interface_id_tree.frame_interface_name AS `Query_frame_interface_id_tree.frame_interface_name`,

    queryx.frame_encap_type AS Query_frame_encap_type,

    queryx.frame_time AS Query_frame_time,

    queryx.frame_offset_shift AS Query_frame_offset_shift,

    queryx.frame_time_epoch AS Query_frame_time_epoch,

    if(isNotNull(queryx.frame_time_epoch),
 FROM_UNIXTIME(toUInt32(substring(queryx.frame_time_epoch,
 1,
 position(queryx.frame_time_epoch,
 '.') - 1))),
 NULL) AS Query_frame_time_epoch_2,

    if(isNotNull(queryx.frame_time_epoch),
 toUInt32(substring(queryx.frame_time_epoch,
 position(queryx.frame_time_epoch,
 '.') + 1)),
 NULL) AS Query_frame_time_epoch_nanos,

    if(isNotNull(queryx.frame_time_epoch),
 toDayOfYear(Query_frame_time_epoch_2),
 NULL) AS Query_day_of_year,

    if(isNotNull(queryx.frame_time_epoch),
 toDayOfWeek(Query_frame_time_epoch_2),
 NULL) AS Query_day_of_week,

    if(isNotNull(queryx.frame_time_epoch),
 toHour(Query_frame_time_epoch_2),
 NULL) AS Query_hour,

    queryx.frame_time_delta AS Query_frame_time_delta,

    queryx.frame_time_delta_displayed AS Query_frame_time_delta_displayed,

    queryx.frame_time_relative AS Query_frame_time_relative,

    queryx.frame_number AS Query_frame_number,

    queryx.frame_len AS Query_frame_len,

    queryx.frame_cap_len AS Query_frame_cap_len,

    queryx.frame_marked AS Query_frame_marked,

    queryx.frame_ignored AS Query_frame_ignored,

    queryx.frame_protocols AS Query_frame_protocols,

    reinterpretAsUInt16(reverse(unhex(queryx.dns_id))) AS Query_dns_id,

    reinterpretAsUInt16(reverse(unhex(queryx.dns_flags))) AS Query_dns_flags,

    queryx.dns_count_queries AS Query_dns_count_queries,

    queryx.dns_count_answers AS Query_dns_count_answers,

    queryx.dns_count_auth_rr AS Query_dns_count_auth_rr,

    queryx.dns_count_add_rr AS Query_dns_count_add_rr,

    queryx.dns_response_to AS Query_dns_response_to,

    queryx.dns_time AS Query_dns_time,

    queryx.dns_flags_response AS Query_dns_flags_response,

    queryx.dns_flags_opcode AS Query_dns_flags_opcode,

    queryx.dns_flags_authoritative AS Query_dns_flags_authoritative,

    queryx.dns_flags_truncated AS Query_dns_flags_truncated,

    queryx.dns_flags_recdesired AS Query_dns_flags_recdesired,

    queryx.dns_flags_recavail AS Query_dns_flags_recavail,

    queryx.dns_flags_z AS Query_dns_flags_z,

    queryx.dns_flags_authenticated AS Query_dns_flags_authenticated,

    queryx.dns_flags_checkdisable AS Query_dns_flags_checkdisable,

    queryx.dns_flags_rcode AS Query_dns_flags_rcode,

    queryx.dns_unsolicited AS Query_dns_unsolicited,

    queryx.dns_retransmit_request_in AS Query_dns_retransmit_request_in,

    queryx.dns_retransmission AS Query_dns_retransmission,

    queryx.dns_retransmit_response_in AS Query_dns_retransmit_response_in,

    queryx.udp_srcport AS Query_udp_srcport,

    queryx.udp_dstport AS Query_udp_dstport,

    queryx.udp_port AS Query_udp_port,

    queryx.udp_length AS Query_udp_length,

    reinterpretAsUInt16(reverse(unhex(queryx.udp_checksum))) AS Query_udp_checksum,

    queryx.udp_checksum_status AS Query_udp_checksum_status,

    queryx.udp_stream AS Query_udp_stream,

    queryx.ip_version AS Query_ip_version,

    queryx.ip_hdr_len AS Query_ip_hdr_len,

    reinterpretAsUInt8(reverse(unhex(queryx.ip_dsfield))) AS Query_ip_dsfield,

    queryx.ip_len AS Query_ip_len,

    reinterpretAsUInt16(reverse(unhex(queryx.ip_id))) AS Query_ip_id,

    reinterpretAsUInt8(reverse(unhex(queryx.ip_flags))) AS Query_ip_flags,

    queryx.ip_ttl AS Query_ip_ttl,

    queryx.ip_proto AS Query_ip_proto,

    reinterpretAsUInt16(reverse(unhex(queryx.ip_checksum))) AS Query_ip_checksum,

    queryx.ip_checksum_status AS Query_ip_checksum_status,

    queryx.ip_src AS Query_ip_src,

    queryx.ip_addr AS Query_ip_addr,

    queryx.ip_src_host AS Query_ip_src_host,

    if(substring(IPv4NumToString(Query_ip_src),
 1,
 6) = '255.25',
 0,
 if(substring(IPv4NumToString(Query_ip_src),
 1,
 6) = '254.25',
 1,
 2)) AS Query_ip_src_class,

    queryx.ip_host AS Query_ip_host,

    queryx.ip_dst AS Query_ip_dst,

    queryx.ip_dst_host AS Query_ip_dst_host,

    queryx.ip_dsfield_dscp AS Query_ip_dsfield_dscp,

    queryx.ip_dsfield_ecn AS Query_ip_dsfield_ecn,

    queryx.ip_flags_rb AS Query_ip_flags_rb,

    queryx.ip_flags_df AS Query_ip_flags_df,

    queryx.ip_flags_mf AS Query_ip_flags_mf,

    queryx.ip_frag_offset AS Query_ip_frag_offset,

    queryx.`Additional_records.dns_resp_name` AS `Query_Additional_records.dns_resp_name`,

    queryx.`Additional_records.dns_resp_type` AS `Query_Additional_records.dns_resp_type`,

    arrayMap(i -> reinterpretAsUInt16(reverse(unhex(i))),
 queryx.`Additional_records.dns_resp_class`) AS `Query_Additional_records.dns_resp_class`,

    queryx.`Additional_records.dns_resp_ttl` AS `Query_Additional_records.dns_resp_ttl`,

    queryx.`Additional_records.dns_resp_len` AS `Query_Additional_records.dns_resp_len`,

    arrayMap(i -> toIPv4(i),
 queryx.`Additional_records.dns_a`) AS `Query_Additional_records.dns_a`,

    arrayMap(i -> toIPv6(i),
 queryx.`Additional_records.dns_aaaa`) AS `Query_Additional_records.dns_aaaa`,

    queryx.`Additional_records.dns_resp_edns0_version` AS `Query_Additional_records.dns_resp_edns0_version`,

    queryx.`Additional_records.dns_resp_ext_rcode` AS `Query_Additional_records.dns_resp_ext_rcode`,

    queryx.`Additional_records.dns_resp_z` AS `Query_Additional_records.dns_resp_z`,

    queryx.`Additional_records.dns_rr_udp_payload_size` AS `Query_Additional_records.dns_rr_udp_payload_size`,

    queryx.`Additional_records.dns_rrsig_algorithm` AS `Query_Additional_records.dns_rrsig_algorithm`,

    queryx.`Additional_records.dns_rrsig_key_tag` AS `Query_Additional_records.dns_rrsig_key_tag`,

    queryx.`Additional_records.dns_rrsig_labels` AS `Query_Additional_records.dns_rrsig_labels`,

    queryx.`Additional_records.dns_rrsig_original_ttl` AS `Query_Additional_records.dns_rrsig_original_ttl`,

    queryx.`Additional_records.dns_rrsig_signature` AS `Query_Additional_records.dns_rrsig_signature`,

    queryx.`Additional_records.dns_rrsig_signature_expiration` AS `Query_Additional_records.dns_rrsig_signature_expiration`,

    queryx.`Additional_records.dns_rrsig_signature_inception` AS `Query_Additional_records.dns_rrsig_signature_inception`,

    queryx.`Additional_records.dns_rrsig_signers_name` AS `Query_Additional_records.dns_rrsig_signers_name`,

    queryx.`Additional_records.dns_rrsig_type_covered` AS `Query_Additional_records.dns_rrsig_type_covered`,

    queryx.`Additional_records.dns_srv_name` AS `Query_Additional_records.dns_srv_name`,

    queryx.`Additional_records.dns_nsec3_algo` AS `Query_Additional_records.dns_nsec3_algo`,

    queryx.`Additional_records.dns_srv_port` AS `Query_Additional_records.dns_srv_port`,

    queryx.`Additional_records.dns_srv_priority` AS `Query_Additional_records.dns_srv_priority`,

    queryx.`Additional_records.dns_srv_proto` AS `Query_Additional_records.dns_srv_proto`,

    queryx.`Additional_records.dns_srv_service` AS `Query_Additional_records.dns_srv_service`,

    queryx.`Additional_records.dns_srv_target` AS `Query_Additional_records.dns_srv_target`,

    queryx.`Additional_records.dns_srv_weight` AS `Query_Additional_records.dns_srv_weight`,

    queryx.`Additional_records.dns_nsec3_flags` AS `Query_Additional_records.dns_nsec3_flags`,

    queryx.`Additional_records.dns_nsec3_hash_length` AS `Query_Additional_records.dns_nsec3_hash_length`,

    queryx.`Additional_records.dns_nsec3_hash_value` AS `Query_Additional_records.dns_nsec3_hash_value`,

    queryx.`Additional_records.dns_nsec3_iterations` AS `Query_Additional_records.dns_nsec3_iterations`,

    queryx.`Additional_records.dns_nsec3_salt_length` AS `Query_Additional_records.dns_nsec3_salt_length`,

    queryx.`Additional_records.dns_nsec3_salt_value` AS `Query_Additional_records.dns_nsec3_salt_value`,

    queryx.`Additional_records.dns_rp_mailbox` AS `Query_Additional_records.dns_rp_mailbox`,

    queryx.`Additional_records.dns_rp_txt_rr` AS `Query_Additional_records.dns_rp_txt_rr`,

    queryx.`Additional_records.dns_tlsa_certificate_association_data` AS `Query_Additional_records.dns_tlsa_certificate_association_data`,

    queryx.`Additional_records.dns_tlsa_certificate_usage` AS `Query_Additional_records.dns_tlsa_certificate_usage`,

    queryx.`Additional_records.dns_tlsa_matching_type` AS `Query_Additional_records.dns_tlsa_matching_type`,

    queryx.`Additional_records.dns_dname` AS `Query_Additional_records.dns_dname`,

    queryx.`Additional_records.dns_tlsa_selector` AS `Query_Additional_records.dns_tlsa_selector`,

    queryx.`Queries.dns_qry_name` AS `Query_Queries.dns_qry_name`,

    queryx.`Queries.dns_qry_name_len` AS `Query_Queries.dns_qry_name_len`,

    queryx.`Queries.dns_count_labels` AS `Query_Queries.dns_count_labels`,

    queryx.`Queries.dns_qry_type` AS `Query_Queries.dns_qry_type`,

    arrayMap(i -> reinterpretAsUInt16(reverse(unhex(i))),
 queryx.`Queries.dns_qry_class`) AS `Query_Queries.dns_qry_class`,

    response.frame_interface_id AS Response_frame_interface_id,

    response.frame_interface_id_tree.frame_interface_name AS `Response_frame_interface_id_tree.frame_interface_name`,

    response.frame_encap_type AS Response_frame_encap_type,

    response.frame_time AS Response_frame_time,

    response.frame_offset_shift AS Response_frame_offset_shift,

    reinterpretAsFloat64(response.frame_time_epoch) AS Response_frame_time_epoch,

    if(isNotNull(response.frame_time_epoch),
 FROM_UNIXTIME(toUInt32(substring(response.frame_time_epoch,
 1,
 position(response.frame_time_epoch,
 '.') - 1))),
 NULL) AS Response_frame_time_epoch_2,

    if(isNotNull(response.frame_time_epoch),
 toUInt32(substring(response.frame_time_epoch,
 position(response.frame_time_epoch,
 '.') + 1)),
 NULL) AS Response_frame_time_epoch_nanos,

    if(isNotNull(response.frame_time_epoch),
 toDayOfYear(Response_frame_time_epoch_2),
 NULL) AS Response_day_of_year,

    if(isNotNull(response.frame_time_epoch),
 toDayOfWeek(Response_frame_time_epoch_2),
 NULL) AS Response_day_of_week,

    if(isNotNull(response.frame_time_epoch),
 toHour(Response_frame_time_epoch_2),
 NULL) AS Response_hour,

    response.frame_time_delta AS Response_frame_time_delta,

    response.frame_time_delta_displayed AS Response_frame_time_delta_displayed,

    response.frame_time_relative AS Response_frame_time_relative,

    response.frame_number AS Response_frame_number,

    response.frame_len AS Response_frame_len,

    response.frame_cap_len AS Response_frame_cap_len,

    response.frame_marked AS Response_frame_marked,

    response.frame_ignored AS Response_frame_ignored,

    response.frame_protocols AS Response_frame_protocols,

    reinterpretAsUInt16(reverse(unhex(response.dns_id))) AS Response_dns_id,

    reinterpretAsUInt16(reverse(unhex(response.dns_flags))) AS Response_dns_flags,

    response.dns_count_queries AS Response_dns_count_queries,

    response.dns_count_answers AS Response_dns_count_answers,

    response.dns_count_auth_rr AS Response_dns_count_auth_rr,

    response.dns_count_add_rr AS Response_dns_count_add_rr,

    response.dns_response_to AS Response_dns_response_to,

    response.dns_time AS Response_dns_time,

    response.dns_flags_response AS Response_dns_flags_response,

    response.dns_flags_opcode AS Response_dns_flags_opcode,

    response.dns_flags_authoritative AS Response_dns_flags_authoritative,

    response.dns_flags_truncated AS Response_dns_flags_truncated,

    response.dns_flags_recdesired AS Response_dns_flags_recdesired,

    response.dns_flags_recavail AS Response_dns_flags_recavail,

    response.dns_flags_z AS Response_dns_flags_z,

    response.dns_flags_authenticated AS Response_dns_flags_authenticated,

    response.dns_flags_checkdisable AS Response_dns_flags_checkdisable,

    response.dns_flags_rcode AS Response_dns_flags_rcode,

    response.dns_unsolicited AS Response_dns_unsolicited,

    response.dns_retransmit_request_in AS Response_dns_retransmit_request_in,

    response.dns_retransmission AS Response_dns_retransmission,

    response.dns_retransmit_response_in AS Response_dns_retransmit_response_in,

    response.udp_srcport AS Response_udp_srcport,

    response.udp_dstport AS Response_udp_dstport,

    response.udp_port AS Response_udp_port,

    response.udp_length AS Response_udp_length,

    reinterpretAsUInt16(reverse(unhex(response.udp_checksum))) AS Response_udp_checksum,

    response.udp_checksum_status AS Response_udp_checksum_status,

    response.udp_stream AS Response_udp_stream,

    response.ip_version AS Response_ip_version,

    response.ip_hdr_len AS Response_ip_hdr_len,

    reinterpretAsUInt8(reverse(unhex(response.ip_dsfield))) AS Response_ip_dsfield,

    response.ip_len AS Response_ip_len,

    reinterpretAsUInt16(reverse(unhex(response.ip_id))) AS Response_ip_id,

    reinterpretAsUInt8(reverse(unhex(response.ip_flags))) AS Response_ip_flags,

    response.ip_ttl AS Response_ip_ttl,

    response.ip_proto AS Response_ip_proto,

    reinterpretAsUInt16(reverse(unhex(response.ip_checksum))) AS Response_ip_checksum,

    response.ip_checksum_status AS Response_ip_checksum_status,

    response.ip_src AS Response_ip_src,

    response.ip_addr AS Response_ip_addr,

    response.ip_src_host AS Response_ip_src_host,

    response.ip_host AS Response_ip_host,

    response.ip_dst AS Response_ip_dst,

    response.ip_dst_host AS Response_ip_dst_host,

    response.ip_dsfield_dscp AS Response_ip_dsfield_dscp,

    response.ip_dsfield_ecn AS Response_ip_dsfield_ecn,

    response.ip_flags_rb AS Response_ip_flags_rb,

    response.ip_flags_df AS Response_ip_flags_df,

    response.ip_flags_mf AS Response_ip_flags_mf,

    response.ip_frag_offset AS Response_ip_frag_offset,

    response.`Additional_records.dns_resp_name` AS `Response_Additional_records.dns_resp_name`,

    response.`Additional_records.dns_resp_type` AS `Response_Additional_records.dns_resp_type`,

    arrayMap(i -> reinterpretAsUInt16(reverse(unhex(i))),
 response.`Additional_records.dns_resp_class`) AS `Response_Additional_records.dns_resp_class`,

    response.`Additional_records.dns_resp_ttl` AS `Response_Additional_records.dns_resp_ttl`,

    response.`Additional_records.dns_resp_len` AS `Response_Additional_records.dns_resp_len`,

    arrayMap(i -> toIPv4(i),
 response.`Additional_records.dns_a`) AS `Response_Additional_records.dns_a`,

    arrayMap(i -> toIPv6(i),
 response.`Additional_records.dns_aaaa`) AS `Response_Additional_records.dns_aaaa`,

    response.`Additional_records.dns_resp_edns0_version` AS `Response_Additional_records.dns_resp_edns0_version`,

    response.`Additional_records.dns_resp_ext_rcode` AS `Response_Additional_records.dns_resp_ext_rcode`,

    response.`Additional_records.dns_resp_z` AS `Response_Additional_records.dns_resp_z`,

    response.`Additional_records.dns_rr_udp_payload_size` AS `Response_Additional_records.dns_rr_udp_payload_size`,

    response.`Additional_records.dns_rrsig_algorithm` AS `Response_Additional_records.dns_rrsig_algorithm`,

    response.`Additional_records.dns_rrsig_key_tag` AS `Response_Additional_records.dns_rrsig_key_tag`,

    response.`Additional_records.dns_rrsig_labels` AS `Response_Additional_records.dns_rrsig_labels`,

    response.`Additional_records.dns_rrsig_original_ttl` AS `Response_Additional_records.dns_rrsig_original_ttl`,

    response.`Additional_records.dns_rrsig_signature` AS `Response_Additional_records.dns_rrsig_signature`,

    response.`Additional_records.dns_rrsig_signature_expiration` AS `Response_Additional_records.dns_rrsig_signature_expiration`,

    response.`Additional_records.dns_rrsig_signature_inception` AS `Response_Additional_records.dns_rrsig_signature_inception`,

    response.`Additional_records.dns_rrsig_signers_name` AS `Response_Additional_records.dns_rrsig_signers_name`,

    response.`Additional_records.dns_rrsig_type_covered` AS `Response_Additional_records.dns_rrsig_type_covered`,

    response.`Additional_records.dns_srv_name` AS `Response_Additional_records.dns_srv_name`,

    response.`Additional_records.dns_nsec3_algo` AS `Response_Additional_records.dns_nsec3_algo`,

    response.`Additional_records.dns_srv_port` AS `Response_Additional_records.dns_srv_port`,

    response.`Additional_records.dns_srv_priority` AS `Response_Additional_records.dns_srv_priority`,

    response.`Additional_records.dns_srv_proto` AS `Response_Additional_records.dns_srv_proto`,

    response.`Additional_records.dns_srv_service` AS `Response_Additional_records.dns_srv_service`,

    response.`Additional_records.dns_srv_target` AS `Response_Additional_records.dns_srv_target`,

    response.`Additional_records.dns_srv_weight` AS `Response_Additional_records.dns_srv_weight`,

    response.`Additional_records.dns_nsec3_flags` AS `Response_Additional_records.dns_nsec3_flags`,

    response.`Additional_records.dns_nsec3_hash_length` AS `Response_Additional_records.dns_nsec3_hash_length`,

    response.`Additional_records.dns_nsec3_hash_value` AS `Response_Additional_records.dns_nsec3_hash_value`,

    response.`Additional_records.dns_nsec3_iterations` AS `Response_Additional_records.dns_nsec3_iterations`,

    response.`Additional_records.dns_nsec3_salt_length` AS `Response_Additional_records.dns_nsec3_salt_length`,

    response.`Additional_records.dns_nsec3_salt_value` AS `Response_Additional_records.dns_nsec3_salt_value`,

    response.`Additional_records.dns_rp_mailbox` AS `Response_Additional_records.dns_rp_mailbox`,

    response.`Additional_records.dns_rp_txt_rr` AS `Response_Additional_records.dns_rp_txt_rr`,

    response.`Additional_records.dns_tlsa_certificate_association_data` AS `Response_Additional_records.dns_tlsa_certificate_association_data`,

    response.`Additional_records.dns_tlsa_certificate_usage` AS `Response_Additional_records.dns_tlsa_certificate_usage`,

    response.`Additional_records.dns_tlsa_matching_type` AS `Response_Additional_records.dns_tlsa_matching_type`,

    response.`Additional_records.dns_dname` AS `Response_Additional_records.dns_dname`,

    response.`Additional_records.dns_tlsa_selector` AS `Response_Additional_records.dns_tlsa_selector`,

    response.`Authoritative_nameservers.dns_resp_name` AS `Response_Authoritative_nameservers.dns_resp_name`,

    response.`Authoritative_nameservers.dns_resp_type` AS `Response_Authoritative_nameservers.dns_resp_type`,

    arrayMap(i -> reinterpretAsUInt16(reverse(unhex(i))),
 response.`Authoritative_nameservers.dns_resp_class`) AS `Response_Authoritative_nameservers.dns_resp_class`,

    response.`Authoritative_nameservers.dns_resp_ttl` AS `Response_Authoritative_nameservers.dns_resp_ttl`,

    response.`Authoritative_nameservers.dns_resp_len` AS `Response_Authoritative_nameservers.dns_resp_len`,

    response.`Authoritative_nameservers.dns_ns` AS `Response_Authoritative_nameservers.dns_ns`,

    response.`Authoritative_nameservers.dns_soa_expire_limit` AS `Response_Authoritative_nameservers.dns_soa_expire_limit`,

    response.`Authoritative_nameservers.dns_soa_mininum_ttl` AS `Response_Authoritative_nameservers.dns_soa_mininum_ttl`,

    response.`Authoritative_nameservers.dns_soa_mname` AS `Response_Authoritative_nameservers.dns_soa_mname`,

    response.`Authoritative_nameservers.dns_soa_refresh_interval` AS `Response_Authoritative_nameservers.dns_soa_refresh_interval`,

    response.`Authoritative_nameservers.dns_soa_retry_interval` AS `Response_Authoritative_nameservers.dns_soa_retry_interval`,

    response.`Authoritative_nameservers.dns_soa_rname` AS `Response_Authoritative_nameservers.dns_soa_rname`,

    response.`Authoritative_nameservers.dns_soa_serial_number` AS `Response_Authoritative_nameservers.dns_soa_serial_number`,

    response.`Authoritative_nameservers.dns_nsec_next_domain_name` AS `Response_Authoritative_nameservers.dns_nsec_next_domain_name`,

    response.`Authoritative_nameservers.dns_rrsig_algorithm` AS `Response_Authoritative_nameservers.dns_rrsig_algorithm`,

    response.`Authoritative_nameservers.dns_rrsig_key_tag` AS `Response_Authoritative_nameservers.dns_rrsig_key_tag`,

    response.`Authoritative_nameservers.dns_rrsig_labels` AS `Response_Authoritative_nameservers.dns_rrsig_labels`,

    response.`Authoritative_nameservers.dns_rrsig_original_ttl` AS `Response_Authoritative_nameservers.dns_rrsig_original_ttl`,

    response.`Authoritative_nameservers.dns_rrsig_signature` AS `Response_Authoritative_nameservers.dns_rrsig_signature`,

    response.`Authoritative_nameservers.dns_rrsig_signature_expiration` AS `Response_Authoritative_nameservers.dns_rrsig_signature_expiration`,

    response.`Authoritative_nameservers.dns_rrsig_signature_inception` AS `Response_Authoritative_nameservers.dns_rrsig_signature_inception`,

    response.`Authoritative_nameservers.dns_rrsig_signers_name` AS `Response_Authoritative_nameservers.dns_rrsig_signers_name`,

    response.`Authoritative_nameservers.dns_rrsig_type_covered` AS `Response_Authoritative_nameservers.dns_rrsig_type_covered`,

    response.`Authoritative_nameservers.dns_ds_algorithm` AS `Response_Authoritative_nameservers.dns_ds_algorithm`,

    response.`Authoritative_nameservers.dns_ds_digest` AS `Response_Authoritative_nameservers.dns_ds_digest`,

    response.`Authoritative_nameservers.dns_ds_digest_type` AS `Response_Authoritative_nameservers.dns_ds_digest_type`,

    response.`Authoritative_nameservers.dns_ds_key_id` AS `Response_Authoritative_nameservers.dns_ds_key_id`,

    response.`Authoritative_nameservers.dns_nsec3_algo` AS `Response_Authoritative_nameservers.dns_nsec3_algo`,

    response.`Authoritative_nameservers.dns_nsec3_flags` AS `Response_Authoritative_nameservers.dns_nsec3_flags`,

    response.`Authoritative_nameservers.dns_nsec3_iterations` AS `Response_Authoritative_nameservers.dns_nsec3_iterations`,

    response.`Authoritative_nameservers.dns_nsec3_salt_length` AS `Response_Authoritative_nameservers.dns_nsec3_salt_length`,

    response.`Authoritative_nameservers.dns_nsec3_salt_value` AS `Response_Authoritative_nameservers.dns_nsec3_salt_value`,

    response.`Authoritative_nameservers.dns_nsec3_hash_length` AS `Response_Authoritative_nameservers.dns_nsec3_hash_length`,

    response.`Authoritative_nameservers.dns_nsec3_hash_value` AS `Response_Authoritative_nameservers.dns_nsec3_hash_value`,

    response.`Authoritative_nameservers.dns_srv_name` AS `Response_Authoritative_nameservers.dns_srv_name`,

    response.`Queries.dns_qry_name` AS `Response_Queries.dns_qry_name`,

    response.`Queries.dns_qry_name_len` AS `Response_Queries.dns_qry_name_len`,

    response.`Queries.dns_count_labels` AS `Response_Queries.dns_count_labels`,

    response.`Queries.dns_qry_type` AS `Response_Queries.dns_qry_type`,

    arrayMap(i -> reinterpretAsUInt16(reverse(unhex(i))),
 response.`Queries.dns_qry_class`) AS `Response_Queries.dns_qry_class`,

    response.`Answers.dns_resp_name` AS `Response_Answers.dns_resp_name`,

    response.`Answers.dns_resp_type` AS `Response_Answers.dns_resp_type`,

    arrayMap(i -> reinterpretAsUInt16(reverse(unhex(i))),
 response.`Answers.dns_resp_class`) AS `Response_Answers.dns_resp_class`,

    response.`Answers.dns_resp_ttl` AS `Response_Answers.dns_resp_ttl`,

    response.`Answers.dns_resp_len` AS `Response_Answers.dns_resp_len`,

    arrayMap(i -> toIPv4(i),
 response.`Answers.dns_a`) AS `Response_Answers.dns_a`,

    arrayMap(i -> toIPv6(i),
 response.`Answers.dns_aaaa`) AS `Response_Answers.dns_aaaa`,

    response.`Answers.dns_cname` AS `Response_Answers.dns_cname`,

    response.`Answers.dns_ptr_domain_name` AS `Response_Answers.dns_ptr_domain_name`,

    response.`Answers.dns_rrsig_algorithm` AS `Response_Answers.dns_rrsig_algorithm`,

    response.`Answers.dns_rrsig_key_tag` AS `Response_Answers.dns_rrsig_key_tag`,

    response.`Answers.dns_rrsig_labels` AS `Response_Answers.dns_rrsig_labels`,

    response.`Answers.dns_rrsig_original_ttl` AS `Response_Answers.dns_rrsig_original_ttl`,

    response.`Answers.dns_rrsig_signature` AS `Response_Answers.dns_rrsig_signature`,

    response.`Answers.dns_rrsig_signature_expiration` AS `Response_Answers.dns_rrsig_signature_expiration`,

    response.`Answers.dns_rrsig_signature_inception` AS `Response_Answers.dns_rrsig_signature_inception`,

    response.`Answers.dns_rrsig_signers_name` AS `Response_Answers.dns_rrsig_signers_name`,

    response.`Answers.dns_rrsig_type_covered` AS `Response_Answers.dns_rrsig_type_covered`,

    response.`Answers.dns_ds_algorithm` AS `Response_Answers.dns_ds_algorithm`,

    response.`Answers.dns_ds_digest` AS `Response_Answers.dns_ds_digest`,

    response.`Answers.dns_ds_digest_type` AS `Response_Answers.dns_ds_digest_type`,

    response.`Answers.dns_ds_key_id` AS `Response_Answers.dns_ds_key_id`,

    response.`Answers.dns_txt` AS `Response_Answers.dns_txt`,

    response.`Answers.dns_txt_length` AS `Response_Answers.dns_txt_length`,

    response.`Answers.dns_mx_mail_exchange` AS `Response_Answers.dns_mx_mail_exchange`,

    response.`Answers.dns_mx_preference` AS `Response_Answers.dns_mx_preference`,

    response.`Answers.dns_dnskey_algorithm` AS `Response_Answers.dns_dnskey_algorithm`,

    response.`Answers.dns_dnskey_flags` AS `Response_Answers.dns_dnskey_flags`,

    response.`Answers.dns_dnskey_key_id` AS `Response_Answers.dns_dnskey_key_id`,

    response.`Answers.dns_dnskey_protocol` AS `Response_Answers.dns_dnskey_protocol`,

    response.`Answers.dns_dnskey_public_key` AS `Response_Answers.dns_dnskey_public_key`,

    response.`Answers.dns_soa_expire_limit` AS `Response_Answers.dns_soa_expire_limit`,

    response.`Answers.dns_soa_mininum_ttl` AS `Response_Answers.dns_soa_mininum_ttl`,

    response.`Answers.dns_soa_mname` AS `Response_Answers.dns_soa_mname`,

    response.`Answers.dns_soa_refresh_interval` AS `Response_Answers.dns_soa_refresh_interval`,

    response.`Answers.dns_soa_retry_interval` AS `Response_Answers.dns_soa_retry_interval`,

    response.`Answers.dns_soa_rname` AS `Response_Answers.dns_soa_rname`,

    response.`Answers.dns_soa_serial_number` AS `Response_Answers.dns_soa_serial_number`,

    response.`Answers.dns_ns` AS `Response_Answers.dns_ns`,

    response.`Answers.dns_srv_name` AS `Response_Answers.dns_srv_name`,

    response.`Answers.dns_srv_port` AS `Response_Answers.dns_srv_port`,

    response.`Answers.dns_naptr_flags` AS `Response_Answers.dns_naptr_flags`,

    response.`Answers.dns_srv_priority` AS `Response_Answers.dns_srv_priority`,

    response.`Answers.dns_srv_proto` AS `Response_Answers.dns_srv_proto`,

    response.`Answers.dns_srv_service` AS `Response_Answers.dns_srv_service`,

    response.`Answers.dns_srv_target` AS `Response_Answers.dns_srv_target`,

    response.`Answers.dns_srv_weight` AS `Response_Answers.dns_srv_weight`,

    response.`Answers.dns_data` AS `Response_Answers.dns_data`,

    response.`Answers.dns_naptr_flags_length` AS `Response_Answers.dns_naptr_flags_length`,

    response.`Answers.dns_naptr_order` AS `Response_Answers.dns_naptr_order`,

    response.`Answers.dns_naptr_preference` AS `Response_Answers.dns_naptr_preference`,

    response.`Answers.dns_naptr_regex` AS `Response_Answers.dns_naptr_regex`,

    response.`Answers.dns_naptr_regex_length` AS `Response_Answers.dns_naptr_regex_length`,

    response.`Answers.dns_naptr_replacement` AS `Response_Answers.dns_naptr_replacement`,

    response.`Answers.dns_naptr_service` AS `Response_Answers.dns_naptr_service`,

    response.`Answers.dns_naptr_service_length` AS `Response_Answers.dns_naptr_service_length`,

    response.`Answers.dns_naptr_replacement_length` AS `Response_Answers.dns_naptr_replacement_length`,

    response.`Answers.dns_spf` AS `Response_Answers.dns_spf`,

    response.`Answers.dns_spf_length` AS `Response_Answers.dns_spf_length`,

    response.`Answers.dns_dname` AS `Response_Answers.dns_dname`,

    response.`Answers.dns_resp_edns0_version` AS `Response_Answers.dns_resp_edns0_version`,

    response.`Answers.dns_resp_ext_rcode` AS `Response_Answers.dns_resp_ext_rcode`,

    response.`Answers.dns_resp_z` AS `Response_Answers.dns_resp_z`,

    response.`Answers.dns_rr_udp_payload_size` AS `Response_Answers.dns_rr_udp_payload_size`
FROM prod_test.no_types AS queryx
LEFT JOIN prod_test.no_types AS response ON queryx.frame_number = response.dns_response_to
WHERE isNull(queryx.dns_response_to) AND (toUInt16OrNull(response.udp_srcport) = 53);
