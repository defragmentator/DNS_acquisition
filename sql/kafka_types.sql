-- prod_test.kafka_types definition

CREATE TABLE prod_test.kafka_types
(

    `Query_frame_interface_id` Nullable(UInt32),

    `Query_frame_interface_id_tree.frame_interface_name` Array(Nullable(String)),

    `Query_frame_encap_type` Nullable(Int16),

    `Query_frame_time` Nullable(String),

    `Query_frame_offset_shift` Nullable(Float64),

    `Query_frame_time_epoch` Float64,

    `Query_frame_time_epoch_2` Nullable(DateTime),

    `Query_frame_time_epoch_nanos` Nullable(UInt32),

    `Query_day_of_year` Nullable(UInt16),

    `Query_day_of_week` Nullable(UInt8),

    `Query_hour` Nullable(UInt8),

    `Query_frame_time_delta` Nullable(Float64),

    `Query_frame_time_delta_displayed` Nullable(Float64),

    `Query_frame_time_relative` Nullable(Float64),

    `Query_frame_number` Nullable(UInt32),

    `Query_frame_len` Nullable(UInt32),

    `Query_frame_cap_len` Nullable(UInt32),

    `Query_frame_marked` Nullable(UInt8),

    `Query_frame_ignored` Nullable(UInt8),

    `Query_frame_protocols` Nullable(String),

    `Query_dns_id` Nullable(UInt16),

    `Query_dns_flags` Nullable(UInt16),

    `Query_dns_count_queries` Nullable(UInt16),

    `Query_dns_count_answers` Nullable(UInt16),

    `Query_dns_count_auth_rr` Nullable(UInt16),

    `Query_dns_count_add_rr` Nullable(UInt16),

    `Query_dns_response_to` Nullable(UInt32),

    `Query_dns_time` Nullable(Float64),

    `Query_dns_flags_response` Nullable(UInt8),

    `Query_dns_flags_opcode` Nullable(UInt16),

    `Query_dns_flags_authoritative` Nullable(UInt8),

    `Query_dns_flags_truncated` Nullable(UInt8),

    `Query_dns_flags_recdesired` Nullable(UInt8),

    `Query_dns_flags_recavail` Nullable(UInt8),

    `Query_dns_flags_z` Nullable(UInt8),

    `Query_dns_flags_authenticated` Nullable(UInt8),

    `Query_dns_flags_checkdisable` Nullable(UInt8),

    `Query_dns_flags_rcode` Nullable(UInt16),

    `Query_dns_unsolicited` Nullable(UInt8),

    `Query_dns_retransmit_request_in` Nullable(String),

    `Query_dns_retransmission` Nullable(UInt8),

    `Query_dns_retransmit_response_in` Nullable(String),

    `Query_udp_srcport` Nullable(UInt16),

    `Query_udp_dstport` Nullable(UInt16),

    `Query_udp_port` Nullable(UInt16),

    `Query_udp_length` Nullable(UInt16),

    `Query_udp_checksum` Nullable(UInt16),

    `Query_udp_checksum_status` Nullable(UInt8),

    `Query_udp_stream` Nullable(UInt32),

    `Query_ip_version` Nullable(UInt8),

    `Query_ip_hdr_len` Nullable(UInt8),

    `Query_ip_dsfield` Nullable(UInt8),

    `Query_ip_len` Nullable(UInt16),

    `Query_ip_id` Nullable(UInt16),

    `Query_ip_flags` Nullable(UInt8),

    `Query_ip_ttl` Nullable(UInt8),

    `Query_ip_proto` Nullable(UInt8),

    `Query_ip_checksum` Nullable(UInt16),

    `Query_ip_checksum_status` Nullable(UInt8),

    `Query_ip_src` Nullable(IPv4),

    `Query_ip_src_class` Nullable(UInt8),

    `Query_ip_addr` Nullable(IPv4),

    `Query_ip_src_host` Nullable(IPv4),

    `Query_ip_host` Nullable(IPv4),

    `Query_ip_dst` Nullable(IPv4),

    `Query_ip_dst_host` Nullable(IPv4),

    `Query_ip_dsfield_dscp` Nullable(UInt8),

    `Query_ip_dsfield_ecn` Nullable(UInt8),

    `Query_ip_flags_rb` Nullable(UInt8),

    `Query_ip_flags_df` Nullable(UInt8),

    `Query_ip_flags_mf` Nullable(UInt8),

    `Query_ip_frag_offset` Nullable(UInt16),

    `Query_Additional_records.dns_resp_name` Array(Nullable(String)),

    `Query_Additional_records.dns_resp_type` Array(Nullable(UInt16)),

    `Query_Additional_records.dns_resp_class` Array(Nullable(UInt16)),

    `Query_Additional_records.dns_resp_ttl` Array(Nullable(UInt32)),

    `Query_Additional_records.dns_resp_len` Array(Nullable(UInt32)),

    `Query_Additional_records.dns_a` Array(Nullable(IPv4)),

    `Query_Additional_records.dns_aaaa` Array(Nullable(IPv6)),

    `Query_Additional_records.dns_resp_edns0_version` Array(Nullable(UInt8)),

    `Query_Additional_records.dns_resp_ext_rcode` Array(Nullable(UInt8)),

    `Query_Additional_records.dns_resp_z` Array(Nullable(UInt16)),

    `Query_Additional_records.dns_rr_udp_payload_size` Array(Nullable(UInt16)),

    `Query_Additional_records.dns_rrsig_algorithm` Array(Nullable(UInt8)),

    `Query_Additional_records.dns_rrsig_key_tag` Array(Nullable(UInt16)),

    `Query_Additional_records.dns_rrsig_labels` Array(Nullable(UInt8)),

    `Query_Additional_records.dns_rrsig_original_ttl` Array(Nullable(UInt32)),

    `Query_Additional_records.dns_rrsig_signature` Array(Nullable(String)),

    `Query_Additional_records.dns_rrsig_signature_expiration` Array(Nullable(DateTime)),

    `Query_Additional_records.dns_rrsig_signature_inception` Array(Nullable(DateTime)),

    `Query_Additional_records.dns_rrsig_signers_name` Array(Nullable(String)),

    `Query_Additional_records.dns_rrsig_type_covered` Array(Nullable(UInt16)),

    `Query_Additional_records.dns_srv_name` Array(Nullable(String)),

    `Query_Additional_records.dns_nsec3_algo` Array(Nullable(UInt8)),

    `Query_Additional_records.dns_srv_port` Array(Nullable(UInt16)),

    `Query_Additional_records.dns_srv_priority` Array(Nullable(UInt16)),

    `Query_Additional_records.dns_srv_proto` Array(Nullable(String)),

    `Query_Additional_records.dns_srv_service` Array(Nullable(String)),

    `Query_Additional_records.dns_srv_target` Array(Nullable(String)),

    `Query_Additional_records.dns_srv_weight` Array(Nullable(UInt16)),

    `Query_Additional_records.dns_nsec3_flags` Array(Nullable(UInt8)),

    `Query_Additional_records.dns_nsec3_hash_length` Array(Nullable(UInt8)),

    `Query_Additional_records.dns_nsec3_hash_value` Array(Nullable(String)),

    `Query_Additional_records.dns_nsec3_iterations` Array(Nullable(UInt16)),

    `Query_Additional_records.dns_nsec3_salt_length` Array(Nullable(UInt8)),

    `Query_Additional_records.dns_nsec3_salt_value` Array(Nullable(String)),

    `Query_Additional_records.dns_rp_mailbox` Array(Nullable(String)),

    `Query_Additional_records.dns_rp_txt_rr` Array(Nullable(String)),

    `Query_Additional_records.dns_tlsa_certificate_association_data` Array(Nullable(String)),

    `Query_Additional_records.dns_tlsa_certificate_usage` Array(Nullable(UInt8)),

    `Query_Additional_records.dns_tlsa_matching_type` Array(Nullable(UInt8)),

    `Query_Additional_records.dns_dname` Array(Nullable(String)),

    `Query_Additional_records.dns_tlsa_selector` Array(Nullable(UInt8)),

    `Query_Queries.dns_qry_name` Array(Nullable(String)),

    `Query_Queries.dns_qry_name_len` Array(Nullable(UInt16)),

    `Query_Queries.dns_count_labels` Array(Nullable(UInt16)),

    `Query_Queries.dns_qry_type` Array(Nullable(UInt16)),

    `Query_Queries.dns_qry_class` Array(Nullable(UInt16)),

    `Response_frame_interface_id` Nullable(UInt32),

    `Response_frame_interface_id_tree.frame_interface_name` Array(Nullable(String)),

    `Response_frame_encap_type` Nullable(Int16),

    `Response_frame_time` Nullable(DateTime),

    `Response_frame_offset_shift` Nullable(Float64),

    `Response_frame_time_epoch` Float64,

    `Response_frame_time_epoch_2` Nullable(DateTime),

    `Response_frame_time_epoch_nanos` Nullable(UInt32),

    `Response_day_of_year` Nullable(UInt16),

    `Response_day_of_week` Nullable(UInt8),

    `Response_hour` Nullable(UInt8),

    `Response_frame_time_delta` Nullable(Float64),

    `Response_frame_time_delta_displayed` Nullable(Float64),

    `Response_frame_time_relative` Nullable(Float64),

    `Response_frame_number` Nullable(UInt32),

    `Response_frame_len` Nullable(UInt32),

    `Response_frame_cap_len` Nullable(UInt32),

    `Response_frame_marked` Nullable(UInt8),

    `Response_frame_ignored` Nullable(UInt8),

    `Response_frame_protocols` Nullable(String),

    `Response_dns_id` Nullable(UInt16),

    `Response_dns_flags` Nullable(UInt16),

    `Response_dns_count_queries` Nullable(UInt16),

    `Response_dns_count_answers` Nullable(UInt16),

    `Response_dns_count_auth_rr` Nullable(UInt16),

    `Response_dns_count_add_rr` Nullable(UInt16),

    `Response_dns_response_to` Nullable(UInt32),

    `Response_dns_time` Nullable(Float64),

    `Response_dns_flags_response` Nullable(UInt8),

    `Response_dns_flags_opcode` Nullable(UInt16),

    `Response_dns_flags_authoritative` Nullable(UInt8),

    `Response_dns_flags_truncated` Nullable(UInt8),

    `Response_dns_flags_recdesired` Nullable(UInt8),

    `Response_dns_flags_recavail` Nullable(UInt8),

    `Response_dns_flags_z` Nullable(UInt8),

    `Response_dns_flags_authenticated` Nullable(UInt8),

    `Response_dns_flags_checkdisable` Nullable(UInt8),

    `Response_dns_flags_rcode` Nullable(UInt16),

    `Response_dns_unsolicited` Nullable(UInt8),

    `Response_dns_retransmit_request_in` Nullable(String),

    `Response_dns_retransmission` Nullable(UInt8),

    `Response_dns_retransmit_response_in` Nullable(String),

    `Response_udp_srcport` Nullable(UInt16),

    `Response_udp_dstport` Nullable(UInt16),

    `Response_udp_port` Nullable(UInt16),

    `Response_udp_length` Nullable(UInt16),

    `Response_udp_checksum` Nullable(UInt16),

    `Response_udp_checksum_status` Nullable(UInt8),

    `Response_udp_stream` Nullable(UInt32),

    `Response_ip_version` Nullable(UInt8),

    `Response_ip_hdr_len` Nullable(UInt8),

    `Response_ip_dsfield` Nullable(UInt8),

    `Response_ip_len` Nullable(UInt16),

    `Response_ip_id` Nullable(UInt16),

    `Response_ip_flags` Nullable(UInt8),

    `Response_ip_ttl` Nullable(UInt8),

    `Response_ip_proto` Nullable(UInt8),

    `Response_ip_checksum` Nullable(UInt16),

    `Response_ip_checksum_status` Nullable(UInt8),

    `Response_ip_src` Nullable(IPv4),

    `Response_ip_addr` Nullable(IPv4),

    `Response_ip_src_host` Nullable(IPv4),

    `Response_ip_host` Nullable(IPv4),

    `Response_ip_dst` Nullable(IPv4),

    `Response_ip_dst_host` Nullable(IPv4),

    `Response_ip_dsfield_dscp` Nullable(UInt8),

    `Response_ip_dsfield_ecn` Nullable(UInt8),

    `Response_ip_flags_rb` Nullable(UInt8),

    `Response_ip_flags_df` Nullable(UInt8),

    `Response_ip_flags_mf` Nullable(UInt8),

    `Response_ip_frag_offset` Nullable(UInt16),

    `Response_Additional_records.dns_resp_name` Array(Nullable(String)),

    `Response_Additional_records.dns_resp_type` Array(Nullable(UInt16)),

    `Response_Additional_records.dns_resp_class` Array(Nullable(UInt16)),

    `Response_Additional_records.dns_resp_ttl` Array(Nullable(UInt32)),

    `Response_Additional_records.dns_resp_len` Array(Nullable(UInt32)),

    `Response_Additional_records.dns_a` Array(Nullable(IPv4)),

    `Response_Additional_records.dns_aaaa` Array(Nullable(IPv6)),

    `Response_Additional_records.dns_resp_edns0_version` Array(Nullable(UInt8)),

    `Response_Additional_records.dns_resp_ext_rcode` Array(Nullable(UInt8)),

    `Response_Additional_records.dns_resp_z` Array(Nullable(UInt16)),

    `Response_Additional_records.dns_rr_udp_payload_size` Array(Nullable(UInt16)),

    `Response_Additional_records.dns_rrsig_algorithm` Array(Nullable(UInt8)),

    `Response_Additional_records.dns_rrsig_key_tag` Array(Nullable(UInt16)),

    `Response_Additional_records.dns_rrsig_labels` Array(Nullable(UInt8)),

    `Response_Additional_records.dns_rrsig_original_ttl` Array(Nullable(UInt32)),

    `Response_Additional_records.dns_rrsig_signature` Array(Nullable(String)),

    `Response_Additional_records.dns_rrsig_signature_expiration` Array(Nullable(DateTime)),

    `Response_Additional_records.dns_rrsig_signature_inception` Array(Nullable(DateTime)),

    `Response_Additional_records.dns_rrsig_signers_name` Array(Nullable(String)),

    `Response_Additional_records.dns_rrsig_type_covered` Array(Nullable(UInt16)),

    `Response_Additional_records.dns_srv_name` Array(Nullable(String)),

    `Response_Additional_records.dns_nsec3_algo` Array(Nullable(UInt8)),

    `Response_Additional_records.dns_srv_port` Array(Nullable(UInt16)),

    `Response_Additional_records.dns_srv_priority` Array(Nullable(UInt16)),

    `Response_Additional_records.dns_srv_proto` Array(Nullable(String)),

    `Response_Additional_records.dns_srv_service` Array(Nullable(String)),

    `Response_Additional_records.dns_srv_target` Array(Nullable(String)),

    `Response_Additional_records.dns_srv_weight` Array(Nullable(UInt16)),

    `Response_Additional_records.dns_nsec3_flags` Array(Nullable(UInt8)),

    `Response_Additional_records.dns_nsec3_hash_length` Array(Nullable(UInt8)),

    `Response_Additional_records.dns_nsec3_hash_value` Array(Nullable(String)),

    `Response_Additional_records.dns_nsec3_iterations` Array(Nullable(UInt16)),

    `Response_Additional_records.dns_nsec3_salt_length` Array(Nullable(UInt8)),

    `Response_Additional_records.dns_nsec3_salt_value` Array(Nullable(String)),

    `Response_Additional_records.dns_rp_mailbox` Array(Nullable(String)),

    `Response_Additional_records.dns_rp_txt_rr` Array(Nullable(String)),

    `Response_Additional_records.dns_tlsa_certificate_association_data` Array(Nullable(String)),

    `Response_Additional_records.dns_tlsa_certificate_usage` Array(Nullable(UInt8)),

    `Response_Additional_records.dns_tlsa_matching_type` Array(Nullable(UInt8)),

    `Response_Additional_records.dns_dname` Array(Nullable(String)),

    `Response_Additional_records.dns_tlsa_selector` Array(Nullable(UInt8)),

    `Response_Authoritative_nameservers.dns_resp_name` Array(Nullable(String)),

    `Response_Authoritative_nameservers.dns_resp_type` Array(Nullable(UInt16)),

    `Response_Authoritative_nameservers.dns_resp_class` Array(Nullable(UInt16)),

    `Response_Authoritative_nameservers.dns_resp_ttl` Array(Nullable(UInt32)),

    `Response_Authoritative_nameservers.dns_resp_len` Array(Nullable(UInt32)),

    `Response_Authoritative_nameservers.dns_ns` Array(Nullable(String)),

    `Response_Authoritative_nameservers.dns_soa_expire_limit` Array(Nullable(UInt32)),

    `Response_Authoritative_nameservers.dns_soa_mininum_ttl` Array(Nullable(UInt32)),

    `Response_Authoritative_nameservers.dns_soa_mname` Array(Nullable(String)),

    `Response_Authoritative_nameservers.dns_soa_refresh_interval` Array(Nullable(UInt32)),

    `Response_Authoritative_nameservers.dns_soa_retry_interval` Array(Nullable(UInt32)),

    `Response_Authoritative_nameservers.dns_soa_rname` Array(Nullable(String)),

    `Response_Authoritative_nameservers.dns_soa_serial_number` Array(Nullable(UInt32)),

    `Response_Authoritative_nameservers.dns_nsec_next_domain_name` Array(Nullable(String)),

    `Response_Authoritative_nameservers.dns_rrsig_algorithm` Array(Nullable(UInt8)),

    `Response_Authoritative_nameservers.dns_rrsig_key_tag` Array(Nullable(UInt16)),

    `Response_Authoritative_nameservers.dns_rrsig_labels` Array(Nullable(UInt8)),

    `Response_Authoritative_nameservers.dns_rrsig_original_ttl` Array(Nullable(UInt32)),

    `Response_Authoritative_nameservers.dns_rrsig_signature` Array(Nullable(String)),

    `Response_Authoritative_nameservers.dns_rrsig_signature_expiration` Array(Nullable(DateTime)),

    `Response_Authoritative_nameservers.dns_rrsig_signature_inception` Array(Nullable(DateTime)),

    `Response_Authoritative_nameservers.dns_rrsig_signers_name` Array(Nullable(String)),

    `Response_Authoritative_nameservers.dns_rrsig_type_covered` Array(Nullable(UInt16)),

    `Response_Authoritative_nameservers.dns_ds_algorithm` Array(Nullable(UInt8)),

    `Response_Authoritative_nameservers.dns_ds_digest` Array(Nullable(String)),

    `Response_Authoritative_nameservers.dns_ds_digest_type` Array(Nullable(UInt8)),

    `Response_Authoritative_nameservers.dns_ds_key_id` Array(Nullable(UInt16)),

    `Response_Authoritative_nameservers.dns_nsec3_algo` Array(Nullable(UInt8)),

    `Response_Authoritative_nameservers.dns_nsec3_flags` Array(Nullable(UInt8)),

    `Response_Authoritative_nameservers.dns_nsec3_iterations` Array(Nullable(UInt16)),

    `Response_Authoritative_nameservers.dns_nsec3_salt_length` Array(Nullable(UInt8)),

    `Response_Authoritative_nameservers.dns_nsec3_salt_value` Array(Nullable(String)),

    `Response_Authoritative_nameservers.dns_nsec3_hash_length` Array(Nullable(UInt8)),

    `Response_Authoritative_nameservers.dns_nsec3_hash_value` Array(Nullable(String)),

    `Response_Authoritative_nameservers.dns_srv_name` Array(Nullable(String)),

    `Response_Queries.dns_qry_name` Array(Nullable(String)),

    `Response_Queries.dns_qry_name_len` Array(Nullable(UInt16)),

    `Response_Queries.dns_count_labels` Array(Nullable(UInt16)),

    `Response_Queries.dns_qry_type` Array(Nullable(UInt16)),

    `Response_Queries.dns_qry_class` Array(Nullable(UInt16)),

    `Response_Answers.dns_resp_name` Array(Nullable(String)),

    `Response_Answers.dns_resp_type` Array(Nullable(UInt16)),

    `Response_Answers.dns_resp_class` Array(Nullable(UInt16)),

    `Response_Answers.dns_resp_ttl` Array(Nullable(UInt32)),

    `Response_Answers.dns_resp_len` Array(Nullable(UInt32)),

    `Response_Answers.dns_a` Array(Nullable(IPv4)),

    `Response_Answers.dns_aaaa` Array(Nullable(IPv6)),

    `Response_Answers.dns_cname` Array(Nullable(String)),

    `Response_Answers.dns_ptr_domain_name` Array(Nullable(String)),

    `Response_Answers.dns_rrsig_algorithm` Array(Nullable(UInt8)),

    `Response_Answers.dns_rrsig_key_tag` Array(Nullable(UInt16)),

    `Response_Answers.dns_rrsig_labels` Array(Nullable(UInt8)),

    `Response_Answers.dns_rrsig_original_ttl` Array(Nullable(UInt32)),

    `Response_Answers.dns_rrsig_signature` Array(Nullable(String)),

    `Response_Answers.dns_rrsig_signature_expiration` Array(Nullable(DateTime)),

    `Response_Answers.dns_rrsig_signature_inception` Array(Nullable(DateTime)),

    `Response_Answers.dns_rrsig_signers_name` Array(Nullable(String)),

    `Response_Answers.dns_rrsig_type_covered` Array(Nullable(UInt16)),

    `Response_Answers.dns_ds_algorithm` Array(Nullable(UInt8)),

    `Response_Answers.dns_ds_digest` Array(Nullable(String)),

    `Response_Answers.dns_ds_digest_type` Array(Nullable(UInt8)),

    `Response_Answers.dns_ds_key_id` Array(Nullable(UInt16)),

    `Response_Answers.dns_txt` Array(Nullable(String)),

    `Response_Answers.dns_txt_length` Array(Nullable(UInt8)),

    `Response_Answers.dns_mx_mail_exchange` Array(Nullable(String)),

    `Response_Answers.dns_mx_preference` Array(Nullable(UInt16)),

    `Response_Answers.dns_dnskey_algorithm` Array(Nullable(UInt8)),

    `Response_Answers.dns_dnskey_flags` Array(Nullable(UInt16)),

    `Response_Answers.dns_dnskey_key_id` Array(Nullable(UInt16)),

    `Response_Answers.dns_dnskey_protocol` Array(Nullable(UInt8)),

    `Response_Answers.dns_dnskey_public_key` Array(Nullable(String)),

    `Response_Answers.dns_soa_expire_limit` Array(Nullable(UInt32)),

    `Response_Answers.dns_soa_mininum_ttl` Array(Nullable(UInt32)),

    `Response_Answers.dns_soa_mname` Array(Nullable(String)),

    `Response_Answers.dns_soa_refresh_interval` Array(Nullable(UInt32)),

    `Response_Answers.dns_soa_retry_interval` Array(Nullable(UInt32)),

    `Response_Answers.dns_soa_rname` Array(Nullable(String)),

    `Response_Answers.dns_soa_serial_number` Array(Nullable(UInt32)),

    `Response_Answers.dns_ns` Array(Nullable(String)),

    `Response_Answers.dns_srv_name` Array(Nullable(String)),

    `Response_Answers.dns_srv_port` Array(Nullable(UInt16)),

    `Response_Answers.dns_naptr_flags` Array(Nullable(String)),

    `Response_Answers.dns_srv_priority` Array(Nullable(UInt16)),

    `Response_Answers.dns_srv_proto` Array(Nullable(String)),

    `Response_Answers.dns_srv_service` Array(Nullable(String)),

    `Response_Answers.dns_srv_target` Array(Nullable(String)),

    `Response_Answers.dns_srv_weight` Array(Nullable(UInt16)),

    `Response_Answers.dns_data` Array(Nullable(String)),

    `Response_Answers.dns_naptr_flags_length` Array(Nullable(UInt8)),

    `Response_Answers.dns_naptr_order` Array(Nullable(UInt16)),

    `Response_Answers.dns_naptr_preference` Array(Nullable(UInt16)),

    `Response_Answers.dns_naptr_regex` Array(Nullable(String)),

    `Response_Answers.dns_naptr_regex_length` Array(Nullable(UInt8)),

    `Response_Answers.dns_naptr_replacement` Array(Nullable(String)),

    `Response_Answers.dns_naptr_service` Array(Nullable(String)),

    `Response_Answers.dns_naptr_service_length` Array(Nullable(UInt8)),

    `Response_Answers.dns_naptr_replacement_length` Array(Nullable(UInt8)),

    `Response_Answers.dns_spf` Array(Nullable(String)),

    `Response_Answers.dns_spf_length` Array(Nullable(UInt8)),

    `Response_Answers.dns_dname` Array(Nullable(String)),

    `Response_Answers.dns_resp_edns0_version` Array(Nullable(UInt8)),

    `Response_Answers.dns_resp_ext_rcode` Array(Nullable(UInt8)),

    `Response_Answers.dns_resp_z` Array(Nullable(UInt16)),

    `Response_Answers.dns_rr_udp_payload_size` Array(Nullable(UInt16))
)
ENGINE = Kafka('localhost:9092',
 'prod_test_in',
 'kafka_no_types',
 'JSONEachRow');
