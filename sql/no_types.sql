-- prod_test.no_types definition

CREATE TABLE prod_test.no_types
(

    `frame_interface_id` Nullable(String),

    `frame_interface_id_tree.frame_interface_name` Array(Nullable(String)),

    `frame_encap_type` Nullable(String),

    `frame_time` Nullable(String),

    `frame_offset_shift` Nullable(String),

    `frame_time_epoch` String,

    `frame_time_delta` Nullable(String),

    `frame_time_delta_displayed` Nullable(String),

    `frame_time_relative` Nullable(String),

    `frame_number` Nullable(String),

    `frame_len` Nullable(String),

    `frame_cap_len` Nullable(String),

    `frame_marked` Nullable(String),

    `frame_ignored` Nullable(String),

    `frame_protocols` Nullable(String),

    `dns_id` Nullable(String),

    `dns_flags` Nullable(String),

    `dns_count_queries` Nullable(String),

    `dns_count_answers` Nullable(String),

    `dns_count_auth_rr` Nullable(String),

    `dns_count_add_rr` Nullable(String),

    `dns_response_to` Nullable(String),

    `dns_time` Nullable(String),

    `dns_flags_response` Nullable(String),

    `dns_flags_opcode` Nullable(String),

    `dns_flags_authoritative` Nullable(String),

    `dns_flags_truncated` Nullable(String),

    `dns_flags_recdesired` Nullable(String),

    `dns_flags_recavail` Nullable(String),

    `dns_flags_z` Nullable(String),

    `dns_flags_authenticated` Nullable(String),

    `dns_flags_checkdisable` Nullable(String),

    `dns_flags_rcode` Nullable(String),

    `dns_unsolicited` Nullable(String),

    `dns_retransmit_request_in` Nullable(String),

    `dns_retransmission` Nullable(String),

    `dns_retransmit_response_in` Nullable(String),

    `udp_srcport` Nullable(String),

    `udp_dstport` Nullable(String),

    `udp_port` Nullable(String),

    `udp_length` Nullable(String),

    `udp_checksum` Nullable(String),

    `udp_checksum_status` Nullable(String),

    `udp_stream` Nullable(String),

    `ip_version` Nullable(String),

    `ip_hdr_len` Nullable(String),

    `ip_dsfield` Nullable(String),

    `ip_len` Nullable(String),

    `ip_id` Nullable(String),

    `ip_flags` Nullable(String),

    `ip_ttl` Nullable(String),

    `ip_proto` Nullable(String),

    `ip_checksum` Nullable(String),

    `ip_checksum_status` Nullable(String),

    `ip_src` Nullable(IPv4),

    `ip_addr` Nullable(IPv4),

    `ip_src_host` Nullable(IPv4),

    `ip_host` Nullable(IPv4),

    `ip_dst` Nullable(IPv4),

    `ip_dst_host` Nullable(IPv4),

    `ip_dsfield_dscp` Nullable(String),

    `ip_dsfield_ecn` Nullable(String),

    `ip_flags_rb` Nullable(String),

    `ip_flags_df` Nullable(String),

    `ip_flags_mf` Nullable(String),

    `ip_frag_offset` Nullable(String),

    `Additional_records.dns_resp_name` Array(Nullable(String)),

    `Additional_records.dns_resp_type` Array(Nullable(String)),

    `Additional_records.dns_resp_class` Array(Nullable(String)),

    `Additional_records.dns_resp_ttl` Array(Nullable(String)),

    `Additional_records.dns_resp_len` Array(Nullable(String)),

    `Additional_records.dns_a` Array(Nullable(String)),

    `Additional_records.dns_aaaa` Array(Nullable(String)),

    `Additional_records.dns_resp_edns0_version` Array(Nullable(String)),

    `Additional_records.dns_resp_ext_rcode` Array(Nullable(String)),

    `Additional_records.dns_resp_z` Array(Nullable(String)),

    `Additional_records.dns_rr_udp_payload_size` Array(Nullable(String)),

    `Additional_records.dns_rrsig_algorithm` Array(Nullable(String)),

    `Additional_records.dns_rrsig_key_tag` Array(Nullable(String)),

    `Additional_records.dns_rrsig_labels` Array(Nullable(String)),

    `Additional_records.dns_rrsig_original_ttl` Array(Nullable(String)),

    `Additional_records.dns_rrsig_signature` Array(Nullable(String)),

    `Additional_records.dns_rrsig_signature_expiration` Array(Nullable(String)),

    `Additional_records.dns_rrsig_signature_inception` Array(Nullable(String)),

    `Additional_records.dns_rrsig_signers_name` Array(Nullable(String)),

    `Additional_records.dns_rrsig_type_covered` Array(Nullable(String)),

    `Additional_records.dns_srv_name` Array(Nullable(String)),

    `Additional_records.dns_nsec3_algo` Array(Nullable(String)),

    `Additional_records.dns_srv_port` Array(Nullable(String)),

    `Additional_records.dns_srv_priority` Array(Nullable(String)),

    `Additional_records.dns_srv_proto` Array(Nullable(String)),

    `Additional_records.dns_srv_service` Array(Nullable(String)),

    `Additional_records.dns_srv_target` Array(Nullable(String)),

    `Additional_records.dns_srv_weight` Array(Nullable(String)),

    `Additional_records.dns_nsec3_flags` Array(Nullable(String)),

    `Additional_records.dns_nsec3_hash_length` Array(Nullable(String)),

    `Additional_records.dns_nsec3_hash_value` Array(Nullable(String)),

    `Additional_records.dns_nsec3_iterations` Array(Nullable(String)),

    `Additional_records.dns_nsec3_salt_length` Array(Nullable(String)),

    `Additional_records.dns_nsec3_salt_value` Array(Nullable(String)),

    `Additional_records.dns_rp_mailbox` Array(Nullable(String)),

    `Additional_records.dns_rp_txt_rr` Array(Nullable(String)),

    `Additional_records.dns_tlsa_certificate_association_data` Array(Nullable(String)),

    `Additional_records.dns_tlsa_certificate_usage` Array(Nullable(String)),

    `Additional_records.dns_tlsa_matching_type` Array(Nullable(String)),

    `Additional_records.dns_dname` Array(Nullable(String)),

    `Additional_records.dns_tlsa_selector` Array(Nullable(String)),

    `Authoritative_nameservers.dns_resp_name` Array(Nullable(String)),

    `Authoritative_nameservers.dns_resp_type` Array(Nullable(String)),

    `Authoritative_nameservers.dns_resp_class` Array(Nullable(String)),

    `Authoritative_nameservers.dns_resp_ttl` Array(Nullable(String)),

    `Authoritative_nameservers.dns_resp_len` Array(Nullable(String)),

    `Authoritative_nameservers.dns_ns` Array(Nullable(String)),

    `Authoritative_nameservers.dns_soa_expire_limit` Array(Nullable(String)),

    `Authoritative_nameservers.dns_soa_mininum_ttl` Array(Nullable(String)),

    `Authoritative_nameservers.dns_soa_mname` Array(Nullable(String)),

    `Authoritative_nameservers.dns_soa_refresh_interval` Array(Nullable(String)),

    `Authoritative_nameservers.dns_soa_retry_interval` Array(Nullable(String)),

    `Authoritative_nameservers.dns_soa_rname` Array(Nullable(String)),

    `Authoritative_nameservers.dns_soa_serial_number` Array(Nullable(String)),

    `Authoritative_nameservers.dns_nsec_next_domain_name` Array(Nullable(String)),

    `Authoritative_nameservers.dns_rrsig_algorithm` Array(Nullable(String)),

    `Authoritative_nameservers.dns_rrsig_key_tag` Array(Nullable(String)),

    `Authoritative_nameservers.dns_rrsig_labels` Array(Nullable(String)),

    `Authoritative_nameservers.dns_rrsig_original_ttl` Array(Nullable(String)),

    `Authoritative_nameservers.dns_rrsig_signature` Array(Nullable(String)),

    `Authoritative_nameservers.dns_rrsig_signature_expiration` Array(Nullable(String)),

    `Authoritative_nameservers.dns_rrsig_signature_inception` Array(Nullable(String)),

    `Authoritative_nameservers.dns_rrsig_signers_name` Array(Nullable(String)),

    `Authoritative_nameservers.dns_rrsig_type_covered` Array(Nullable(String)),

    `Authoritative_nameservers.dns_ds_algorithm` Array(Nullable(String)),

    `Authoritative_nameservers.dns_ds_digest` Array(Nullable(String)),

    `Authoritative_nameservers.dns_ds_digest_type` Array(Nullable(String)),

    `Authoritative_nameservers.dns_ds_key_id` Array(Nullable(String)),

    `Authoritative_nameservers.dns_nsec3_algo` Array(Nullable(String)),

    `Authoritative_nameservers.dns_nsec3_flags` Array(Nullable(String)),

    `Authoritative_nameservers.dns_nsec3_iterations` Array(Nullable(String)),

    `Authoritative_nameservers.dns_nsec3_salt_length` Array(Nullable(String)),

    `Authoritative_nameservers.dns_nsec3_salt_value` Array(Nullable(String)),

    `Authoritative_nameservers.dns_nsec3_hash_length` Array(Nullable(String)),

    `Authoritative_nameservers.dns_nsec3_hash_value` Array(Nullable(String)),

    `Authoritative_nameservers.dns_srv_name` Array(Nullable(String)),

    `Queries.dns_qry_name` Array(Nullable(String)),

    `Queries.dns_qry_name_len` Array(Nullable(String)),

    `Queries.dns_count_labels` Array(Nullable(String)),

    `Queries.dns_qry_type` Array(Nullable(String)),

    `Queries.dns_qry_class` Array(Nullable(String)),

    `Answers.dns_resp_name` Array(Nullable(String)),

    `Answers.dns_resp_type` Array(Nullable(String)),

    `Answers.dns_resp_class` Array(Nullable(String)),

    `Answers.dns_resp_ttl` Array(Nullable(String)),

    `Answers.dns_resp_len` Array(Nullable(String)),

    `Answers.dns_a` Array(Nullable(String)),

    `Answers.dns_aaaa` Array(Nullable(String)),

    `Answers.dns_cname` Array(Nullable(String)),

    `Answers.dns_ptr_domain_name` Array(Nullable(String)),

    `Answers.dns_rrsig_algorithm` Array(Nullable(String)),

    `Answers.dns_rrsig_key_tag` Array(Nullable(String)),

    `Answers.dns_rrsig_labels` Array(Nullable(String)),

    `Answers.dns_rrsig_original_ttl` Array(Nullable(String)),

    `Answers.dns_rrsig_signature` Array(Nullable(String)),

    `Answers.dns_rrsig_signature_expiration` Array(Nullable(String)),

    `Answers.dns_rrsig_signature_inception` Array(Nullable(String)),

    `Answers.dns_rrsig_signers_name` Array(Nullable(String)),

    `Answers.dns_rrsig_type_covered` Array(Nullable(String)),

    `Answers.dns_ds_algorithm` Array(Nullable(String)),

    `Answers.dns_ds_digest` Array(Nullable(String)),

    `Answers.dns_ds_digest_type` Array(Nullable(String)),

    `Answers.dns_ds_key_id` Array(Nullable(String)),

    `Answers.dns_txt` Array(Nullable(String)),

    `Answers.dns_txt_length` Array(Nullable(String)),

    `Answers.dns_mx_mail_exchange` Array(Nullable(String)),

    `Answers.dns_mx_preference` Array(Nullable(String)),

    `Answers.dns_dnskey_algorithm` Array(Nullable(String)),

    `Answers.dns_dnskey_flags` Array(Nullable(String)),

    `Answers.dns_dnskey_key_id` Array(Nullable(String)),

    `Answers.dns_dnskey_protocol` Array(Nullable(String)),

    `Answers.dns_dnskey_public_key` Array(Nullable(String)),

    `Answers.dns_soa_expire_limit` Array(Nullable(String)),

    `Answers.dns_soa_mininum_ttl` Array(Nullable(String)),

    `Answers.dns_soa_mname` Array(Nullable(String)),

    `Answers.dns_soa_refresh_interval` Array(Nullable(String)),

    `Answers.dns_soa_retry_interval` Array(Nullable(String)),

    `Answers.dns_soa_rname` Array(Nullable(String)),

    `Answers.dns_soa_serial_number` Array(Nullable(String)),

    `Answers.dns_ns` Array(Nullable(String)),

    `Answers.dns_srv_name` Array(Nullable(String)),

    `Answers.dns_srv_port` Array(Nullable(String)),

    `Answers.dns_naptr_flags` Array(Nullable(String)),

    `Answers.dns_srv_priority` Array(Nullable(String)),

    `Answers.dns_srv_proto` Array(Nullable(String)),

    `Answers.dns_srv_service` Array(Nullable(String)),

    `Answers.dns_srv_target` Array(Nullable(String)),

    `Answers.dns_srv_weight` Array(Nullable(String)),

    `Answers.dns_data` Array(Nullable(String)),

    `Answers.dns_naptr_flags_length` Array(Nullable(String)),

    `Answers.dns_naptr_order` Array(Nullable(String)),

    `Answers.dns_naptr_preference` Array(Nullable(String)),

    `Answers.dns_naptr_regex` Array(Nullable(String)),

    `Answers.dns_naptr_regex_length` Array(Nullable(String)),

    `Answers.dns_naptr_replacement` Array(Nullable(String)),

    `Answers.dns_naptr_service` Array(Nullable(String)),

    `Answers.dns_naptr_service_length` Array(Nullable(String)),

    `Answers.dns_naptr_replacement_length` Array(Nullable(String)),

    `Answers.dns_spf` Array(Nullable(String)),

    `Answers.dns_spf_length` Array(Nullable(String)),

    `Answers.dns_dname` Array(Nullable(String)),

    `Answers.dns_resp_edns0_version` Array(Nullable(String)),

    `Answers.dns_resp_ext_rcode` Array(Nullable(String)),

    `Answers.dns_resp_z` Array(Nullable(String)),

    `Answers.dns_rr_udp_payload_size` Array(Nullable(String))
)
ENGINE = Null;
