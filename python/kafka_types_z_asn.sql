create table test3.kafka_types_z_asn
(
Query_frame_interface_id Nullable(UInt32),
   Query_frame_interface_id_tree Nested (frame_interface_name Nullable(String)),
   Query_frame_encap_type Nullable(Int16),
   Query_frame_time Nullable(String), -- nie da sie latwo scastowac z formatu jaki jest
   Query_frame_offset_shift Nullable(Float64),
   Query_frame_time_epoch Float64,
   Query_frame_time_epoch_2 Nullable(DateTime),
   Query_frame_time_epoch_nanos Nullable(UInt32),
   Query_day_of_year Nullable(UInt16),
   Query_day_of_week Nullable(UInt8),
   Query_hour Nullable(UInt8),
   Query_frame_time_delta Nullable(Float64),
   Query_frame_time_delta_displayed Nullable(Float64),
   Query_frame_time_relative Nullable(Float64),
   Query_frame_number Nullable(UInt32),
   Query_frame_len Nullable(UInt32),
   Query_frame_cap_len Nullable(UInt32),
   Query_frame_marked Nullable(UInt8),
   Query_frame_ignored Nullable(UInt8),
   Query_frame_protocols Nullable(String),
   
   Query_dns_id Nullable(UInt16),
   Query_dns_flags Nullable(UInt16),
   Query_dns_count_queries Nullable(UInt16),
   Query_dns_count_answers Nullable(UInt16),
   Query_dns_count_auth_rr Nullable(UInt16),
   Query_dns_count_add_rr Nullable(UInt16),
   Query_dns_response_to Nullable(UInt32),
   Query_dns_time Nullable(Float64),
   Query_dns_flags_response Nullable(UInt8),
   Query_dns_flags_opcode Nullable(UInt16),
   Query_dns_flags_authoritative Nullable(UInt8),
   Query_dns_flags_truncated Nullable(UInt8),
   Query_dns_flags_recdesired Nullable(UInt8),
   Query_dns_flags_recavail Nullable(UInt8),
   Query_dns_flags_z Nullable(UInt8),
   Query_dns_flags_authenticated Nullable(UInt8),
   Query_dns_flags_checkdisable Nullable(UInt8),
   Query_dns_flags_rcode Nullable(UInt16),
   Query_dns_unsolicited Nullable(UInt8),
   
   Query_dns_retransmit_request_in Nullable(String),
   Query_dns_retransmission  Nullable(UInt8),
   Query_dns_retransmit_response_in Nullable(String),
   Query_udp_srcport Nullable(UInt16),
   Query_udp_dstport Nullable(UInt16),
   Query_udp_port Nullable(UInt16),
   Query_udp_length Nullable(UInt16),
   Query_udp_checksum Nullable(UInt16),
   Query_udp_checksum_status Nullable(UInt8),
   Query_udp_stream Nullable(UInt32),
   
   
   Query_ip_version Nullable(UInt8),
   Query_ip_hdr_len Nullable(UInt8),
   Query_ip_dsfield Nullable(UInt8),
   Query_ip_len Nullable(UInt16),
   Query_ip_id Nullable(UInt16),
   Query_ip_flags Nullable(UInt16),
   Query_ip_ttl Nullable(UInt8),
   Query_ip_proto Nullable(UInt8),
   Query_ip_checksum Nullable(UInt16),
   Query_ip_checksum_status Nullable(UInt8),
   Query_ip_src Nullable(IPv4),
   Query_ip_src_class Nullable(UInt8),
   Query_ip_addr Nullable(IPv4),
   Query_ip_src_host Nullable(IPv4),
   Query_ip_host Nullable(IPv4),
   Query_ip_dst Nullable(IPv4),
   Query_ip_dst_host Nullable(IPv4),
   Query_ip_dsfield_dscp Nullable(UInt8),
   Query_ip_dsfield_ecn Nullable(UInt8),
   Query_ip_flags_rb Nullable(UInt8),
   Query_ip_flags_df Nullable(UInt8),
   Query_ip_flags_mf Nullable(UInt8),
   Query_ip_frag_offset Nullable(UInt16),
   
   Query_Additional_records Nested (
      dns_resp_name Nullable(String),
      dns_resp_type Nullable(UInt16),
      dns_resp_class Nullable(UInt16),
      dns_resp_ttl Nullable(UInt32),
      dns_resp_len Nullable(UInt32),
      dns_a Nullable(IPv4),
      dns_aaaa Nullable(IPv6),
      dns_resp_edns0_version  Nullable(UInt8),
      dns_resp_ext_rcode   Nullable(UInt8),
      dns_resp_z   Nullable(UInt16),
      -- dns_resp_z_tree Nullable(String)
      "dns_rr_udp_payload_size" Nullable(UInt16),
      -- dns_opt Nullable(String)
      dns_rrsig_algorithm Nullable(UInt8),
      dns_rrsig_key_tag Nullable(UInt16),
      dns_rrsig_labels Nullable(UInt8),
      dns_rrsig_original_ttl Nullable(UInt32),
      dns_rrsig_signature Nullable(String),
      dns_rrsig_signature_expiration Nullable(Datetime),
      dns_rrsig_signature_inception Nullable(Datetime),
      dns_rrsig_signers_name Nullable(String),
      dns_rrsig_type_covered Nullable(UInt16),
      dns_srv_name Nullable(String),
      dns_nsec3_algo Nullable(UInt8),
      dns_srv_port Nullable(UInt16),
      dns_srv_priority Nullable(UInt16),
      dns_srv_proto Nullable(String),
      dns_srv_service Nullable(String),
      dns_srv_target Nullable(String),
      dns_srv_weight Nullable(UInt16),
      dns_nsec3_flags Nullable(UInt8),
      -- dns_nsec3_flags_tree
      dns_nsec3_hash_length Nullable(UInt8),
      dns_nsec3_hash_value Nullable(String), --sequence of bytes
      dns_nsec3_iterations Nullable(UInt16),
      dns_nsec3_salt_length Nullable(UInt8),
      dns_nsec3_salt_value Nullable(String),--sequence of bytes
      dns_rp_mailbox Nullable(String),
      dns_rp_txt_rr Nullable(String),
      dns_tlsa_certificate_association_data Nullable(String),--sequence of bytes
      dns_tlsa_certificate_usage Nullable(UInt8),
      dns_tlsa_matching_type Nullable(UInt8),
      dns_dname Nullable(String),
      dns_tlsa_selector Nullable(UInt8)
   ),

   Query_Queries Nested (
      dns_qry_name Nullable(String),
      dns_qry_name_len Nullable(UInt16),
      dns_count_labels Nullable(UInt16),
      dns_qry_type Nullable(UInt16),
      dns_qry_class Nullable(UInt16)
   ),

   -- Response
   Response_frame_interface_id Nullable(UInt32),
   Response_frame_interface_id_tree Nested (frame_interface_name Nullable(String)),
   Response_frame_encap_type Nullable(Int16),
   Response_frame_time Nullable(String),
   Response_frame_offset_shift Nullable(Float64),
   Response_frame_time_epoch Float64,
   Response_frame_time_epoch_2 Nullable(DateTime),
   Response_frame_time_epoch_nanos Nullable(UInt32),
   Response_day_of_year Nullable(UInt16),
   Response_day_of_week Nullable(UInt8),
   Response_hour Nullable(UInt8),
   Response_frame_time_delta Nullable(Float64),
   Response_frame_time_delta_displayed Nullable(Float64),
   Response_frame_time_relative Nullable(Float64),
   Response_frame_number Nullable(UInt32),
   Response_frame_len Nullable(UInt32),
   Response_frame_cap_len Nullable(UInt32),
   Response_frame_marked Nullable(UInt8),
   Response_frame_ignored Nullable(UInt8),
   Response_frame_protocols Nullable(String),

   Response_dns_id Nullable(UInt16),
   Response_dns_flags Nullable(UInt16),
   Response_dns_count_queries Nullable(UInt16),
   Response_dns_count_answers Nullable(UInt16),
   Response_dns_count_auth_rr Nullable(UInt16),
   Response_dns_count_add_rr Nullable(UInt16),
   Response_dns_response_to Nullable(UInt32),
   Response_dns_time Nullable(Float64),
   Response_dns_flags_response Nullable(UInt8),
   Response_dns_flags_opcode Nullable(UInt16),
   Response_dns_flags_authoritative Nullable(UInt8),
   Response_dns_flags_truncated Nullable(UInt8),
   Response_dns_flags_recdesired Nullable(UInt8),
   Response_dns_flags_recavail Nullable(UInt8),
   Response_dns_flags_z Nullable(UInt8),
   Response_dns_flags_authenticated Nullable(UInt8),
   Response_dns_flags_checkdisable Nullable(UInt8),
   Response_dns_flags_rcode Nullable(UInt16),
   Response_dns_unsolicited Nullable(UInt8),
   -- dns_id_tree
   Response_dns_retransmit_request_in Nullable(String),
   Response_dns_retransmission  Nullable(UInt8),
   Response_dns_retransmit_response_in Nullable(String),

   Response_udp_srcport Nullable(UInt16),
   Response_udp_dstport Nullable(UInt16),
   Response_udp_port Nullable(UInt16),
   Response_udp_length Nullable(UInt16),
   Response_udp_checksum Nullable(UInt16),
   Response_udp_checksum_status Nullable(UInt8),
   Response_udp_stream Nullable(UInt32),
   -- udp_srcport_tree
   -- udp_dstport_tree

   Response_ip_version Nullable(UInt8),
   Response_ip_hdr_len Nullable(UInt8),
   Response_ip_dsfield Nullable(UInt8),
   Response_ip_len Nullable(UInt16),
   Response_ip_id Nullable(UInt16),
   Response_ip_flags Nullable(UInt16),
   Response_ip_ttl Nullable(UInt8),
   Response_ip_proto Nullable(UInt8),
   Response_ip_checksum Nullable(UInt16),
   Response_ip_checksum_status Nullable(UInt8),
   Response_ip_src Nullable(IPv4),
   Response_ip_addr Nullable(IPv4),
   Response_ip_src_host Nullable(IPv4),
   Response_ip_host Nullable(IPv4),
   Response_ip_dst Nullable(IPv4),
   Response_ip_dst_host Nullable(IPv4),
   Response_ip_dsfield_dscp Nullable(UInt8),
   Response_ip_dsfield_ecn Nullable(UInt8),
   Response_ip_flags_rb Nullable(UInt8),
   Response_ip_flags_df Nullable(UInt8),
   Response_ip_flags_mf Nullable(UInt8),
   Response_ip_frag_offset Nullable(UInt16),

   Response_Additional_records Nested (
      dns_resp_name Nullable(String),
      dns_resp_type Nullable(UInt16),
      dns_resp_class Nullable(UInt16),
      dns_resp_ttl Nullable(UInt32),
      dns_resp_len Nullable(UInt32),
      dns_a Nullable(IPv4),
      dns_aaaa Nullable(IPv6),
      dns_resp_edns0_version  Nullable(UInt8),
      dns_resp_ext_rcode   Nullable(UInt8),
      dns_resp_z   Nullable(UInt16),
      -- dns_resp_z_tree Nullable(String)
      "dns_rr_udp_payload_size" Nullable(UInt16),
      -- dns_opt Nullable(String)
      dns_rrsig_algorithm Nullable(UInt8),
      dns_rrsig_key_tag Nullable(UInt16),
      dns_rrsig_labels Nullable(UInt8),
      dns_rrsig_original_ttl Nullable(UInt32),
      dns_rrsig_signature Nullable(String),
      dns_rrsig_signature_expiration Nullable(Datetime),
      dns_rrsig_signature_inception Nullable(Datetime),
      dns_rrsig_signers_name Nullable(String),
      dns_rrsig_type_covered Nullable(UInt16),
      --nowe
      dns_srv_name Nullable(String),
      dns_nsec3_algo Nullable(UInt8),
      dns_srv_port Nullable(UInt16),
      dns_srv_priority Nullable(UInt16),
      dns_srv_proto Nullable(String),
      dns_srv_service Nullable(String),
      dns_srv_target Nullable(String),
      dns_srv_weight Nullable(UInt16),
      dns_nsec3_flags Nullable(UInt8),
      -- dns_nsec3_flags_tree
      dns_nsec3_hash_length Nullable(UInt8),
      dns_nsec3_hash_value Nullable(String), --sequence of bytes 
      dns_nsec3_iterations Nullable(UInt16),
      dns_nsec3_salt_length Nullable(UInt8),
      dns_nsec3_salt_value Nullable(String), --sequence of bytes
      dns_rp_mailbox Nullable(String),
      dns_rp_txt_rr Nullable(String),
      dns_tlsa_certificate_association_data Nullable(String), --sequence of bytes
      dns_tlsa_certificate_usage Nullable(UInt8),
      dns_tlsa_matching_type Nullable(UInt8),
      dns_dname Nullable(String),
      dns_tlsa_selector Nullable(UInt8)
   ),

   Response_Authoritative_nameservers Nested (
      dns_resp_name Nullable(String),
      dns_resp_type Nullable(UInt16),
      dns_resp_class Nullable(UInt16),
      dns_resp_ttl Nullable(UInt32),
      dns_resp_len Nullable(UInt32),
      dns_ns Nullable(String),
      dns_soa_expire_limit Nullable(UInt32),
      dns_soa_mininum_ttl Nullable(UInt32),
      dns_soa_mname Nullable(String),
      dns_soa_refresh_interval Nullable(UInt32),
      dns_soa_retry_interval Nullable(UInt32),
      dns_soa_rname Nullable(String),
      dns_soa_serial_number Nullable(UInt32),
      dns_nsec_next_domain_name Nullable(String),
      dns_rrsig_algorithm Nullable(UInt8),
      dns_rrsig_key_tag Nullable(UInt16),
      dns_rrsig_labels Nullable(UInt8),
      dns_rrsig_original_ttl Nullable(UInt32),
      dns_rrsig_signature Nullable(String),
      dns_rrsig_signature_expiration Nullable(Datetime),
      dns_rrsig_signature_inception Nullable(Datetime),
      dns_rrsig_signers_name Nullable(String),
      dns_rrsig_type_covered Nullable(UInt16),
      dns_ds_algorithm Nullable(UInt8),
      dns_ds_digest Nullable(String),
      dns_ds_digest_type Nullable(UInt8),
      dns_ds_key_id Nullable(UInt16),
      -- "dns_nsec3.flags_tree"
      "dns_nsec3_algo" Nullable(UInt8),
      "dns_nsec3_flags" Nullable(UInt8),
      "dns_nsec3_iterations" Nullable(UInt16),
      "dns_nsec3_salt_length" Nullable(UInt8),
      "dns_nsec3_salt_value" Nullable(String),--sequence of bytes
      "dns_nsec3_hash_length" Nullable(UInt8),
      "dns_nsec3_hash_value" Nullable(String), --sequenc of bytes
      dns_srv_name Nullable(String)
   ),

   Response_Queries Nested (
      dns_qry_name Nullable(String),
      dns_qry_name_len Nullable(UInt16),
      dns_count_labels Nullable(UInt16),
      dns_qry_type Nullable(UInt16),
      dns_qry_class Nullable(UInt16)
   ),

   Response_Answers Nested (
      dns_resp_name Nullable(String),
      dns_resp_type Nullable(UInt16),
      dns_resp_class Nullable(UInt16),
      dns_resp_ttl Nullable(UInt32),
      dns_resp_len Nullable(UInt32),
      dns_a Nullable(IPv4),
      dns_aaaa Nullable(IPv6),
      dns_cname Nullable(String),
      dns_ptr_domain_name Nullable(String),
      dns_rrsig_algorithm Nullable(UInt8),
      dns_rrsig_key_tag Nullable(UInt16),
      dns_rrsig_labels Nullable(UInt8),
      dns_rrsig_original_ttl Nullable(UInt32),
      dns_rrsig_signature Nullable(String),
      dns_rrsig_signature_expiration Nullable(Datetime),
      dns_rrsig_signature_inception Nullable(Datetime),
      dns_rrsig_signers_name Nullable(String),
      dns_rrsig_type_covered Nullable(UInt16),
      dns_ds_algorithm Nullable(UInt8),
      dns_ds_digest Nullable(String),
      dns_ds_digest_type Nullable(UInt8),
      dns_ds_key_id Nullable(UInt16),
      "dns_txt" Nullable(String),
      "dns_txt_length" Nullable(UInt8),
      "dns_mx_mail_exchange" Nullable(String),
      "dns_mx_preference" Nullable(UInt16),
      dns_dnskey_algorithm Nullable(UInt8),
      dns_dnskey_flags Nullable(UInt16),
      -- dns_dnskey_flags_tree
      dns_dnskey_key_id  Nullable(UInt16),
      dns_dnskey_protocol Nullable(UInt8),
      dns_dnskey_public_key Nullable(String),
      dns_soa_expire_limit Nullable(UInt32),
      dns_soa_mininum_ttl  Nullable(UInt32),
      dns_soa_mname Nullable(String),
      dns_soa_refresh_interval Nullable(UInt32),
      dns_soa_retry_interval  Nullable(UInt32),
      dns_soa_rname  Nullable(String),
      dns_soa_serial_number  Nullable(UInt32),
      dns_ns Nullable(String),
      -- _ws_expert
      dns_srv_name Nullable(String),
      dns_srv_port Nullable(UInt16),
      dns_naptr_flags Nullable(String),
      dns_srv_priority Nullable(UInt16),
      dns_srv_proto Nullable(String),
      dns_srv_service Nullable(String),
      dns_srv_target Nullable(String),
      dns_srv_weight Nullable(UInt16),
      dns_data Nullable(String), -- sequence of bytes
      dns_naptr_flags_length Nullable(UInt8),
      dns_naptr_order Nullable(UInt16),
      dns_naptr_preference Nullable(UInt16),
      dns_naptr_regex Nullable(String),
      dns_naptr_regex_length Nullable(UInt8),
      dns_naptr_replacement Nullable(String),
      dns_naptr_service Nullable(String),
      dns_naptr_service_length Nullable(UInt8),
      dns_naptr_replacement_length Nullable(UInt8),
      dns_spf Nullable(String),
      dns_spf_length Nullable(UInt8),
      dns_dname Nullable(String),--ok
      dns_resp_edns0_version Nullable(UInt8),
      dns_resp_ext_rcode Nullable(UInt8),
      dns_resp_z Nullable(UInt16),
      -- dns_resp_z_tree
      dns_rr_udp_payload_size Nullable(UInt16)
   )
)
ENGINE =  Kafka('localhost:9092', 'ip_z_ASN_7', 'no_types_ip_z_asn', 'JSONEachRow');