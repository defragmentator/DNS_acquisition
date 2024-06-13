create table test3.types_z_asn 
(
 Query_frame_interface_id Nullable(UInt32),-- do wyrzucenia
   Query_frame_interface_id_tree Nested (frame_interface_name Nullable(String)), --do wyrzucenia
   Query_frame_encap_type Nullable(Int16), -- do wyrzucenia
   Query_frame_time Nullable(String), -- nie da sie latwo scastowac z formatu jaki jest
   Query_frame_offset_shift Nullable(Float64), -- do wyrzucenia
   Query_frame_time_epoch Float64, -- nie uzywac
   Query_frame_time_epoch_2 Nullable(DateTime), -- nie uzywac
   Query_frame_time_epoch_nanos Nullable(UInt32), -- nie uzywac
   Query_day_of_year Nullable(UInt16),  -- nie uzywac na razie - to trzeba by powiazac z kalendarze dni wolnych i swiat
   Query_day_of_week Nullable(UInt8), -- analizowac jako wartosc ciagla
   Query_hour Nullable(UInt8), -- analizowac jako wartosc ciagla
   Query_frame_time_delta Nullable(Float64), -- nie uzywac
   Query_frame_time_delta_displayed Nullable(Float64), -- do wyrzucenia
   Query_frame_time_relative Nullable(Float64), -- nie uzywać - może sluzyc do obliczenia czasu polaczenia jezeli nie ma w innym polu Response-Query chociaz to jest w Response_dns_time juz
   Query_frame_number Nullable(UInt32), -- nie uzywac
   Query_frame_len Nullable(UInt32), -- nie uzywac
   Query_frame_cap_len Nullable(UInt32), -- do wyrzucenia
   Query_frame_marked Nullable(UInt8), -- do wyrzucenia
   Query_frame_ignored Nullable(UInt8), -- do wyrzucenia
   Query_frame_protocols Nullable(String), -- do wyrzucenia
   
   Query_dns_id Nullable(UInt16), -- do wyrzucenia 
   Query_dns_flags Nullable(UInt16),-- analizować jako etykieta lub uzywac rozbitych kolumn boolean dns_flags_....
   Query_dns_count_queries Nullable(UInt16nt_), -- na teraz nie analizowac bo zawsze 1 ale kiedys moze jak anomalie
   Query_dns_count_answers Nullable(UInt16), -- nie uzywac
   Query_dns_count_auth_rr Nullable(UInt16), -- nie uzywac
   Query_dns_count_add_rr Nullable(UInt16), -- analizowac jako wartosc ciagla
   Query_dns_response_to Nullable(UInt32), -- do wyrzucenia
   Query_dns_time Nullable(Float64), -- do wyrzucenia bo zawsze zero - uzyc dla Response

   Query_dns_flags_response Nullable(UInt8), -- patrz dns_flgs
   Query_dns_flags_opcode Nullable(UInt16), -- patrz dns_flgs
   Query_dns_flags_authoritative Nullable(UInt8), -- patrz dns_flgs
   Query_dns_flags_truncated Nullable(UInt8), -- patrz dns_flgs
   Query_dns_flags_recdesired Nullable(UInt8), -- patrz dns_flgs
   Query_dns_flags_recavail Nullable(UInt8), -- patrz dns_flgs
   Query_dns_flags_z Nullable(UInt8), -- patrz dns_flgs
   Query_dns_flags_authenticated Nullable(UInt8), -- patrz dns_flgs
   Query_dns_flags_checkdisable Nullable(UInt8), -- patrz dns_flgs
   Query_dns_flags_rcode Nullable(UInt16), -- patrz dns_flgs
   Query_dns_unsolicited Nullable(UInt8), -- do wyrzucenia
   
   Query_dns_retransmit_request_in Nullable(String), -- nie uzywac - filt port 53 powoduje null
   Query_dns_retransmission  Nullable(UInt8), -- nie uzywac - filt port 53 powoduje null

   Query_dns_retransmit_response_in Nullable(String), -- nie uzywac - filt port 53 powoduje null
   Query_udp_srcport Nullable(UInt16), -- analizowac jako wartosc ciagla
   Query_udp_dstport Nullable(UInt16), -- do wyrzucenia
   Query_udp_port Nullable(UInt16), -- do wyrzucenia
   Query_udp_length Nullable(UInt16), -- analizowac jako wartosc ciagla
   Query_udp_checksum Nullable(UInt16), -- do wyrzucenia
   Query_udp_checksum_status Nullable(UInt8), -- analizowac jako etykieta
   Query_udp_stream Nullable(UInt32),-- ????
   
   
   Query_ip_version Nullable(UInt8),-- do wyrzucenia
   Query_ip_hdr_len Nullable(UInt8),-- do wyrzucenia
   Query_ip_dsfield Nullable(UInt8),-- analizowac jako etykieta
   Query_ip_len Nullable(UInt16), -- nie uzywac
   Query_ip_id Nullable(UInt16), -- do wyrzucenia
   Query_ip_flags Nullable(UInt16),-- analizować jako etykieta lub uzywac rozbitych kolumn boolean ip_flags_....
   Query_ip_ttl Nullable(UInt8), -- analizowac ale jako etykieta
   Query_ip_proto Nullable(UInt8), --do wyrzucenia
   Query_ip_checksum Nullable(UInt16), -- do wyrzucenia
   Query_ip_checksum_status Nullable(UInt8), -- nie uzywac
   Query_ip_src Nullable(IPv4), -- analizować jako etykieta
   Query_ip_src_class Nullable(UInt8), -- jako zmienna decyzyjna przy klasyfikacji mozna probowac
   Query_ip_addr Nullable(IPv4), -- do wyrzucenia
   Query_ip_src_host Nullable(IPv4), -- do wyrzucenia
   Query_ip_host Nullable(IPv4),-- do wyrzucenia
   Query_ip_dst Nullable(IPv4) ,-- to pole wypada puszczać przez API chociaz wiekszosc bedzie 192.168.99.133, na razie mozna brac jako flage czy inne od 192.168.99.133
   Query_ip_dst_host Nullable(IPv4),-- kiedys do uzycia do analizy jezykowej !!!!tutaj powinien być string i hostname zamiast ip w tresci - konfiguracja tshark "-N ndN"
   Query_ip_dsfield_dscp Nullable(UInt8),-- analizowac jako etykieta
   Query_ip_dsfield_ecn Nullable(UInt8), -- nie uzywac
   Query_ip_flags_rb Nullable(UInt8), -- patrz ip_flags
   Query_ip_flags_df Nullable(UInt8), -- patrz ip_flags
   Query_ip_flags_mf Nullable(UInt8), -- patrz ip_flags
   Query_ip_frag_offset Nullable(UInt16), -- nie uzywac
   
   Query_Additional_records Nested ( -- tutaj raczej nie powinien sie zdarzyc wiecej niz jeden element tablicy
      dns_resp_name Nullable(String),  -- analizowac jako flaga (null lub ['Root'])
      dns_resp_type Nullable(UInt16),-- do wyrzucenia
      dns_resp_class Nullable(UInt16),-- do wyrzucenia
      dns_resp_ttl Nullable(UInt32),-- do wyrzucenia
      dns_resp_len Nullable(UInt32),-- do wyrzucenia
      dns_a Nullable(IPv4),-- do wyrzucenia
      dns_aaaa Nullable(IPv6),-- do wyrzucenia
      dns_resp_edns0_version  Nullable(UInt8),-- do wyrzucenia
      dns_resp_ext_rcode   Nullable(UInt8),-- do wyrzucenia
      dns_resp_z   Nullable(UInt16), -- analizowac jako etykieta (null jako jedna z etykiet, 0 , 32768)
      -- dns_resp_z_tree Nullable(String)
      "dns_rr_udp_payload_size" Nullable(UInt16), -- analizowac jako etykieta (null jako jedna z etykiet)
      -- dns_opt Nullable(String)
      dns_rrsig_algorithm Nullable(UInt8),-- do wyrzucenia
      dns_rrsig_key_tag Nullable(UInt16),-- do wyrzucenia
      dns_rrsig_labels Nullable(UInt8),-- do wyrzucenia
      dns_rrsig_original_ttl Nullable(UInt32),-- do wyrzucenia
      dns_rrsig_signature Nullable(String),-- do wyrzucenia
      dns_rrsig_signature_expiration Nullable(Datetime),-- do wyrzucenia
      dns_rrsig_signature_inception Nullable(Datetime),-- do wyrzucenia
      dns_rrsig_signers_name Nullable(String),-- do wyrzucenia
      dns_rrsig_type_covered Nullable(UInt16),-- do wyrzucenia
      dns_srv_name Nullable(String),-- do wyrzucenia
      dns_nsec3_algo Nullable(UInt8), -- do wyrzucenia
      dns_srv_port Nullable(UInt16),-- do wyrzucenia
      dns_srv_priority Nullable(UInt16),-- do wyrzucenia
      dns_srv_proto Nullable(String),-- do wyrzucenia
      dns_srv_service Nullable(String),-- do wyrzucenia
      dns_srv_target Nullable(String),-- do wyrzucenia
      dns_srv_weight Nullable(UInt16),-- do wyrzucenia
      dns_nsec3_flags Nullable(UInt8),-- do wyrzucenia
      -- dns_nsec3_flags_tree
      dns_nsec3_hash_length Nullable(UInt8),-- do wyrzucenia
      dns_nsec3_hash_value Nullable(String),-- do wyrzucenia --sequence of bytes
      dns_nsec3_iterations Nullable(_hostUInt16),-- do wyrzucenia
      dns_nsec3_salt_length Nullable(UInt8),-- do wyrzucenia
      dns_nsec3_salt_value Nullable(String),-- do wyrzucenia --sequence of bytes
      dns_rp_mailbox Nullable(String),-- do wyrzucenia
      dns_rp_txt_rr Nullable(String),-- do wyrzucenia
      dns_tlsa_certificate_association_data Nullable(String),-- do wyrzucenia --sequence of bytes
      dns_tlsa_certificate_usage Nullable(UInt8),-- do wyrzucenia
      dns_tlsa_matching_type Nullable(UInt8),-- do wyrzucenia
      dns_dname Nullable(String),-- do wyrzucenia
      dns_tlsa_selector Nullable(UInt8)-- do wyrzucenia
   ),

   Query_Queries Nested ( -- tutaj raczej nie powinien sie zdarzyc wiecej niz jeden element tablicy
      dns_qry_name Nullable(String),-- kiedys do uzycia do analizy jezykowej 
      dns_qry_name_len Nullable(UInt16), -- analizowac jako warotsc ciagla
      dns_count_labels Nullable(UInt16), -- analizowac jako warotsc ciagla
      dns_qry_type Nullable(UInt16),-- analizowac jako etykieta
      dns_qry_class Nullable(UInt16) -- nie uzywac - kiedys moze byc do anomalii jak inne niz 1
   ),

   -- Response
   Response_frame_interface_id Nullable(UInt32),-- do wyrzucenia
   Response_frame_interface_id_tree Nested (frame_interface_name Nullable(String)),-- do wyrzucenia
   Response_frame_encap_type Nullable(Int16),-- do wyrzucenia
   Response_frame_time Nullable(String), -- nie mozna scastowac ze stringa na czas
   Response_frame_offset_shift Nullable(Float64),-- do wyrzucenia
   Response_frame_time_epoch Float64, -- nie uzywac
   Response_frame_time_epoch_2 Nullable(DateTime), -- nie uzywac
   Response_frame_time_epoch_nanos Nullable(UInt32), -- nie uzywac
   Response_day_of_year Nullable(UInt16), -- do wyrzucenia bo w parze identyczne
   Response_day_of_week Nullable(UInt8),-- do wyrzucenia bo w parze identyczne
   Response_hour Nullable(UInt8),-- do wyrzucenia bo w parze identyczne
   Response_frame_time_delta Nullable(Float64), -- do wyrzucenia
   Response_frame_time_delta_displayed Nullable(Float64), -- do wyrzucenia
   Response_frame_time_relative Nullable(Float64), -- nie uzywać - może sluzyc do obliczenia czasu polaczenia jezeli nie ma w innym polu Response-Query chociaz to jest w Response_dns_time juz
   Response_frame_number Nullable(UInt32), -- nie uzywac
   Response_frame_len Nullable(UInt32), -- nie uzywac
   Response_frame_cap_len Nullable(UInt32), -- do wyrzucenia
   Response_frame_marked Nullable(UInt8), -- do wyrzucenia
   Response_frame_ignored Nullable(UInt8), -- do wyrzucenia
   Response_frame_protocols Nullable(String), -- do wyrzucenia

   Response_dns_id Nullable(UInt16), -- do wyrzucenia
   Response_dns_flags Nullable(UInt16),-- analizować jako etykieta lub uzywac rozbitych kolumn boolean dns_flags_....
   Response_dns_count_queries Nullable(UInt16), -- na teraz nie analizowac bo zawsze 1 ale kiedys moze jak anomalie
   Response_dns_count_answers Nullable(UInt16), -- analizowac jako wartosc ciagla
   Response_dns_count_auth_rr Nullable(UInt16), -- nie uzywac
   Response_dns_count_add_rr Nullable(UInt16), -- analizowac jako wartosc ciagla
   Response_dns_response_to Nullable(UInt32), -- do wyrzucenia
   Response_dns_time Nullable(Float64), -- analizowac jako wartosc ciagla
   Response_dns_flags_response Nullable(UInt8),-- patrz dns_flags
   Response_dns_flags_opcode Nullable(UInt16),-- patrz dns_flags
   Response_dns_flags_authoritative Nullable(UInt8),-- patrz dns_flags
   Response_dns_flags_truncated Nullable(UInt8),-- patrz dns_flags
   Response_dns_flags_recdesired Nullable(UInt8),-- patrz dns_flags
   Response_dns_flags_recavail Nullable(UInt8),-- patrz dns_flags
   Response_dns_flags_z Nullable(UInt8),-- patrz dns_flags
   Response_dns_flags_authenticated Nullable(UInt8),-- patrz dns_flags
   Response_dns_flags_checkdisable Nullable(UInt8),-- patrz dns_flags
   Response_dns_flags_rcode Nullable(UInt16),-- patrz dns_flags
   Response_dns_unsolicited Nullable(UInt8), -- do wyrzucenia
   -- dns_id_tree
   Response_dns_retransmit_request_in Nullable(String), -- nie uzywac - filt port 53 powoduje null
   Response_dns_retransmission  Nullable(UInt8), -- nie uzywac - filt port 53 powoduje null
   Response_dns_retransmit_response_in Nullable(String), -- nie uzywac - filt port 53 powoduje null

   Response_udp_srcport Nullable(UInt16),  -- do wyrzucenia bo wiadomo ze zawsze 53
   Response_udp_dstport Nullable(UInt16), -- nie uzywac, bo jezeli laczymy wpary to musi byc identyczny jak w query - beez par potencjalnie moglbybyc do anomalii uzyty
   Response_udp_port Nullable(UInt16), -- do wyrzucenia
   Response_udp_length Nullable(UInt16), -- analizowac jako wartosc ciagla
   Response_udp_checksum Nullable(UInt16), -- do wyrzucenia
   Response_udp_checksum_status Nullable(UInt8), -- analizowac jako etykieta
   Response_udp_stream Nullable(UInt32), -- ????
   -- udp_srcport_tree
   -- udp_dstport_tree

   Response_ip_version Nullable(UInt8),-- do wyrzucenia
   Response_ip_hdr_len Nullable(UInt8),-- do wyrzucenia
   Response_ip_dsfield Nullable(UInt8),-- analizowac jako etykieta
   Response_ip_len Nullable(UInt16), -- nie uzywac
   Response_ip_id Nullable(UInt16), -- do wyrzucenia
   Response_ip_flags Nullable(UInt16),-- analizować jako etykieta lub uzywac rozbitych kolumn boolean ip_flags_....
   Response_ip_ttl Nullable(UInt8), -- analizowac ale jako etykieta
   Response_ip_proto Nullable(UInt8), --do wyrzucenia
   Response_ip_checksum Nullable(UInt16), --do wyrzucenia
   Response_ip_checksum_status Nullable(UInt8),-- nie uzywac
   Response_ip_src Nullable(IPv4),-- do wyrzucenia, bo identyczne w parze
   Response_ip_addr Nullable(IPv4),-- do wyrzucenia
   Response_ip_src_host Nullable(IPv4),-- do wyrzucenia, bo identyczne w parze
   Response_ip_host Nullable(IPv4),-- do wyrzucenia
   Response_ip_dst Nullable(IPv4),-- do wyrzucenia, bo identyczne w parze
   Response_ip_dst_host Nullable(IPv4), -- do wyrzucenia bo lokalne i identyczne w parze
   Response_ip_dsfield_dscp Nullable(UInt8),-- analizowac jako etykieta
   Response_ip_dsfield_ecn Nullable(UInt8), -- nie uzywac
   Response_ip_flags_rb Nullable(UInt8),-- patrz ip_flags
   Response_ip_flags_df Nullable(UInt8),-- patrz ip_flags
   Response_ip_flags_mf Nullable(UInt8),-- patrz ip_flags
   Response_ip_frag_offset Nullable(UInt16), -- nie uzywac

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

   Response_Queries Nested (-- tutaj raczej nie powinien sie zdarzyc wiecej niz jeden element tablicy - podejrzewam ze beda sie roznic albo wszystkie albo zadno
      dns_qry_name Nullable(String), -- te interesuja nas tylko o tyle czy sie roznia od odpowiednikow w query - mozna by zrobic selecta z == i brac jako flage
      dns_qry_name_len Nullable(UInt16), -- te interesuja nas tylko o tyle czy sie roznia od odpowiednikow w query - mozna by zrobic selecta z == i brac jako flage
      dns_count_labels Nullable(UInt16), -- te interesuja nas tylko o tyle czy sie roznia od odpowiednikow w query - mozna by zrobic selecta z == i brac jako flage
      dns_qry_type Nullable(UInt16), -- te interesuja nas tylko o tyle czy sie roznia od odpowiednikow w query - mozna by zrobic selecta z == i brac jako flage
      dns_qry_class Nullable(UInt16) -- te interesuja nas tylko o tyle czy sie roznia od odpowiednikow w query - mozna by zrobic selecta z == i brac jako flage
   ),

   Response_Answers Nested (
      dns_resp_name Nullable(String),
      dns_resp_type Nullable(UInt16), -- te sa wg mnie wazne: na raize dla uproszczenia zliczalbym ile jest elementow o danej wartosci
                                      -- lista mozliwych wartosci tutaj: http://edgedirector.com/app/type.htm - 0x01-0x29, 0x2b,0x2e,0x2f,0x30,0x31,0x64-0x67, 0xf8-0xff, 0xff01, 0xff02 
                                      --  dla kazdej z tych wartosci wypadalo by zrobic kolumne a w niej ilosc wystąpien i to brac jako wartosc ciagla             
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
      "dns_txt" Nullable(String), -- analizowac jako etykieta regexp anycase czy zawiera slowa spf,dmarc,google,sophos,verification,STSv1,TLSRPTv1,DKIM,k=rsa,blocked,abuse
      "dns_txt_length" Nullable(UInt8), -- analizowac jako warotsc ciagla
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
ENGINE = MergeTree
order by (Query_frame_time_epoch)
settings index_granularity = 8196;
