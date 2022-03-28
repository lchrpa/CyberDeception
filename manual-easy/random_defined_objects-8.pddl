;Copyright 2018 The MITRE Corporation. All rights reserved.
; NOT FOR PUBLIC RELEASE. DO NOT REDISTRIBUTE.
; For more information on CALDERA, the automated adversary emulation system, visit https://github.com/mitre/caldera or email attack@mitre.org
; This has 4 hosts, 8 user, 2 admin per host, 2 active account per host
(define (problem p4_hosts_trial_16)
(:domain caldera)
(:objects
    wilbur_cred pris_cred rick_cred rachael_cred roy_cred john_cred cred_fortyeight cred_fifty cred_fiftytwo - observeddomaincredential
    host1 host2 host3 host4 host5 host_sixteen host_twenty host_twentyfour host_twentyeight host_thirtytwo - observedhost
    host1_schtask host2_schtask host3_schtask host4_schtask host5_schtask - observedschtask
    host1_file host2_file host3_file host4_file host5_file - observedfile
    domain_str2 str_two str_three str_five str_six str_eight str_nine str_eleven str_twelve str_fourteen str_fifteen str_seventeen str_eighteen str_nineteen str_twentyone str_twentytwo str_twentythree str_twentyfive str_twentysix str_twentyseven str_twentynine str_thirty str_thirtyone str_thirtythree str_thirtyfour str_thirtyfive str_thirtyseven str_thirtyeight str_forty str_fortyone str_fortythree str_fortyfour str_fortysix str_fortyseven str_fortynine str_fiftyone str_fiftythree - string
    host1_str - string
    host2_str - string
    host3_str - string
    host4_str - string
    host5_str - string
    host1_hostname - string
    host2_hostname - string
    host3_hostname - string
    host4_hostname - string
    host5_hostname - string
    rat_host1_ex_str - string
    host1_fqdn_str - string
    host2_fqdn_str - string
    host3_fqdn_str - string
    host4_fqdn_str - string
    host5_fqdn_str - string
    wilbur_cred_str - string
    pris_cred_str - string
    rick_cred_str - string
    rachael_cred_str - string
    roy_cred_str - string
    john_cred_str - string
    wilbur_sid - string
    pris_sid - string
    rick_sid - string
    rachael_sid - string
    roy_sid - string
    john_sid - string
    wilbur_name - string
    pris_name - string
    rick_name - string
    john_name - string
    roy_name - string
    rachael_name - string
    domain_str - string
    domain dom_one dom_four dom_seven dom_ten dom_thirteen - observeddomain
    rat_host1 rat_host2 rat_host3 rat_host4 rat_host5 - observedrat
    host1_td  - observedtimedelta
    host2_td - observedtimedelta
    host3_td - observedtimedelta
    host4_td - observedtimedelta
    host5_td - observedtimedelta
    host1_share - observedshare
    host2_share - observedshare
    host3_share - observedshare
    host4_share - observedshare
    host5_share - observedshare
    host1_num  - num
    host2_num - num
    host3_num - num
    host4_num - num
    host5_num - num
    host1_num2 - num
    host2_num2 - num
    host3_num2 - num
    host4_num2 - num
    host5_num2 - num
    wilbur rick rachael roy pris john user_thirtysix user_thirtynine user_fortytwo user_fortyfive - observeddomainuser
)
(:init (PROP_WINDOWS_DOMAIN dom_one str_two) (PROP_DNS_DOMAIN dom_one str_three) (PROP_WINDOWS_DOMAIN dom_four str_five) (PROP_DNS_DOMAIN dom_four str_six) (PROP_WINDOWS_DOMAIN dom_seven str_eight) (PROP_DNS_DOMAIN dom_seven str_nine) (PROP_WINDOWS_DOMAIN dom_ten str_eleven) (PROP_DNS_DOMAIN dom_ten str_twelve) (PROP_WINDOWS_DOMAIN dom_thirteen str_fourteen) (PROP_DNS_DOMAIN dom_thirteen str_fifteen) (PROP_DNS_DOMAIN_NAME host_sixteen str_seventeen) (PROP_FQDN host_sixteen str_eighteen) (PROP_DC host_sixteen no) (PROP_HOSTNAME host_sixteen str_nineteen) (PROP_DNS_DOMAIN_NAME host_twenty str_twentyone) (PROP_FQDN host_twenty str_twentytwo) (PROP_DC host_twenty no) (PROP_HOSTNAME host_twenty str_twentythree) (PROP_DNS_DOMAIN_NAME host_twentyfour str_twentyfive) (PROP_FQDN host_twentyfour str_twentysix) (PROP_DC host_twentyfour no) (PROP_HOSTNAME host_twentyfour str_twentyseven) (PROP_DNS_DOMAIN_NAME host_twentyeight str_twentynine) (PROP_FQDN host_twentyeight str_thirty) (PROP_DC host_twentyeight no) (PROP_HOSTNAME host_twentyeight str_thirtyone) (PROP_DNS_DOMAIN_NAME host_thirtytwo str_thirtythree) (PROP_FQDN host_thirtytwo str_thirtyfour) (PROP_DC host_thirtytwo no) (PROP_HOSTNAME host_thirtytwo str_thirtyfive) (PROP_SID user_thirtysix str_thirtyeight) (PROP_USERNAME user_thirtysix str_thirtyseven) (PROP_IS_GROUP user_thirtysix no) (PROP_SID user_thirtynine str_fortyone) (PROP_USERNAME user_thirtynine str_forty) (PROP_IS_GROUP user_thirtynine no) (PROP_SID user_fortytwo str_fortyfour) (PROP_USERNAME user_fortytwo str_fortythree) (PROP_IS_GROUP user_fortytwo no) (PROP_SID user_fortyfive str_fortyseven) (PROP_USERNAME user_fortyfive str_fortysix) (PROP_IS_GROUP user_fortyfive no) (PROP_PASSWORD cred_fortyeight str_fortynine) (PROP_PASSWORD cred_fifty str_fiftyone) (PROP_PASSWORD cred_fiftytwo str_fiftythree)
    (knows host1)
    (knows rat_host1)
    (knows_property host1 pfqdn)
    (knows_property rat_host1 pexecutable)
    (knows_property rat_host1 phost)
    (prop_elevated rat_host1 yes)
    (prop_executable rat_host1 rat_host1_ex_str)
    (prop_host rat_host1 host1)
    (MEM_CACHED_DOMAIN_CREDS host1 rick_cred)
    (MEM_CACHED_DOMAIN_CREDS host1 rachael_cred)
    (MEM_CACHED_DOMAIN_CREDS host2 roy_cred)
    (MEM_CACHED_DOMAIN_CREDS host2 wilbur_cred)
    (MEM_CACHED_DOMAIN_CREDS host4 john_cred)
    (MEM_CACHED_DOMAIN_CREDS host4 rachael_cred)
    (MEM_CACHED_DOMAIN_CREDS host5 pris_cred)
    (MEM_CACHED_DOMAIN_CREDS host3 roy_cred)
    (MEM_DOMAIN_USER_ADMINS host1 pris)
    (MEM_DOMAIN_USER_ADMINS host2 rick)
    (MEM_DOMAIN_USER_ADMINS host2 pris)
    (MEM_DOMAIN_USER_ADMINS host3 rachael)
    (MEM_DOMAIN_USER_ADMINS host4 roy)
    (MEM_DOMAIN_USER_ADMINS host5 wilbur)
    (MEM_DOMAIN_USER_ADMINS host5 pris)
    (mem_hosts domain host1)
    (mem_hosts domain host2)
    (mem_hosts domain host3)
    (mem_hosts domain host4)
    (mem_hosts domain host5)
    (prop_cred wilbur wilbur_cred)
    (prop_cred pris pris_cred)
    (prop_cred rick rick_cred)
    (prop_cred rachael rachael_cred)
    (prop_cred roy roy_cred)
    (prop_cred john john_cred)
    (prop_DC host1 no)
    (prop_DC host2 no)
    (prop_DC host3 no)
    (prop_DC host4 no)
    (prop_DC host5 no)
    (PROP_DNS_DOMAIN domain domain_str2)
    (PROP_DNS_DOMAIN_NAME host1 host1_str)
    (PROP_DNS_DOMAIN_NAME host2 host2_str)
    (PROP_DNS_DOMAIN_NAME host3 host3_str)
    (PROP_DNS_DOMAIN_NAME host4 host4_str)
    (PROP_DNS_DOMAIN_NAME host5 host5_str)
    (PROP_DOMAIN host1 domain)
    (PROP_DOMAIN host2 domain)
    (PROP_DOMAIN host3 domain)
    (PROP_DOMAIN host4 domain)
    (PROP_DOMAIN host5 domain)
    (PROP_DOMAIN wilbur domain)
    (PROP_DOMAIN pris domain)
    (PROP_DOMAIN rick domain)
    (PROP_DOMAIN rachael domain)
    (PROP_DOMAIN roy domain)
    (PROP_DOMAIN john domain)
    (PROP_DOMAIN wilbur_cred domain)
    (PROP_DOMAIN rick_cred domain)
    (PROP_DOMAIN pris_cred domain)
    (PROP_DOMAIN roy_cred domain)
    (PROP_DOMAIN john_cred domain)
    (PROP_DOMAIN rachael_cred domain)
    (PROP_FQDN host1 host1_fqdn_str)
    (PROP_FQDN host2 host2_fqdn_str)
    (PROP_FQDN host3 host3_fqdn_str)
    (PROP_FQDN host4 host4_fqdn_str)
    (PROP_FQDN host5 host5_fqdn_str)
    (prop_host host1_td host1)
    (prop_host host2_td host2)
    (prop_host host3_td host3)
    (prop_host host4_td host4)
    (prop_host host5_td host5)
    (PROP_HOSTNAME host1 host1_hostname)
    (PROP_HOSTNAME host2 host2_hostname)
    (PROP_HOSTNAME host3 host3_hostname)
    (PROP_HOSTNAME host4 host4_hostname)
    (PROP_HOSTNAME host5 host5_hostname)
    (PROP_IS_GROUP wilbur no)
    (PROP_IS_GROUP roy no)
    (PROP_IS_GROUP john no)
    (PROP_IS_GROUP rick no)
    (PROP_IS_GROUP rachael no)
    (PROP_IS_GROUP pris no)
    (PROP_MICROSECONDS host1_td host1_num)
    (PROP_MICROSECONDS host2_td host2_num)
    (PROP_MICROSECONDS host3_td host3_num)
    (PROP_MICROSECONDS host4_td host4_num)
    (PROP_MICROSECONDS host5_td host5_num)
    (PROP_PASSWORD wilbur_cred wilbur_cred_str)
    (PROP_PASSWORD pris_cred pris_cred_str)
    (PROP_PASSWORD roy_cred roy_cred_str)
    (PROP_PASSWORD rick_cred rick_cred_str)
    (PROP_PASSWORD john_cred john_cred_str)
    (PROP_PASSWORD rachael_cred rachael_cred_str)
    (PROP_SECONDS host1_td host1_num2)
    (PROP_SECONDS host2_td host2_num2)
    (PROP_SECONDS host3_td host3_num2)
    (PROP_SECONDS host4_td host4_num2)
    (PROP_SECONDS host5_td host5_num2)
    (PROP_SID rick rick_sid)
    (PROP_SID wilbur wilbur_sid)
    (PROP_SID roy roy_sid)
    (PROP_SID rachael rachael_sid)
    (PROP_SID pris pris_sid)
    (PROP_SID john john_sid)
    (PROP_TIMEDELTA host1 host1_td)
    (PROP_TIMEDELTA host2 host2_td)
    (PROP_TIMEDELTA host3 host3_td)
    (PROP_TIMEDELTA host4 host4_td)
    (PROP_TIMEDELTA host5 host5_td)
    (PROP_USER wilbur_cred wilbur)
    (PROP_USER roy_cred roy)
    (PROP_USER rachael_cred rachael)
    (PROP_USER pris_cred pris)
    (PROP_USER john_cred john)
    (PROP_USER rick_cred rick)
    (PROP_USERNAME rick rick_name)
    (PROP_USERNAME wilbur wilbur_name)
    (PROP_USERNAME roy roy_name)
    (PROP_USERNAME john john_name)
    (PROP_USERNAME rachael rachael_name)
    (PROP_USERNAME pris pris_name)
    (PROP_WINDOWS_DOMAIN domain domain_str)
)
(:goal
(and
    (prop_host rat_host2 host2)
    (prop_host rat_host3 host3)
    (prop_host rat_host4 host4)
    (prop_host rat_host5 host5)
)
)
)
