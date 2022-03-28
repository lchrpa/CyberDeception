;Copyright 2018 The MITRE Corporation. All rights reserved.
; NOT FOR PUBLIC RELEASE. DO NOT REDISTRIBUTE.
; For more information on CALDERA, the automated adversary emulation system, visit https://github.com/mitre/caldera or email attack@mitre.org
; This has 4 hosts, 8 user, 2 admin per host, 2 active account per host
(define (problem p4_hosts_trial_16)
(:domain caldera)
(:objects
    id_bfdomaincredential id_bbdomaincredential id_tdomaincredential id_xdomaincredential id_pdomaincredential id_ddomaincredential id_ldomaincredential id_hdomaincredential cred_four - observeddomaincredential
    id_bihost id_cdhost id_bwhost id_bphost  - observedhost
    id_ctschtask id_crschtask id_csschtask id_cqschtask - observedschtask
    id_dbfile id_czfile id_dafile id_cyfile - observedfile
    str__patricia str__bg str__v str__cc str__f str__bd str__u str__robert str__q str__james str__linda str__bt str__barbara str__ci str__m str__cb str__cj str__ca str__mary str__bu str__alpha str__j str__bv str__ch str__n str__z str__bh str__bm str__r str__b str__bn str__i str__bc str__michael str__john str__bo str__y str__cl str__e str_two str_three str_five str_seven str_eight - string
    id_adomain dom_six - observeddomain
    id_ckrat id_corat id_cprat id_cnrat id_cmrat - observedrat
    id_cetimedelta id_bjtimedelta id_bqtimedelta id_bxtimedelta  - observedtimedelta
    id_cwshare id_cushare id_cxshare id_cvshare - observedshare
    num__43 num__51 num__44 num__58 num__57 num__36 num__50 num__37  - num
    id_badomainuser id_bedomainuser id_sdomainuser id_wdomainuser id_kdomainuser id_gdomainuser id_odomainuser id_cdomainuser user_one - observeddomainuser
)
(:init (PROP_SID user_one str_three) (PROP_USERNAME user_one str_two) (PROP_IS_GROUP user_one no) (PROP_PASSWORD cred_four str_five) (PROP_WINDOWS_DOMAIN dom_six str_seven) (PROP_DNS_DOMAIN dom_six str_eight) (PROP_USER cred_four user_one) (prop_cred user_one cred_four) (PROP_DOMAIN cred_four id_adomain) (PROP_DOMAIN user_one id_adomain) (PROP_DOMAIN cred_four dom_six) (PROP_DOMAIN user_one dom_six) (MEM_CACHED_DOMAIN_CREDS id_bphost cred_four) (mem_hosts dom_six id_bphost) (PROP_DOMAIN id_bphost dom_six) (MEM_CACHED_DOMAIN_CREDS id_bihost cred_four) (mem_hosts dom_six id_bihost) (PROP_DOMAIN id_bihost dom_six) (MEM_CACHED_DOMAIN_CREDS id_bwhost cred_four) (mem_hosts dom_six id_bwhost) (PROP_DOMAIN id_bwhost dom_six)
    (not (ransomed id_bihost))
    (not (ransomed id_cdhost))
    (not (ransomed id_bwhost))
    (not (ransomed id_bphost))
    (knows id_cdhost)
    (knows id_ckrat)
    (knows_property id_cdhost pfqdn)
    (knows_property id_ckrat pexecutable)
    (knows_property id_ckrat phost)
    (MEM_CACHED_DOMAIN_CREDS id_bihost id_tdomaincredential)
    (MEM_CACHED_DOMAIN_CREDS id_bihost id_xdomaincredential)
    (MEM_CACHED_DOMAIN_CREDS id_bphost id_ldomaincredential)
    (MEM_CACHED_DOMAIN_CREDS id_bphost id_xdomaincredential)
    (MEM_CACHED_DOMAIN_CREDS id_bwhost id_ddomaincredential)
    (MEM_CACHED_DOMAIN_CREDS id_bwhost id_hdomaincredential)
    (MEM_CACHED_DOMAIN_CREDS id_cdhost id_hdomaincredential)
    (MEM_CACHED_DOMAIN_CREDS id_cdhost id_xdomaincredential)
    (MEM_DOMAIN_USER_ADMINS id_bihost id_gdomainuser)
    (MEM_DOMAIN_USER_ADMINS id_bihost id_odomainuser)
    (MEM_DOMAIN_USER_ADMINS id_bphost id_kdomainuser)
    (MEM_DOMAIN_USER_ADMINS id_bphost id_sdomainuser)
    (MEM_DOMAIN_USER_ADMINS id_bwhost id_gdomainuser)
    (MEM_DOMAIN_USER_ADMINS id_bwhost id_odomainuser)
    (MEM_DOMAIN_USER_ADMINS id_cdhost id_badomainuser)
    (MEM_DOMAIN_USER_ADMINS id_cdhost id_sdomainuser)
    (mem_hosts id_adomain id_bihost)
    (mem_hosts id_adomain id_bphost)
    (mem_hosts id_adomain id_bwhost)
    (mem_hosts id_adomain id_cdhost)
    (prop_cred id_badomainuser id_bbdomaincredential)
    (prop_cred id_bedomainuser id_bfdomaincredential)
    (prop_cred id_cdomainuser id_ddomaincredential)
    (prop_cred id_gdomainuser id_hdomaincredential)
    (prop_cred id_kdomainuser id_ldomaincredential)
    (prop_cred id_odomainuser id_pdomaincredential)
    (prop_cred id_sdomainuser id_tdomaincredential)
    (prop_cred id_wdomainuser id_xdomaincredential)
    (PROP_DC id_bihost no)
    (PROP_DC id_bphost no)
    (PROP_DC id_bwhost no)
    (PROP_DC id_cdhost no)
    (PROP_DNS_DOMAIN id_adomain str__b)
    (PROP_DNS_DOMAIN_NAME id_bihost str__bm)
    (PROP_DNS_DOMAIN_NAME id_bphost str__bt)
    (PROP_DNS_DOMAIN_NAME id_bwhost str__ca)
    (PROP_DNS_DOMAIN_NAME id_cdhost str__ch)
    (PROP_DOMAIN id_badomainuser id_adomain)
    (PROP_DOMAIN id_bbdomaincredential id_adomain)
    (PROP_DOMAIN id_bedomainuser id_adomain)
    (PROP_DOMAIN id_bfdomaincredential id_adomain)
    (PROP_DOMAIN id_bihost id_adomain)
    (PROP_DOMAIN id_bphost id_adomain)
    (PROP_DOMAIN id_bwhost id_adomain)
    (PROP_DOMAIN id_cdomainuser id_adomain)
    (PROP_DOMAIN id_cdhost id_adomain)
    (PROP_DOMAIN id_ddomaincredential id_adomain)
    (PROP_DOMAIN id_gdomainuser id_adomain)
    (PROP_DOMAIN id_hdomaincredential id_adomain)
    (PROP_DOMAIN id_kdomainuser id_adomain)
    (PROP_DOMAIN id_ldomaincredential id_adomain)
    (PROP_DOMAIN id_odomainuser id_adomain)
    (PROP_DOMAIN id_pdomaincredential id_adomain)
    (PROP_DOMAIN id_sdomainuser id_adomain)
    (PROP_DOMAIN id_tdomaincredential id_adomain)
    (PROP_DOMAIN id_wdomainuser id_adomain)
    (PROP_DOMAIN id_xdomaincredential id_adomain)
    (prop_elevated id_ckrat yes)
    (prop_executable id_ckrat str__cl)
    (PROP_FQDN id_bihost str__bn)
    (PROP_FQDN id_bphost str__bu)
    (PROP_FQDN id_bwhost str__cb)
    (PROP_FQDN id_cdhost str__ci)
    (prop_host id_bjtimedelta id_bihost)
    (prop_host id_bqtimedelta id_bphost)
    (prop_host id_bxtimedelta id_bwhost)
    (prop_host id_cetimedelta id_cdhost)
    (prop_host id_ckrat id_cdhost)
    (PROP_HOSTNAME id_bihost str__bo)
    (PROP_HOSTNAME id_bphost str__bv)
    (PROP_HOSTNAME id_bwhost str__cc)
    (PROP_HOSTNAME id_cdhost str__cj)
    (PROP_IS_GROUP id_badomainuser no)
    (PROP_IS_GROUP id_bedomainuser no)
    (PROP_IS_GROUP id_cdomainuser no)
    (PROP_IS_GROUP id_gdomainuser no)
    (PROP_IS_GROUP id_kdomainuser no)
    (PROP_IS_GROUP id_odomainuser no)
    (PROP_IS_GROUP id_sdomainuser no)
    (PROP_IS_GROUP id_wdomainuser no)
    (PROP_MICROSECONDS id_bjtimedelta num__36)
    (PROP_MICROSECONDS id_bqtimedelta num__43)
    (PROP_MICROSECONDS id_bxtimedelta num__50)
    (PROP_MICROSECONDS id_cetimedelta num__57)
    (PROP_PASSWORD id_bbdomaincredential str__bc)
    (PROP_PASSWORD id_bfdomaincredential str__bg)
    (PROP_PASSWORD id_ddomaincredential str__e)
    (PROP_PASSWORD id_hdomaincredential str__i)
    (PROP_PASSWORD id_ldomaincredential str__m)
    (PROP_PASSWORD id_pdomaincredential str__q)
    (PROP_PASSWORD id_tdomaincredential str__u)
    (PROP_PASSWORD id_xdomaincredential str__y)
    (PROP_SECONDS id_bjtimedelta num__37)
    (PROP_SECONDS id_bqtimedelta num__44)
    (PROP_SECONDS id_bxtimedelta num__51)
    (PROP_SECONDS id_cetimedelta num__58)
    (PROP_SID id_badomainuser str__bd)
    (PROP_SID id_bedomainuser str__bh)
    (PROP_SID id_cdomainuser str__f)
    (PROP_SID id_gdomainuser str__j)
    (PROP_SID id_kdomainuser str__n)
    (PROP_SID id_odomainuser str__r)
    (PROP_SID id_sdomainuser str__v)
    (PROP_SID id_wdomainuser str__z)
    (PROP_TIMEDELTA id_bihost id_bjtimedelta)
    (PROP_TIMEDELTA id_bphost id_bqtimedelta)
    (PROP_TIMEDELTA id_bwhost id_bxtimedelta)
    (PROP_TIMEDELTA id_cdhost id_cetimedelta)
    (PROP_USER id_bbdomaincredential id_badomainuser)
    (PROP_USER id_bfdomaincredential id_bedomainuser)
    (PROP_USER id_ddomaincredential id_cdomainuser)
    (PROP_USER id_hdomaincredential id_gdomainuser)
    (PROP_USER id_ldomaincredential id_kdomainuser)
    (PROP_USER id_pdomaincredential id_odomainuser)
    (PROP_USER id_tdomaincredential id_sdomainuser)
    (PROP_USER id_xdomaincredential id_wdomainuser)
    (PROP_USERNAME id_badomainuser str__michael)
    (PROP_USERNAME id_bedomainuser str__barbara)
    (PROP_USERNAME id_cdomainuser str__james)
    (PROP_USERNAME id_gdomainuser str__mary)
    (PROP_USERNAME id_kdomainuser str__john)
    (PROP_USERNAME id_odomainuser str__patricia)
    (PROP_USERNAME id_sdomainuser str__robert)
    (PROP_USERNAME id_wdomainuser str__linda)
    (PROP_WINDOWS_DOMAIN id_adomain str__alpha)
)
(:goal
(and
    (ransomed id_bihost)
    (ransomed id_cdhost)
    (ransomed id_bwhost)
    (ransomed id_bphost)
)
)
)
