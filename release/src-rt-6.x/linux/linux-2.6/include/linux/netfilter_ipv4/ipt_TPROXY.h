#ifndef _IPT_TPROXY_H_target
#define _IPT_TPROXY_H_target

struct ipt_tproxy_target_info {
	u_int16_t lport;
	u_int32_t laddr;
};

#endif
