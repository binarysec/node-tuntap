/*
 * Copyright (c) 2010-2014 BinarySEC SAS
 * Tuntap binding for nodejs [http://www.binarysec.com]
 * 
 * This file is part of Gate.js.
 * 
 * Gate.js is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#ifndef _H_NODETUNTAP_TUNTAP_ITF
#define _H_NODETUNTAP_TUNTAP_ITF

#include <string>
#include <vector>

#define TUNTAP_DFT_PATH			"/dev/net/tun"
#define TUNTAP_DFT_MTU			1500
#define TUNTAP_DFT_PERSIST		true
#define TUNTAP_DFT_UP			true
#define TUNTAP_DFT_RUNNING		true

enum tuntap_etcomp_t {
	TUNTAP_ETCOMP_NONE,
	TUNTAP_ETCOMP_HALF,
	TUNTAP_ETCOMP_FULL,
};

struct tuntap_itf_opts_t {
	tuntap_itf_opts_t() :
		mode(MODE_TUN),
		mtu(TUNTAP_DFT_MTU),
		is_persistant(TUNTAP_DFT_PERSIST),
		is_up(TUNTAP_DFT_UP),
		is_running(TUNTAP_DFT_RUNNING),
		ethtype_comp(TUNTAP_ETCOMP_NONE)
	{}
	
	enum option_e {
		OPT_ADDR,
		OPT_DEST,
		OPT_MASK,
		OPT_MTU,
		OPT_PERSIST,
		OPT_UP,
		OPT_RUNNING,
	};
	
	enum {
		MODE_TUN,
		MODE_TAP,
	} mode;
	
	std::string itf_name;
	std::string addr;
	std::string dest;
	std::string mask;
	int mtu;
	bool is_persistant;
	bool is_up;
	bool is_running;
	tuntap_etcomp_t ethtype_comp;
};

bool tuntapItfCreate(tuntap_itf_opts_t &opts, int *fd, std::string *err);
bool tuntapItfSet(const std::vector<tuntap_itf_opts_t::option_e> &options, const tuntap_itf_opts_t &data, std::string *err);

#endif