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

#ifndef _H_NODETUNTAP_MODULE
#define _H_NODETUNTAP_MODULE

#include <node.h>
#include <node_buffer.h>
#include <node_object_wrap.h>
#include <uv.h>

#include <deque>
#include <string>
#include <map>

#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <cerrno>
#include <cmath>

#include <sys/types.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <linux/fs.h>
#include <endian.h>

#include "ethertypes.hh"
#include "tuntap.hh"

#define TT_THROW(str) \
	isolate->ThrowException(Exception::Error(String::NewFromUtf8(isolate, str)))

#define TT_THROW_TYPE(str) \
	isolate->ThrowException(Exception::TypeError(String::NewFromUtf8(isolate, str)))

#define NVM_NEW_INSTANCE(target, isolate, argc, argv) ( \
	(target) \
	->NewInstance(isolate->GetCurrentContext(), argc, argv) \
	.FromMaybe(Local<Object>()) \
)

#endif
