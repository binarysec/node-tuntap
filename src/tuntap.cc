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

#include "module.hh"

using namespace v8;

Persistent<Function> Tuntap::constructor;

Tuntap::Tuntap() :
	fd(-1),
	mode(MODE_TUN),
	mtu(TUNTAP_DFT_MTU),
	is_persistant(TUNTAP_DFT_PERSIST),
	is_up(TUNTAP_DFT_UP),
	is_running(TUNTAP_DFT_RUNNING),
	ethtype_comp(TUNTAP_ETCOMP_NONE),
	read_buff(NULL),
	is_reading(true),
	is_writing(false)
{}

Tuntap::~Tuntap() {
	if(this->fd >= 0) {
		::close(this->fd);
		uv_poll_stop(&this->uv_handle_);
	}
	if(this->read_buff)
		delete[] this->read_buff;
}

void Tuntap::Init(Handle<Object> module) {
	Isolate* isolate = Isolate::GetCurrent();
	
	// Prepare constructor template
	Local<FunctionTemplate> tpl = FunctionTemplate::New(isolate, New);
	tpl->SetClassName(String::NewFromUtf8(isolate, "tuntap"));
	tpl->InstanceTemplate()->SetInternalFieldCount(1);
	
	// Prototype
#define SETFUNC(_name_) \
	NODE_SET_PROTOTYPE_METHOD(tpl, #_name_, _name_);
	SETFUNC(writeBuffer)
	SETFUNC(open)
	SETFUNC(close)
	SETFUNC(set)
	SETFUNC(unset)
	SETFUNC(stopRead)
	SETFUNC(startRead)
	
#undef SETFUNC
	
	constructor.Reset(isolate, tpl->GetFunction());
	
	module->Set(String::NewFromUtf8(isolate, "exports"), tpl->GetFunction());
}

void Tuntap::New(const FunctionCallbackInfo<Value>& args) {
	Isolate* isolate = Isolate::GetCurrent();
	HandleScope scope(isolate);
	bool ret;
	std::string err_str;
	Local<Object> main_obj;
	Tuntap* obj;
	
	if(args.IsConstructCall()) {
		// Invoked as constructor: `new Tuntap(...)`
		obj = new Tuntap();
		obj->Wrap(args.This());
		if(args[0]->IsObject()) {
			main_obj = args[0]->ToObject();
			ret = obj->construct(main_obj, err_str);
			if(ret == false) {
				obj->fd = -1;
				TT_THROW(err_str.c_str());
				return;
			}
		}
		
		args.GetReturnValue().Set(args.This());
	}
	else {
		// Invoked as plain function `Tuntap(...)`, turn into construct call.
		const int argc = 1;
		Local<Value> argv[argc] = { args[0] };
		Local<Function> cons = Local<Function>::New(isolate, constructor);
		args.GetReturnValue().Set(cons->NewInstance(argc, argv));
	}
}

bool Tuntap::construct(Handle<Object> main_obj, std::string &error) {
	Isolate* isolate = Isolate::GetCurrent();
	HandleScope scope(isolate);
	Local<Array> keys_arr;
	Local<Value> key;
	Local<Value> val;
	
	this->objset(main_obj);
	
	#define RETURN(_e) { error = std::string(_e) + " : " + strerror(errno); return(false); }
	
	#define MK_IOCTL(fd, opt, data) {\
		if(Tuntap::do_ioctl(fd, opt, data) == false) \
			RETURN("Error calling ioctl (" #opt ")") \
	}
	
	#define MK_IFREQ_ADDR_IOCTL(fd, ifr_field, this_field, opt) \
	if(Tuntap::do_ifreq(fd, &ifr, &ifr.ifr_field, this->this_field, 0, opt) == false) \
		RETURN("Error calling ioctl (" #opt ")") \
	
	struct ifreq ifr;
	int tun_sock;
	
	/* First open the device */
	if((this->fd = ::open(TUNTAP_DFT_PATH, O_RDWR)) < 0)
		RETURN("Cannot open " TUNTAP_DFT_PATH)
	
	Tuntap::ifreq_prep(&ifr, this->itf_name.c_str());
	
	if(this->mode == MODE_TUN)
		ifr.ifr_flags |= IFF_TUN;
	else if(this->mode == MODE_TAP)
		ifr.ifr_flags |= IFF_TAP;
	
	if(this->itf_name.size() > 0)
		MK_IOCTL(this->fd, TUNSETIFF, &ifr)
	
	MK_IOCTL(this->fd, TUNGETIFF, &ifr)
	if(strlen(ifr.ifr_name) > 0)
		this->itf_name = ifr.ifr_name;
	
	MK_IOCTL(this->fd, TUNSETPERSIST, this->is_persistant?1:0)
	
	/* Then open a socket to change device parameters */
	tun_sock = socket(AF_INET, SOCK_DGRAM, 0);
	if(tun_sock < 0)
		RETURN("Call of socket() failed!");
	
	ifr.ifr_mtu = this->mtu;
	MK_IOCTL(tun_sock, SIOCSIFMTU, &ifr)
	
	if(this->addr.size() > 0) {
		MK_IFREQ_ADDR_IOCTL(tun_sock, ifr_addr, addr, SIOCSIFADDR)
		MK_IFREQ_ADDR_IOCTL(tun_sock, ifr_netmask, mask, SIOCSIFNETMASK)
		MK_IFREQ_ADDR_IOCTL(tun_sock, ifr_dstaddr, dest, SIOCSIFDSTADDR)
	}
	
	ifr.ifr_flags |= (this->is_up ? IFF_UP : 0) | (this->is_running ? IFF_RUNNING : 0);
	MK_IOCTL(tun_sock, SIOCSIFFLAGS, &ifr)
	
	::close(tun_sock);
	
	this->read_buff = new unsigned char[this->mtu + 4];
	
	#undef RETURN
	#undef MK_IOCTL
	#undef MK_IFREQ_ADDR_IOCTL
	
	uv_poll_init(uv_default_loop(), &this->uv_handle_, this->fd);
	this->uv_handle_.data = this;
	uv_poll_start(&this->uv_handle_, UV_READABLE, uv_event_cb);
	
	return(true);
}

void Tuntap::writeBuffer(const FunctionCallbackInfo<Value>& args) {
	Isolate* isolate = Isolate::GetCurrent();
	HandleScope scope(isolate);
	Tuntap *obj = ObjectWrap::Unwrap<Tuntap>(args.This());
	Buffer *wbuff;
	unsigned char *data;
	size_t data_length;
	Local<Value> in_buff;
	
	if(obj->fd == -1) {
		TT_THROW_TYPE("Object is closed and cannot be written!");
		return;
	}
	
	if(args.Length() != 1) {
		TT_THROW_TYPE("Wrong number of arguments");
		return;
	}
	
	if(!args[0]->IsObject()) {
		TT_THROW_TYPE("Wrong argument type");
		return;
	}
	
	in_buff = args[0];
	
	if(!node::Buffer::HasInstance(in_buff)) {
		TT_THROW_TYPE("Wrong argument type");
		return;
	}
	
	in_buff = args[0];
	
	data = reinterpret_cast<unsigned char*>(node::Buffer::Data(in_buff));
	data_length = node::Buffer::Length(in_buff);
	
	if(obj->ethtype_comp == TUNTAP_ETCOMP_NONE) {
		wbuff = new Buffer(data, data_length);
	}
	else if(obj->ethtype_comp == TUNTAP_ETCOMP_HALF) {
		wbuff = new Buffer(data_length + 2);
		wbuff->data[0] = 0;
		wbuff->data[1] = 0;
		memcpy(
			wbuff->data + 2,
			data,
			data_length
		);
	}
	else if(obj->ethtype_comp == TUNTAP_ETCOMP_FULL) {
		uint32_t type = htobe32(EtherTypes::getType(data[0]));
		wbuff = new Buffer(data_length + 3);
		memcpy(
			wbuff->data,
			&type,
			4
		);
		memcpy(
			wbuff->data + 4,
			data + 1,
			data_length - 1
		);
	}
	else {
		wbuff = new Buffer(data, data_length);
	}
	
	obj->writ_buff.push_back(wbuff);
	obj->set_write(true);
	
	args.GetReturnValue().Set(args.This());
}
void Tuntap::open(const FunctionCallbackInfo<Value>& args) {
	Isolate* isolate = Isolate::GetCurrent();
	HandleScope scope(isolate);
	Local<Object> main_obj = Object::New(isolate);
	std::string err_str;
	Tuntap *obj = ObjectWrap::Unwrap<Tuntap>(args.This());
	bool ret;
	
	if(obj->fd != -1) {
		TT_THROW_TYPE("You need to close the tunnel before opening it back!");
		return;
	}
	
	if(args.Length() > 0) {
		if(!args[0]->IsObject()) {
			TT_THROW_TYPE("Wrong argument type");
			return;
		}
		
		main_obj = args[0]->ToObject();
	}
	
	ret = obj->construct(main_obj, err_str);
	if(ret == false) {
		obj->fd = -1;
		TT_THROW_TYPE(err_str.c_str());
		return;
	}
	
	args.GetReturnValue().Set(args.This());
}
 
void Tuntap::close(const FunctionCallbackInfo<Value>& args) {
	Isolate* isolate = Isolate::GetCurrent();
	HandleScope scope(isolate);
	Tuntap *obj = ObjectWrap::Unwrap<Tuntap>(args.This());
	
	if(obj->fd == -1) {
		TT_THROW_TYPE("The tunnel is already closed!");
		return;
	}
	
	uv_poll_stop(&obj->uv_handle_);
	::close(obj->fd);
	obj->fd = -1;
	delete[] obj->read_buff;
	obj->read_buff = NULL;
	
	args.GetReturnValue().Set(args.This());
}

void Tuntap::set(const FunctionCallbackInfo<Value>& args) {
	Isolate* isolate = Isolate::GetCurrent();
	HandleScope scope(isolate);
	Tuntap *obj = ObjectWrap::Unwrap<Tuntap>(args.This());
	Local<Array> keys_arr;
	Local<Value> key;
	Local<Value> val;
	Local<Object> main_obj;
	struct ifreq ifr;
	int tun_sock;
	
	if(!args[0]->IsObject()) {
		TT_THROW_TYPE("Invalid argument type");
		return;
	}
	
	Tuntap::ifreq_prep(&ifr, obj->itf_name.c_str());
	
	tun_sock = socket(AF_INET, SOCK_DGRAM, 0);
	if(tun_sock < 0) {
		TT_THROW_TYPE("Call of socket() failed!");
		return;
	}
	
	main_obj = args[0]->ToObject();
	
	if(main_obj->Has(String::NewFromUtf8(isolate, "type")) || main_obj->Has(String::NewFromUtf8(isolate, "name"))) {
		TT_THROW_TYPE("Cannot set name and type from this function!");
		return;
	}
	
	obj->objset(main_obj);
	
	keys_arr = main_obj->GetPropertyNames();
	for (unsigned int i = 0, limiti = keys_arr->Length(); i < limiti; i++) {
		key = keys_arr->Get(i);
		val = main_obj->Get(key);
		String::Utf8Value key_str(key->ToString());
		
		if(strcmp(*key_str, "addr") == 0) {
			String::Utf8Value val_str(val->ToString());
			obj->addr = *val_str;
			if(obj->fd)
				Tuntap::do_ifreq(tun_sock, &ifr, &ifr.ifr_addr, obj->addr.c_str(), 0, SIOCSIFADDR);
		}
		else if(strcmp(*key_str, "mask") == 0) {
			String::Utf8Value val_str(val->ToString());
			obj->mask = *val_str;
			if(obj->fd)
				Tuntap::do_ifreq(tun_sock, &ifr, &ifr.ifr_netmask, obj->mask.c_str(), 0, SIOCSIFNETMASK);
		}
		else if(strcmp(*key_str, "dest") == 0) {
			String::Utf8Value val_str(val->ToString());
			obj->dest = *val_str;
			if(obj->fd)
				Tuntap::do_ifreq(tun_sock, &ifr, &ifr.ifr_dstaddr, obj->dest.c_str(), 0, SIOCSIFDSTADDR);
		}
		else if(strcmp(*key_str, "mtu") == 0) {
			int val_int(val->ToInteger()->Value());
			obj->mtu = val_int;
			if(obj->fd)
				Tuntap::do_ioctl(tun_sock, SIOCSIFMTU, obj->mtu);
		}
		else if(strcmp(*key_str, "persist") == 0) {
			bool val_bool(val->ToBoolean()->Value());
			obj->is_persistant = val_bool;
			if(obj->fd)
				Tuntap::do_ioctl(tun_sock, TUNSETPERSIST, obj->is_persistant?1:0);
		}
		else if(strcmp(*key_str, "up") == 0) {
			bool val_bool(val->ToBoolean()->Value());
			obj->is_up = val_bool;
			
			if(obj->fd) {
				Tuntap::do_ioctl(tun_sock, SIOCGIFFLAGS, &ifr);
				if(obj->is_up)
					ifr.ifr_flags |= IFF_UP;
				else
					ifr.ifr_flags &= ~(IFF_UP);
				Tuntap::do_ioctl(tun_sock, SIOCSIFFLAGS, &ifr);
			}
		}
		else if(strcmp(*key_str, "running") == 0) {
			bool val_bool(val->ToBoolean()->Value());
			obj->is_running = val_bool;
			
			if(obj->fd) {
				Tuntap::do_ioctl(tun_sock, SIOCGIFFLAGS, &ifr);
				if(obj->is_running)
					ifr.ifr_flags |= IFF_RUNNING;
				else
					ifr.ifr_flags &= ~(IFF_RUNNING);
				Tuntap::do_ioctl(tun_sock, SIOCSIFFLAGS, &ifr);
			}
		}
		else if(strcmp(*key_str, "ethtype_comp") == 0) {
			String::Utf8Value val_str(val->ToString());
			
			if(strcmp(*val_str, "none") == 0)
				obj->ethtype_comp = TUNTAP_ETCOMP_NONE;
			else if(strcmp(*val_str, "half") == 0)
				obj->ethtype_comp = TUNTAP_ETCOMP_HALF;
			else if(strcmp(*val_str, "full") == 0)
				obj->ethtype_comp = TUNTAP_ETCOMP_FULL;
		}
	}
	
	::close(tun_sock);
	
	args.GetReturnValue().Set(args.This());
}

void Tuntap::unset(const FunctionCallbackInfo<Value>& args) {
	Isolate* isolate = Isolate::GetCurrent();
	HandleScope scope(isolate);
	Tuntap *obj = ObjectWrap::Unwrap<Tuntap>(args.This());
	Local<Array> keys_arr;
	Local<Value> val;
	struct ifreq ifr;
	int tun_sock;
	
	if(!args[0]->IsArray()) {
		TT_THROW_TYPE("Invalid argument type");
		return;
	}
	
	Tuntap::ifreq_prep(&ifr, obj->itf_name.c_str());
	
	tun_sock = socket(AF_INET, SOCK_DGRAM, 0);
	if(tun_sock < 0) {
		TT_THROW_TYPE("Call of socket() failed!");
		return;
	}
	
	keys_arr = args[0].As<Array>();
	
	for (unsigned int i = 0, limiti = keys_arr->Length(); i < limiti; i++) {
		val = keys_arr->Get(i);
		String::Utf8Value val_str(val->ToString());
		
		if(strcmp(*val_str, "addr") == 0) {
			obj->addr = "";
			if(obj->fd)
				Tuntap::do_ifreq(tun_sock, &ifr, &ifr.ifr_addr, "0.0.0.0", 0, SIOCSIFADDR);
		}
		else if(strcmp(*val_str, "mtu") == 0) {
			obj->mtu = TUNTAP_DFT_MTU;
			ifr.ifr_mtu = obj->mtu;
			if(obj->fd)
				Tuntap::do_ioctl(tun_sock, SIOCSIFMTU, &ifr);
		}
		else if(strcmp(*val_str, "persist") == 0) {
			obj->is_persistant = TUNTAP_DFT_PERSIST;
			if(obj->fd)
				Tuntap::do_ioctl(obj->fd, TUNSETPERSIST, obj->is_persistant?1:0);
		}
		else if(strcmp(*val_str, "up") == 0) {
			obj->is_up = TUNTAP_DFT_UP;
			if(obj->fd) {
				Tuntap::do_ioctl(tun_sock, SIOCGIFFLAGS, &ifr);
				if(obj->is_up)
					ifr.ifr_flags |= IFF_UP;
				else
					ifr.ifr_flags &= ~(IFF_UP);
				Tuntap::do_ioctl(tun_sock, SIOCSIFFLAGS, &ifr);
			}
		}
		else if(strcmp(*val_str, "running") == 0) {
			obj->is_running = TUNTAP_DFT_RUNNING;
			if(obj->fd) {
				Tuntap::do_ioctl(tun_sock, SIOCGIFFLAGS, &ifr);
				if(obj->is_up)
					ifr.ifr_flags |= IFF_RUNNING;
				else
					ifr.ifr_flags &= ~(IFF_RUNNING);
				Tuntap::do_ioctl(tun_sock, SIOCSIFFLAGS, &ifr);
			}
		}
		else if(strcmp(*val_str, "ethtype_comp") == 0) {
			obj->ethtype_comp = TUNTAP_ETCOMP_NONE;
		}
	}
	
	::close(tun_sock);
	
	args.GetReturnValue().Set(args.This());
}

void Tuntap::stopRead(const FunctionCallbackInfo<Value>& args) {
	Isolate* isolate = Isolate::GetCurrent();
	HandleScope scope(isolate);
	Tuntap *obj = ObjectWrap::Unwrap<Tuntap>(args.This());
	
	obj->set_read(false);
	
	args.GetReturnValue().Set(args.This());
}

void Tuntap::startRead(const FunctionCallbackInfo<Value>& args) {
	Isolate* isolate = Isolate::GetCurrent();
	HandleScope scope(isolate);
	Tuntap *obj = ObjectWrap::Unwrap<Tuntap>(args.This());
	
	obj->set_read(true);
	
	args.GetReturnValue().Set(args.This());
}

void Tuntap::objset(Handle<Object> obj) {
	Local<Array> keys_arr;
	Local<Value> key;
	Local<Value> val;
	
	keys_arr = obj->GetPropertyNames();
	for (unsigned int i = 0, limiti = keys_arr->Length(); i < limiti; i++) {
		key = keys_arr->Get(i);
		val = obj->Get(key);
		String::Utf8Value key_str(key->ToString());
		String::Utf8Value val_str(val->ToString());
		
		if(strcmp(*key_str, "type") == 0) {
			if(strcmp(*val_str, "tun") == 0) {
				this->mode = MODE_TUN;
			}
			else if(strcmp(*val_str, "tap") == 0) {
				this->mode = MODE_TAP;
			}
		}
		else if(strcmp(*key_str, "name") == 0) {
			this->itf_name = *val_str;
		}
		else if(strcmp(*key_str, "addr") == 0) {
			this->addr = *val_str;
		}
		else if(strcmp(*key_str, "mask") == 0) {
			this->mask = *val_str;
		}
		else if(strcmp(*key_str, "dest") == 0) {
			this->dest = *val_str;
		}
		else if(strcmp(*key_str, "mtu") == 0) {
			this->mtu = val->ToInteger()->Value();
			if(this->mtu <= 50)
				this->mtu = 50;
		}
		else if(strcmp(*key_str, "persist") == 0) {
			this->is_persistant = val->ToBoolean()->Value();
		}
		else if(strcmp(*key_str, "up") == 0) {
			this->is_up = val->ToBoolean()->Value();
		}
		else if(strcmp(*key_str, "running") == 0) {
			this->is_running = val->ToBoolean()->Value();
		}
		else if(strcmp(*key_str, "ethtype_comp") == 0) {
			String::Utf8Value val_str(val->ToString());
			
			if(strcmp(*val_str, "none") == 0)
				this->ethtype_comp = TUNTAP_ETCOMP_NONE;
			else if(strcmp(*val_str, "half") == 0)
				this->ethtype_comp = TUNTAP_ETCOMP_HALF;
			else if(strcmp(*val_str, "full") == 0)
				this->ethtype_comp = TUNTAP_ETCOMP_FULL;
		}
	}
}

void Tuntap::ifreq_prep(struct ifreq *ifr, const char *itf_name) {
	memset(ifr, 0, sizeof(*ifr));
	
	if(itf_name != NULL) {
		int len = strlen(itf_name);
		if(len > 0) {
			strncpy(
				ifr->ifr_name,
				itf_name,
				(IFNAMSIZ < len ? IFNAMSIZ : len)
			);
		}
	}
}

void Tuntap::uv_event_cb(uv_poll_t* handle, int status, int events) {
	Tuntap *obj = static_cast<Tuntap*>(handle->data);
	
	if(events | UV_READABLE) {
		obj->do_read();
	}
	
	if(events | UV_WRITABLE) {
		obj->do_write();
	}
}

void Tuntap::set_read(bool r) {
	if(r != this->is_reading) {
		this->is_reading = r;
		uv_poll_start(
			&this->uv_handle_,
			(this->is_reading ? UV_READABLE : 0) | (this->is_writing ? UV_WRITABLE : 0),
			uv_event_cb
		);
	}
}

void Tuntap::set_write(bool w) {
	if(w != this->is_writing) {
		this->is_writing = w;
		uv_poll_start(
			&this->uv_handle_,
			(this->is_reading ? UV_READABLE : 0) | (this->is_writing ? UV_WRITABLE : 0),
			uv_event_cb
		);
	}
}


void Tuntap::do_read() {
	Isolate* isolate = Isolate::GetCurrent();
	HandleScope scope(isolate);
	
	Local<Object> ret_buff;
	int ret;
	
	ret = read(this->fd, this->read_buff, this->mtu + 4);
	
	if(ret <= 0) {
		printf("PHAYL1\n");
	}
	
#if defined(V8_MAJOR_VERSION) && (V8_MAJOR_VERSION > 4 || (V8_MAJOR_VERSION == 4 && defined(V8_MINOR_VERSION) && V8_MINOR_VERSION >= 3))
	if(this->ethtype_comp == TUNTAP_ETCOMP_NONE) {
		ret_buff = node::Buffer::New(isolate, (char*) this->read_buff, ret).ToLocalChecked();
	}
	else if(this->ethtype_comp == TUNTAP_ETCOMP_HALF) {
		ret_buff = node::Buffer::New(isolate, (char*) this->read_buff + 2, ret - 2).ToLocalChecked();
	}
	else if(this->ethtype_comp == TUNTAP_ETCOMP_FULL) {
		uint8_t etval = EtherTypes::getId(be32toh(*(uint32_t*) this->read_buff));
		this->read_buff[3] = etval;
		ret_buff = node::Buffer::New(isolate, (char*) this->read_buff + 3, ret - 3).ToLocalChecked();
	}
	else {
		ret_buff = node::Buffer::New(isolate, (char*) this->read_buff, ret).ToLocalChecked();
	}
#else
	if(this->ethtype_comp == TUNTAP_ETCOMP_NONE) {
		ret_buff = node::Buffer::New(isolate, (char*) this->read_buff, ret);
	}
	else if(this->ethtype_comp == TUNTAP_ETCOMP_HALF) {
		ret_buff = node::Buffer::New(isolate, (char*) this->read_buff + 2, ret - 2);
	}
	else if(this->ethtype_comp == TUNTAP_ETCOMP_FULL) {
		uint8_t etval = EtherTypes::getId(be32toh(*(uint32_t*) this->read_buff));
		this->read_buff[3] = etval;
		ret_buff = node::Buffer::New(isolate, (char*) this->read_buff + 3, ret - 3);
	}
	else {
		ret_buff = node::Buffer::New(isolate, (char*) this->read_buff, ret);
	}
#endif
	
	const int argc = 1;
	Local<Value> argv[argc] = {
		ret_buff
	};
	
	node::MakeCallback(
		isolate,
		this->handle(isolate),
		"_on_read",
		argc,
		argv
	);
}

void Tuntap::do_write() {
	Buffer *cur;
	int ret;
	
	if(this->writ_buff.size() == 0) {
		this->set_write(false);
		return;
	}
	
	cur = this->writ_buff[0];
	this->writ_buff.pop_front();
	
	ret = write(this->fd, cur->data, cur->size);
	if(ret != cur->size) {
		printf("PHAYL2!\n");
	}
	
	delete cur;
	
	if(this->writ_buff.size() == 0) {
		this->set_write(false);
	}
}
