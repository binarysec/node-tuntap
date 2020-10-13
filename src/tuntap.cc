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

void Tuntap::Init(Local<Object> module) {
	Isolate* isolate = module->GetIsolate();
	Local<Context> context = isolate->GetCurrentContext();
	
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
	
	constructor.Reset(isolate, tpl->GetFunction(context).ToLocalChecked());
	
	module->Set(String::NewFromUtf8(isolate, "exports"), tpl->GetFunction(context).ToLocalChecked());
}

void Tuntap::New(const FunctionCallbackInfo<Value>& args) {
	Isolate* isolate = args.GetIsolate();
	HandleScope scope(isolate);
	Local<Context> context = isolate->GetCurrentContext();
	bool ret;
	std::string err_str;
	Local<Object> main_obj;
	Tuntap* obj;
	
	if(args.IsConstructCall()) {
		// Invoked as constructor: `new Tuntap(...)`
		obj = new Tuntap();
		obj->Wrap(args.This());
		if(args[0]->IsObject()) {
			main_obj = args[0]->ToObject(context).ToLocalChecked();
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
		args.GetReturnValue().Set(NVM_NEW_INSTANCE(cons, isolate, argc, argv));
	}
}

bool Tuntap::construct(Local<Object> main_obj, std::string &error) {
	Isolate* isolate = main_obj->GetIsolate();
	HandleScope scope(isolate);
	Local<Array> keys_arr;
	Local<Value> key;
	Local<Value> val;
	
	this->objset(main_obj);
	
	if(!tuntapItfCreate(this->itf_opts, &this->fd, &error))
		return(false);
	
	this->read_buff = new unsigned char[this->itf_opts.mtu + 4];
	
	uv_poll_init(uv_default_loop(), &this->uv_handle_, this->fd);
	this->uv_handle_.data = this;
	uv_poll_start(&this->uv_handle_, UV_READABLE, uv_event_cb);
	
	return(true);
}

void Tuntap::writeBuffer(const FunctionCallbackInfo<Value>& args) {
	Isolate* isolate = args.GetIsolate();
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
	
	if(obj->itf_opts.ethtype_comp == TUNTAP_ETCOMP_NONE) {
		wbuff = new Buffer(data, data_length);
	}
	else if(obj->itf_opts.ethtype_comp == TUNTAP_ETCOMP_HALF) {
		wbuff = new Buffer(data_length + 2);
		wbuff->data[0] = 0;
		wbuff->data[1] = 0;
		memcpy(
			wbuff->data + 2,
			data,
			data_length
		);
	}
	else if(obj->itf_opts.ethtype_comp == TUNTAP_ETCOMP_FULL) {
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
	Isolate* isolate = args.GetIsolate();
	Local<Context> context = isolate->GetCurrentContext();
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
		
		main_obj = args[0]->ToObject(context).ToLocalChecked();
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
	Isolate* isolate = args.GetIsolate();
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
	Isolate* isolate = args.GetIsolate();
	Local<Context> context = isolate->GetCurrentContext();
	HandleScope scope(isolate);
	Tuntap *obj = ObjectWrap::Unwrap<Tuntap>(args.This());
	std::vector<tuntap_itf_opts_t::option_e> options;
	std::string err_str;
	Local<Array> keys_arr;
	Local<Value> key;
	Local<Value> val;
	Local<Object> main_obj;
	
	if(!args[0]->IsObject()) {
		TT_THROW_TYPE("Invalid argument type");
		return;
	}
	
	main_obj = args[0]->ToObject(context).ToLocalChecked();
	
	if(main_obj->Has(context, String::NewFromUtf8(isolate, "type")).ToChecked() || main_obj->Has(context, String::NewFromUtf8(isolate, "name")).ToChecked()) {
		TT_THROW_TYPE("Cannot set name and type from this function!");
		return;
	}
	
	obj->objset(main_obj);
	
	keys_arr = main_obj->GetPropertyNames(context).ToLocalChecked();
	for (unsigned int i = 0, limiti = keys_arr->Length(); i < limiti; i++) {
		key = keys_arr->Get(i);
		val = main_obj->Get(key);
		String::Utf8Value key_str(isolate, key);
		
		if(strcmp(*key_str, "addr") == 0) {
			if(obj->fd)
				options.push_back(tuntap_itf_opts_t::OPT_ADDR);
		}
		else if(strcmp(*key_str, "mask") == 0) {
			if(obj->fd)
				options.push_back(tuntap_itf_opts_t::OPT_MASK);
		}
		else if(strcmp(*key_str, "dest") == 0) {
			if(obj->fd)
				options.push_back(tuntap_itf_opts_t::OPT_DEST);
		}
		else if(strcmp(*key_str, "mtu") == 0) {
			if(obj->fd)
				options.push_back(tuntap_itf_opts_t::OPT_MTU);
		}
		else if(strcmp(*key_str, "persist") == 0) {
			if(obj->fd)
				options.push_back(tuntap_itf_opts_t::OPT_PERSIST);
		}
		else if(strcmp(*key_str, "up") == 0) {
			if(obj->fd)
				options.push_back(tuntap_itf_opts_t::OPT_UP);
		}
		else if(strcmp(*key_str, "running") == 0) {
			if(obj->fd)
				options.push_back(tuntap_itf_opts_t::OPT_RUNNING);
		}
		else if(strcmp(*key_str, "ethtype_comp") == 0) {
			String::Utf8Value val_str(isolate, val);
			
			if(strcmp(*val_str, "none") == 0)
				obj->itf_opts.ethtype_comp = TUNTAP_ETCOMP_NONE;
			else if(strcmp(*val_str, "half") == 0)
				obj->itf_opts.ethtype_comp = TUNTAP_ETCOMP_HALF;
			else if(strcmp(*val_str, "full") == 0)
				obj->itf_opts.ethtype_comp = TUNTAP_ETCOMP_FULL;
		}
	}
	
	if(!tuntapItfSet(options, obj->itf_opts, &err_str)) {
		TT_THROW_TYPE(err_str.c_str());
		return;
	}
	
	args.GetReturnValue().Set(args.This());
}

void Tuntap::unset(const FunctionCallbackInfo<Value>& args) {
	Isolate* isolate = args.GetIsolate();
	HandleScope scope(isolate);
	Tuntap *obj = ObjectWrap::Unwrap<Tuntap>(args.This());
	std::vector<tuntap_itf_opts_t::option_e> options;
	std::string err_str;
	Local<Array> keys_arr;
	Local<Value> val;
	
	if(!args[0]->IsArray()) {
		TT_THROW_TYPE("Invalid argument type");
		return;
	}
	
	keys_arr = args[0].As<Array>();
	
	for (unsigned int i = 0, limiti = keys_arr->Length(); i < limiti; i++) {
		val = keys_arr->Get(i);
		String::Utf8Value val_str(isolate, val);
		
		if(strcmp(*val_str, "addr") == 0) {
			obj->itf_opts.addr = "";
			if(obj->fd)
				options.push_back(tuntap_itf_opts_t::OPT_ADDR);
		}
		else if(strcmp(*val_str, "mtu") == 0) {
			obj->itf_opts.mtu = TUNTAP_DFT_MTU;
			if(obj->fd)
				options.push_back(tuntap_itf_opts_t::OPT_MTU);
		}
		else if(strcmp(*val_str, "persist") == 0) {
			obj->itf_opts.is_persistant = TUNTAP_DFT_PERSIST;
			if(obj->fd)
				options.push_back(tuntap_itf_opts_t::OPT_PERSIST);
		}
		else if(strcmp(*val_str, "up") == 0) {
			obj->itf_opts.is_up = TUNTAP_DFT_UP;
			if(obj->fd)
				options.push_back(tuntap_itf_opts_t::OPT_UP);
		}
		else if(strcmp(*val_str, "running") == 0) {
			obj->itf_opts.is_running = TUNTAP_DFT_RUNNING;
			if(obj->fd)
				options.push_back(tuntap_itf_opts_t::OPT_RUNNING);
		}
		else if(strcmp(*val_str, "ethtype_comp") == 0) {
			obj->itf_opts.ethtype_comp = TUNTAP_ETCOMP_NONE;
		}
	}
	
	if(!tuntapItfSet(options, obj->itf_opts, &err_str)) {
		TT_THROW_TYPE(err_str.c_str());
		return;
	}
	
	args.GetReturnValue().Set(args.This());
}

void Tuntap::stopRead(const FunctionCallbackInfo<Value>& args) {
	Isolate* isolate = args.GetIsolate();
	HandleScope scope(isolate);
	Tuntap *obj = ObjectWrap::Unwrap<Tuntap>(args.This());
	
	obj->set_read(false);
	
	args.GetReturnValue().Set(args.This());
}

void Tuntap::startRead(const FunctionCallbackInfo<Value>& args) {
	Isolate* isolate = args.GetIsolate();
	HandleScope scope(isolate);
	Tuntap *obj = ObjectWrap::Unwrap<Tuntap>(args.This());
	
	obj->set_read(true);
	
	args.GetReturnValue().Set(args.This());
}

void Tuntap::objset(Local<Object> obj) {
	Isolate* isolate = obj->GetIsolate();
	Local<Context> context = isolate->GetCurrentContext();

	Local<Array> keys_arr;
	Local<Value> key;
	Local<Value> val;
	
	keys_arr = obj->GetPropertyNames(context).ToLocalChecked();
	for (unsigned int i = 0, limiti = keys_arr->Length(); i < limiti; i++) {
		key = keys_arr->Get(i);
		val = obj->Get(key);
		String::Utf8Value key_str(isolate, key);
		String::Utf8Value val_str(isolate, val);
		
		if(strcmp(*key_str, "type") == 0) {
			if(strcmp(*val_str, "tun") == 0) {
				this->itf_opts.mode = tuntap_itf_opts_t::MODE_TUN;
			}
			else if(strcmp(*val_str, "tap") == 0) {
				this->itf_opts.mode = tuntap_itf_opts_t::MODE_TAP;
			}
		}
		else if(strcmp(*key_str, "name") == 0) {
			this->itf_opts.itf_name = *val_str;
		}
		else if(strcmp(*key_str, "addr") == 0) {
			this->itf_opts.addr = *val_str;
		}
		else if(strcmp(*key_str, "mask") == 0) {
			this->itf_opts.mask = *val_str;
		}
		else if(strcmp(*key_str, "dest") == 0) {
			this->itf_opts.dest = *val_str;
		}
		else if(strcmp(*key_str, "mtu") == 0) {
			this->itf_opts.mtu = val->ToInteger(context).ToLocalChecked()->Value();
			if(this->itf_opts.mtu <= 50)
				this->itf_opts.mtu = 50;
		}
		else if(strcmp(*key_str, "persist") == 0) {
			this->itf_opts.is_persistant = val->ToBoolean(context).ToLocalChecked()->Value();
		}
		else if(strcmp(*key_str, "up") == 0) {
			this->itf_opts.is_up = val->ToBoolean(context).ToLocalChecked()->Value();
		}
		else if(strcmp(*key_str, "running") == 0) {
			this->itf_opts.is_running = val->ToBoolean(context).ToLocalChecked()->Value();
		}
		else if(strcmp(*key_str, "ethtype_comp") == 0) {
			String::Utf8Value val_str(isolate, val);
			
			if(strcmp(*val_str, "none") == 0)
				this->itf_opts.ethtype_comp = TUNTAP_ETCOMP_NONE;
			else if(strcmp(*val_str, "half") == 0)
				this->itf_opts.ethtype_comp = TUNTAP_ETCOMP_HALF;
			else if(strcmp(*val_str, "full") == 0)
				this->itf_opts.ethtype_comp = TUNTAP_ETCOMP_FULL;
		}
	}
}

void Tuntap::uv_event_cb(uv_poll_t* handle, int status, int events) {
	Tuntap *obj = static_cast<Tuntap*>(handle->data);
	
	if(events & UV_READABLE) {
		obj->do_read();
	}
	
	if(events & UV_WRITABLE) {
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
	
	ret = read(this->fd, this->read_buff, this->itf_opts.mtu + 4);
	
	if(ret <= 0) {
		printf("PHAYL1\n");
	}
	
#if defined(V8_MAJOR_VERSION) && (V8_MAJOR_VERSION > 4 || (V8_MAJOR_VERSION == 4 && defined(V8_MINOR_VERSION) && V8_MINOR_VERSION >= 3))
	if(this->itf_opts.ethtype_comp == TUNTAP_ETCOMP_HALF) {
		ret_buff = node::Buffer::Copy(isolate, (char*) this->read_buff + 2, ret - 2).ToLocalChecked();
	}
	else if(this->itf_opts.ethtype_comp == TUNTAP_ETCOMP_FULL) {
		uint8_t etval = EtherTypes::getId(be32toh(*(uint32_t*) this->read_buff));
		this->read_buff[3] = etval;
		ret_buff = node::Buffer::Copy(isolate, (char*) this->read_buff + 3, ret - 3).ToLocalChecked();
	}
	else { /* Also matches TUNTAP_ETCOMP_NONE */
		ret_buff = node::Buffer::Copy(isolate, (char*) this->read_buff, ret).ToLocalChecked();
	}
#else
	if(this->itf_opts.ethtype_comp == TUNTAP_ETCOMP_HALF) {
		ret_buff = node::Buffer::Copy(isolate, (char*) this->read_buff + 2, ret - 2);
	}
	else if(this->itf_opts.ethtype_comp == TUNTAP_ETCOMP_FULL) {
		uint8_t etval = EtherTypes::getId(be32toh(*(uint32_t*) this->read_buff));
		this->read_buff[3] = etval;
		ret_buff = node::Buffer::Copy(isolate, (char*) this->read_buff + 3, ret - 3);
	}
	else { /* Also matches TUNTAP_ETCOMP_NONE */
		ret_buff = node::Buffer::Copy(isolate, (char*) this->read_buff, ret);
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
