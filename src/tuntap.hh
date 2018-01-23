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

#ifndef _H_NODETUNTAP_TUNTAP
#define _H_NODETUNTAP_TUNTAP

#include "tuntap-itf/tuntap-itf.hh"

class Tuntap : public node::ObjectWrap {
	public:
		static void Init(v8::Handle<v8::Object> module);
		
	private:
		Tuntap();
		~Tuntap();
		
		struct Buffer {
			Buffer();
			
			Buffer(int size_in) :
					size(size_in)
				{
				this->data = new uint8_t[size_in];
			}
			
			Buffer(uint8_t *data_in, int size_in, bool copy = true) :
					size(size_in)
				{
				this->size = size_in;
				if(copy) {
					this->data = new uint8_t[size_in];
					memcpy(this->data, data_in, size_in);
				}
				else {
					this->data = data_in;
				}
			}
			
			~Buffer() {
				delete this->data;
			}
			
			uint8_t *data;
			int size;
		};
		
		bool construct(v8::Handle<v8::Object> main_obj, std::string &error);
		void objset(v8::Handle<v8::Object> obj);
		static void writeBuffer(const v8::FunctionCallbackInfo<v8::Value>& args);
		static void open(const v8::FunctionCallbackInfo<v8::Value>& args);
		static void close(const v8::FunctionCallbackInfo<v8::Value>& args);
		static void set(const v8::FunctionCallbackInfo<v8::Value>& args);
		static void unset(const v8::FunctionCallbackInfo<v8::Value>& args);
		static void stopRead(const v8::FunctionCallbackInfo<v8::Value>& args);
		static void startRead(const v8::FunctionCallbackInfo<v8::Value>& args);
		
		static void uv_event_cb(uv_poll_t* handle, int status, int events);
		
		static void New(const v8::FunctionCallbackInfo<v8::Value>& args);
		static v8::Persistent<v8::Function> constructor;
		
		void set_read(bool r);
		void set_write(bool w);
		
		void do_read();
		void do_write();
		
		int fd;
		
		tuntap_itf_opts_t itf_opts;
		
		unsigned char *read_buff;
		std::deque<Buffer*> writ_buff;
		bool is_reading;
		bool is_writing;
		
		uv_poll_t uv_handle_;
};

#endif
