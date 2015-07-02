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

var stream = require('stream');
var tuntapBind = require('./build/Release/tuntap');
var util = require('util');

util.inherits(tuntap, stream.Duplex);

function tuntap(params, options) {
	if(!(this instanceof tuntap)) {
		return(new tuntap(params, options));
	}
	
	var self = this;
	
	stream.Duplex.call(this, options);
	
	//May throw error. Needs to be catched by the caller.
	this.handle_ = new tuntapBind(params);
	
	this.is_open = true;
	
	this.handle_._on_read = function(buffer) {
		if (!self.push(buffer))
			self.handle_.stopRead();
	}
	
	this.handle_._on_error = function(error) {
		self.emit('error', error);
	}
};

tuntap.prototype._read = function(size) {
	this.handle_.startRead();
}

tuntap.prototype._write = function(buffer, encoding, callback) {
	if(this.is_open) {
		if(!Buffer.isBuffer(buffer)) {
			buffer = new Buffer(buffer, encoding);
		}
		
		try {
			this.handle_.writeBuffer(buffer);
		}
		catch(e) {
			this.emit('error', e);
		}
	}
	
	callback();
}

tuntap.prototype.open = function(arg) {
	var ret;
	
	this.is_open = true;
	
	try {
		if(arg != undefined)
			ret = this.handle_.open(arg);
		else
			ret = this.handle_.open();
	}
	catch(e) {
		this.emit('error', e);
	}
	
	if(typeof(ret) != 'object')
		return(ret);
	
	return(this);
}

tuntap.prototype.close = function() {
	this.is_open = false;
	
	try {
		this.handle_.close();
	}
	catch(e) {
		this.emit('error', e);
	}
	
	return(this);
}

tuntap.prototype.set = function(params) {
	try {
		this.handle_.set(params);
	}
	catch(e) {
		this.emit('error', e);
	}
	
	return(this);
}

tuntap.prototype.unset = function(params) {
	try {
		this.handle_.unset(params);
	}
	catch(e) {
		this.emit('error', e);
	}
	
	return(this);
}

tuntap.muxer = function(mtu, options) {
	if(!(this instanceof tuntap.muxer)) {
		return(new tuntap.muxer(mtu, options));
	}
	
	this.mtu = mtu;
	this.encBuffer = new Buffer(mtu + 2);
	
	stream.Transform.call(this, options);
}

tuntap.demuxer = function(mtu, options) {
	if(!(this instanceof tuntap.demuxer)) {
		return(new tuntap.demuxer(mtu, options));
	}
	
	this.mtu = mtu;
	this.decBuffer = new Buffer(mtu + 2);
	this.length = 0;
	this.header = 0;
	this.remain = 0;
	
	stream.Transform.call(this, options);
}

util.inherits(tuntap.muxer, stream.Transform);
util.inherits(tuntap.demuxer, stream.Transform);

tuntap.muxer.prototype._transform = function(buffer, encoding, callback) {
	if(!Buffer.isBuffer(buffer)) {
		buffer = new Buffer(buffer, encoding);
	}
	
	this.encBuffer.writeUInt16LE(buffer.length, 0);
	buffer.copy(this.encBuffer, 2);
	
	this.push(this.encBuffer.slice(0, buffer.length + 2));
	
	callback();
}

tuntap.demuxer.prototype._transform = function(buffer, encoding, callback) {
	if(!Buffer.isBuffer(buffer)) {
		buffer = new Buffer(buffer, encoding);
	}
	
	var cursor = 0;
	var copy;
	
	while(buffer.length - cursor > 0) {
		if(this.header < 2) {
			if(buffer.length >= (2 - this.header))
				copy = (2 - this.header);
			else
				copy = buffer.length;
				
			buffer.copy(this.decBuffer, this.header, cursor);
			this.header += copy;
			cursor += copy;
			
			if(this.header == 2)
				this.length = this.remain = this.decBuffer.readUInt16LE(0);
			
			continue;
		}
		
		if(buffer.length >= this.remain)
			copy = this.remain;
		else
			copy = buffer.length;
		
		buffer.copy(this.decBuffer, this.length - this.remain, cursor, cursor + copy);
		this.remain -= copy;
		cursor += copy;
		
		if(this.remain == 0) {
			this.push(this.decBuffer.slice(0, this.length));
			this.header = 0;
		}
	}
	
	callback();
}

module.exports = tuntap;

