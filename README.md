node-tuntap
===========

Node-tuntap is a node module that allows creating and using [`tun` and `tap`
interfaces](https://en.wikipedia.org/wiki/TUN/TAP) in javascript.

TL;DR
-----

Simple sample :

	var tuntap = require('./index.js');
	
	try {
		var tt = tuntap({
			type: 'tun',
			name: 'tun12',
			mtu: 1500,
			addr: '192.168.123.1',
			dest: '192.168.123.2',
			mask: '255.255.255.192',
			ethtype_comp: 'half',
			persist: false,
			up: true,
			running: true,
		});
	}
	catch(e) {
		console.log('Tuntap creation error: ', e);
		process.exit(0);
	}
	
	tt.pipe(tt);

Building/installing
-------------------

To build the module, just run `make`. *node-gyp* is required to build it.

There is currently no way to install it. You will have to copy the files in 
the right places by hand.

Available options
-----------------

These options can be given in the tuntap constructor, in an object.

* `type` The interface type. May be 'tun' or 'tap'. The default is 'tun'.
* `name` The name of the interface. If nothing is given, the next available
  name will be used (selected by the Operating System).
* `mtu` The MTU, in bytes. The default value is 1500.
* `addr` The network address of the interface. If nothing is given, no address
  is set.
* `dest` The network remote address of the tunnel. If nothing is given, no
  address is set.
* `mask` The network mask of the interface, in dotted notation.
* `ethtype_comp` The compression of the ethernet header (Only for the 'tap'
  type). May be 'none', 'half' or 'full'. The default is 'none'. See the 
  next part for more explanations.
* `persist` Tells if the interface will persist when it will be closed.
  Defaults to true.
* `up` Tells if the interface should be up. Defaults to true.
* `running` Tells if the interface should be running. Defaults to true.

The `ethertype_comp` option is used to have a smaller overhead of the 
ethernet type header. The 'none' option send the full header as given by the 
interface (No encoding/decoding is done). the 'half' option remove the two 
unused bytes of the header (the header is on 4 bytes, but only two bytes are 
used currently). The 'full' option maps the 4 bytes most common values to a 
1 byte equivalent, used internally in the module (See the ethertypes.itm 
files for a list of supported codes).

Available methods
-----------------

* `open(options)` Open the interface (When a new interface is created, it is 
  already open. Close it first to reopen it later). The options are the same 
  as in the constructor.
* `close()` Close the interface. This function takes no arguments.
* `set(options)` Set the given options on the interface. The object given can
  contain the same parameters as the constructor, except the `type` key.
* `unset(array)` Unset the given options (Can be useful to unset an IP
  Address). The only parameter is an array of constructor keys to unset. The available elements are `addr`, `mtu`, `persist`, `up`, `running` and `ethertype_comp`.

Two classes are also available : 

* tuntap.muxer
* tuntap.demuxer

These classes can be used to wrap packets from/to tuntap interfaces, for 
example if you have to send them through a tcp connection. They take only 
one parameter in the constructor : the datagram maximum size (for an MTU of 
1500 on a TAP interface, the maximum size can be 1504, 1502 ot 1501, if you 
are using a 'none', 'half' or 'full' compression with `ethertype_comp`).

Any of the tuntap, tuntap.muxer and tuntap.demuxer classes are streams and 
can be used like it (.on('data'), .write(), .pipe()).
