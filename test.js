var tuntap = require('./index.js');

try {
	var tt = tuntap({
		type: 'tap',
		name: 'tun12',
		mtu: 1500,
		addr: '192.168.100.3',
		dest: '192.168.100.2',
		mask: '255.255.255.254',
		ethtype_comp: 'none',
		persist: false,
		//up: true,
		//running: true,
	});
}
catch(e) {
	console.log('Tuntap creation error: ', e);
	process.exit(0);
}

var enc = new tuntap.muxer(1500);
var dec = new tuntap.demuxer(1500);

tt.pipe(enc).pipe(dec).on('data', function() {
	console.log("ARGSZ", arguments);
});
