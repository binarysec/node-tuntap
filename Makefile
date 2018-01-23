all: build

build: build/Release/tuntap.node

build/Release/tuntap.node: src/*.cc src/*.hh src/tuntap-itf/*.cc src/tuntap-itf/*.hh
	node-gyp build

config: configure

configure:
	node-gyp configure

clean:
	node-gyp clean

rebuild:
	node-gyp clean configure build
