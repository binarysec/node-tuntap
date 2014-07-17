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

#define ETHERTYPES_16BIT_MAX	65536

EtherTypes EtherTypes::singleton;

EtherTypes::EtherTypes() :
		type_count(0)
	{
	int i;
	
	//count types
	#define ITEM(X) \
		this->type_count++;
	#include "ethertypes.itm"
	#undef ITEM
	
	this->id2type = new uint16_t[this->type_count];
	this->type2id = new uint8_t[ETHERTYPES_16BIT_MAX];
	memset(this->type2id, 0, ETHERTYPES_16BIT_MAX);
	
	//insert types
	i = 0;
	#define ITEM(X) \
		this->id2type[i] = X; \
		this->type2id[X] = i; \
		i++;
	#include "ethertypes.itm"
	#undef ITEM
}

uint8_t EtherTypes::getId(uint16_t type) {
	return(EtherTypes::singleton.type2id[type]);
}

uint16_t EtherTypes::getType(uint8_t id) {
	if(id >= EtherTypes::singleton.type_count)
		return(0);
	
	return(EtherTypes::singleton.id2type[id]);
}
