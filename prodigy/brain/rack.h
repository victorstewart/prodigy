#pragma once

class Machine;

class Rack {
public:

	uint32_t uuid;
	bytell_hash_set<Machine *> machines;
};