program EXAMPLE_PROG {
	version EXAMPLE_VERS {
		string EXAMPLE_PROC(string) = 1;
	} = 1;
} = 0x20000001;

struct example_data {
	string name<255>;
	int value;
};

enum example_status {
	OK = 0,
	ERR = 1
};
