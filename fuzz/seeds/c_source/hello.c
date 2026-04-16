#include <stdio.h>

#define MAX 100

int
main(int argc, char *argv[])
{
	int i;

	for (i = 0; i < MAX; i++)
		printf("hello %d\n", i);
	return 0;
}
