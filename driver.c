#include <stdio.h>
#include <stdlib.h>

int
main(void)
{
	char *p = malloc(512);
	for (int i = 0; i < 510; i++)
		p[i] = 'A' + (i % 26);
	p[511] = '\0';
	printf("%s\n", p);
	free(p);

	/* leak! */
	p = malloc(2048);
	for (int i = 0; i < 2046; i++)
		p[i] = 'A' + (i % 26);
	p[2047] = '\0';
	printf("%s\n", p);

	return 0;
}
