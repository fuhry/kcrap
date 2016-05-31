#include <unistd.h>
#include <stdio.h>
#include <ctype.h>

#include "../config.h"
#include "util.h"

void dump_data (char* data, int len) {
    int i, pos;
    char tail[18];

    tail[17] = 0;

    for (i = 0; i < len || i%16 > 0; i++, pos++) {
	if (i%16 == 0) {
	    pos = 0;
	    fprintf(stderr, " [%03d] ", i);
	} else if (pos == 8) {
	    tail[pos++] = ' ';
	    fprintf(stderr, " ");
	}

	if (i < len) {
	    fprintf(stderr, "%02X ", (unsigned char)data[i]);
	    if (isprint(data[i]))
		tail[pos] = data[i];
	    else
		tail[pos] = '.';
	} else {
	    fprintf(stderr, "   ");
	    tail[pos] = ' ';
	}

	if (pos == 16)
	    fprintf(stderr, " %s\n", tail);
    }
}
