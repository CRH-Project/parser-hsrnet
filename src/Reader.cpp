#include "Reader.h"

BufferProvider provider;


void printErr(int errcode, u_char *err)
{
    fprintf(stderr,"Error occurs when pcap_loop! Error code: %d\n",
            errcode);
    fprintf(stderr,"Error is %s\n", err);
}

