#ifndef MAIN_H
#define MAIN_H

#define SPLIT_APP   1
#define SPLIT_PATCH 2

typedef struct
{
    int split;
    int notify;
    int shutdown;
} configuration;

extern configuration config;

#endif
