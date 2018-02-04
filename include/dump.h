#ifndef DUMP_H
#define DUMP_H

#include "types.h"

int is_self(const char *fn);
void decrypt_and_dump_self(char *selfFile, char *saveFile);
int wait_for_game(char *title_id);
int wait_for_bdcopy(char *title_id);
int wait_for_usb(char *usb_name, char *usb_path);
void dump_game(char *title_id, char *usb_path);

#endif
