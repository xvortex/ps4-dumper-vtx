// Copyright (C) 2013       Hykem <hykem@hotmail.com>
// Licensed under the terms of the GNU GPL, version 2
// http://www.gnu.org/licenses/gpl-2.0.txt

#include "ps4.h"
#include "defines.h"
#include "debug.h"
#include "unpfs.h"

int pfs;
struct pfs_header_t *header;
struct di_d32 *inodes;

#define BUFFER_SIZE 65536

void memcpy_to_file(const char *fname, uint64_t ptr, uint64_t size)
{
  lseek(pfs, ptr, SEEK_SET);
  size_t bytes;
  char *buffer = malloc(BUFFER_SIZE);
  if (buffer != NULL)
  {
    FILE *fp = fopen(fname, "wb");
    if (fp)
    {
      while (size > 0)
      {
         bytes = (size > BUFFER_SIZE) ? BUFFER_SIZE : size;
         read(pfs, buffer, bytes);
         fwrite(buffer, 1, bytes, fp);
         size -= bytes;
      }
      fclose(fp);
    }
    free(buffer);
  }
}

static void parse_directory(int ino, int lev, struct di_d32 *parent, char *parent_name)
{
  uint32_t z;
  uint32_t *dataBlocks;
  uint32_t dbSize;

  if (inodes[ino].db[1] == 0xFFFFFFFF)
  {
    dbSize = inodes[ino].blocks;
    dataBlocks = malloc(sizeof(uint32_t) * dbSize);
    for (int i = 0; i < dbSize; i++)
      dataBlocks[i] = i + inodes[ino].db[0];
  }
  else
  {
    dbSize = 12;
    dataBlocks = malloc(sizeof(uint32_t) * dbSize);
    for (int i = 0; i < dbSize; i++)
      dataBlocks[i] = inodes[ino].db[i];
  }
  for (z = 0; z < dbSize; z++) 
  {
    if (dataBlocks[z] == 0) { break; }
		
    printfsocket("inode ino=%x size=%lld mode=%x db=%x\n", ino, inodes[ino].size, inodes[ino].mode, dataBlocks[z]);
    uint64_t pos = (uint64_t)header->blocksz * (uint64_t)dataBlocks[z];

    while ( pos < header->blocksz * (dataBlocks[z] + 1))
    {
      struct dirent_t *ent = malloc(sizeof(struct dirent_t));
      lseek(pfs, pos, SEEK_SET);
      read(pfs, ent, sizeof(struct dirent_t));
      if (ent->type == 0)
      {
        break;
      }						
				
      printfsocket("==> pos %x ino=%d \n", pos, ent->ino);
				
      char *name;
      name = malloc(ent->namelen + 1);
      name[ent->namelen] = '\0';

      if (lev > 0)
        read(pfs, name, ent->namelen);
      else
        name[0] = '\0';

      char fname[256];
      if (parent_name != NULL)
      {
        sprintf(fname, "%s/%s", parent_name, name);
      }
      else
      {
        sprintf(fname, "%s", name);
      }

      if ((ent->type == 2) && (lev > 0))
      {
        printfsocket("len: %x name: '%.*s' type: %x index:%d\n",ent->namelen,ent->namelen, name, ent->type, ent->ino);
        printfsocket("Dumping from pos=%x destination=%s\n", inodes[ent->ino].db[0] * header->blocksz, fname);
        memcpy_to_file(fname, (uint64_t)inodes[ent->ino].db[0] * (uint64_t)header->blocksz, inodes[ent->ino].size);
      }
      else
      if (ent->type == 3)
      {
        printfsocket("len: %x name: '%.*s' type: %x\n",ent->namelen,ent->namelen, name, ent->type);
        printfsocket("scan directory ent->ino %x - '%s'\n", ent->ino, name);
        mkdir(fname, 0777);
        parse_directory(ent->ino, lev + 1, &inodes[ino], fname);
      }
      pos += ent->entsize;
    }						
  }
  free(dataBlocks);
}

int unpfs(char *pfsfn, char *tidpath)
{
  uint32_t i;
  uint32_t j;	

  mkdir(tidpath, 0777);

  pfs = open(pfsfn, O_RDONLY, 0);
  if (pfs < 0) return -1;

  header = malloc(sizeof(struct pfs_header_t));
  lseek(pfs, 0, SEEK_SET);
  read(pfs, header, sizeof(struct pfs_header_t));

  for (i = 0; i < header->ndinodeblock; i++)
  {		
    printfsocket("stream pos %x\n", header->blocksz + header->blocksz * i);
    inodes = malloc(sizeof(struct di_d32) * header->ndinode);
    memset(inodes, 0, sizeof(struct di_d32) * header->ndinode);
    for (j = 0; j < header->ndinode; j++)
    {
      lseek(pfs, (uint64_t)header->blocksz + (uint64_t)(sizeof(struct di_d32) * j), SEEK_SET);
      read(pfs, &inodes[j], sizeof(struct di_d32));
      printfsocket("inode ino=%x pos=%x mode=%x size=%llu uid=%x gid=%x\n",j, header->blocksz + (sizeof(struct di_d32) * j), inodes[j].mode, inodes[j].size, inodes[j].uid, inodes[j].gid);
    }
    parse_directory(header->superroot_ino, 0, NULL, tidpath);
  }

  close(pfs);
	
  return 0;
}
