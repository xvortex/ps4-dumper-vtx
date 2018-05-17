// Copyright (C) 2013       Hykem <hykem@hotmail.com>
// Licensed under the terms of the GNU GPL, version 2
// http://www.gnu.org/licenses/gpl-2.0.txt

#include "ps4.h"
#include "defines.h"
#include "debug.h"
#include "unpkg.h"

#define EOF '\00'

// Helper functions.
static inline uint16_t bswap_16(uint16_t val)
{
  return ((val & (uint16_t)0x00ffU) << 8)
    | ((val & (uint16_t)0xff00U) >> 8);
}

static inline uint32_t bswap_32(uint32_t val)
{
  return ((val & (uint32_t)0x000000ffUL) << 24)
    | ((val & (uint32_t)0x0000ff00UL) <<  8)
    | ((val & (uint32_t)0x00ff0000UL) >>  8)
    | ((val & (uint32_t)0xff000000UL) >> 24);
}

static inline int fgetc(int fd)
{
  char c;

  if (read(fd, &c, 1) < 1)
    return (EOF);
  return (c);
}

char *read_string(int fd)
{
  char *string = malloc(sizeof(char) * 256);
  int c;
  int length = 0;
  if (!string) return string;
  while((c = fgetc(fd)) != EOF)
  {
    string[length++] = c;
  }
  string[length++] = '\0';

  return realloc(string, sizeof(char) * length);
}

static void _mkdir(const char *dir)
{
  char tmp[256];
  char *p = NULL;

  snprintf(tmp, sizeof(tmp), "%s", dir);
  for (p = tmp + 1; *p; p++)
  {
    if (*p == '/')
    {
      *p = 0;
      mkdir(tmp, 0777);
      *p = '/';
    }
  }
}

typedef struct
{
  uint32_t type;
  char *name;
} pkg_entry_value;

char *get_entry_name_by_type(uint32_t type)
{
  static const pkg_entry_value entries [] = {
	{ 0x0400, "license.dat" },
	{ 0x0401, "license.info" },
	{ 0x0402, "nptitle.dat" },
	{ 0x0403, "npbind.dat" },
	{ 0x0404, "selfinfo.dat" },
	{ 0x0406, "imageinfo.dat" },
	{ 0x0407, "target-deltainfo.dat" },
	{ 0x0408, "origin-deltainfo.dat" },
	{ 0x0409, "psreserved.dat" },
	{ 0x1000, "param.sfo" },
	{ 0x1001, "playgo-chunk.dat" },
	{ 0x1002, "playgo-chunk.sha" },
	{ 0x1003, "playgo-manifest.xml" },
	{ 0x1004, "pronunciation.xml" },
	{ 0x1005, "pronunciation.sig" },
	{ 0x1006, "pic1.png" },
	{ 0x1007, "pubtoolinfo.dat" },
	{ 0x1008, "app/playgo-chunk.dat" },
	{ 0x1009, "app/playgo-chunk.sha" },
	{ 0x100A, "app/playgo-manifest.xml" },
	{ 0x100B, "shareparam.json" },
	{ 0x100C, "shareoverlayimage.png" },
	{ 0x100D, "save_data.png" },
	{ 0x100E, "shareprivacyguardimage.png" },
	{ 0x1200, "icon0.png" },
	{ 0x1220, "pic0.png" },
	{ 0x1240, "snd0.at9" },
	{ 0x1260, "changeinfo/changeinfo.xml" },
	{ 0x1280, "icon0.dds" },
	{ 0x12A0, "pic0.dds" },
	{ 0x12C0, "pic1.dds" },
  };

  char *entry_name = malloc(32);

  if ((type >= 0x1201) && (type <= 0x121F))
    sprintf(entry_name, "icon0_%02u.png", type - 0x1201);
  else
  if ((type >= 0x1241) && (type <= 0x125F))
    sprintf(entry_name, "pic1_%02u.png", type - 0x1241);
  else
  if ((type >= 0x1261) && (type <= 0x127F))
    sprintf(entry_name, "changeinfo/changeinfo_%02u.xml", type - 0x1261);
  else
  if ((type >= 0x1281) && (type <= 0x129F))
    sprintf(entry_name, "icon0_%02u.dds", type - 0x1281);
  else
  if ((type >= 0x12C1) && (type <= 0x12DF))
    sprintf(entry_name, "pic1_%02u.dds", type - 0x12C1);
  else
  if ((type >= 0x1400) && (type <= 0x1463))
    sprintf(entry_name, "trophy/trophy%02u.trp", type - 0x1400);
  else
  if ((type >= 0x1600) && (type <= 0x1609))
    sprintf(entry_name, "keymap_rp/%03u.png", type - 0x1600);
  else
  if ((type >= 0x1610) && (type <= 0x17F9))
    sprintf(entry_name, "keymap_rp/%02u/%03u.png", (type - 0x1610) / 0x10, (type - 0x1610) % 0x10);
  else
  {
    free(entry_name);
    entry_name = NULL;
    for (int i = 0; i < sizeof entries / sizeof entries[0]; i++)
    {
      if (type == entries[i].type)
      {
        entry_name = entries[i].name;
        break;
      }
    }
  }

  return entry_name;
}

int unpkg(char *pkgfn, char *tidpath)
{
  struct cnt_pkg_main_header m_header;
  struct cnt_pkg_content_header c_header;
  memset(&m_header, 0, sizeof(struct cnt_pkg_main_header));
  memset(&c_header, 0, sizeof(struct cnt_pkg_content_header));

  int fdin = open(pkgfn, O_RDONLY, 0);
  if (fdin == -1)
  {
    printfsocket("File not found!\n");
    return 1;
  }

  // Read in the main CNT header (size seems to be 0x180 with 4 hashes included).
  lseek(fdin, 0, SEEK_SET);
  read(fdin, &m_header, 0x180);

  if (m_header.magic != PS4_PKG_MAGIC)
  {
    printfsocket("Invalid PS4 PKG file!\n");
    return 2;
  }

  printfsocket("PS4 PKG header:\n");
  printfsocket("- PKG magic: 0x%X\n", bswap_32(m_header.magic));
  printfsocket("- PKG type: 0x%X\n", bswap_32(m_header.type));
  printfsocket("- PKG table entries: %d\n", bswap_16(m_header.table_entries_num));
  printfsocket("- PKG system entries: %d\n", bswap_16(m_header.system_entries_num));
  printfsocket("- PKG table offset: 0x%X\n", bswap_32(m_header.file_table_offset));
  printfsocket("\n");

  // Seek to offset 0x400 and read content associated header (size seems to be 0x80 with 2 hashes included).
  lseek(fdin, 0x400, SEEK_SET);
  read(fdin, &c_header, 0x80);

  printfsocket("PS4 PKG content header:\n");
  printfsocket("- PKG content offset: 0x%X\n", bswap_32(c_header.content_offset));
  printfsocket("- PKG content size: 0x%X\n", bswap_32(c_header.content_size));
  printfsocket("\n");

  // Locate the entry table and list each type of section inside the PKG/CNT file.
  lseek(fdin, bswap_32(m_header.file_table_offset), SEEK_SET);

  printfsocket("PS4 PKG table entries:\n");
  struct cnt_pkg_table_entry *entries = malloc(sizeof(struct cnt_pkg_table_entry) * bswap_16(m_header.table_entries_num));
  memset(entries, 0, sizeof(struct cnt_pkg_table_entry) * bswap_16(m_header.table_entries_num));
  int i;
  for (i = 0; i < bswap_16(m_header.table_entries_num); i++)
  {
    read(fdin, &entries[i], 0x20);
    printfsocket("Entry #%d\n", i);
    printfsocket("- PKG table entry type: 0x%X\n", bswap_32(entries[i].type));
    printfsocket("- PKG table entry offset: 0x%X\n", bswap_32(entries[i].offset));
    printfsocket("- PKG table entry size: 0x%X\n", bswap_32(entries[i].size));
    printfsocket("\n");
  }

  // Vars for file name listing.
  struct file_entry *entry_files = malloc(sizeof(struct file_entry) * bswap_16(m_header.table_entries_num));
  memset(entry_files, 0, sizeof(struct file_entry) * bswap_16(m_header.table_entries_num));
  char *file_name_list[256];
  int file_name_index = 0;
  int file_count = 0;

  // Var for file writing.
  unsigned char *entry_file_data;

  // Search through the data entries and locate the name table entry.
  // This section should keep relevant strings for internal files inside the PKG/CNT file.
  for (i = 0; i < bswap_16(m_header.table_entries_num); i++)
  {
    if (bswap_32(entries[i].type) == PS4_PKG_ENTRY_TYPE_NAME_TABLE)
    {
      printfsocket("Found name table entry. Extracting file names:\n");
      lseek(fdin, bswap_32(entries[i].offset) + 1, SEEK_SET);
      while ((file_name_list[file_name_index] = read_string(fdin))[0] != '\0')
      {
        printfsocket("%s\n", file_name_list[file_name_index]);
        file_name_index++;
      }
      printfsocket("\n");
    }
  }

  // Search through the data entries and locate file entries.
  // These entries need to be mapped with the names collected from the name table.
  for (i = 0; i < bswap_16(m_header.table_entries_num); i++)
  {
    // Use a predefined list for most file names.
    entry_files[i].name = get_entry_name_by_type(bswap_32(entries[i].type));
    entry_files[i].offset = bswap_32(entries[i].offset);
    entry_files[i].size = bswap_32(entries[i].size);

    if (((bswap_32(entries[i].type) & PS4_PKG_ENTRY_TYPE_FILE1) == PS4_PKG_ENTRY_TYPE_FILE1)
    || (((bswap_32(entries[i].type) & PS4_PKG_ENTRY_TYPE_FILE2) == PS4_PKG_ENTRY_TYPE_FILE2)))
    {
      // If a file was found and it's name is not on the predefined list, try to map it with
      // a name from the name table.
      if (entry_files[i].name == NULL)
      {
        entry_files[i].name = file_name_list[file_count];
      }
      if (entry_files[i].name != NULL)
      {
        file_count++;
      }
    }
  }
  printfsocket("Successfully mapped %d files.\n\n", file_count);

  // Set up the output directory for file writing.
  char dest_path[256];
  char title_id[256];

  memset(title_id, 0, 256);
  memcpy(title_id, tidpath, 255);
  mkdir(title_id, 0777);

  // Search through the entries for mapped file data and output it.
  printfsocket("Dumping internal PKG files...\n");
  for (i = 0; i < bswap_16(m_header.table_entries_num); i++)
  {
    entry_file_data = (unsigned char *)realloc(NULL, entry_files[i].size);

    lseek(fdin, entry_files[i].offset, SEEK_SET);
    read(fdin, entry_file_data, entry_files[i].size);

    if (entry_files[i].name == NULL) continue;

    sprintf(dest_path, "%s/sce_sys/%s", title_id, entry_files[i].name);
    printfsocket("%s\n", dest_path);

    _mkdir (dest_path);

    int fdout = open(dest_path, O_WRONLY | O_CREAT | O_TRUNC, 0777);
    if (fdout != -1)
    {
      write(fdout, entry_file_data, entry_files[i].size);
      close(fdout);
    }
    else
    {
      printfsocket("Can't open file for writing!\n");
      return 3;
    }
  }

  // Clean up.
  close(fdin);

  free(entries);
  free(entry_files);

  printfsocket("Done.\n");

  return 0;
}
