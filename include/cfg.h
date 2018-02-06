/* inih -- simple .ini/.cfg file parser

inih is released under the New BSD license (see LICENSE.txt). Go to the project
home page for more info:

https://github.com/benhoyt/inih

*/

#ifndef __CFG_H__
#define __CFG_H__

/* Nonzero if cfg_handler callback should accept lineno parameter. */
#ifndef CFG_HANDLER_LINENO
#define CFG_HANDLER_LINENO 0
#endif

/* Typedef for prototype of handler function. */
#if CFG_HANDLER_LINENO
typedef int (*cfg_handler)(void* user, const char* name, const char* value, int lineno);
#else
typedef int (*cfg_handler)(void* user, const char* name, const char* value);
#endif

/* Typedef for prototype of fgets-style reader function. */
typedef char* (*cfg_reader)(char* str, int num, void* stream);

/* Parse given CONF-style file. May have name=value pairs
   (whitespace stripped), and comments starting with ';' (semicolon).

   For each name=value pair parsed, call handler function with given user
   pointer and value (data only valid for duration
   of handler call). Handler should return nonzero on success, zero on error.

   Returns 0 on success, line number of first error on parse error (doesn't
   stop on first error), -1 on file open error, or -2 on memory allocation
   error (only when CFG_USE_STACK is zero).
*/
int cfg_parse(const char* filename, cfg_handler handler, void* user);

/* Same as cfg_parse(), but takes a FILE* instead of filename. This doesn't
   close the file when it's finished -- the caller must do that. */
int cfg_parse_file(FILE* file, cfg_handler handler, void* user);

/* Same as cfg_parse(), but takes an cfg_reader function pointer instead of
   filename. Used for implementing custom or string-based I/O (see also
   cfg_parse_string). */
int cfg_parse_stream(cfg_reader reader, void* stream, cfg_handler handler,
                     void* user);

/* Same as cfg_parse(), but takes a zero-terminated string with the CONF data
instead of a file. Useful for parsing CONF data from a network socket or
already in memory. */
int cfg_parse_string(const char* string, cfg_handler handler, void* user);

/* Nonzero to allow multi-line value parsing, in the style of Python's
   configparser. If allowed, cfg_parse() will call the handler with the same
   name for each subsequent line parsed. */
#ifndef CFG_ALLOW_MULTILINE
#define CFG_ALLOW_MULTILINE 0
#endif

/* Nonzero to allow a UTF-8 BOM sequence (0xEF 0xBB 0xBF) at the start of
   the file. See http://code.google.com/p/inih/issues/detail?id=21 */
#ifndef CFG_ALLOW_BOM
#define CFG_ALLOW_BOM 0
#endif

/* Nonzero to allow inline comments (with valid inline comment characters
   specified by CFG_INLINE_COMMENT_PREFIXES). Set to 0 to turn off and match
   Python 3.2+ configparser behaviour. */
#ifndef CFG_ALLOW_INLINE_COMMENTS
#define CFG_ALLOW_INLINE_COMMENTS 1
#endif
#ifndef CFG_INLINE_COMMENT_PREFIXES
#define CFG_INLINE_COMMENT_PREFIXES ";"
#endif

/* Nonzero to use stack for line buffer, zero to use heap (malloc/free). */
#ifndef CFG_USE_STACK
#define CFG_USE_STACK 1
#endif

/* Maximum line length for any line in CONF file (stack or heap). Note that
   this must be 3 more than the longest line (due to '\r', '\n', and '\0'). */
#ifndef CFG_MAX_LINE
#define CFG_MAX_LINE 200
#endif

/* Nonzero to allow heap line buffer to grow via realloc(), zero for a
   fixed-size buffer of CFG_MAX_LINE bytes. Only applies if CFG_USE_STACK is
   zero. */
#ifndef CFG_ALLOW_REALLOC
#define CFG_ALLOW_REALLOC 0
#endif

/* Initial size in bytes for heap line buffer. Only applies if CFG_USE_STACK
   is zero. */
#ifndef CFG_INITIAL_ALLOC
#define CFG_INITIAL_ALLOC 200
#endif

/* Stop parsing on first error (default is to keep parsing). */
#ifndef CFG_STOP_ON_FIRST_ERROR
#define CFG_STOP_ON_FIRST_ERROR 0
#endif

#endif /* __CFG_H__ */
