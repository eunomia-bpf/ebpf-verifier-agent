#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define MAX_RULES 50
#define MAX_RULE_NAME 20
#define MAX_BYTE_PATTERN 11

struct filter_rule
{
   char rule_name[MAX_RULE_NAME];
   char byte_pattern[MAX_BYTE_PATTERN];
};

unsigned char mystrlen(const char *s, unsigned char max_len)
{
    unsigned char i = 0;
    if(s == NULL)
       return 0;
    for (i = 0; i < max_len; i++)
    {
       if (s[i] == '\0')
          return i;
    }
    return i;
}

bool find_substring(const char *str, const char *search)
{
   if(str != NULL && search != NULL)
   {
      unsigned char l1 = mystrlen(str,50);
      unsigned char l2 = mystrlen(search, MAX_BYTE_PATTERN);
      unsigned char i = 0, j = 0;
      unsigned char flag = 0;
      if(l1 == 0 || l2 == 0)
         return false;
      for (i = 0; i <= l1 - l2; i++)
      {
         for (j = i; j < i + l2; j++)
         {
            flag = 1;
            if (str[j] != search[j - i])
            {
               flag = 0;
               break;
            }
         }
         if (flag == 1)
         {
            break;
         }
      }
      if(flag == 1)
         return true;
      else
         return false;
   }
   else
   {
      return false;
   }
}
char _license[] SEC("license") = "GPL";
