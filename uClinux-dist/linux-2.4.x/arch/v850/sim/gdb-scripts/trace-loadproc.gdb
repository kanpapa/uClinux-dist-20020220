break binfmt_flat.c:727
command
  silent
  printf "[loaded process `%s' at 0x%x (text 0x%x-0x%x, data 0x%x-0x%x, bss 0x%x-0x%x)]\n", bprm->filename, textpos, current->mm->start_code, current->mm->end_code, current->mm->start_data, current->mm->end_data, current->mm->end_data, current->mm->brk
  cont
end
