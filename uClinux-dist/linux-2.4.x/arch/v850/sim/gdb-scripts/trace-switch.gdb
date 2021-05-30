break *switch_thread
command
  silent
  printf "[switch 0x%x -> 0x%x]:\n", $r6, $r7
  #call show_regs ($r7 + 24)
  #printf "New: "
  #p/x *(struct pt_regs *)($r7 + 24)
  cont
end

#break *(switch_thread + 38)
#command
#  silent
#  printf "Old: "
#  p/x *(struct pt_regs *)($sp + 24)
#  cont
#end
#