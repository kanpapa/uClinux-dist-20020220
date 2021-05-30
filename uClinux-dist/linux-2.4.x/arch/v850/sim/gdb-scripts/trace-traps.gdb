break *trap
command
  silent
  printf "[trap %d, %d]\n", ($ecr - 0x40), $r12
  cont
end

break *ret_from_trap
command
  silent
  printf "[ret_from_trap %d, 0x%x]\n", ((struct pt_regs *)($sp + 24))->gpr[0], $r10
  cont
end
