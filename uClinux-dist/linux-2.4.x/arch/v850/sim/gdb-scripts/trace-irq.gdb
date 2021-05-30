break *irq
command
  silent
  printf "[irq %d]\n", ($ecr - 0x80) / 16
  cont
end

break *ret_from_interrupt
command
  silent
  printf "[ret_from_interrupt]\n"
  cont
end
