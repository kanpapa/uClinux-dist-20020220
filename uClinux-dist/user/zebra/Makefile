
all clean romfs: dummy_target
	$(MAKE) -C lib $@
	$(MAKE) -C ripd $@
	$(MAKE) -C ospfd $@
	$(MAKE) -C bgpd $@
	$(MAKE) -C zebra $@

dummy_target:

