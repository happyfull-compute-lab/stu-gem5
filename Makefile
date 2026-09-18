CC ?= gcc
GEM5 ?= gem5/build/X86/gem5.opt

BINS = flush_test spectre_v1_fr benign_compute benign_cache benign_syscall \
       benign_flush benign_proc_mix benign_privdrop attack_setuid_exhaust

.PHONY: all clean flush-check spectre-check

all: $(BINS)

flush_test: flush_test.c
	$(CC) -O2 -static -o $@ $<

spectre_v1_fr: spectre_v1_fr.c
	$(CC) -O2 -static -o $@ $<

benign_compute: benign_compute.c
	$(CC) -O2 -static -o $@ $<

benign_cache: benign_cache.c
	$(CC) -O2 -static -o $@ $<

benign_syscall: benign_syscall.c
	$(CC) -O2 -static -o $@ $<

benign_flush: benign_flush.c
	$(CC) -O2 -static -o $@ $<

benign_proc_mix: benign_proc_mix.c
	$(CC) -O2 -static -o $@ $<

benign_privdrop: benign_privdrop.c
	$(CC) -O2 -static -o $@ $<

attack_setuid_exhaust: attack_setuid_exhaust.c
	$(CC) -O2 -static -o $@ $<

flush-check: flush_test
	$(GEM5) --outdir=m5out_flush se_flush.py

spectre-check: spectre_v1_fr
	$(GEM5) --outdir=m5out_spectre_check se-spectre.py 8 10

clean:
	rm -f $(BINS)
