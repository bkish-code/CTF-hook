# Makefile for notes.c
CC = gcc
CFLAGS = -Wall -Wextra -g

# use PIE + ASLR
notes: notes.c
	$(CC) $(CFLAGS) -fPIE -pie -fno-stack-protector -z norelro -o notes notes.c

clean:

# Show symbols for exploit
debug: notes
	@echo "=== Runtime addresses require a leak (PIE enabled) ==="
	@echo ""
	@echo "Static offsets from binary (add PIE base at runtime):"
	@nm -n notes 2>/dev/null | grep -E "execveat_sim|cleanup_callback|create_note" || echo "Run 'make notes' first"
	@echo ""
	@echo "Check heap layout after create_note():"
	@echo "gdb -q ./notes -ex 'b create_note' -ex 'r' -ex 'fin' -ex 'heap chunks'"


# To run
run:
	./notes