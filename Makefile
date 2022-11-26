DIAGS = -fdiagnostics-color=always -fdiagnostics-show-option -fno-common -fno-strict-aliasing -fstack-protector -fstack-protector-strong -fvisibility=hidden --param=ssp-buffer-size=4 -fno-omit-frame-pointer

WARNINGS = -Wall -Winvalid-pch -Wextra -Wno-missing-field-initializers -Wno-unused-parameter -Wdate-time -Wendif-labels -Werror=format=2 -Werror=format-signedness -Werror=implicit-function-declaration -Werror=incompatible-pointer-types -Werror=int-conversion -Werror=overflow -Werror=override-init -Werror=return-type -Werror=shift-count-overflow -Werror=shift-overflow=2 -Werror=undef -Wfloat-equal -Wimplicit-fallthrough=5 -Winit-self -Wlogical-op -Wmissing-include-dirs -Wmissing-noreturn -Wnested-externs -Wold-style-definition -Wpointer-arith -Wredundant-decls -Wshadow -Wstrict-aliasing=2 -Wstrict-prototypes -Wsuggest-attribute=noreturn -Wunused-function -Wwrite-strings -Wno-maybe-uninitialized -Wno-unused-result -Werror=missing-declarations -Werror=missing-prototypes -Werror=shadow

CFLAGS = -pipe -D_FILE_OFFSET_BITS=64 -std=gnu11 -g $(DIAGS) $(WARNINGS)

CPPFLAGS = -I . -D_GNU_SOURCE

PROG_CGLS = cgls
SRC_CGLS = log.c characters.c locale-util.c unit.c sdbus.c misc.c cgroup.c \
	termcolors.c glyph-util.c cgls.c
OBJ_CGLS = $(SRC_CGLS:%.c=%.o)

PROGS = $(PROG_CGLS)
OBJS = $(OBJ_CGLS)

$(PROG_CGLS): LDFLAGS += -L/usr/lib/x86_64-linux-gnu -zdefs -zcombreloc -znow
$(PROG_CGLS): LDLIBS += -lsystemd
cgls.o:	CPPFLAGS += -I /usr/include/systemd

$(PROG_CGLS): $(OBJ_CGLS)

%.o: %.c %.h Makefile
	$(COMPILE.c) $(OUTPUT_OPTION) $<

cleandocs:
	rm -rf docs/html docs/latex Doxyfile.tmp

clean: cleandocs
	rm -f $(PROGS) $(OBJS)

# INTERNAL documentation, i.e. unstable! May change at any time.
docs: cleandocs
	VERS=$$( sed -ne '/^#define VERSION/ { s/^.* //; p }' cgls.h ) && \
		sed -e "s|@VERSION@|$$VERS|" Doxyfile >Doxyfile.tmp
	doxygen Doxyfile.tmp
