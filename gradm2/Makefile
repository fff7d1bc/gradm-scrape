##############################################################################
# gradm (c) 2002-2009 - Brad Spengler, Open Source Security Inc.             #
# http://www.grsecurity.net                                                  #
#----------------------------------------------------------------------------#
# gradm is licensed under the GNU GPL v2 or higher http://www.gnu.org        #
##############################################################################

GRADM_BIN=gradm
GRADM_PAM=gradm_pam
GRSEC_DIR=/etc/grsec

LLEX=/usr/bin/lex
FLEX=/usr/bin/flex
LEX := $(shell if [ -x $(FLEX) ]; then echo $(FLEX); else echo $(LLEX); fi)
LEXFLAGS=-B
#ubuntu broke byacc for who knows why, disable it
#BYACC=/usr/bin/byacc
BISON=/usr/bin/bison
#YACC := $(shell if [ -x $(BYACC) ]; then echo $(BYACC); else echo $(BISON); fi)
YACC=$(BISON)
MKNOD=/bin/mknod
#for dietlibc
#CC=/usr/bin/diet /usr/bin/gcc
CC=/usr/bin/gcc
FIND=/usr/bin/find
STRIP=/usr/bin/strip
LIBS := $(shell if [ "`uname -m`" != "sparc64" -a "`uname -m`" != "x86_64" ]; then echo "-lfl" ; else echo "" ; fi)
OPT_FLAGS := $(shell if [ "`uname -m`" != "sparc64" ] && [ "`uname -m`" != "x86_64" ]; then echo "-O2" ; else echo "-O2 -m64" ; fi)
CFLAGS := $(OPT_FLAGS) -Wcast-qual -DGRSEC_DIR=\"$(GRSEC_DIR)\" -D_LARGEFILE64_SOURCE
LDFLAGS=
INSTALL = /usr/bin/install -c

# FHS
MANDIR=/usr/share/man
# older MANDIR
#MANDIR=/usr/man
DESTDIR=

OBJECTS=gradm.tab.o lex.gradm.o learn_pass1.tab.o learn_pass2.tab.o \
	fulllearn_pass1.tab.o fulllearn_pass2.tab.o fulllearn_pass3.tab.o \
	gradm_misc.o gradm_parse.o gradm_arg.o gradm_pw.o gradm_opt.o \
	gradm_cap.o gradm_sha256.o gradm_adm.o gradm_analyze.o gradm_res.o \
	gradm_human.o gradm_learn.o gradm_net.o gradm_nest.o gradm_pax.o \
	gradm_sym.o gradm_newlearn.o gradm_fulllearn.o gradm_lib.o \
	lex.fulllearn_pass1.o lex.fulllearn_pass2.o \
	lex.fulllearn_pass3.o lex.learn_pass1.o lex.learn_pass2.o \
	grlearn_config.tab.o lex.grlearn_config.o gradm_globals.o \
	gradm_replace.o

all: $(GRADM_BIN) $(GRADM_PAM) grlearn
nopam: $(GRADM_BIN) grlearn

$(GRADM_BIN): $(OBJECTS) gradm.h gradm_defs.h gradm_func.h
	$(CC) $(CFLAGS) -o $@ $(OBJECTS) $(LIBS) $(LDFLAGS)

$(GRADM_PAM): gradm_pam.c gradm.h gradm_defs.h gradm_func.h
	@if [ ! -f /usr/include/security/pam_appl.h ] ; then \
		echo "Unable to detect PAM headers, disabling PAM support." ; \
	else \
		$(CC) $(CFLAGS) -o $@ gradm_pam.c -lpam -lpam_misc $(LDFLAGS) ; \
	fi

grlearn: grlearn.c gradm_lib.c grlearn2_config.tab.c lex.grlearn_config.c
	$(CC) $(CFLAGS) -DIS_GRLEARN -o $@ grlearn.c gradm_lib.c grlearn2_config.tab.c lex.grlearn_config.c $(LIBS) $(LDFLAGS)

grlearn2_config.tab.c: grlearn2_config.y
	$(YACC) -b grlearn2_config -p grlearn2_config -d ./grlearn2_config.y

grlearn_config.tab.c: grlearn_config.y
	$(YACC) -b grlearn_config -p grlearn_config -d ./grlearn_config.y

lex.grlearn_config.c: grlearn_config.l
	$(LEX) $(LEXFLAGS) -Pgrlearn_config ./grlearn_config.l

gradm.tab.c: gradm.y
	$(YACC) -b gradm -p gradm -d ./gradm.y

lex.gradm.c: gradm.l
	$(LEX) $(LEXFLAGS) -Pgradm ./gradm.l

fulllearn_pass1.tab.c: gradm_fulllearn_pass1.y
	$(YACC) -b fulllearn_pass1 -p fulllearn_pass1 -d ./gradm_fulllearn_pass1.y
fulllearn_pass2.tab.c: gradm_fulllearn_pass2.y
	$(YACC) -b fulllearn_pass2 -p fulllearn_pass2 -d ./gradm_fulllearn_pass2.y
fulllearn_pass3.tab.c: gradm_fulllearn_pass3.y
	$(YACC) -b fulllearn_pass3 -p fulllearn_pass3 -d ./gradm_fulllearn_pass3.y

lex.fulllearn_pass1.c: gradm_fulllearn_pass1.l
	$(LEX) $(LEXFLAGS) -Pfulllearn_pass1 ./gradm_fulllearn_pass1.l
lex.fulllearn_pass2.c: gradm_fulllearn_pass2.l
	$(LEX) $(LEXFLAGS) -Pfulllearn_pass2 ./gradm_fulllearn_pass2.l
lex.fulllearn_pass3.c: gradm_fulllearn_pass3.l
	$(LEX) $(LEXFLAGS) -Pfulllearn_pass3 ./gradm_fulllearn_pass3.l

learn_pass1.tab.c: gradm_learn_pass1.y
	$(YACC) -b learn_pass1 -p learn_pass1 -d ./gradm_learn_pass1.y
learn_pass2.tab.c: gradm_learn_pass2.y
	$(YACC) -b learn_pass2 -p learn_pass2 -d ./gradm_learn_pass2.y

lex.learn_pass1.c: gradm_learn_pass1.l
	$(LEX) $(LEXFLAGS) -Plearn_pass1 ./gradm_learn_pass1.l
lex.learn_pass2.c: gradm_learn_pass2.l
	$(LEX) $(LEXFLAGS) -Plearn_pass2 ./gradm_learn_pass2.l

install: $(GRADM_BIN) gradm.8 policy grlearn
	@mkdir -p $(DESTDIR)/sbin
	@echo "Installing gradm..."
	@$(INSTALL) -m 0755 $(GRADM_BIN) $(DESTDIR)/sbin
	@$(STRIP) $(DESTDIR)/sbin/$(GRADM_BIN)
	@if [ -f $(GRADM_PAM) ] ; then \
		echo "Installing gradm_pam..." ; \
		$(INSTALL) -m 4755 $(GRADM_PAM) $(DESTDIR)/sbin ; \
		$(STRIP) $(DESTDIR)/sbin/$(GRADM_PAM) ; \
	fi
	@echo "Installing grlearn..."
	@$(INSTALL) -m 0700 grlearn $(DESTDIR)/sbin
	@$(STRIP) $(DESTDIR)/sbin/grlearn
	@mkdir -p -m 700 $(DESTDIR)$(GRSEC_DIR)
	@if [ ! -f $(DESTDIR)$(GRSEC_DIR)/policy ] ; then \
		if [ -f $(DESTDIR)$(GRSEC_DIR)/acl ] ; then \
			mv $(DESTDIR)$(GRSEC_DIR)/acl $(DESTDIR)$(GRSEC_DIR)/policy ; \
		else \
			$(INSTALL) -m 0600 policy $(DESTDIR)$(GRSEC_DIR) ; \
		fi \
	fi
	@$(FIND) $(DESTDIR)$(GRSEC_DIR) -type f -name learn_config -size 1291c -exec rm -f $(DESTDIR)$(GRSEC_DIR)/learn_config \;
	@if [ ! -f $(DESTDIR)$(GRSEC_DIR)/learn_config ] ; then \
		$(INSTALL) -m 0600 learn_config $(DESTDIR)$(GRSEC_DIR) ; \
	fi
	@if [ -z "`cut -d" " -f3 /proc/mounts | grep "^devfs"`" ] ; then \
		rm -f $(DESTDIR)/dev/grsec ; \
		if [ ! -e $(DESTDIR)/dev/grsec ] ; then \
			mkdir -p $(DESTDIR)/dev ; \
			$(MKNOD) -m 0622 $(DESTDIR)/dev/grsec c 1 13 ; \
		fi \
	fi
	@if [ -d $(DESTDIR)/etc/udev/rules.d ] ; then \
		echo "ACTION!=\"add|change\", GOTO=\"permissions_end\"" > $(DESTDIR)/etc/udev/rules.d/80-grsec.rules ; \
		echo "KERNEL==\"grsec\",          MODE=\"0622\"" >> $(DESTDIR)/etc/udev/rules.d/80-grsec.rules ; \
		echo "LABEL=\"permissions_end\"" >> $(DESTDIR)/etc/udev/rules.d/80-grsec.rules ; \
	fi
	@if [ -f $(DESTDIR)/sbin/udevadm ] ; then \
		$(DESTDIR)/sbin/udevadm trigger --action=change ; \
	fi
	@echo "Installing gradm manpage..."
	@mkdir -p $(DESTDIR)$(MANDIR)/man8
	@$(INSTALL) -m 0644 gradm.8 $(DESTDIR)$(MANDIR)/man8/$(GRADM_BIN).8
	@if [ -x /sbin/$(GRADM_BIN) ] ; then \
		if [ -z $(DESTDIR) ] && [ ! -f $(GRSEC_DIR)/pw ] ; then \
			/sbin/$(GRADM_BIN) -P ; \
		fi \
	fi
	@true

clean:
	rm -f core *.o $(GRADM_BIN) $(GRADM_PAM) lex.*.c *.tab.c *.tab.h grlearn
