#
# Copyright(c) 2019-2021 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause
#
OSTYPE=$(shell echo $$OSTYPE)
# true for MinGW, Win-Builds, git bash
MSYS=$(shell [[ $$OSTYPE == msys* ]] && echo "yes")

ifneq ($(MSYS), yes)
	OCF_ENV="posix"
else
	OCF_ENV="windows"
endif

ADAPTERDIR=pyocf
SRCDIR=$(ADAPTERDIR)/ocf/src
INCDIR=$(ADAPTERDIR)/ocf/include
WRAPDIR=$(ADAPTERDIR)/wrappers
# TODO: this should be achieved by setting SHELL=/bin/bash
# rather than explicitly calling bash binary
SRC=$(shell bash -c "find $(SRCDIR) $(WRAPDIR) -name \*.c")

# target objs and library path - relative to makefile
# to work as makefile targets
OBJS=$(patsubst %.c, %.o, $(SRC))
OCFLIB=$(ADAPTERDIR)/libocf.so

PWD=$(shell pwd)

# path to OCF install dir - absolute not to lose relevance after
# passing to top level OCF makefile
INSTALDIR=$(PWD)/$(ADAPTERDIR)/ocf
OCFDIR=$(PWD)/../../

CC=gcc
CFLAGS=-g -Wall -I$(INCDIR) -I$(SRCDIR)/ocf/env
LDFLAGS=-pthread -lz
ifeq ($(MSYS), yes)
	LDFLAGS+= -ldbghelp
endif

all: | sync config_random
	@bash -c "$(MAKE) -C $(PWD) $(OCFLIB)"

$(OCFLIB): $(OBJS)
	@echo "Building $@"
	@$(CC) -coverage -shared -o $@ $(CFLAGS) $^ -fPIC $(LDFLAGS)

%.o: %.c
	@echo "Compiling $@"
	@$(CC) -coverage -c $(CFLAGS) -o $@ -fPIC $^ $(LDFLAGS)

sync:
	@echo "Syncing OCF sources"
	@mkdir -p $(INSTALDIR)
	@bash -c "$(MAKE) -C $(OCFDIR) inc O=$(INSTALDIR)"
	@bash -c "$(MAKE) -C $(OCFDIR) src O=$(INSTALDIR)"
	@bash -c "$(MAKE) -C $(OCFDIR) env O=$(INSTALDIR) OCF_ENV=windows"

config_random:
	@python3 utils/configure_random.py

clean:
	@rm -rf $(OCFLIB) $(OBJS)
	@echo "  CLEAN "

distclean: clean
	@rm -rf $(OCFLIB) $(OBJS)
	@rm -rf $(SRCDIR)/ocf
	@rm -rf $(INCDIR)/ocf
	@echo "  DISTCLEAN "

.PHONY: all clean sync config_random distclean
