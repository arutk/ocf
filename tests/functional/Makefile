#
# Copyright(c) 2019-2021 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause
#

PWD=$(shell pwd)
OCFDIR=/../../
ADAPTERDIR=./pyocf
SRCDIR=$(ADAPTERDIR)/ocf/src
INCDIR=$(ADAPTERDIR)/ocf/include
WRAPDIR=$(ADAPTERDIR)/wrappers

CC=gcc
CFLAGS=-g -Wall -I$(INCDIR) -I$(SRCDIR)/ocf/env
LDFLAGS=-pthread -lz
SRC=$(shell find ./pyocf/ocf/src ./pyocf/wrappers  -name \*.c)
OBJS=$(patsubst %.c, %.o, $(SRC))
OCFLIB=$(ADAPTERDIR)/libocf.so

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
	@mkdir -p $(ADAPTERDIR)/ocf
	@bash -c "$(MAKE) -C $(OCFDIR) inc O=$(ADAPTERDIR)/ocf"
	@bash -c "$(MAKE) -C $(OCFDIR) src O=$(ADAPTERDIR)/ocf"
	@bash -c "$(MAKE) -C $(OCFDIR) env O=$(ADAPTERDIR)/ocf OCF_ENV=windows"

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
