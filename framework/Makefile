# Makefile for Cyb3rhq Framework
# Copyright (C) 2015, Cyb3rhq Inc.
# May 3, 2017
#
# Syntax: make [ all | build | install | examples | clean ]

CYB3RHQ_GROUP       = cyb3rhq
INSTALLDIR       ?= /var/ossec

CC           = gcc
CFLAGS       = -pipe -Wall -Wextra
THREAD_FLAGS = -pthread
MV_FILE      = mv -f
RM_FILE      = rm -f
INSTALL_DIR  = install -o root -g ${CYB3RHQ_GROUP} -m 0750  -d
INSTALL_EXEC = install -o root -g ${CYB3RHQ_GROUP} -m 0750
INSTALL_FILE = install -o root -g ${CYB3RHQ_GROUP} -m 0640

ifdef DEBUG
	CFLAGS+=-g -I ../src
	LFLAGS+=-g
else
	CFLAGS+=-O2 -I ../src
	LFLAGS+=-O2
endif

.PHONY: all build install examples clean

all: build

install:
	$(INSTALL_DIR) $(INSTALLDIR)/framework
	$(INSTALL_DIR) $(INSTALLDIR)/framework/scripts
	$(INSTALL_DIR) $(INSTALLDIR)/framework/cyb3rhq
	$(INSTALL_DIR) $(INSTALLDIR)/framework/cyb3rhq/core/cluster
	$(INSTALL_DIR) $(INSTALLDIR)/framework/cyb3rhq/core/cluster/dapi
	$(INSTALL_DIR) $(INSTALLDIR)/framework/cyb3rhq/core/cluster/hap_helper

	$(INSTALL_FILE) scripts/*.py ${INSTALLDIR}/framework/scripts
	$(INSTALL_FILE) cyb3rhq/*.py ${INSTALLDIR}/framework/cyb3rhq
	$(INSTALL_FILE) cyb3rhq/core/cluster/*.json ${INSTALLDIR}/framework/cyb3rhq/core/cluster
	$(INSTALL_FILE) cyb3rhq/core/cluster/*.py ${INSTALLDIR}/framework/cyb3rhq/core/cluster
	$(INSTALL_FILE) cyb3rhq/core/cluster/dapi/*.py ${INSTALLDIR}/framework/cyb3rhq/core/cluster/dapi
	$(INSTALL_FILE) cyb3rhq/core/cluster/hap_helper/*.py ${INSTALLDIR}/framework/cyb3rhq/core/cluster/hap_helper

#	Remove update_ruleset script when upgrading to >=4.2.0 (deprecated)
	[ ! -e ${INSTALLDIR}/bin/update_ruleset ] || $(RM_FILE) ${INSTALLDIR}/bin/update_ruleset
#	Install scripts/%.py on $(INSTALLDIR)/bin/%
	$(foreach script,$(wildcard scripts/*.py),$(INSTALL_EXEC) wrappers/generic_wrapper.sh $(patsubst scripts/%.py,$(INSTALLDIR)/bin/%,$(script));)
#   Provisional name change for cyb3rhq-logtest and cyb3rhq-clusterd
	$(MV_FILE) $(INSTALLDIR)/bin/cyb3rhq_logtest $(INSTALLDIR)/bin/cyb3rhq-logtest
	$(MV_FILE) $(INSTALLDIR)/bin/cyb3rhq_clusterd $(INSTALLDIR)/bin/cyb3rhq-clusterd
	$(RM_FILE) $(INSTALLDIR)/bin/__init__

examples: install
	$(INSTALL_DIR) $(INSTALLDIR)/framework/examples
	$(INSTALL_EXEC) examples/*.py ${INSTALLDIR}/framework/examples

clean:
	$(RM_FILE) $(BUILD_TARGET) *.o *.so.0
