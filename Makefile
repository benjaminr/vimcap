# vimcap — convenience targets.

VENV ?= .venv
PYTHON ?= $(VENV)/bin/python

.PHONY: install test tags clean

install: ## Create the venv with scapy and generate help tags
	./install.sh

tags: ## (Re)generate help tags
	vim -u NONE -es -c 'helptags doc' -c q

test: ## Run the integration suite (uses $(PYTHON))
	VIMCAP_PYTHON=$(PYTHON) test/run.sh

clean: ## Remove the venv and generated artefacts
	rm -rf $(VENV) doc/tags python/__pycache__
