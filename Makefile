.DEFAULT_GOAL := help

# Interactive config generator (pick client → pick template → enter sub URL → name output)
.PHONY: config
config:
	@bash generate.sh

.PHONY: help
help:
	@echo "Available commands:"
	@echo "  make config    Interactive config generator"
	@echo "  make help      Show this help"
