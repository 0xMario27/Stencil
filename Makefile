.DEFAULT_GOAL := help

# Interactive config generator (pick client → pick template → enter sub URL → name output)
.PHONY: config
config:
	@bash generate.sh

.PHONY: help
help:
	@echo "Available commands:"
	@echo "  make config              Interactive config generator"
	@echo "  make templates-json      Rebuild templates.json from dirs"
	@echo "  make help                Show this help"

.PHONY: templates-json
templates-json:
	@python3 scripts/build_templates.py > templates.json
	@echo "templates.json regenerated"
