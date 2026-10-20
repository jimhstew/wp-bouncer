# WP Bouncer build and test tasks.
#
#   make            Build builds/wp-bouncer-<version>.zip, ready for Plugins > Add New > Upload
#   make test       Unit tests (needs PHP and `composer install`)
#   make analyse    PHPStan static analysis
#   make lint       WordPress Coding Standards
#   make e2e        End-to-end tests against the wp-bouncer/ source folder
#   make check      Unit tests, build, then end-to-end tests against the built zip
#   make clean      Delete builds/
#
# Only the wp-bouncer/ folder goes into the zip. Tests (including the WAF test
# payloads that some hosts' malware scanners flag), documentation and tooling
# stay out of it, and the build fails if anything test-like slips in.
#
# Override tools if they aren't on PATH, e.g. `make test PHP=/opt/php/bin/php`.

PHP      ?= php
COMPOSER ?= composer

PLUGIN   := wp-bouncer
SRC      := $(PLUGIN)
BUILDS   := builds
VERSION  := $(shell sed -n 's/^ \* Version: *//p' $(SRC)/$(PLUGIN).php | tr -d '[:space:]')
ZIP      := $(BUILDS)/$(PLUGIN)-$(VERSION).zip
STAGE    := $(BUILDS)/.stage
SOURCES  := $(shell find $(SRC) -type f ! -name '.DS_Store')

# Files that must never ship.
FORBIDDEN := -e '/tests/' -e 'Test\.php$$' -e '/fixtures/' -e 'phpunit' -e '\.phar$$' -e '/\.' -e 'composer\.'

.PHONY: all build test analyse lint e2e check clean version

all: build

build: $(ZIP)

$(ZIP): $(SOURCES) Makefile
	@test -n "$(VERSION)" || { echo "Could not read Version from $(SRC)/$(PLUGIN).php"; exit 1; }
	@command -v zip > /dev/null || { echo "zip is not installed"; exit 1; }
	@if command -v $(PHP) > /dev/null; then \
		echo "Checking PHP syntax"; \
		find $(SRC) -name '*.php' -print0 | xargs -0 -n1 $(PHP) -l > /dev/null || exit 1; \
	else \
		echo "($(PHP) not found: skipping the PHP syntax check)"; \
	fi
	@rm -rf $(STAGE) && mkdir -p $(STAGE)
	@# Copy without dotfiles (.DS_Store, .gitkeep and the like).
	@cd $(SRC) && find . -type f ! -name '.*' | while read -r f; do \
		mkdir -p "$(CURDIR)/$(STAGE)/$(PLUGIN)/$$(dirname "$$f")"; \
		cp -p "$$f" "$(CURDIR)/$(STAGE)/$(PLUGIN)/$$f"; \
	done
	@mkdir -p $(STAGE)/$(PLUGIN)/languages
	@rm -f $@
	@cd $(STAGE) && zip -qrX "$(CURDIR)/$@" $(PLUGIN)
	@rm -rf $(STAGE)
	@if unzip -Z1 $@ | grep -q $(FORBIDDEN); then \
		echo "Refusing to ship test or tooling files:"; unzip -Z1 $@ | grep $(FORBIDDEN); rm -f $@; exit 1; \
	fi
	@if command -v sha256sum > /dev/null; then (cd $(BUILDS) && sha256sum $(notdir $@) > $(notdir $@).sha256); \
	else (cd $(BUILDS) && shasum -a 256 $(notdir $@) > $(notdir $@).sha256); fi
	@echo "Built $@ ($$(unzip -Z1 $@ | grep -vc '/$$') files, $$(du -k $@ | cut -f1) KB)"

version:
	@echo $(VERSION)

vendor/autoload.php: composer.json
	$(COMPOSER) install --no-interaction --no-progress
	@touch $@

test: vendor/autoload.php
	$(PHP) vendor/bin/phpunit

analyse: vendor/autoload.php
	$(PHP) vendor/bin/phpstan analyse

lint: vendor/autoload.php
	$(PHP) vendor/bin/phpcs

e2e:
	PHP=$(PHP) tests/e2e/run.sh

check: test build
	PHP=$(PHP) WPB_E2E_ZIP=$(CURDIR)/$(ZIP) tests/e2e/run.sh

clean:
	rm -rf $(BUILDS)
