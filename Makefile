# WP Bouncer build and test tasks.
#
#   make            Build builds/wp-bouncer-<version>.zip, ready for Plugins > Add New > Upload
#   make manifest   Also write builds/update.json and release-notes.md (needs PHP). The release
#                   workflow attaches these to the GitHub release; installed sites read update.json.
#   make test       Unit tests (needs PHP and `composer install`)
#   make test-js    JS logic tests with node --test (skipped if node is missing)
#   make integration  WordPress integration tests (needs PHP with mysqli and a MySQL/MariaDB;
#                   set WPB_TESTS_DB_HOST/USER/PASSWORD/NAME, optionally WP_VERSION=7.0)
#   make analyse    PHPStan static analysis
#   make lint       WordPress Coding Standards
#   make e2e        End-to-end tests against the wp-bouncer/ source folder
#   make check      Unit tests, build, then end-to-end tests against the built zip
#   make map IN=<dir>  Rebuild assets/map/world.svg and Centroids from Natural Earth files in <dir>
#                   (outside the repo; see scripts/build-world-map.php for the inputs)
#   make clean      Delete builds/
#
# Only the wp-bouncer/ folder goes into the zip. Tests (including the WAF test
# payloads that some hosts' malware scanners flag), documentation and tooling
# stay out of it, and the build fails if anything test-like slips in.
#
# The zip is reproducible (SB-13): file order, modes, owners and timestamps are fixed, so building
# the same commit anywhere gives the same sha256. Timestamps come from SOURCE_DATE_EPOCH, which
# defaults to the last commit's time (outside a git checkout, set it yourself or a fixed fallback
# date is used). Compare a local build with the published .sha256 to check a release.
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
# Seconds since the epoch: the environment, else the last commit, else 2020-01-01 UTC.
SOURCE_DATE_EPOCH ?= $(shell git log -1 --format=%ct 2>/dev/null)
ifeq ($(strip $(SOURCE_DATE_EPOCH)),)
SOURCE_DATE_EPOCH := 1577836800
endif
export SOURCE_DATE_EPOCH
SOURCES  := $(shell find $(SRC) -type f ! -name '.DS_Store')

# Files that must never ship.
FORBIDDEN := -e '/tests/' -e 'Test\.php$$' -e '/fixtures/' -e 'phpunit' -e '\.phar$$' -e '/\.' -e 'composer\.'

.PHONY: all build manifest test test-js integration analyse lint e2e map check clean version

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
	@# Copy without dotfiles (.DS_Store, .gitkeep and the like), then normalise modes and mtimes.
	@umask 022; cd $(SRC) && find . -type f ! -name '.*' | while read -r f; do \
		mkdir -p "$(CURDIR)/$(STAGE)/$(PLUGIN)/$$(dirname "$$f")"; \
		cp "$$f" "$(CURDIR)/$(STAGE)/$(PLUGIN)/$$f"; \
	done
	@mkdir -p $(STAGE)/$(PLUGIN)/languages
	@find $(STAGE) -type d -exec chmod 755 {} + && find $(STAGE) -type f -exec chmod 644 {} +
	@stamp=$$(date -u -d @$(SOURCE_DATE_EPOCH) +%Y%m%d%H%M.%S 2>/dev/null || date -u -r $(SOURCE_DATE_EPOCH) +%Y%m%d%H%M.%S) \
		&& find $(STAGE) -exec env TZ=UTC touch -h -t "$$stamp" {} +
	@rm -f $@
	@# Sorted list (directories included, so the empty languages/ folder survives), no extra
	@# attributes (-X), UTC so the stored times do not depend on the builder's time zone.
	@cd $(STAGE) && find $(PLUGIN) | LC_ALL=C sort | TZ=UTC zip -q -X "$(CURDIR)/$@" -@
	@rm -rf $(STAGE)
	@if unzip -Z1 $@ | grep -q $(FORBIDDEN); then \
		echo "Refusing to ship test or tooling files:"; unzip -Z1 $@ | grep $(FORBIDDEN); rm -f $@; exit 1; \
	fi
	@if unzip -Z1 $@ | grep '\.svg$$' | grep -vqx '$(PLUGIN)/assets/map/world.svg'; then \
		echo "Refusing to ship unexpected .svg files:"; unzip -Z1 $@ | grep '\.svg$$' | grep -vx '$(PLUGIN)/assets/map/world.svg'; rm -f $@; exit 1; \
	fi
	@if unzip -Z1 $@ | grep -qx '$(PLUGIN)/assets/map/world.svg' && [ $$(unzip -p $@ $(PLUGIN)/assets/map/world.svg | wc -c) -gt 102400 ]; then \
		echo "world.svg is over 100 KB"; rm -f $@; exit 1; \
	fi
	@if command -v sha256sum > /dev/null; then (cd $(BUILDS) && sha256sum $(notdir $@) > $(notdir $@).sha256); \
	else (cd $(BUILDS) && shasum -a 256 $(notdir $@) > $(notdir $@).sha256); fi
	@echo "Built $@ ($$(unzip -Z1 $@ | grep -vc '/$$') files, $$(( $$(wc -c < $@) / 1024 )) KB)"

manifest: $(ZIP)
	$(PHP) scripts/build-manifest.php --zip $(ZIP)

version:
	@echo $(VERSION)

vendor/autoload.php: composer.json
	$(COMPOSER) install --no-interaction --no-progress
	@touch $@

test: vendor/autoload.php
	$(PHP) vendor/bin/phpunit

# Node's built-in runner: no npm, no package.json. Skipped when node is missing.
test-js:
	@if command -v node >/dev/null 2>&1; then node --test tests/js/*.test.js; else echo "node not found, skipping JS tests"; fi

WP_VERSION  ?= latest
WP_CORE_DIR ?= $(CURDIR)/builds/wp-core/$(WP_VERSION)

integration: vendor/autoload.php
	@test -f "$(WP_CORE_DIR)/wp-settings.php" || PHP=$(PHP) COMPOSER="$(COMPOSER)" WP_CORE_DIR="$(WP_CORE_DIR)" tests/Integration/install-wp.sh $(WP_VERSION)
	WP_CORE_DIR="$(WP_CORE_DIR)" $(PHP) vendor/bin/phpunit -c phpunit-integration.xml.dist

analyse: vendor/autoload.php
	$(PHP) vendor/bin/phpstan analyse

lint: vendor/autoload.php
	$(PHP) vendor/bin/phpcs

e2e:
	PHP=$(PHP) tests/e2e/run.sh

map:
	@test -n "$(IN)" || { echo 'Usage: make map IN=<dir>'; exit 1; }
	$(PHP) scripts/build-world-map.php --in $(IN)

check: test build
	PHP=$(PHP) WPB_E2E_ZIP=$(CURDIR)/$(ZIP) tests/e2e/run.sh

clean:
	rm -rf $(BUILDS)
