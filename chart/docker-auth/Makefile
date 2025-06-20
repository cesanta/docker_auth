CHART_NAME := docker-auth
CHART_VERSION := $(shell grep '^version:' Chart.yaml | cut -d' ' -f2)
PACKAGE_NAME := $(CHART_NAME)-$(CHART_VERSION).tgz

# Repository settings
REPO_URL := https://cesanta.github.io/docker_auth/
DOCS_DIR := ../../docs

.PHONY: lint
lint:
	helm lint .

.PHONY: test
test:
	helm template test-release . --dry-run > /dev/null

.PHONY: validate
validate: lint test ## Run all validation checks
	@echo "All validations passed"

.PHONY: package
package: validate ## Package the helm chart
	helm package .

.PHONY: update-repo
update-repo: package
	mv $(PACKAGE_NAME) $(DOCS_DIR)/
	helm repo index $(DOCS_DIR)/ --url $(REPO_URL)
	@echo "Repository updated"
	@echo ""
	@echo "Please review changes, then commit and push the changes to GitHub."

.PHONY: debug
debug:
	helm template debug-$(CHART_NAME) . --debug
