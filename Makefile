PYTHON = .venv/bin/python3
PIP = .venv/bin/pip3

.PHONY: install setup live logs status stop clean test check-root

# --- 🚀 High-Level Commands ---

setup: ## Initial setup of environment and database
	python3 -m venv .venv
	$(PIP) install --upgrade pip
	$(PIP) install -r requirements.txt
	PYTHONPATH=. $(PYTHON) -m radar.database.migrations

install: ## Install as a permanent background service (Systemd)
	@echo "📡 Installing Radar as a system service..."
	@echo "Checking for sudo privileges..."
	sudo cp deploy/radar.service /etc/systemd/system/
	sudo systemctl daemon-reload
	sudo systemctl enable radar
	sudo systemctl start radar
	@echo "✅ Radar is now installed and cloaked as 'kworker/sys'."

live: ## Launch the web dashboard (Normal mode)
	@PYTHONPATH=. $(PYTHON) -m uvicorn radar.web.app:app --host 0.0.0.0 --port 8000

live-root: ## Launch the web dashboard with FULL PERMISSIONS (Sudo)
	@sudo PYTHONPATH=. $(PYTHON) -m uvicorn radar.web.app:app --host 0.0.0.0 --port 8000

brain: ## Launch the Intelligence Daemon with FULL PERMISSIONS (Sudo)
	@sudo PYTHONPATH=. $(PYTHON) -m radar.main

intercept: ## Unlock 'Outside' traffic for a specific IP (usage: make intercept IP=192.168.1.10)
	@sudo PYTHONPATH=. $(PYTHON) -m radar.fingerprint.tactical $(IP)

live-term: ## Watch everything in real-time (Legacy Terminal UI)
	@PYTHONPATH=. $(PYTHON) -m radar.utils.dashboard

logs: ## Audit the stealth logs
	tail -f ~/.radar/radar.log

status: ## Check the status of the service
	sudo systemctl status radar

stop: ## Stop the background service
	sudo systemctl stop radar

uninstall: ## Remove the service completely
	sudo systemctl disable radar
	sudo rm /etc/systemd/system/radar.service
	sudo systemctl daemon-reload
	@echo "🗑️ Radar service removed."

# --- 🛠️ Development & Testing ---

test: ## Run the full test suite with coverage
	PYTHONPATH=. $(PYTHON) -m pytest --cov=radar tests/

clean: ## Remove temporary files
	rm -rf .pytest_cache .coverage htmlcov
	find . -type d -name "__pycache__" -exec rm -rf {} +

help: ## Show this help message
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-15s\033[0m %s\n", $$1, $$2}'
