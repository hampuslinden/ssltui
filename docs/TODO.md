# TODO

## Packaging & distribution

### Make it pip-installable

The project already builds a wheel and sdist via `hatchling` (`uv build`), so the
remaining work is about getting it in front of users:

- [ ] Publish to PyPI so `pip install ssltui` works (with the optional API extra:
      `pip install "ssltui[api]"`).
  - [ ] Register the `ssltui` name on PyPI / TestPyPI.
  - [ ] Add a release workflow (build + `twine upload`, or `uv publish`) gated on
        version tags.
  - [ ] Verify metadata renders on the PyPI page (README, license, project URLs).
- [ ] Document the install path in README (`pip install ssltui`, plus `pipx install
      ssltui` for an isolated user install).
- [ ] Pin/declare a minimum `openssl` expectation in the docs (runtime dependency,
      not a Python package).

### Run as a standard Linux command (future)

Goal: `ssltui` behaves like a first-class system tool, not just a Python entry point.

- [ ] Ship via system package managers so it lands on `$PATH` natively:
  - [ ] A `pipx`-based one-liner as the interim story.
  - [ ] Distro packages — `.deb` / `.rpm`, and an AUR entry.
  - [ ] Explore a self-contained binary (e.g. `pyinstaller` / `shiv` / `zipapp`)
        so it runs without a managed Python environment.
- [ ] Provide a man page (`man ssltui`) and shell completions (bash/zsh/fish).
- [ ] Optional `systemd` user units for the API/dashboard serve mode and a
      timer-based alternative to the cron renewal entry.

## Test coverage

## Improve test harness

- [ ] Add a test harness for the CLI
- [ ] Add a test harness for the TUI
- [ ] Add a web test harness for the API