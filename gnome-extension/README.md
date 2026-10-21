# Fingerprint Wake

A GNOME Shell extension that lets a fingerprint unlock the session straight from
the lock screen's clock view or a blanked screen, without pressing a key first.

## Why

In GNOME Shell 50 the lock screen starts on the clock page. The fingerprint PAM
conversation (`gdm-fingerprint`) only runs while the password page is shown, and
`pam_fprintd` gives up after 30 seconds without a finger. So on the clock page,
or after the screen has blanked, the reader is idle until you press a key.

## What it does

While the screen is locked and showing the clock page, once per second:

- If the unlock dialog has no auth prompt, it creates one invisibly, using the
  shell's own `_ensureAuthPrompt()`, and keeps keyboard focus off the hidden
  password entry so the first key press still reveals the prompt as usual.
- If the fingerprint conversation is not running (for example after the
  `pam_fprintd` timeout), it resets the prompt so the reader is waiting again.

When a fingerprint is scanned, matched or not, it emits the unlock dialog's
`wake-up-screen` signal, which turns the display back on. A match unlocks as
usual.

It never touches the password page, so a password being typed is never reset.

## Requirements

- GNOME Shell 50
- A working fingerprint setup: fprintd with an enrolled finger, and fingerprint
  authentication enabled for the lock screen (on Fedora:
  `authselect enable-feature with-fingerprint`)

## Install

```sh
mkdir -p ~/.local/share/gnome-shell/extensions
cp -r fingerprint-wake@rea.local ~/.local/share/gnome-shell/extensions/
```

Log out and back in (on Wayland the shell only loads new extensions at login),
then:

```sh
gnome-extensions enable fingerprint-wake@rea.local
```

The extension runs in both the `user` and `unlock-dialog` session modes, so it
stays active while the screen is locked.

To build an installable bundle instead:

```sh
gnome-extensions pack fingerprint-wake@rea.local
gnome-extensions install fingerprint-wake@rea.local.shell-extension.zip
```

## Uninstall

```sh
gnome-extensions disable fingerprint-wake@rea.local
rm -r ~/.local/share/gnome-shell/extensions/fingerprint-wake@rea.local
```

## Debugging

Errors are logged to the journal with a `fingerprint-wake:` prefix:

```sh
journalctl --user -b -o cat | grep fingerprint-wake
```

## Caveats

This depends on GNOME Shell internals that are not a stable API: the screen
shield's `_dialog`, the unlock dialog's `_activePage`, `_clock`, `_authPrompt`
and `_ensureAuthPrompt()`, and the user verifier's `_activeServices`. Check them
again after a GNOME Shell upgrade before adding the new version to
`shell-version` in `metadata.json`.

Keeping the fingerprint conversation alive means the reader is powered and
polling the whole time the screen is locked.
