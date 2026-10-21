// Fingerprint Wake: unlock with a fingerprint straight from the lock screen's
// clock view or a blanked screen, without pressing a key first.
//
// Why this is needed (GNOME Shell 50, ui/unlockDialog.js): the lock screen
// starts on the clock page, and its AuthPrompt, which runs the gdm-fingerprint
// PAM conversation, only exists while the password page is shown (a key press,
// click or swipe creates it; returning to the clock destroys it). pam_fprintd
// also ends the conversation after 30 s without a finger, and the shell does
// not restart it on the clock page. So while locked, the fingerprint reader is
// normally idle.
//
// While the screen is locked and on the clock page, this extension:
//   - creates the AuthPrompt invisibly (the shell's own _ensureAuthPrompt), and
//     resets it whenever the fingerprint conversation has stopped, so a finger
//     is always being waited for;
//   - on any fingerprint scan result, emits the unlock dialog's wake-up-screen
//     signal (the same path lock screen notifications use), which turns the
//     display back on; a match then unlocks as usual.
// It only touches the clock page, so a password being typed is never reset.
//
// It relies on Shell internals (_dialog, _activePage, _clock, _authPrompt,
// _ensureAuthPrompt, _userVerifier._activeServices); re-check them when GNOME
// Shell is upgraded.

import GLib from 'gi://GLib';
import * as Main from 'resource:///org/gnome/shell/ui/main.js';
import * as GdmUtil from 'resource:///org/gnome/shell/gdm/util.js';
import {AuthPromptStatus} from 'resource:///org/gnome/shell/gdm/authPrompt.js';
import {Extension} from 'resource:///org/gnome/shell/extensions/extension.js';

const TICK_SECONDS = 1;

export default class FingerprintWakeExtension extends Extension {
    enable() {
        this._verifier = null;
        this._tickId = GLib.timeout_add_seconds(GLib.PRIORITY_DEFAULT, TICK_SECONDS, () => {
            try {
                this._tick();
            } catch (e) {
                console.error(`fingerprint-wake: ${e}`);
            }
            return GLib.SOURCE_CONTINUE;
        });
    }

    disable() {
        if (this._tickId) {
            GLib.source_remove(this._tickId);
            this._tickId = 0;
        }
        this._unhook();
    }

    _tick() {
        const shield = Main.screenShield;
        const dialog = shield?._dialog;
        if (!shield?.locked || !dialog || dialog._activePage !== dialog._clock)
            return;

        if (!dialog._authPrompt) {
            dialog._ensureAuthPrompt();
            // Keep keyboard focus off the hidden password entry, so the first
            // key press still reveals the prompt as usual.
            dialog.grab_key_focus();
        }

        const prompt = dialog._authPrompt;
        const verifier = prompt?._userVerifier;
        if (!verifier)
            return;

        this._hook(dialog, verifier);

        const verifying =
            prompt.verificationStatus === AuthPromptStatus.VERIFYING ||
            prompt.verificationStatus === AuthPromptStatus.VERIFICATION_IN_PROGRESS;
        const fingerprintActive =
            verifier._activeServices?.has(GdmUtil.FINGERPRINT_SERVICE_NAME);

        if (!verifying || !fingerprintActive) {
            prompt.reset();
            dialog.grab_key_focus();
        }
    }

    _hook(dialog, verifier) {
        if (this._verifier === verifier)
            return;
        this._unhook();
        this._verifier = verifier;

        const wake = () => dialog.emit('wake-up-screen');
        verifier.connectObject(
            'show-message', (_v, serviceName, _message, type) => {
                // A scan that did not match, or any fingerprint feedback other
                // than the standing "place finger" hint: show the screen.
                if (serviceName === GdmUtil.FINGERPRINT_SERVICE_NAME &&
                    type !== GdmUtil.MessageType.HINT)
                    wake();
            },
            'verification-complete', wake,
            this);
    }

    _unhook() {
        this._verifier?.disconnectObject(this);
        this._verifier = null;
    }
}
