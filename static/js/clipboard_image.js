/* Getting an image off the clipboard, in one place.
 *
 * Used by the asset library page, the asset picker modal and the page editor's
 * image sections. It is its own file rather than part of photo_library_modal.js
 * because the library page has no picker on it — pulling the whole modal in for
 * two helpers would load code that reaches for DOM that isn't there.
 *
 * Reading the clipboard needs a secure context AND the reader's permission.
 * Over plain http — a self-hosted instance on a LAN without TLS — the API is
 * absent entirely. So read() never throws: it reports why it could not, and
 * every caller is expected to fall back to the keyboard, which fromEvent()
 * handles.
 */
window.ClipboardImage = (function () {
    /* One image from the clipboard. Resolves to {file, reason}: exactly one is
     * set. reason is 'unavailable' (no API / insecure page), 'denied' (the
     * reader said no) or 'empty' (nothing on the clipboard is an image). */
    async function read() {
        if (!navigator.clipboard || !navigator.clipboard.read) {
            return { file: null, reason: 'unavailable' };
        }
        try {
            const items = await navigator.clipboard.read();
            for (const item of items) {
                const type = (item.types || []).find(t => t.indexOf('image/') === 0);
                if (type) {
                    const blob = await item.getType(type);
                    return { file: toFile(blob, type), reason: null };
                }
            }
            return { file: null, reason: 'empty' };
        } catch (e) {
            return { file: null, reason: 'denied' };
        }
    }

    /* The first image on a paste or drop event, or null. Needs no permission —
     * the browser hands the data over because the reader performed the
     * gesture, which is why this is the fallback the button points at. */
    function fromEvent(e) {
        const items = ((e.clipboardData || e.dataTransfer || {}).items) || [];
        for (let i = 0; i < items.length; i++) {
            if (items[i].kind === 'file' && /^image\//.test(items[i].type)) {
                const f = items[i].getAsFile();
                if (f) return f;
            }
        }
        const files = ((e.clipboardData || e.dataTransfer || {}).files) || [];
        for (let i = 0; i < files.length; i++) {
            if (/^image\//.test(files[i].type || '')) return files[i];
        }
        return null;
    }

    function toFile(blob, type) {
        const ext = ((type || 'image/png').split('/')[1] || 'png').split('+')[0];
        return new File([blob], 'pasted.' + ext, { type: type || 'image/png' });
    }

    /* Named rather than shown as a glyph, because it differs by platform. */
    function hint() {
        const mac = /Mac|iPhone|iPad/.test(navigator.platform || '');
        return 'Press ' + (mac ? '⌘V' : 'Ctrl+V') + ' to paste your image.';
    }

    /* Only images, and only real ones — a drop can carry anything. */
    function onlyImages(files) {
        return Array.from(files || []).filter(function (f) {
            return f && /^image\//.test(f.type || '');
        });
    }

    /* True when the event targets somewhere text should go, so a paste there
     * is left alone rather than hijacked into an upload. */
    function isTextTarget(target) {
        return !!(target && (target.tagName === 'INPUT'
                             || target.tagName === 'TEXTAREA'
                             || target.isContentEditable));
    }

    return { read, fromEvent, hint, onlyImages, isTextTarget };
})();
