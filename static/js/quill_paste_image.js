/*
 * Paste-to-upload for Quill rich editors.
 *
 * A single document-level (capture-phase) paste listener that covers EVERY
 * Quill editor on the page — including ones created dynamically (e.g. the page
 * editor's per-section editors) — with no per-instance wiring. When the paste
 * lands inside a .ql-editor and the clipboard carries an image, the image is
 * uploaded to the asset library (into a "Pasted images" folder) and the stored
 * URL is embedded at the caret. Non-image pastes fall through to Quill's own
 * clipboard handling untouched.
 *
 * Load this AFTER quill.min.js on any admin page that hosts a Quill editor.
 */
(function () {
  'use strict';
  if (window.__quillPasteImageInstalled) return;
  window.__quillPasteImageInstalled = true;

  var FOLDER_NAME = 'Pasted images';

  function imageFilesFromClipboard(cd) {
    var out = [];
    if (!cd) return out;
    var items = cd.items || [];
    for (var i = 0; i < items.length; i++) {
      if (items[i].kind === 'file' && /^image\//.test(items[i].type || '')) {
        var f = items[i].getAsFile();
        if (f) out.push(f);
      }
    }
    // Fallback for browsers that only populate clipboardData.files.
    if (!out.length && cd.files && cd.files.length) {
      for (var j = 0; j < cd.files.length; j++) {
        if (/^image\//.test(cd.files[j].type || '')) out.push(cd.files[j]);
      }
    }
    return out;
  }

  // Resolve the Quill instance that owns a .ql-editor node.
  function quillForEditor(editorEl) {
    if (!window.Quill || !window.Quill.find) return null;
    var container = editorEl.closest ? editorEl.closest('.ql-container') : null;
    var q = container ? window.Quill.find(container) : null;
    // Fall back to walking up from the editor node itself.
    if (!q) q = window.Quill.find(editorEl, true);
    return (q && typeof q.insertEmbed === 'function') ? q : null;
  }

  function uploadAndInsert(quill, file) {
    var range = quill.getSelection(true);
    var index = range ? range.index : quill.getLength();

    // A visible placeholder while the upload is in flight, replaced on success.
    // Plain (unformatted) so no italic/colour bleeds onto text typed afterwards.
    var placeholder = '⏳ Uploading image… ';
    quill.insertText(index, placeholder, 'user');

    function clearPlaceholder() {
      // Remove exactly the placeholder text we inserted.
      quill.deleteText(index, placeholder.length, 'user');
    }

    var fd = new FormData();
    var name = (file.name && file.name.toLowerCase() !== 'image.png')
      ? file.name
      : ('pasted-' + Date.now() + '.png');
    fd.append('asset', file, name);
    fd.append('folder_name', FOLDER_NAME);

    fetch('/admin/assets/upload', { method: 'POST', body: fd })
      .then(function (r) { return r.json(); })
      .then(function (d) {
        clearPlaceholder();
        if (d && d.status === 'success' && d.assets && d.assets.length) {
          quill.insertEmbed(index, 'image', d.assets[0].url, 'user');
          quill.setSelection(index + 1, 0, 'user');
        } else {
          var msg = (d && d.error) || 'Image paste upload failed.';
          window.alert(msg);
        }
      })
      .catch(function () {
        clearPlaceholder();
        window.alert('Image paste upload failed. Check your connection and asset permissions.');
      });
  }

  document.addEventListener('paste', function (e) {
    var target = e.target;
    var editorEl = (target && target.closest) ? target.closest('.ql-editor') : null;
    if (!editorEl) return;                       // not pasting into a Quill editor

    var files = imageFilesFromClipboard(e.clipboardData);
    if (!files.length) return;                   // let Quill handle text/html pastes

    var quill = quillForEditor(editorEl);
    if (!quill) return;                          // couldn't resolve the instance

    e.preventDefault();
    e.stopPropagation();
    files.forEach(function (f) { uploadAndInsert(quill, f); });
  }, true);
})();
