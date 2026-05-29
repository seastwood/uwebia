/* Shared modal backdrop-dismiss helper.
 *
 * A `click` fires on the nearest common ancestor of where the mouse was pressed
 * and where it was released. So a press that starts *inside* a dialog and is
 * released on the backdrop (selecting/dragging text out of the modal) produces
 * a click whose target is the overlay — which would wrongly dismiss the modal.
 *
 * Gate dismissal on the press having started on the backdrop too:
 *
 *   <div class="uw-overlay"
 *        onmousedown="uwOverlayDown(event)"
 *        onclick="uwOverlayClick(event, closeFn)">
 */
(function () {
    var downOnBackdrop = false;

    // Record whether the press began directly on the overlay (the backdrop)
    // rather than on the dialog or its contents.
    window.uwOverlayDown = function (e) {
        downOnBackdrop = (e.target === e.currentTarget);
    };

    // Dismiss only when both the press and the release landed on the backdrop.
    window.uwOverlayClick = function (e, closeFn) {
        var onBackdrop = (e.target === e.currentTarget);
        downOnBackdrop = downOnBackdrop && onBackdrop;
        if (downOnBackdrop && typeof closeFn === 'function') closeFn();
        downOnBackdrop = false;
    };
})();
