
// document.addEventListener('DOMContentLoaded', function() {
//     const searchContainer = document.querySelector('.search-container');
//     const searchIcon = document.getElementById('searchIcon');
    
//     searchIcon.addEventListener('click', function() {
//         searchContainer.classList.toggle('active');
//     });
// });

document.addEventListener('DOMContentLoaded', function () {
    const profileIcon = document.getElementById('profileIcon');
    const dropdownContent = document.getElementById('profileDropdownContent');

    profileIcon.addEventListener('click', function () {
        dropdownContent.classList.toggle('show');
    });

    window.addEventListener('click', function (event) {
        if (!event.target.matches('.profile-icon') && !event.target.matches('.fas.fa-user-circle')) {
            if (dropdownContent.classList.contains('show')) {
                dropdownContent.classList.remove('show');
            }
        }
    });
});

document.addEventListener('DOMContentLoaded', function () {
    const profileIcon = document.getElementById('profileIcon');
    const profileDropdownContent = document.getElementById('profileDropdownContent');

    if (profileIcon && profileDropdownContent) {
        profileIcon.addEventListener('click', function (e) {
            e.stopPropagation();
            profileDropdownContent.classList.toggle('show');
        });
    }

    const pagesBtn = document.querySelector('.pages-btn');
    const pagesDropdown = document.querySelector('.pages-dropdown');

    if (pagesBtn && pagesDropdown) {
        pagesBtn.addEventListener('click', function (e) {
            e.stopPropagation();
            pagesDropdown.classList.toggle('open');
        });
    }

    const toolsBtn = document.querySelector('.nav-tools-btn');
    const toolsDropdown = document.querySelector('.nav-tools-dropdown');

    if (toolsBtn && toolsDropdown) {
        toolsBtn.addEventListener('click', function (e) {
            e.stopPropagation();
            toolsDropdown.classList.toggle('open');
        });
    }

    document.addEventListener('click', function () {
        if (profileDropdownContent) {
            profileDropdownContent.classList.remove('show');
        }
        if (pagesDropdown) {
            pagesDropdown.classList.remove('open');
        }
        if (toolsDropdown) {
            toolsDropdown.classList.remove('open');
        }
        const usersSubDropdown = document.getElementById('usersSubDropdown');
        if (usersSubDropdown) usersSubDropdown.classList.remove('open');
    });
});

// ── Responsive center nav: inline items ↔ dropdown ───────────────────────
(function () {
    let _rafId = null;

    function checkNavLayout() {
        const navbar  = document.querySelector('.navbar');
        const navHome = document.querySelector('.nav-home');
        const navLeft = document.querySelector('.nav-left');
        const navRight = document.querySelector('.nav-right');
        if (!navbar || !navHome || !navLeft || !navRight) return;

        // Available width for the centre column (total minus the fixed left/right wings)
        const availableCenter = navbar.offsetWidth - navLeft.offsetWidth - navRight.offsetWidth;

        // Expand so we measure the natural (uncompressed) content width
        navHome.classList.remove('nav-compact');
        void navHome.offsetHeight; // force synchronous reflow so CSS takes effect

        let contentWidth = 0;
        Array.from(navHome.children).forEach(el => {
            contentWidth += el.offsetWidth;
        });

        navHome.classList.toggle('nav-compact', contentWidth + 12 > availableCenter);
    }

    function scheduleCheck() {
        cancelAnimationFrame(_rafId);
        _rafId = requestAnimationFrame(checkNavLayout);
    }

    document.addEventListener('DOMContentLoaded', () => {
        checkNavLayout();
        new ResizeObserver(scheduleCheck).observe(document.querySelector('.navbar') || document.body);
    });
})();
// ─────────────────────────────────────────────────────────────────────────

function closeNavToolsDropdown() {
    const toolsDropdown = document.querySelector('.nav-tools-dropdown');
    if (toolsDropdown) toolsDropdown.classList.remove('open');
}

function toggleUsersSubdropdown(e) {
    if (e) e.stopPropagation();
    const el = document.getElementById('usersSubDropdown');
    if (el) el.classList.toggle('open');
}


    function updateUnreadMessagesBadge(count) {
        const badge = document.getElementById('unreadMessagesBadge');
        if (!badge) return;

        if (count > 0) {
            badge.textContent = count;
            badge.style.display = 'inline-flex';
        } else {
            badge.textContent = '0';
            badge.style.display = 'none';
        }
    }

    async function fetchUnreadMessagesCount() {
        try {
            const response = await fetch('/admin/dashboard/messages/unread_count');
            if (!response.ok) return;

            const data = await response.json();
            updateUnreadMessagesBadge(data.count);
        } catch (error) {
            console.error('Failed to fetch unread message count:', error);
        }
    }

    document.addEventListener('DOMContentLoaded', function () {
        fetchUnreadMessagesCount();

        // refresh every 10 seconds
        setInterval(fetchUnreadMessagesCount, 10000);
    });

    function toggleGlobalColorPalette() {
    const panel = document.getElementById('globalColorPalettePanel');
    if (!panel) return;

    panel.classList.toggle('open');

    renderSavedColors('global_palette');
    enableSavedColorDropZone('global_palette');
    enableColorPickerDropTargets();
    enableDraggingFromColorInputs();
}

function makeGlobalColorPaletteDraggable() {
    const panel = document.getElementById('globalColorPalettePanel');
    const handle = document.getElementById('globalColorPaletteDragHandle');

    if (!panel || !handle || panel.dataset.draggableReady === 'true') return;

    panel.dataset.draggableReady = 'true';

    let isDragging = false;
    let offsetX = 0;
    let offsetY = 0;

    handle.addEventListener('mousedown', function (event) {
        isDragging = true;

        const rect = panel.getBoundingClientRect();
        offsetX = event.clientX - rect.left;
        offsetY = event.clientY - rect.top;

        panel.style.right = 'auto';
        panel.style.left = `${rect.left}px`;
        panel.style.top = `${rect.top}px`;

        document.body.style.userSelect = 'none';
    });

    document.addEventListener('mousemove', function (event) {
        if (!isDragging) return;

        const left = Math.max(8, Math.min(window.innerWidth - panel.offsetWidth - 8, event.clientX - offsetX));
        const top = Math.max(8, Math.min(window.innerHeight - panel.offsetHeight - 8, event.clientY - offsetY));

        panel.style.left = `${left}px`;
        panel.style.top = `${top}px`;
    });

    document.addEventListener('mouseup', function () {
        if (!isDragging) return;
        isDragging = false;
        document.body.style.userSelect = '';
    });
}

function toggleGlobalColorPalette() {
    const panel = document.getElementById('globalColorPalettePanel');
    if (!panel) return;

    panel.classList.toggle('open');

    renderSavedColors('global_palette');
    enableSavedColorDropZone('global_palette');
    enableColorPickerDropTargets();
    enableDraggingFromColorInputs();
    makeGlobalColorPaletteDraggable();
}
