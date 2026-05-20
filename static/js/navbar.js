
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
            // After the dropdown opens, sync the scroll-cue indicators so the
            // top/bottom arrows reflect actual overflow.
            if (toolsDropdown.classList.contains('open')) {
                requestAnimationFrame(_syncNavToolsScrollCues);
            }
        });

        const content = document.getElementById('navToolsDropdownContent');
        if (content) {
            content.addEventListener('scroll', _syncNavToolsScrollCues);
            // Re-check on resize since max-height is viewport-relative.
            window.addEventListener('resize', _syncNavToolsScrollCues);
        }
    }

    function _syncNavToolsScrollCues() {
        const el = document.getElementById('navToolsDropdownContent');
        if (!el) return;
        const canScrollUp   = el.scrollTop > 4;
        const canScrollDown = (el.scrollHeight - el.scrollTop - el.clientHeight) > 4;
        el.classList.toggle('has-overflow-top',    canScrollUp);
        el.classList.toggle('has-overflow-bottom', canScrollDown);
        // The CSS uses --nav-mask-top/--nav-mask-bot to fade the edges. 1 = fully
        // transparent, 0 = fully opaque. Tween via the same toggles so the
        // mask animates in/out with the indicators.
        el.style.setProperty('--nav-mask-top', canScrollUp ? '1' : '0');
        el.style.setProperty('--nav-mask-bot', canScrollDown ? '1' : '0');
    }

    const storeBtn = document.querySelector('.store-dropdown-btn');
    const storeDropdown = document.querySelector('.store-dropdown');
    if (storeBtn && storeDropdown) {
        storeBtn.addEventListener('click', function (e) {
            e.stopPropagation();
            storeDropdown.classList.toggle('open');
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
        if (storeDropdown) {
            storeDropdown.classList.remove('open');
        }
        const usersSubDropdown = document.getElementById('usersSubDropdown');
        if (usersSubDropdown) usersSubDropdown.classList.remove('open');
    });
});

// ── Responsive center nav: inline items ↔ dropdown ───────────────────────
(function () {
    let _rafId = null;
    let _lastCompact = null;  // tracks current applied state to avoid no-op writes

    function _cacheKey() {
        return 'uwNavCompact:' + window.innerWidth;
    }

    function checkNavLayout() {
        const navbar  = document.querySelector('.navbar');
        const navHome = document.querySelector('.nav-home');
        const navLeft = document.querySelector('.nav-left');
        const navRight = document.querySelector('.nav-right');
        if (!navbar || !navHome || !navLeft || !navRight) return;

        const availableCenter = navbar.offsetWidth - navLeft.offsetWidth - navRight.offsetWidth;

        // The dropdown toggle is now always visible, so include its width in the
        // expanded-layout measurement. Inline items get hidden offscreen in
        // compact mode but stay in the DOM so we can always measure them here.
        let expandedWidth = 0;
        Array.from(navHome.children).forEach(el => {
            expandedWidth += el.offsetWidth;
        });

        const shouldCompact = (expandedWidth + 12) > availableCenter;
        if (shouldCompact !== _lastCompact) {
            navHome.classList.toggle('nav-compact', shouldCompact);
            _lastCompact = shouldCompact;
            try { sessionStorage.setItem(_cacheKey(), shouldCompact ? '1' : '0'); } catch (e) {}
        }
    }

    function scheduleCheck() {
        cancelAnimationFrame(_rafId);
        _rafId = requestAnimationFrame(checkNavLayout);
    }

    function init() {
        const navHome = document.querySelector('.nav-home');
        const navbar = document.querySelector('.navbar');
        if (!navHome || !navbar) return;

        // Apply cached decision instantly so we don't wait for fonts to flicker into the
        // right mode. The HTML default (expanded) is correct for wide screens; this only
        // forces compact early for narrow viewports we've seen before.
        try {
            const cached = sessionStorage.getItem(_cacheKey());
            if (cached === '1') {
                navHome.classList.add('nav-compact');
                _lastCompact = true;
            } else if (cached === '0') {
                _lastCompact = false;
            }
        } catch (e) {}

        // Authoritative measurement once fonts are ready (icon widths depend on FA font).
        const fontsReady = (document.fonts && document.fonts.ready) || Promise.resolve();
        fontsReady.then(() => {
            checkNavLayout();
            new ResizeObserver(scheduleCheck).observe(navbar);
        });
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }
})();
// ─────────────────────────────────────────────────────────────────────────

// ── Admin Chat ────────────────────────────────────────────────────────────
let _chatOpen = false;
let _chatPollTimer = null;
let _lastChatId = 0;

function toggleAdminChat() {
    const panel = document.getElementById('adminChatPanel');
    if (!panel) return;
    _chatOpen = !_chatOpen;
    panel.style.display = _chatOpen ? 'flex' : 'none';
    if (_chatOpen) {
        loadAdminChatMessages();
        markAdminChatRead();
        document.getElementById('adminChatInput')?.focus();
    }
}

async function loadAdminChatMessages() {
    const list = document.getElementById('adminChatMessages');
    if (!list) return;
    try {
        const r = await fetch('/admin/chat/messages');
        const msgs = await r.json();
        list.innerHTML = '';
        msgs.forEach(m => appendChatMessage(m, false));
        if (msgs.length) _lastChatId = msgs[msgs.length - 1].id;
        list.scrollTop = list.scrollHeight;
    } catch {}
}

function appendChatMessage(m, scroll = true) {
    const list = document.getElementById('adminChatMessages');
    if (!list) return;
    const el = document.createElement('div');
    Object.assign(el.style, {
        maxWidth: '85%', padding: '7px 10px', borderRadius: '10px',
        fontSize: '0.82rem', lineHeight: '1.45', wordBreak: 'break-word',
        alignSelf: m.mine ? 'flex-end' : 'flex-start',
        background: m.mine ? 'rgba(126,226,204,0.18)' : 'rgba(255,255,255,0.08)',
        color: m.mine ? '#a8f0e0' : 'rgba(255,255,255,0.85)',
    });
    el.innerHTML = `${m.mine ? '' : `<div style="font-size:0.7rem;color:rgba(255,255,255,0.4);margin-bottom:3px;">${m.username}</div>`}${m.message.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')}<div style="font-size:0.65rem;opacity:0.45;margin-top:3px;text-align:${m.mine?'right':'left'}">${m.created_at}</div>`;
    list.appendChild(el);
    if (scroll) list.scrollTop = list.scrollHeight;
}

async function sendAdminChat() {
    const input = document.getElementById('adminChatInput');
    if (!input) return;
    const msg = input.value.trim();
    if (!msg) return;
    input.value = '';
    try {
        const r = await fetch('/admin/chat/send', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ message: msg })
        });
        const d = await r.json();
        if (d.ok) {
            appendChatMessage({ mine: true, message: msg, created_at: 'now', username: '' });
            _lastChatId = d.id || _lastChatId;
        }
    } catch {}
}

async function markAdminChatRead() {
    const badge = document.getElementById('adminChatBadge');
    const dot   = document.getElementById('adminChatDot');
    if (badge) badge.style.display = 'none';
    if (dot)   dot.style.display   = 'none';
    try { await fetch('/admin/chat/mark-read', { method: 'POST' }); } catch {}
}

async function pollAdminChatUnread() {
    try {
        const r = await fetch('/admin/chat/unread-count');
        const d = await r.json();
        const badge = document.getElementById('adminChatBadge');
        if (!badge) return;
        const dot = document.getElementById('adminChatDot');
        if (d.count > 0 && !_chatOpen) {
            badge.textContent = d.count > 99 ? '99+' : d.count;
            badge.style.display = 'inline-flex';
            if (dot) dot.style.display = 'inline-flex';
        } else {
            badge.style.display = 'none';
            if (dot) dot.style.display = 'none';
            if (_chatOpen) markAdminChatRead();
        }
    } catch {}
}

document.addEventListener('DOMContentLoaded', () => {
    pollAdminChatUnread();
    setInterval(pollAdminChatUnread, 15000);
});
// ─────────────────────────────────────────────────────────────────────────

function toggleNavSiteSwitcher(e) {
    e.stopPropagation();
    const list = document.getElementById('navSiteList');
    const chevron = document.querySelector('.nav-site-chevron');
    if (!list) return;
    const open = list.classList.toggle('open');
    if (chevron) chevron.style.transform = open ? 'rotate(90deg)' : '';
}

function closeNavToolsDropdown() {
    const toolsDropdown = document.querySelector('.nav-tools-dropdown');
    if (toolsDropdown) toolsDropdown.classList.remove('open');
}

function toggleUsersSubdropdown(e) {
    if (e) e.stopPropagation();
    const el = document.getElementById('usersSubDropdown');
    if (el) el.classList.toggle('open');
}

function toggleNavStoreSubgroup(e) {
    if (e) e.stopPropagation();
    const el = document.getElementById('navToolsStoreGroup');
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

    function startDrag(clientX, clientY) {
        isDragging = true;
        const rect = panel.getBoundingClientRect();
        offsetX = clientX - rect.left;
        offsetY = clientY - rect.top;
        panel.style.right = 'auto';
        panel.style.left = `${rect.left}px`;
        panel.style.top = `${rect.top}px`;
        document.body.style.userSelect = 'none';
    }

    function moveDrag(clientX, clientY) {
        if (!isDragging) return;
        const left = Math.max(8, Math.min(window.innerWidth  - panel.offsetWidth  - 8, clientX - offsetX));
        const top  = Math.max(8, Math.min(window.innerHeight - panel.offsetHeight - 8, clientY - offsetY));
        panel.style.left = `${left}px`;
        panel.style.top  = `${top}px`;
    }

    function endDrag() {
        if (!isDragging) return;
        isDragging = false;
        document.body.style.userSelect = '';
    }

    // Mouse
    handle.addEventListener('mousedown', e => startDrag(e.clientX, e.clientY));
    document.addEventListener('mousemove', e => moveDrag(e.clientX, e.clientY));
    document.addEventListener('mouseup', endDrag);

    // Touch
    handle.addEventListener('touchstart', e => {
        // Let button taps (e.g. the × close button) pass through normally
        if (e.target.closest('button')) return;
        startDrag(e.touches[0].clientX, e.touches[0].clientY);
    }, { passive: true });
    document.addEventListener('touchmove', e => {
        if (!isDragging) return;
        e.preventDefault(); // prevent page scroll only while dragging
        moveDrag(e.touches[0].clientX, e.touches[0].clientY);
    }, { passive: false });
    document.addEventListener('touchend', endDrag, { passive: true });
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
