
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

    document.addEventListener('click', function () {
        if (profileDropdownContent) {
            profileDropdownContent.classList.remove('show');
        }
        if (pagesDropdown) {
            pagesDropdown.classList.remove('open');
        }
    });
});


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
            const response = await fetch('/dashboard/messages/unread_count');
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
