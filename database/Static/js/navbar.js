
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