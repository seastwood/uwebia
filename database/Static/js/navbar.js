function submitSearch() {
    const query = document.getElementById('searchQuery').value;
    const url = `/browse_websites?query=${encodeURIComponent(query)}`;
    window.location.href = url;
}

// document.addEventListener('DOMContentLoaded', function() {
//     const searchContainer = document.querySelector('.search-container');
//     const searchIcon = document.getElementById('searchIcon');
    
//     searchIcon.addEventListener('click', function() {
//         searchContainer.classList.toggle('active');
//     });
// });

document.getElementById('searchIcon').addEventListener('click', function() {
    // this.classList.toggle('active');
    const searchContainer = document.querySelector('.search-container');
    searchContainer.classList.toggle('active');
});

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


