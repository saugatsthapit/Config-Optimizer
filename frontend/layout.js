// layout.js
document.addEventListener('DOMContentLoaded', function() {
    // Dynamically insert the navbar
    var navbarPlaceholder = document.getElementById('navbar-placeholder');
    if (navbarPlaceholder) {
        navbarPlaceholder.innerHTML = `
            <nav class="navbar navbar-expand-lg navbar-dark navbar-custom fixed-top">
                <div class="container">
                    <a class="navbar-brand" href="/">Configuration Optimizer</a>
                </div>
            </nav>`;
    }

    // Dynamically insert the sidebar
    var sidebarPlaceholder = document.getElementById('sidebar-placeholder');
    if (sidebarPlaceholder) {
        sidebarPlaceholder.innerHTML = `
            <div class="sidebar-custom">
                <a href="/">Matched Rule Conditions</a>
                <a href="/datastream">DataStream</a> <!-- New Sidebar Menu Item -->
                <a href="/image-text">Image-to-Text</a> <!-- New Sidebar Menu Item -->
            </div>`;
    }
});
