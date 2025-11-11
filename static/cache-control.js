// Prevent browser back button after logout
if (window.history && window.history.pushState) {
    window.history.pushState('', null, './');
    window.addEventListener('popstate', function () {
        window.history.pushState('', null, './');
    });
}

// Force page reload when using browser back/forward
window.addEventListener('pageshow', function (event) {
    if (event.persisted) {
        window.location.reload();
    }
});

// Disable browser cache for the current page
window.onload = function() {
    if (typeof window.performance != 'undefined' 
        && window.performance.navigation.type == 2) {
            window.location.reload();
    }
};