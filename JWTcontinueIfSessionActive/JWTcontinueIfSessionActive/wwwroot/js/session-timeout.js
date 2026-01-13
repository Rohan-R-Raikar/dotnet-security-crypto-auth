let timeoutId;
const timeoutMinutes = 2; // keep same as SessionSettings

function logoutUser() {
    fetch('/Account/Logout', { method: 'POST' })
        .finally(() => {
            window.location.href = '/Account/Login';
        });
}

function resetTimer() {
    clearTimeout(timeoutId);
    timeoutId = setTimeout(logoutUser, timeoutMinutes * 60 * 1000);
}

// User activity listeners
['load', 'mousemove', 'keypress', 'click', 'scroll'].forEach(event => {
    window.addEventListener(event, resetTimer);
});

resetTimer();
