// Risk indicator animation
document.addEventListener('DOMContentLoaded', function() {
    const alerts = document.querySelectorAll('.alert');
    alerts.forEach(alert => {
        alert.style.transition = 'all 0.5s';
    });
});

// Confirm before deleting/quarantining
function confirmAction(message) {
    return confirm(message);
}
