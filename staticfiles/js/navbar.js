document.addEventListener('DOMContentLoaded', () => {
    const hamburger = document.getElementById('hamburger');
    const modal = document.getElementById('modal');

    hamburger.addEventListener('click', () => {
        modal.style.display = 'block';
        modal.querySelector('.modal-content').classList.add('show'); // Add class to trigger animation
    });

    window.addEventListener('click', (event) => {
        if (event.target == modal) {
            modal.querySelector('.modal-content').classList.remove('show'); // Remove class to trigger hide animation
            setTimeout(() => {
                modal.style.display = 'none';
            }, 300); // Match this time with the CSS transition duration
        }
    });
});
