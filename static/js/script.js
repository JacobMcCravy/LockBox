document.addEventListener('click', e => {
  // Handle click on masked or revealed password
  if (e.target.classList.contains('masked') || e.target.classList.contains('real-password')) {
    const td = e.target.closest('td');
    const masked = td.querySelector('.masked');
    const real = td.querySelector('.real-password');

    // Check if either element exists to avoid null errors
    if (masked && real) {
      const isMaskedVisible = masked.style.display !== 'none';

      // Toggle display
      masked.style.display = isMaskedVisible ? 'none' : 'inline';
      real.style.display = isMaskedVisible ? 'inline' : 'none';
    }
  }
});

function copyPassword(button) {
  const password = button.getAttribute('data-password');
  if (!password) return;

  navigator.clipboard.writeText(password).then(() => {
    button.textContent = 'Copied!';
    setTimeout(() => {
      button.textContent = 'Copy';
    }, 1500);
  }).catch(err => {
    console.error('Copy failed', err);
    button.textContent = 'Error';
  });
}