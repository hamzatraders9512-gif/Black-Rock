// Handle Google Sign In
function handleGoogleSignIn() {
    // Store the current page URL to redirect back after login
    localStorage.setItem('loginRedirect', window.location.pathname);
    // On Vercel we use serverless endpoints under /api
    window.location.href = '/api/auth/google';
}

// Show error message in the form
function showFormError(form, message) {
    // Use the centralized toast UI for all form-level errors
    if (typeof showToast === 'function') {
        showToast(message, 'error', 5000);
    } else {
        // Fallback: log to console (toast should always be available)
        console.error('Form error:', message);
    }
}

function hideFormError(form) {
    // No-op because we use toasts for form errors. Kept for compatibility with listeners.
    return;
}

// Handle form submission with loading state
async function handleFormSubmit(form) {
    const submitBtn = form.querySelector('button[type="submit"]');
    const emailInput = form.querySelector('input[name="email"]');
    const passwordInput = form.querySelector('input[type="password"]');
    
    // Clear previous error (toasts are used site-wide)

    // Basic validation
    if (!emailInput.value.trim() || !passwordInput.value) {
        showFormError(form, 'Please enter both email and password.');
        return;
    }

    // Email format validation
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(emailInput.value.trim())) {
        showFormError(form, 'Please enter a valid email address.');
        emailInput.focus();
        return;
    }

    // Show loading state
    const originalText = submitBtn.innerHTML;
    submitBtn.disabled = true;
    submitBtn.innerHTML = 'Signing in...';

    try {
        const response = await fetch('/api/auth/login', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                email: emailInput.value.trim(),
                password: passwordInput.value
            })
        });

        const data = await response.json();

        if (response.ok) {
            // Successful login
            window.location.href = '/dashboard';
        } else if (data.needsVerification) {
            // Email needs verification
            window.location.href = `/verify-email.html?email=${encodeURIComponent(emailInput.value)}`;
        } else {
            // Show error from server
            showFormError(form, data.message || 'Invalid email or password.');
            if (data.field === 'email') {
                emailInput.focus();
            } else if (data.field === 'password') {
                passwordInput.focus();
            }
        }
    } catch (error) {
        console.error('Error:', error);
        showFormError(form, 'Connection error. Please try again.');
    } finally {
        submitBtn.disabled = false;
        submitBtn.innerHTML = originalText;
    }
}

// Initialize auth features
function initializeAuth() {
    // Handle Google Sign In buttons
    const googleBtns = document.querySelectorAll('.google-btn');
    googleBtns.forEach(btn => {
        btn.addEventListener('click', handleGoogleSignIn);
    });

    // Handle password visibility toggle
    const eyeBtns = document.querySelectorAll('.eye-btn');
    eyeBtns.forEach(btn => {
        btn.addEventListener('click', () => {
            const input = btn.closest('.password-field').querySelector('input');
            const icon = btn.querySelector('svg');
            input.type = input.type === 'password' ? 'text' : 'password';
            icon.style.opacity = input.type === 'password' ? 1 : 0.7;
        });
    });

    // Handle login form submission
    const loginForm = document.getElementById('loginForm');
    if (loginForm) {
        loginForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            await handleFormSubmit(loginForm);
        });
        // Hide error message as soon as the user starts typing again
        const inputs = loginForm.querySelectorAll('input[name="email"], input[name="password"]');
        inputs.forEach(inp => {
            inp.addEventListener('input', () => {
                hideFormError(loginForm);
            });
        });
    }

}

// Initialize when DOM is loaded
document.addEventListener('DOMContentLoaded', initializeAuth);