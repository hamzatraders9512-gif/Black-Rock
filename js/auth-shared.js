// Shared authentication functions

// Initialize password visibility toggle buttons
function initializePasswordToggles() {
    const eyeBtns = document.querySelectorAll('.eye-btn');
    eyeBtns.forEach(btn => {
        btn.addEventListener('click', () => {
            const passwordField = btn.closest('.password-field');
            const input = passwordField.querySelector('input');
            const svg = btn.querySelector('svg');
            
            if (input.type === 'password') {
                input.type = 'text';
                svg.style.opacity = '0.7';
            } else {
                input.type = 'password';
                svg.style.opacity = '1';
            }
        });
    });
}

// Initialize OTP input handling
function initializeOTPInputs(inputs) {
    inputs.forEach((input, index) => {
        // Auto-focus first input
        if (index === 0) input.focus();

        input.addEventListener('input', (e) => {
            // Only allow numbers
            e.target.value = e.target.value.replace(/[^0-9]/g, '');
            
            if (e.target.value && index < inputs.length - 1) {
                inputs[index + 1].focus();
            }
        });

        // Handle backspace
        input.addEventListener('keydown', (e) => {
            if (e.key === 'Backspace') {
                if (!e.target.value && index > 0) {
                    inputs[index - 1].focus();
                }
                return;
            }
            
            // Prevent non-numeric input
            if (!/^[0-9]$/.test(e.key) && !['Tab', 'ArrowLeft', 'ArrowRight'].includes(e.key)) {
                e.preventDefault();
            }
        });

        // Handle paste
        input.addEventListener('paste', (e) => {
            e.preventDefault();
            const pastedText = e.clipboardData.getData('text');
            const numbers = pastedText.match(/[0-9]/g);
            
            if (numbers) {
                numbers.forEach((num, idx) => {
                    if (idx < inputs.length) {
                        inputs[idx].value = num;
                        if (idx < inputs.length - 1) {
                            inputs[idx + 1].focus();
                        }
                    }
                });
            }
        });
    });
}

// Initialize countdown timer
function initializeCountdown(buttonElement, countdownElement, duration) {
    if (!buttonElement || !countdownElement) return;

    let timeLeft = duration;
    buttonElement.disabled = true;
    
    const formatTime = (seconds) => {
        const minutes = Math.floor(seconds / 60);
        const remainingSeconds = seconds % 60;
        return `${minutes}:${remainingSeconds.toString().padStart(2, '0')}`;
    };

    const updateDisplay = () => {
        if (countdownElement) {
            countdownElement.textContent = formatTime(timeLeft);
        }
        buttonElement.textContent = `Resend in ${formatTime(timeLeft)}`;
    };

    const timer = setInterval(() => {
        timeLeft--;
        updateDisplay();

        if (timeLeft <= 0) {
            clearInterval(timer);
            buttonElement.disabled = false;
            buttonElement.textContent = 'Resend code';
            if (countdownElement) {
                countdownElement.textContent = '0:00';
            }
        }
    }, 1000);

    updateDisplay();
    
    return timer;
}

// Form validation helper
function validateForm(form, rules) {
    const errors = {};
    
    for (const [field, validations] of Object.entries(rules)) {
        const input = form.querySelector(`[name="${field}"]`);
        if (!input) continue;

        const value = input.value.trim();
        
        for (const validation of validations) {
            switch (validation) {
                case 'required':
                    if (!value) {
                        errors[field] = 'This field is required';
                    }
                    break;
                    
                case 'email':
                    if (value && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value)) {
                        errors[field] = 'Please enter a valid email address';
                    }
                    break;
                    
                case 'password':
                    if (value && value.length < 8) {
                        errors[field] = 'Password must be at least 8 characters';
                    }
                    break;
            }
            
            if (errors[field]) break;
        }
    }
    
    return errors;
}

// Show validation errors
function showValidationErrors(form, errors) {
    // Clear previous errors
    form.querySelectorAll('.error-message').forEach(el => el.remove());
    
    for (const [field, message] of Object.entries(errors)) {
        const input = form.querySelector(`[name="${field}"]`);
        if (!input) continue;
        
        const errorElement = document.createElement('div');
        errorElement.className = 'error-message';
        errorElement.textContent = message;
        
        const inputGroup = input.closest('.input-group') || input.parentElement;
        inputGroup.appendChild(errorElement);
        input.classList.add('error');
    }
}

// Format phone numbers
function formatPhoneNumber(input) {
    let value = input.value.replace(/\D/g, '');
    if (value.length > 10) value = value.slice(0, 10);
    
    if (value.length >= 6) {
        value = `(${value.slice(0, 3)}) ${value.slice(3, 6)}-${value.slice(6)}`;
    } else if (value.length >= 3) {
        value = `(${value.slice(0, 3)}) ${value.slice(3)}`;
    } else if (value.length > 0) {
        value = `(${value}`;
    }
    
    input.value = value;
}

// --- Toast / notification helpers ---
function ensureToastContainer() {
    let container = document.getElementById('toast-container');
    if (!container) {
        container = document.createElement('div');
        container.id = 'toast-container';
        // use the class so CSS rules apply
        container.className = 'toast-container';
        // layout handled by CSS (.toast-container)
        document.body.appendChild(container);
    }
    return container;
}

function showToast(message, type = 'info', duration = 4000, title = null) {
    const container = ensureToastContainer();
    const toast = document.createElement('div');

    toast.className = `toast toast-${type} toast-enter`;

    const content = document.createElement('div');
    content.className = 'toast-content';
    content.style.flex = '1';
    content.style.marginRight = '8px';

    if (title) {
        const titleEl = document.createElement('div');
        titleEl.className = 'toast-title';
        titleEl.textContent = title;
        titleEl.style.fontWeight = '700';
        titleEl.style.marginBottom = '4px';
        content.appendChild(titleEl);
    }

    const msg = document.createElement('div');
    msg.className = 'toast-message';
    msg.textContent = message;
    content.appendChild(msg);
    toast.appendChild(content);

    const closeBtn = document.createElement('button');
    closeBtn.textContent = '✕';
    closeBtn.className = 'toast-close';
    closeBtn.addEventListener('click', () => {
        // start exit animation
        startExit();
    });
    toast.appendChild(closeBtn);

    // append and let CSS animate entry
    container.appendChild(toast);

    // helpers to remove with animation
    let exiting = false;
    function startExit() {
        if (exiting) return;
        exiting = true;
        toast.classList.remove('toast-enter');
        toast.classList.add('toast-exit');
        toast.addEventListener('animationend', () => {
            toast.remove();
        });
        if (toast._timer) clearTimeout(toast._timer);
    }

    // auto-close timer
    toast._timer = setTimeout(() => {
        startExit();
    }, duration);

    return toast;
}

// ---------------- Password strength helpers ----------------
// Returns an object with booleans for each rule and a score (0-100)
function evaluatePasswordStrength(pw) {
    const result = {
        length: pw.length >= 8,
        upper: /[A-Z]/.test(pw),
        lower: /[a-z]/.test(pw),
        number: /[0-9]/.test(pw),
        special: /[!@#$%^&*()_+\-=[\]{};':"\\|,.<>/?]/.test(pw)
    };
    // Score: each rule counts equally
    const passed = Object.values(result).filter(Boolean).length;
    const score = Math.round((passed / Object.keys(result).length) * 100);
    return { rules: result, score };
}

// Attach a visual strength meter and checklist to a password input
function attachPasswordStrength(input) {
    if (!input) return;
    // Create container
    const container = document.createElement('div');
    container.className = 'pw-strength-container';

    // Create a wrapper for the visual strength bar
    const barWrap = document.createElement('div');
    barWrap.className = 'pw-bar-wrap';
    // Minimal inline styles so the bar shows correctly even if CSS isn't loaded yet
    barWrap.style.height = '4px';
    barWrap.style.marginBottom = '0.25rem';
    barWrap.style.background = 'rgba(255,255,255,0.04)';
    barWrap.style.borderRadius = '6px';
    barWrap.style.overflow = 'hidden';

    const bar = document.createElement('div');
    bar.className = 'pw-bar';
    bar.style.height = '100%';
    bar.style.width = '0%';
    bar.style.background = 'var(--green)';
    bar.style.transition = 'width 180ms ease, background 180ms ease';
    barWrap.appendChild(bar);

    const checklist = document.createElement('div');
    checklist.className = 'pw-checklist';
    // Increase checklist font-size by ~1.5x (was 0.425rem)
    checklist.style.fontSize = '0.64rem';
    checklist.style.color = 'var(--dim)';
    checklist.style.display = 'grid';
    checklist.style.gridTemplateColumns = '1fr';
    checklist.style.gap = '2px';

    const items = [
        { key: 'upper', text: 'Uppercase and lowercase letters' },
        { key: 'number', text: 'Numbers and special characters' },
        { key: 'special', text: 'Contains a symbol (e.g. !@#$%)' }
    ];

    const elItems = {};
    items.forEach(it => {
        const row = document.createElement('div');
        row.className = 'pw-item pw-item-' + it.key;
        const txt = document.createElement('div');
        txt.textContent = '• ' + it.text;
        row.appendChild(txt);
        checklist.appendChild(row);
        elItems[it.key] = { row, txt };
    });

    container.appendChild(barWrap);
    container.appendChild(checklist);
    const requirementsContainer = document.getElementById('passwordRequirements');
    if (requirementsContainer) {
        requirementsContainer.appendChild(container);
    }

    function update() {
        const val = input.value || '';
        const res = evaluatePasswordStrength(val);
        bar.style.width = res.score + '%';
        // color transitions
        if (res.score >= 80) bar.style.background = 'var(--green)';
        else if (res.score >= 50) bar.style.background = '#f5a623';
        else bar.style.background = '#ff5c5c';

        // Update checklist
        Object.entries(res.rules).forEach(([k, v]) => {
            if (elItems[k]) {
                if (v) {
                    elItems[k].row.classList.add('valid');
                } else {
                    elItems[k].row.classList.remove('valid');
                }
            }
        });
    }

    input.addEventListener('input', update);
    // initialize
    update();
    return { update, container };
}