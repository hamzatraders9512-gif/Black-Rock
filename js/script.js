document.addEventListener('DOMContentLoaded', function(){
  const passwordInput = document.querySelector('input[type="password"]');
  const eyeBtn = document.querySelector('.eye-btn');
  const googleBtn = document.querySelector('.google-btn');
  const signinBtn = document.querySelector('.signin-btn');
  
  // Toggle password visibility
  eyeBtn?.addEventListener('click', () => {
    const type = passwordInput.type === 'password' ? 'text' : 'password';
    passwordInput.type = type;
    eyeBtn.querySelector('.eye-icon').style.opacity = type === 'password' ? 1 : 0.7;
  });

  // Google sign in
  googleBtn?.addEventListener('click', () => {
    // In a real app, this would redirect to Google OAuth
    console.log('Initiating Google sign in...');
  });

  // Form submission
  signinBtn?.addEventListener('click', () => {
    const email = document.querySelector('input[type="email"]').value;
    const password = passwordInput.value;
    
    if (!email || !password) {
      console.log('Please fill in all fields');
      return;
    }
    
    // In a real app, this would submit to your auth endpoint
    console.log('Signing in...'); 
  });
});