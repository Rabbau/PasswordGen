// ============================================================================
// CONSTANTS & CONFIG
// ============================================================================

const API_BASE = '';
const STRENGTH_LABELS = {
    0: 'Очень слабый',
    1: 'Слабый',
    2: 'Средний',
    3: 'Сильный',
    4: 'Очень сильный'
};

const STRENGTH_CLASSES = {
    0: 'very-weak',
    1: 'weak',
    2: 'medium',
    3: 'strong',
    4: 'very-strong'
};

// ============================================================================
// UTILITIES
// ============================================================================

function showElement(element) {
    element.classList.remove('hidden');
}

function hideElement(element) {
    element.classList.add('hidden');
}

function toggleClass(element, className) {
    element.classList.toggle(className);
}

async function apiCall(endpoint, method = 'POST', body = null) {
    const options = {
        method,
        headers: { 'Content-Type': 'application/json' }
    };

    if (body) {
        options.body = JSON.stringify(body);
    }

    const response = await fetch(`${API_BASE}${endpoint}`, options);
    
    if (!response.ok) {
        const error = await response.json();
        throw new Error(error.detail || `API Error: ${response.status}`);
    }

    return response.json();
}

function getStrengthPercentage(score) {
    return (score / 4) * 100;
}

// ============================================================================
// TAB NAVIGATION
// ============================================================================

function initTabs() {
    const tabButtons = document.querySelectorAll('.tab-button');
    const tabContents = document.querySelectorAll('.tab-content');

    tabButtons.forEach(button => {
        button.addEventListener('click', () => {
            const tabName = button.getAttribute('data-tab');

            // Remove active class from all buttons and contents
            tabButtons.forEach(btn => btn.classList.remove('active'));
            tabContents.forEach(content => content.classList.remove('active'));

            // Add active class to clicked button and corresponding content
            button.classList.add('active');
            document.getElementById(tabName).classList.add('active');
        });
    });
}

// ============================================================================
// GENERATE TAB
// ============================================================================

function initGenerateTab() {
    const lengthSlider = document.getElementById('length');
    const lengthValue = document.getElementById('length-value');
    const generateBtn = document.getElementById('generate-btn');
    const copyBtn = document.getElementById('copy-btn');

    // Update slider value display
    lengthSlider.addEventListener('input', () => {
        lengthValue.textContent = lengthSlider.value;
    });

    // Generate password
    generateBtn.addEventListener('click', async () => {
        try {
            generateBtn.disabled = true;
            generateBtn.textContent = 'Генерирую...';

            const request = {
                length: parseInt(lengthSlider.value),
                include_lowercase: document.getElementById('lowercase').checked,
                include_uppercase: document.getElementById('uppercase').checked,
                include_digits: document.getElementById('digits').checked,
                include_symbols: document.getElementById('symbols').checked
            };

            const response = await apiCall('/api/generate', 'POST', request);

            document.getElementById('generated-password').value = response.password;
            document.getElementById('gen-entropy').textContent = response.entropy_bits;
            
            const strengthLabel = STRENGTH_LABELS[response.strength_score];
            const strengthClass = STRENGTH_CLASSES[response.strength_score];
            const strengthEl = document.getElementById('gen-strength');
            
            strengthEl.textContent = strengthLabel;
            strengthEl.className = `value strength-badge ${strengthClass}`;

            showElement(document.getElementById('generate-result'));
        } catch (error) {
            alert('Ошибка: ' + error.message);
        } finally {
            generateBtn.disabled = false;
            generateBtn.textContent = 'Сгенерировать пароль';
        }
    });

    // Copy password to clipboard
    copyBtn.addEventListener('click', async () => {
        const password = document.getElementById('generated-password').value;
        try {
            await navigator.clipboard.writeText(password);
            copyBtn.textContent = '✓';
            setTimeout(() => {
                copyBtn.textContent = '📋';
            }, 2000);
        } catch (error) {
            alert('Не удалось скопировать пароль');
        }
    });
}

// ============================================================================
// CHECK TAB
// ============================================================================

function initCheckTab() {
    const checkPasswordInput = document.getElementById('check-password');
    const checkBtn = document.getElementById('check-btn');
    const toggleVisibilityBtn = document.getElementById('toggle-visibility');

    // Toggle password visibility
    toggleVisibilityBtn.addEventListener('click', () => {
        const type = checkPasswordInput.type === 'password' ? 'text' : 'password';
        checkPasswordInput.type = type;
        toggleVisibilityBtn.textContent = type === 'password' ? '👁️' : '🙈';
    });

    // Check strength
    checkBtn.addEventListener('click', async () => {
        const password = checkPasswordInput.value;

        if (!password) {
            alert('Пожалуйста, введите пароль');
            return;
        }

        try {
            checkBtn.disabled = true;
            checkBtn.textContent = 'Проверяю...';

            const response = await apiCall('/api/strength-check', 'POST', { password });

            // Update strength bar
            const percentage = getStrengthPercentage(response.score);
            const strengthFill = document.getElementById('strength-fill');
            strengthFill.style.width = percentage + '%';

            // Update strength label
            const strengthLabel = STRENGTH_LABELS[response.score];
            const strengthClass = STRENGTH_CLASSES[response.score];
            const strengthLabelEl = document.getElementById('strength-label');
            strengthLabelEl.textContent = strengthLabel;
            strengthLabelEl.className = `strength-label ${strengthClass}`;

            // Update metrics
            document.getElementById('check-length').textContent = response.length;
            document.getElementById('check-charset').textContent = response.charset_size;
            document.getElementById('check-entropy').textContent = response.entropy_bits;

            showElement(document.getElementById('check-result'));
        } catch (error) {
            alert('Ошибка: ' + error.message);
        } finally {
            checkBtn.disabled = false;
            checkBtn.textContent = 'Проверить сложность';
        }
    });

    // Allow Enter key
    checkPasswordInput.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') {
            checkBtn.click();
        }
    });
}

// ============================================================================
// ENTROPY TAB
// ============================================================================

function initEntropyTab() {
    const entropyPasswordInput = document.getElementById('entropy-password');
    const entropyBtn = document.getElementById('entropy-btn');
    const entropyToggleVisibilityBtn = document.getElementById('entropy-toggle-visibility');

    // Toggle password visibility
    entropyToggleVisibilityBtn.addEventListener('click', () => {
        const type = entropyPasswordInput.type === 'password' ? 'text' : 'password';
        entropyPasswordInput.type = type;
        entropyToggleVisibilityBtn.textContent = type === 'password' ? '👁️' : '🙈';
    });

    // Calculate entropy
    entropyBtn.addEventListener('click', async () => {
        const password = entropyPasswordInput.value;

        if (!password) {
            alert('Пожалуйста, введите пароль');
            return;
        }

        try {
            entropyBtn.disabled = true;
            entropyBtn.textContent = 'Считаю...';

            const response = await apiCall('/api/entropy', 'POST', { password });

            // Update entropy display
            document.getElementById('entropy-bits').textContent = response.entropy_bits;
            document.getElementById('entropy-power').textContent = response.entropy_bits.toFixed(0);
            document.getElementById('entropy-length').textContent = response.length;
            document.getElementById('entropy-charset').textContent = response.charset_size;

            // Generate recommendations
            generateRecommendations(response);

            showElement(document.getElementById('entropy-result'));
        } catch (error) {
            alert('Ошибка: ' + error.message);
        } finally {
            entropyBtn.disabled = false;
            entropyBtn.textContent = 'Расчитать энтропию';
        }
    });

    // Allow Enter key
    entropyPasswordInput.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') {
            entropyBtn.click();
        }
    });
}

function generateRecommendations(entropyData) {
    const recommendations = [];
    const { entropy_bits, length, charset_size } = entropyData;

    // Check length
    if (length < 12) {
        recommendations.push('Увеличьте длину пароля до минимум 12 символов');
    }

    // Check charset diversity
    if (charset_size < 60) {
        recommendations.push('Используйте комбинацию букв (верхнего и нижнего регистра), цифр и символов');
    }

    // Check entropy
    if (entropy_bits < 60) {
        recommendations.push('Энтропия пароля низкая. Добавьте больше символов или используйте более разнообразный набор');
    }

    if (entropy_bits < 80) {
        recommendations.push('Рекомендуется использовать пароли с энтропией не менее 80 бит');
    }

    // Positive recommendations
    if (length >= 16 && charset_size >= 80) {
        recommendations.push('Отличный пароль! Он хорошо защищён от перебора');
    }

    if (entropy_bits >= 80) {
        recommendations.push('Высокая энтропия - пароль устойчив к атакам перебора');
    }

    // Update UI
    const recommendationsList = document.getElementById('entropy-recommendations');
    recommendationsList.innerHTML = '';

    if (recommendations.length === 0) {
        recommendations.push('Пароль соответствует стандартам безопасности');
    }

    recommendations.forEach(rec => {
        const li = document.createElement('li');
        li.textContent = rec;
        recommendationsList.appendChild(li);
    });
}

// ============================================================================
// INITIALIZATION
// ============================================================================

document.addEventListener('DOMContentLoaded', () => {
    initTabs();
    initGenerateTab();
    initCheckTab();
    initEntropyTab();
});
