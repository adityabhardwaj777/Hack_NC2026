/* ==========================================================
   SECUREBANK - FULLY FUNCTIONAL BANKING APPLICATION
   Complete implementation with all features working
   ========================================================== */

// ==================== DATA MODELS ====================

class BankAccount {
    constructor(type, accountNumber) {
        this.type = type;
        this.accountNumber = accountNumber;
        this.balance = type === 'checking' ? 2500.00 : 5000.00;
        this.transactions = [];
    }

    deposit(amount) {
        this.balance += amount;
        return this.balance;
    }

    withdraw(amount) {
        if (this.balance >= amount) {
            this.balance -= amount;
            return true;
        }
        return false;
    }

    getBalance() {
        return this.balance;
    }
}

class Transaction {
    constructor(type, amount, description, category, fromAccount, toAccount = null) {
        this.id = Date.now() + Math.random();
        this.type = type;
        this.amount = amount;
        this.description = description;
        this.category = category;
        this.fromAccount = fromAccount;
        this.toAccount = toAccount;
        this.timestamp = new Date();
        this.fraudCheck = null;
    }
}

class FraudDetector {
    constructor() {
        this.suspiciousPatterns = [
            { merchant: /dark\s*web/i, risk: 100 },
            { merchant: /unknown/i, risk: 80 },
            { merchant: /crypto\s*exchange/i, risk: 60 },
            { merchant: /suspicious/i, risk: 70 }
        ];
        this.blockedCount = 0;
        this.moneyProtected = 0;
    }

    analyzeTransaction(transaction) {
        let riskScore = 0;
        let reasons = [];

        // Check merchant patterns
        if (transaction.description) {
            for (let pattern of this.suspiciousPatterns) {
                if (pattern.merchant && pattern.merchant.test(transaction.description)) {
                    riskScore += pattern.risk;
                    reasons.push(`Suspicious merchant: ${transaction.description}`);
                    break;
                }
            }
        }

        // Check amount
        if (transaction.amount > 5000) {
            riskScore += 40;
            reasons.push(`Large transaction: $${transaction.amount.toFixed(2)}`);
        } else if (transaction.amount > 2000) {
            riskScore += 20;
            reasons.push(`Elevated transaction amount`);
        }

        // Check velocity
        const recentTransactions = appState.transactions.filter(t => 
            Date.now() - t.timestamp.getTime() < 300000
        );
        if (recentTransactions.length > 5) {
            riskScore += 30;
            reasons.push('High transaction velocity');
        }

        const isBlocked = riskScore >= 70;
        const isSuspicious = riskScore >= 40 && riskScore < 70;

        if (isBlocked) {
            this.blockedCount++;
            this.moneyProtected += transaction.amount;
        }

        return {
            riskScore,
            isBlocked,
            isSuspicious,
            reasons: reasons.length > 0 ? reasons : ['Normal transaction pattern'],
            status: isBlocked ? 'BLOCKED' : isSuspicious ? 'FLAGGED' : 'SAFE'
        };
    }
}

// ==================== APPLICATION STATE ====================

const appState = {
    accounts: {
        checking: new BankAccount('checking', '4521'),
        savings: new BankAccount('savings', '7832')
    },
    transactions: [],
    fraudDetector: new FraudDetector(),
    budget: {
        total: 3000,
        categories: {
            groceries: { limit: 600, spent: 0 },
            utilities: { limit: 300, spent: 0 },
            entertainment: { limit: 400, spent: 0 },
            dining: { limit: 500, spent: 0 },
            transport: { limit: 400, spent: 0 },
            shopping: { limit: 800, spent: 0 }
        }
    },
    game: {
        score: 0,
        currentQuestion: null,
        questionsAnswered: 0,
        questions: [
            {
                question: "What is a good debt-to-income ratio?",
                options: ["Below 36%", "50-60%", "70-80%", "Above 90%"],
                correct: 0,
                reward: 50
            },
            {
                question: "How much should you save for emergencies?",
                options: ["1 month expenses", "3-6 months expenses", "1 year expenses", "No savings needed"],
                correct: 1,
                reward: 75
            },
            {
                question: "What is compound interest?",
                options: [
                    "Interest paid once",
                    "Interest earned on interest",
                    "High interest rate",
                    "Bank fees"
                ],
                correct: 1,
                reward: 100
            },
            {
                question: "When should you start investing for retirement?",
                options: ["Age 50+", "Age 40", "As early as possible", "Never"],
                correct: 2,
                reward: 100
            },
            {
                question: "What's a credit score used for?",
                options: [
                    "Gaming points",
                    "Loan approval & interest rates",
                    "Tax deductions",
                    "Salary negotiations"
                ],
                correct: 1,
                reward: 75
            },
            {
                question: "What does 'diversification' mean in investing?",
                options: [
                    "Putting all money in one stock",
                    "Spreading investments across different assets",
                    "Only investing in bonds",
                    "Avoiding the stock market"
                ],
                correct: 1,
                reward: 100
            }
        ]
    }
};

// ==================== UI FUNCTIONS ====================

function showSection(sectionName) {
    // Hide all sections
    document.querySelectorAll('.section').forEach(section => {
        section.classList.remove('active');
    });

    // Show selected section
    document.getElementById(sectionName).classList.add('active');

    // Update nav
    document.querySelectorAll('.nav-item').forEach(item => {
        item.classList.remove('active');
    });
    event.target.classList.add('active');

    // Update section-specific content
    if (sectionName === 'budget') {
        updateBudgetDisplay();
    } else if (sectionName === 'security') {
        updateSecurityDisplay();
    } else if (sectionName === 'transactions') {
        updateAllTransactions();
    } else if (sectionName === 'learn') {
        // Reset game if needed
        document.getElementById('gameScore').textContent = '$' + appState.game.score;
    }
}

function updateBalances() {
    document.getElementById('checkingBalance').textContent = 
        '$' + appState.accounts.checking.getBalance().toLocaleString('en-US', { minimumFractionDigits: 2 });
    document.getElementById('savingsBalance').textContent = 
        '$' + appState.accounts.savings.getBalance().toLocaleString('en-US', { minimumFractionDigits: 2 });
}

function updateAllTransactions() {
    const allContainer = document.getElementById('allTransactions');
    
    if (appState.transactions.length === 0) {
        allContainer.innerHTML = `
            <div class="empty-state">
                <div class="empty-icon">📊</div>
                <div class="empty-text">No transactions yet</div>
                <div class="empty-subtext">Your transaction history will appear here</div>
            </div>
        `;
        return;
    }

    const all = [...appState.transactions].reverse();
    allContainer.innerHTML = all.map(t => createTransactionHTML(t)).join('');
}

function updateRecentTransactions() {
    const recentContainer = document.getElementById('recentTransactions');
    
    if (appState.transactions.length === 0) {
        recentContainer.innerHTML = `
            <div class="empty-state">
                <div class="empty-icon">📊</div>
                <div class="empty-text">No transactions yet</div>
                <div class="empty-subtext">Try making a deposit or payment to get started</div>
            </div>
        `;
        return;
    }

    const recent = appState.transactions.slice(-5).reverse();
    recentContainer.innerHTML = recent.map(t => createTransactionHTML(t)).join('');
}

function createTransactionHTML(transaction) {
    let isPositive = false;
    let amount = '';
    let icon = '💳';

    if (transaction.type === 'deposit') {
        isPositive = true;
        amount = `+$${transaction.amount.toFixed(2)}`;
        icon = '💰';
    } else if (transaction.type === 'transfer') {
        // For transfers, show as positive if it's TO this account
        isPositive = transaction.toAccount !== null;
        amount = isPositive ? `+$${transaction.amount.toFixed(2)}` : `-$${transaction.amount.toFixed(2)}`;
        icon = '💸';
    } else {
        amount = `-$${transaction.amount.toFixed(2)}`;
        icon = '💳';
    }

    const fraudBadge = transaction.fraudCheck ? 
        (transaction.fraudCheck.isBlocked ? '<span class="badge badge-danger">🛡️ BLOCKED</span>' : 
         transaction.fraudCheck.isSuspicious ? '<span class="badge badge-warning">⚠️ FLAGGED</span>' : 
         '<span class="badge badge-success">✓ VERIFIED</span>') : '';

    return `
        <div class="transaction-item ${isPositive ? 'income' : 'expense'}">
            <div class="transaction-icon">${icon}</div>
            <div class="transaction-details">
                <div class="transaction-name">${transaction.description} ${fraudBadge}</div>
                <div class="transaction-meta">${transaction.timestamp.toLocaleString()} • ${transaction.category || 'general'}</div>
            </div>
            <div class="transaction-amount ${isPositive ? 'positive' : 'negative'}">${amount}</div>
        </div>
    `;
}

function updateBudgetDisplay() {
    const totalSpent = Object.values(appState.budget.categories).reduce((sum, cat) => sum + cat.spent, 0);
    const remaining = appState.budget.total - totalSpent;

    document.getElementById('totalBudget').textContent = '$' + appState.budget.total.toLocaleString();
    document.getElementById('totalSpent').textContent = '$' + totalSpent.toFixed(2).replace(/\B(?=(\d{3})+(?!\d))/g, ",");
    document.getElementById('remaining').textContent = '$' + remaining.toFixed(2).replace(/\B(?=(\d{3})+(?!\d))/g, ",");

    const container = document.getElementById('budgetCategories');
    container.innerHTML = Object.entries(appState.budget.categories).map(([name, data]) => {
        const percentage = (data.spent / data.limit) * 100;
        const progressClass = percentage >= 90 ? 'danger' : percentage >= 75 ? 'warning' : '';

        return `
            <div class="budget-category">
                <div class="budget-header">
                    <span class="category-name">${name.charAt(0).toUpperCase() + name.slice(1)}</span>
                    <span class="budget-spent">$${data.spent.toFixed(2)} / $${data.limit}</span>
                </div>
                <div class="progress-bar">
                    <div class="progress-fill ${progressClass}" style="width: ${Math.min(percentage, 100)}%"></div>
                </div>
                <div class="progress-text">
                    ${Math.round(percentage)}% used
                </div>
            </div>
        `;
    }).join('');
}

function updateSecurityDisplay() {
    document.getElementById('threatsBlocked').textContent = appState.fraudDetector.blockedCount;
    document.getElementById('moneyProtected').textContent = '$' + appState.fraudDetector.moneyProtected.toLocaleString('en-US', { minimumFractionDigits: 2 });

    const alertsContainer = document.getElementById('securityAlerts');
    const blockedTransactions = appState.transactions.filter(t => t.fraudCheck && t.fraudCheck.isBlocked);

    if (blockedTransactions.length === 0) {
        alertsContainer.innerHTML = `
            <div class="empty-state">
                <div class="empty-icon">🛡️</div>
                <div class="empty-text">No security threats detected</div>
                <div class="empty-subtext">AI is actively monitoring all transactions</div>
            </div>
        `;
    } else {
        alertsContainer.innerHTML = blockedTransactions.map(t => `
            <div class="alert-box">
                <div class="alert-title">🚨 Fraud Attempt Blocked</div>
                <div class="alert-description">
                    <strong>${t.description}</strong> - $${t.amount.toFixed(2)}
                </div>
                <div class="alert-meta">
                    Risk Score: ${t.fraudCheck.riskScore}% | ${t.fraudCheck.reasons.join(', ')} | ${t.timestamp.toLocaleString()}
                </div>
            </div>
        `).join('');
    }
}

// ==================== TRANSACTION HANDLERS ====================

function handleDeposit(event) {
    event.preventDefault();
    
    const account = document.getElementById('depositAccount').value;
    const amount = parseFloat(document.getElementById('depositAmount').value);

    if (!amount || amount <= 0) {
        showNotification('Please enter a valid amount', 'error');
        return;
    }

    const transaction = new Transaction('deposit', amount, 'Direct Deposit', 'income', null, account);
    appState.accounts[account].deposit(amount);
    appState.transactions.push(transaction);

    updateBalances();
    updateRecentTransactions();
    updateAllTransactions();
    closeModal('deposit');
    
    // Reset form
    document.getElementById('depositAmount').value = '';
    
    showNotification(`✓ Deposited $${amount.toFixed(2)} to ${account}`, 'success');
}

function handleTransfer(event) {
    event.preventDefault();
    
    const from = document.getElementById('fromAccount').value;
    const to = document.getElementById('toAccount').value;
    const amount = parseFloat(document.getElementById('transferAmount').value);

    if (!amount || amount <= 0) {
        showNotification('Please enter a valid amount', 'error');
        return;
    }

    if (from === to) {
        showNotification('Cannot transfer to the same account', 'error');
        return;
    }

    if (appState.accounts[from].withdraw(amount)) {
        appState.accounts[to].deposit(amount);
        
        const transaction = new Transaction('transfer', amount, `Transfer from ${from} to ${to}`, 'transfer', from, to);
        appState.transactions.push(transaction);

        updateBalances();
        updateRecentTransactions();
        updateAllTransactions();
        closeModal('transfer');
        
        // Reset form
        document.getElementById('transferAmount').value = '';
        
        showNotification(`✓ Transferred $${amount.toFixed(2)} from ${from} to ${to}`, 'success');
    } else {
        showNotification('Insufficient funds in ' + from + ' account', 'error');
    }
}

function handlePayment(event) {
    event.preventDefault();
    
    const payee = document.getElementById('payee').value.trim();
    const category = document.getElementById('category').value;
    const amount = parseFloat(document.getElementById('payAmount').value);

    if (!payee) {
        showNotification('Please enter a payee name', 'error');
        return;
    }

    if (!amount || amount <= 0) {
        showNotification('Please enter a valid amount', 'error');
        return;
    }

    const transaction = new Transaction('payment', amount, payee, category, 'checking');
    
    // FRAUD DETECTION
    const fraudCheck = appState.fraudDetector.analyzeTransaction(transaction);
    transaction.fraudCheck = fraudCheck;

    if (fraudCheck.isBlocked) {
        // Log blocked transaction but don't process
        appState.transactions.push(transaction);
        updateRecentTransactions();
        updateAllTransactions();
        updateSecurityDisplay();
        closeModal('pay');
        
        // Reset form
        document.getElementById('payee').value = '';
        document.getElementById('payAmount').value = '';
        
        showNotification(`🚨 TRANSACTION BLOCKED - ${fraudCheck.reasons.join(', ')}`, 'error');
        return;
    }

    if (appState.accounts.checking.withdraw(amount)) {
        // Update budget
        if (appState.budget.categories[category]) {
            appState.budget.categories[category].spent += amount;
        }

        appState.transactions.push(transaction);

        updateBalances();
        updateRecentTransactions();
        updateAllTransactions();
        updateBudgetDisplay();
        closeModal('pay');
        
        // Reset form
        document.getElementById('payee').value = '';
        document.getElementById('payAmount').value = '';

        if (fraudCheck.isSuspicious) {
            showNotification(`⚠️ Payment processed but flagged: ${fraudCheck.reasons.join(', ')}`, 'warning');
        } else {
            showNotification(`✓ Payment of $${amount.toFixed(2)} to ${payee} successful`, 'success');
        }
    } else {
        showNotification('Insufficient funds in checking account', 'error');
    }
}

// ==================== GAME FUNCTIONS ====================

let currentQuestionIndex = 0;

function startGame() {
    currentQuestionIndex = 0;
    appState.game.questionsAnswered = 0;
    loadQuestion();
}

function loadQuestion() {
    if (currentQuestionIndex >= appState.game.questions.length) {
        showGameComplete();
        return;
    }

    const question = appState.game.questions[currentQuestionIndex];
    document.getElementById('startGameBtn').style.display = 'none';

    document.getElementById('gameQuestion').innerHTML = `
        <h3>${question.question}</h3>
        <div class="game-options">
            ${question.options.map((option, index) => `
                <div class="game-option" onclick="checkAnswer(${index})">
                    ${option}
                </div>
            `).join('')}
        </div>
    `;
}

function checkAnswer(selectedIndex) {
    const question = appState.game.questions[currentQuestionIndex];
    const options = document.querySelectorAll('.game-option');

    // Disable all options
    options.forEach((option, index) => {
        if (index === question.correct) {
            option.classList.add('correct');
        } else if (index === selectedIndex) {
            option.classList.add('incorrect');
        }
        option.style.pointerEvents = 'none';
    });

    if (selectedIndex === question.correct) {
        appState.game.score += question.reward;
        appState.accounts.checking.deposit(question.reward);
        
        // Create transaction for game earnings
        const transaction = new Transaction('deposit', question.reward, 'Game Earnings: Correct Answer', 'income', null, 'checking');
        appState.transactions.push(transaction);
        
        updateBalances();
        updateRecentTransactions();
        showNotification(`🎉 Correct! +$${question.reward} earned and added to checking!`, 'success');
    } else {
        showNotification('❌ Incorrect. Try the next question!', 'error');
    }

    document.getElementById('gameScore').textContent = '$' + appState.game.score;
    appState.game.questionsAnswered++;

    setTimeout(() => {
        currentQuestionIndex++;
        loadQuestion();
    }, 2000);
}

function showGameComplete() {
    document.getElementById('gameQuestion').innerHTML = `
        <h3 style="font-size: 2.5rem;">🎉 Congratulations!</h3>
        <p style="font-size: 1.5rem; margin-top: 1.5rem;">You earned <strong>$${appState.game.score}</strong>!</p>
        <p style="margin-top: 1rem; font-size: 1.125rem;">Money has been added to your checking account.</p>
        <p style="margin-top: 1rem; opacity: 0.9;">Questions answered: ${appState.game.questionsAnswered} / ${appState.game.questions.length}</p>
    `;
    
    document.getElementById('startGameBtn').textContent = 'Play Again';
    document.getElementById('startGameBtn').style.display = 'block';
    
    // Reset game but keep the score shown
    const earnedThisRound = appState.game.score;
    appState.game.score = 0;
    
    // Update recent transactions to show game earnings
    updateRecentTransactions();
}

// ==================== MODAL FUNCTIONS ====================

function openModal(type) {
    document.getElementById(type + 'Modal').classList.add('active');
    
    // Focus first input
    setTimeout(() => {
        const firstInput = document.querySelector(`#${type}Modal input, #${type}Modal select`);
        if (firstInput) firstInput.focus();
    }, 100);
}

function closeModal(type) {
    document.getElementById(type + 'Modal').classList.remove('active');
}

// Close modal on background click
document.addEventListener('click', function(event) {
    if (event.target.classList.contains('modal')) {
        const modals = ['transfer', 'deposit', 'pay'];
        modals.forEach(modal => {
            if (event.target.id === modal + 'Modal') {
                closeModal(modal);
            }
        });
    }
});

// Close modal on Escape key
document.addEventListener('keydown', function(event) {
    if (event.key === 'Escape') {
        const modals = ['transfer', 'deposit', 'pay'];
        modals.forEach(modal => {
            const modalEl = document.getElementById(modal + 'Modal');
            if (modalEl && modalEl.classList.contains('active')) {
                closeModal(modal);
            }
        });
    }
});

// ==================== NOTIFICATIONS ====================

function showNotification(message, type) {
    const notification = document.createElement('div');
    
    const colors = {
        success: '#00875A',
        error: '#DE350B',
        warning: '#FF8B00'
    };

    const icons = {
        success: '✓',
        error: '✗',
        warning: '⚠'
    };
    
    notification.style.cssText = `
        position: fixed;
        top: 20px;
        right: 20px;
        background: ${colors[type] || colors.success};
        color: white;
        padding: 1rem 1.5rem;
        border-radius: 10px;
        box-shadow: 0 8px 24px rgba(0,0,0,0.3);
        z-index: 10000;
        animation: slideInRight 0.3s cubic-bezier(0.4, 0, 0.2, 1);
        max-width: 400px;
        font-weight: 500;
        display: flex;
        align-items: center;
        gap: 0.75rem;
    `;
    
    notification.innerHTML = `
        <span style="font-size: 1.25rem;">${icons[type] || icons.success}</span>
        <span>${message}</span>
    `;
    
    document.body.appendChild(notification);

    // Add animation
    const style = document.createElement('style');
    style.textContent = `
        @keyframes slideInRight {
            from {
                opacity: 0;
                transform: translateX(100px);
            }
            to {
                opacity: 1;
                transform: translateX(0);
            }
        }
        @keyframes slideOutRight {
            from {
                opacity: 1;
                transform: translateX(0);
            }
            to {
                opacity: 0;
                transform: translateX(100px);
            }
        }
    `;
    document.head.appendChild(style);

    setTimeout(() => {
        notification.style.animation = 'slideOutRight 0.3s cubic-bezier(0.4, 0, 0.2, 1)';
        setTimeout(() => {
            notification.remove();
            style.remove();
        }, 300);
    }, 4000);
}

// ==================== INITIALIZATION ====================

window.addEventListener('load', () => {
    // Update initial balances
    updateBalances();
    updateRecentTransactions();
    updateAllTransactions();
    updateBudgetDisplay();
    updateSecurityDisplay();
    
    // Welcome notification
    setTimeout(() => {
        showNotification('Welcome to SecureBank! Your accounts are ready.', 'success');
    }, 500);
    
    // Add some demo transactions for better UX
    setTimeout(() => {
        const demoDeposit = new Transaction('deposit', 2500, 'Initial Deposit', 'income', null, 'checking');
        appState.transactions.push(demoDeposit);
        
        const savingsDeposit = new Transaction('deposit', 5000, 'Savings Deposit', 'income', null, 'savings');
        appState.transactions.push(savingsDeposit);
        
        updateRecentTransactions();
        updateAllTransactions();
    }, 1000);
});

// ==================== FORM VALIDATION ====================

// Prevent non-numeric input in amount fields
document.addEventListener('input', function(event) {
    if (event.target.type === 'number') {
        if (event.target.value < 0) {
            event.target.value = '';
        }
    }
});