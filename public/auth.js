async function login(email, password) {
    const res = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password })
    });

    const data = await res.json();

    if (data.token) {
        localStorage.setItem('token', data.token);
        localStorage.setItem('userId', data.userId);
        alert("Login successful");
        loadAccounts();
    } else {
        alert(data.error || "Login failed");
    }
}

async function register(username, email, password) {
    const res = await fetch('/api/auth/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, email, password })
    });

    const data = await res.json();

    if (data.token) {
        localStorage.setItem('token', data.token);
        localStorage.setItem('userId', data.userId);
        alert("Registered successfully");
        loadAccounts();
    } else {
        alert(data.error || "Registration failed");
    }
}

async function loadAccounts() {
    const token = localStorage.getItem('token');
    const userId = localStorage.getItem('userId');

    const res = await fetch(`/api/accounts/${userId}`, {
        headers: {
            Authorization: `Bearer ${token}`
        }
    });

    const accounts = await res.json();

    if (!Array.isArray(accounts)) return;

    accounts.forEach(acc => {
        if (acc.account_type === "checking") {
            document.querySelector(".checking-balance").textContent =
                "$" + acc.balance.toLocaleString(undefined, { minimumFractionDigits: 2 });
        }

        if (acc.account_type === "savings") {
            document.querySelector(".savings-balance").textContent =
                "$" + acc.balance.toLocaleString(undefined, { minimumFractionDigits: 2 });
        }
    });
}

