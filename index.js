const express = require('express');
const jwt = require('jsonwebtoken');
const fs = require('fs');
const bcrypt = require('bcrypt');

const app = express();
app.use(express.json());

const staffData = JSON.parse(fs.readFileSync('staffs.json'));
const loansData = JSON.parse(fs.readFileSync('loans.json'));

const secretKey = 'QgsydyYuiduU8jj78IIUuie89kkxyfg'; 

// Middleware for verifying JWT token
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (token == null) return res.sendStatus(401);

    jwt.verify(token, secretKey, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
};

// Login endpoint
app.post('/login', (req, res) => {
    const { email, password } = req.body;
    const user = staffData.find(user => user.email === email);
    if (user == null) return res.status(400).send('User not found');

    bcrypt.compare(password, user.password, (err, result) => {
        if (err || !result) return res.status(401).send('Invalid credentials');
        
        const token = jwt.sign({ email: user.email, role: user.role }, secretKey);
        res.json({ token });
    });
});

// Logout endpoint
app.post('/logout', (req, res) => {
    res.sendStatus(204);
});

// Middleware for role-based authentication
const authorizeRole = (roles) => {
    return (req, res, next) => {
        if (!roles.includes(req.user.role)) {
            return res.status(403).json({ message: 'Unauthorized' });
        }
        next();
    };
};

// Loans endpoint
app.get('/loans', authenticateToken, (req, res) => {
    const { role } = req.user;
    const loansToSend = loansData.map(loan => {
        if (role === 'admin' || role === 'superadmin') {
            return { ...loan };
        } else {
            return { ...loan, totalLoan: undefined };
        }
    });
    res.json(loansToSend);
});

// Filter loans based on status
app.get('/loans', authenticateToken, (req, res) => {
    const { status } = req.query;
    const filteredLoans = loansData.filter(loan => loan.status === status);
    res.json(filteredLoans);
});

// Get loans by user email
app.get('/loans/:userEmail/get', authenticateToken, (req, res) => {
    const { userEmail } = req.params;
    const userLoans = loansData.filter(loan => loan.userEmail === userEmail);
    res.json({ loans: userLoans });
});

// Get expired loans
app.get('/loans/expired', authenticateToken, (req, res) => {
    const currentDate = new Date();
    const expiredLoans = loansData.filter(loan => new Date(loan.maturityDate) < currentDate);
    res.json(expiredLoans);
});

// Delete loan by loan ID
app.delete('/loans/:loanId/delete', authenticateToken, authorizeRole(['superadmin']), (req, res) => {
    const { loanId } = req.params;
    const index = loansData.findIndex(loan => loan.id === loanId);
    if (index === -1) return res.status(404).json({ message: 'Loan not found' });

    loansData.splice(index, 1);
    res.sendStatus(204);
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
