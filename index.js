const express = require('express')
const {open} = require('sqlite')
const sqlite3 = require('sqlite3')
const path = require('path')
const bodyParser = require('body-parser')
const bcrypt = require('bcrypt')

const app = express()
const dbPath = path.join(__dirname, 'goodreads.db')
let db = null

app.use(bodyParser.json())

// Initialize DB and Server
const initializeDbAndServer = async () => {
  try {
    db = await open({
      filename: dbPath,
      driver: sqlite3.Database,
    })

    // Create tables after the database connection is established
    createUsersTable()
    createBooksTable()
    createBorrowRequestsTable()
    createBorrowHistoryTable()

    app.listen(3000, () => {
      console.log('Server running at http://localhost:3000/')
    })
  } catch (e) {
    console.error(`Error: ${e.message}`)
    process.exit(1)
  }
}

// Create the users table
const createUsersTable = () => {
  db.run(
    `CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      is_admin BOOLEAN NOT NULL DEFAULT 0
    )`,
    err => {
      if (err) {
        console.error('Error creating users table:', err.message)
      } else {
        console.log('Users table created successfully.')
      }
    },
  )
}

// Create the books table
const createBooksTable = () => {
  db.run(
    `CREATE TABLE IF NOT EXISTS books (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      title TEXT NOT NULL,
      author TEXT NOT NULL
    )`,
    err => {
      if (err) {
        console.error('Error creating books table:', err.message)
      } else {
        console.log('Books table created successfully.')
      }
    },
  )
}

// Create the borrow_requests table
const createBorrowRequestsTable = () => {
  db.run(
    `CREATE TABLE IF NOT EXISTS borrow_requests (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      book_id INTEGER NOT NULL,
      user_id INTEGER NOT NULL,
      start_date TEXT NOT NULL,
      end_date TEXT NOT NULL,
      status TEXT NOT NULL CHECK(status IN ('Pending', 'Approved', 'Denied')),
      FOREIGN KEY (book_id) REFERENCES books(id),
      FOREIGN KEY (user_id) REFERENCES users(id)
    )`,
    err => {
      if (err) {
        console.error('Error creating borrow_requests table:', err.message)
      } else {
        console.log('Borrow requests table created successfully.')
      }
    },
  )
}

// Create the borrow_history table
const createBorrowHistoryTable = () => {
  db.run(
    `CREATE TABLE IF NOT EXISTS borrow_history (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      book_id INTEGER NOT NULL,
      user_id INTEGER NOT NULL,
      borrowed_on TEXT NOT NULL,
      returned_on TEXT,
      FOREIGN KEY (book_id) REFERENCES books(id),
      FOREIGN KEY (user_id) REFERENCES users(id)
    )`,
    err => {
      if (err) {
        console.error('Error creating borrow_history table:', err.message)
      } else {
        console.log('Borrow history table created successfully.')
      }
    },
  )
}

// Middleware for Basic Authentication
const authenticateUser = async (req, res, next) => {
  const authHeader = req.headers['authorization']
  if (!authHeader) {
    return res.status(401).send('Authorization header missing')
  }

  const base64Credentials = authHeader.split(' ')[1]
  const [email, password] = Buffer.from(base64Credentials, 'base64')
    .toString()
    .split(':')

  const user = await db.get('SELECT * FROM users WHERE email = ?', [email])
  if (user && bcrypt.compareSync(password, user.password)) {
    req.user = user
    next()
  } else {
    res.status(401).send('Invalid credentials')
  }
}

// Librarian API: Create User
app.post('/users', authenticateUser, async (req, res) => {
  if (!req.user.is_admin) {
    return res.status(403).send('Access denied')
  }

  const {email, password, is_admin = false} = req.body
  const hashedPassword = bcrypt.hashSync(password, 10)

  try {
    await db.run(
      'INSERT INTO users (email, password, is_admin) VALUES (?, ?, ?)',
      [email, hashedPassword, is_admin],
    )
    res.send('User created successfully')
  } catch (err) {
    res.status(400).send('Error creating user')
  }
})

// Librarian API: View Borrow Requests
app.get('/borrow-requests', authenticateUser, async (req, res) => {
  if (!req.user.is_admin) {
    return res.status(403).send('Access denied')
  }

  const requests = await db.all('SELECT * FROM borrow_requests')
  res.send(requests)
})

// Librarian API: Approve/Deny Request
app.put('/borrow-requests/:id', authenticateUser, async (req, res) => {
  if (!req.user.is_admin) {
    return res.status(403).send('Access denied')
  }

  const {id} = req.params
  const {status} = req.body

  try {
    await db.run('UPDATE borrow_requests SET status = ? WHERE id = ?', [
      status,
      id,
    ])
    res.send('Request updated')
  } catch (err) {
    res.status(400).send('Error updating request')
  }
})

// User API: Get Books
app.get('/books', authenticateUser, async (req, res) => {
  const books = await db.all('SELECT * FROM books')
  res.send(books)
})

// User API: Borrow Book
app.post('/borrow-requests', authenticateUser, async (req, res) => {
  const {book_id, start_date, end_date} = req.body

  // Check if the book is already borrowed during this period
  const conflict = await db.get(
    'SELECT * FROM borrow_requests WHERE book_id = ? AND status = "Approved" AND (? BETWEEN start_date AND end_date OR ? BETWEEN start_date AND end_date)',
    [book_id, start_date, end_date],
  )

  if (conflict) {
    return res
      .status(400)
      .send('Book already borrowed during the selected period')
  }

  try {
    await db.run(
      'INSERT INTO borrow_requests (book_id, user_id, start_date, end_date, status) VALUES (?, ?, ?, ?, "Pending")',
      [book_id, req.user.id, start_date, end_date],
    )
    res.send('Request submitted')
  } catch (err) {
    res.status(400).send('Error submitting request')
  }
})

// Initialize the Database and Server
initializeDbAndServer()
